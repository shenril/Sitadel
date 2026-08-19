import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, ThreadingMixIn
from urllib.parse import urlsplit

import pytest

from sitadel.model import TargetProfile
from sitadel.modules.discovery import discover
from sitadel.modules.discovery.api import _parse_spec, targets_from_spec
from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output

OAS3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "/api/v1"}],
    "paths": {
        "/login": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Login"}
                        }
                    }
                }
            }
        },
        "/items/{id}": {
            "get": {"parameters": [{"in": "query", "name": "filter"}]}
        },
    },
    "components": {
        "schemas": {"Login": {"properties": {"username": {}, "password": {}}}}
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "basePath": "/rest",
    "paths": {
        "/users": {
            "post": {
                "parameters": [
                    {"in": "body", "name": "b",
                     "schema": {"properties": {"email": {}, "role": {}}}}
                ]
            }
        }
    },
}


# --------------------------------------------------------------------------- #
# Spec parsing
# --------------------------------------------------------------------------- #
def test_parse_spec_accepts_openapi_rejects_junk():
    if _parse_spec(json.dumps(OAS3)) is None:
        raise AssertionError
    if _parse_spec("<html>not a spec</html>") is not None:
        raise AssertionError
    if _parse_spec(json.dumps({"paths": {}})) is not None:  # no openapi/swagger key
        raise AssertionError


def test_targets_from_openapi3():
    targets = targets_from_spec(OAS3, "http://h")
    by_desc = {t.describe(): t for t in targets}
    login = next(t for t in targets if t.body_format == "json")
    if login.url != "http://h/api/v1/login" or login.method != "POST":
        raise AssertionError
    if set(login.params) != {"username", "password"}:
        raise AssertionError("JSON body params must come from the $ref schema")
    get = next(t for t in targets if t.method == "GET")
    if "filter=1" not in get.url or "/items/1" not in get.url:
        raise AssertionError("path template and query param must be materialized")
    if not by_desc:
        raise AssertionError


def test_targets_from_swagger2_body_param():
    targets = targets_from_spec(SWAGGER2, "http://h")
    t = targets[0]
    if t.url != "http://h/rest/users" or t.body_format != "json":
        raise AssertionError
    if set(t.params) != {"email", "role"}:
        raise AssertionError


# --------------------------------------------------------------------------- #
# Integration: spec served over HTTP + a SQL-vulnerable JSON endpoint
# --------------------------------------------------------------------------- #
class _Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def server_bind(self):
        TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name, self.server_port = host, port


class _ApiHandler(BaseHTTPRequestHandler):
    spec = OAS3

    def log_message(self, *a):
        pass

    def _send(self, body, code=200, ctype="application/json"):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/openapi.json":
            # Rewrite server url to this host so targets hit us.
            spec = json.loads(json.dumps(self.spec))
            spec["servers"] = [{"url": "/"}]
            return self._send(json.dumps(spec))
        return self._send("{}", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        # Vulnerable: a single quote in any field triggers a SQL error.
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        if any("'" in str(v) for v in data.values()):
            return self._send(
                "You have an error in your SQL syntax; check the manual",
                code=500, ctype="text/html",
            )
        return self._send("ok")


@pytest.fixture
def api_site():
    server = _Server(("127.0.0.1", 0), _ApiHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    Services.register("output", Output())
    Services.register("logger", logging.getLogger("test"))
    Services.register("datastore", Datastore("sitadel/data"))
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        Services.services.pop("api_targets", None)


def test_discover_finds_spec_and_sets_profile(api_site):
    profile = TargetProfile()
    targets = discover(api_site, SingleRequest(timeout=5), profile=profile,
                       output=Output())
    if not any(t.body_format == "json" for t in targets):
        raise AssertionError("a JSON body target must be discovered")
    if profile.api_type != "rest" or not profile.is_api():
        raise AssertionError("profile.api_type must be set to rest")


def test_json_body_sql_injection_detected_end_to_end(api_site, capsys):
    targets = discover(api_site, SingleRequest(timeout=5))
    Services.register("api_targets", targets)
    Services.register(
        "request_factory", SingleRequest(url=api_site, timeout=5)
    )
    # Import lazily: the plugin resolves Services at class-definition time.
    from sitadel.modules.attacks.injection.sql import Sql
    # Crawled URLs empty: the only injectable surface is the discovered API.
    Sql().process(api_site, [])
    out = capsys.readouterr().out
    if "SQL Injection" not in out and "MySQL Injection" not in out:
        raise AssertionError("JSON body SQLi must be detected via the spec")
    if "json body" not in out:
        raise AssertionError("finding must point at the JSON body surface")


def test_no_spec_is_a_clean_no_op(capsys):
    # A server with no spec: discovery returns nothing, profile stays non-API.
    class _Blank(_ApiHandler):
        def do_GET(self):
            self._send("not found", 404, "text/html")

    server = _Server(("127.0.0.1", 0), _Blank)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    site = f"http://{host}:{port}"
    try:
        profile = TargetProfile()
        targets = discover(site, SingleRequest(timeout=5), profile=profile)
        if targets:
            raise AssertionError("no spec must yield no targets")
        if profile.is_api():
            raise AssertionError("HTML-only target must not be flagged as API")
    finally:
        server.shutdown()
        server.server_close()
