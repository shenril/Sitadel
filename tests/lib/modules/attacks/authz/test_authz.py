import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, ThreadingMixIn
from urllib.parse import parse_qs, urlsplit

import pytest

from lib.modules.attacks.authz.access_control import AccessControl
from lib.modules.attacks.authz.idor import Idor
from lib.modules.attacks.authz.idutils import object_refs, replace_id, different
from lib.request.auth import Authenticator
from lib.request.request import SingleRequest
from lib.utils.container import Services
from lib.utils.output import Output


# --------------------------------------------------------------------------- #
# Unit tests
# --------------------------------------------------------------------------- #
def test_object_refs():
    refs = object_refs("http://h/item?id=5&q=x")
    if ("query", "id", "5") not in refs:
        raise AssertionError
    refs = object_refs("http://h/users/42/profile")
    if ("path", "42", "42") not in refs:
        raise AssertionError
    if object_refs("http://h/about"):
        raise AssertionError


def test_replace_id():
    if replace_id("http://h/item?id=5&q=x", "query", "id", 6) != "http://h/item?id=6&q=x":
        raise AssertionError
    if replace_id("http://h/users/42/x", "path", "42", 43) != "http://h/users/43/x":
        raise AssertionError


def test_different():
    if different("object one payload " * 5, "object two payload " * 5) is not True:
        raise AssertionError
    if different("same", "same") is not False:
        raise AssertionError


# --------------------------------------------------------------------------- #
# Integration
# --------------------------------------------------------------------------- #
class _Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def server_bind(self):
        TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name, self.server_port = host, port


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/item":
            ids = parse_qs(parts.query).get("id", ["0"])
            num = ids[0]
            if num in ("1", "2", "3"):
                self._send(f"Confidential object number {num} " * 4)
            else:
                self._send("not found", code=404)
        elif parts.path == "/doc":
            # A protected-looking document served to everyone (misconfig).
            self._send("Confidential document body content here " * 3)
        else:
            self._send("root page")

    def do_POST(self):
        self._send("ok")


@pytest.fixture
def site():
    server = _Server(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    Services.register("output", Output())
    Services.register("logger", logging.getLogger("test"))
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_idor_detected(site, capsys):
    Services.register("request_factory", SingleRequest(timeout=5))
    Idor().process(site, [f"{site}/item?id=1"])
    if "Possible IDOR" not in capsys.readouterr().out:
        raise AssertionError


def test_access_control_flags_anonymous_access(site, capsys):
    req = SingleRequest(timeout=5)
    req.set_authenticator(
        Authenticator.from_options(login_url=f"{site}/login", login_data="u=a")
    )
    Services.register("request_factory", req)
    AccessControl().process(site, [f"{site}/doc?id=1"])
    if "Broken Access Control" not in capsys.readouterr().out:
        raise AssertionError


def test_access_control_skips_without_auth(site, capsys):
    Services.register("request_factory", SingleRequest(timeout=5))
    AccessControl().process(site, [f"{site}/doc?id=1"])
    out = capsys.readouterr().out
    if "Skipping access-control" not in out:
        raise AssertionError
