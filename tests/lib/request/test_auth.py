import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, ThreadingMixIn
from urllib.parse import parse_qs, urlsplit

import pytest

from lib.request.auth import Authenticator
from lib.request.request import SingleRequest
from lib.utils.container import Services
from lib.utils.output import Output


# --------------------------------------------------------------------------- #
# Unit tests
# --------------------------------------------------------------------------- #
def test_from_options_builds_headers():
    auth = Authenticator.from_options(basic="admin:secret")
    if not auth.headers["Authorization"].startswith("Basic "):
        raise AssertionError

    auth = Authenticator.from_options(bearer="tok")
    if auth.headers["Authorization"] != "Bearer tok":
        raise AssertionError

    auth = Authenticator.from_options(headers=["X-Api-Key: abc", "X-Env: test"])
    if auth.headers["X-Api-Key"] != "abc" or auth.headers["X-Env"] != "test":
        raise AssertionError

    if Authenticator.from_options() is not None:
        raise AssertionError  # no auth configured


def test_singlerequest_merges_auth_header():
    Services.register("output", Output())
    req = SingleRequest()
    req.set_authenticator(Authenticator.from_options(bearer="tok"))
    prepped = req.prepare_request("http://example.com", "GET", None, None, None)
    if prepped.headers.get("Authorization") != "Bearer tok":
        raise AssertionError


# --------------------------------------------------------------------------- #
# Integration against a local login-protected site
# --------------------------------------------------------------------------- #
_VALID_TOKENS = set()


class _Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def server_bind(self):
        TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name, self.server_port = host, port


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, cookie=None):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def _session_ok(self):
        cookie = self.headers.get("Cookie", "")
        return any(
            c.strip().startswith("session=") and c.strip().split("=", 1)[1] in _VALID_TOKENS
            for c in cookie.split(";")
        )

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/login":
            self._send('<form><input name="csrf" value="tok123"></form>')
        elif path == "/expire":
            _VALID_TOKENS.clear()
            self._send("expired")
        elif path == "/home":
            self._send("Welcome admin" if self._session_ok() else "Please login")
        else:
            self._send("root")

    def do_POST(self):
        if urlsplit(self.path).path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode())
            ok = (
                data.get("user") == ["admin"]
                and data.get("password") == ["secret"]
                and data.get("csrf") == ["tok123"]
            )
            if ok:
                token = f"t{len(_VALID_TOKENS)}x"
                _VALID_TOKENS.add(token)
                self._send("logged in", cookie=f"session={token}; Path=/")
            else:
                self._send("bad creds", code=403)
        else:
            self._send("nope", code=404)


@pytest.fixture
def login_site():
    _VALID_TOKENS.clear()
    server = _Server(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _authenticator(base):
    return Authenticator.from_options(
        login_url=f"{base}/login",
        login_data="user=admin&password=secret",
        csrf_field="csrf",
        logged_in_check="Welcome",
    )


def test_form_login_reaches_protected_page(login_site):
    Services.register("output", Output())
    req = SingleRequest(timeout=5)
    req.set_authenticator(_authenticator(login_site))
    req.login()
    resp = req.send(url=f"{login_site}/home")
    if "Welcome admin" not in resp.text:
        raise AssertionError

    # Without authentication, the same page is not accessible.
    anon = SingleRequest(timeout=5)
    if "Welcome admin" in anon.send(url=f"{login_site}/home").text:
        raise AssertionError


def test_reauth_on_session_drop(login_site):
    Services.register("output", Output())
    req = SingleRequest(timeout=5)
    req.set_authenticator(_authenticator(login_site))
    req.login()
    if "Welcome admin" not in req.send(url=f"{login_site}/home").text:
        raise AssertionError

    # Force the server to drop the session, then a normal request must detect
    # the logged-out response, re-authenticate, and still succeed.
    req.send(url=f"{login_site}/expire")
    resp = req.send(url=f"{login_site}/home")
    if "Welcome admin" not in resp.text:
        raise AssertionError
