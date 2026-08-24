import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, ThreadingMixIn
from urllib.parse import urlsplit

import jwt as pyjwt
import pytest

from sitadel.modules.attacks.auth import jwtutils as ju
from sitadel.modules.attacks.auth.jwt import Jwt
from sitadel.request.auth import Authenticator
from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output

SECRET = "secret"  # weak, present in lib/data/jwt-secrets.txt


def _valid_token(**claims):
    payload = {"user": "alice", "exp": 9999999999}
    payload.update(claims)
    return pyjwt.encode(payload, SECRET, algorithm="HS256")


# --------------------------------------------------------------------------- #
# Unit tests: token surgery
# --------------------------------------------------------------------------- #
def test_looks_like_jwt():
    if not ju.looks_like_jwt(_valid_token()):
        raise AssertionError
    if ju.looks_like_jwt("not.a.jwt") or ju.looks_like_jwt("plain"):
        raise AssertionError


def test_discover_tokens_header_and_cookie():
    tok = _valid_token()
    locs = ju.discover_tokens(
        {"Authorization": f"Bearer {tok}", "X-Api-Key": "nope"},
        {"session": tok, "other": "abc"},
    )
    kinds = {(loc.kind, loc.name, loc.prefix) for loc in locs}
    if ("header", "Authorization", "Bearer ") not in kinds:
        raise AssertionError("bearer header token must be discovered")
    if ("cookie", "session", "") not in kinds:
        raise AssertionError("cookie token must be discovered")
    if len(locs) != 2:
        raise AssertionError("non-JWT values must be ignored")


def test_forge_alg_none_strips_signature():
    tok = _valid_token()
    forged = ju.forge_alg_none(tok)
    if ju.decode_header(forged)["alg"] != "none":
        raise AssertionError
    if not forged.endswith("."):  # empty signature segment
        raise AssertionError
    if ju.decode_claims(forged)["user"] != "alice":
        raise AssertionError("claims must be preserved")


def test_brute_hmac_secret_finds_weak_key():
    tok = _valid_token()
    if ju.brute_hmac_secret(tok, ["wrong", SECRET, "other"]) != SECRET:
        raise AssertionError
    if ju.brute_hmac_secret(tok, ["wrong", "other"]) is not None:
        raise AssertionError


def test_brute_ignores_non_hmac():
    priv = _rsa_private()
    rs = pyjwt.encode({"user": "alice"}, priv, algorithm="RS256")
    if ju.brute_hmac_secret(rs, [SECRET]) is not None:
        raise AssertionError


def test_forge_hmac_roundtrips():
    tok = _valid_token()
    forged = ju.forge_hmac(tok, b"pubkeyish", alg="HS256")
    if ju.brute_hmac_secret(forged, ["pubkeyish"]) != "pubkeyish":
        raise AssertionError


def test_forge_kid_empty_sets_traversal_and_empty_key():
    tok = _valid_token()
    forged = ju.forge_kid_empty(tok)
    header = ju.decode_header(forged)
    if "dev/null" not in header["kid"]:
        raise AssertionError
    # Signed with an empty key.
    if ju.brute_hmac_secret(forged, [""]) != "":
        raise AssertionError


def _rsa_private():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_confusion_forge_uses_public_key_as_hmac_secret():
    from cryptography.hazmat.primitives import serialization
    priv = _rsa_private()
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    rs = pyjwt.encode({"user": "alice"}, priv, algorithm="RS256")
    forged = ju.forge_confusion(rs, pem)
    if ju.decode_header(forged)["alg"] != "HS256":
        raise AssertionError
    if ju.brute_hmac_secret(forged, [pem]) is None:
        raise AssertionError


def test_jwks_to_pem_roundtrip():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = RSAAlgorithm.to_jwk(priv.public_key())
    body = '{"keys": [%s]}' % jwk
    pem = Jwt._jwks_to_pem(body)
    if pem is None or "BEGIN PUBLIC KEY" not in pem:
        raise AssertionError


# --------------------------------------------------------------------------- #
# Integration: a server that accepts alg:none (vulnerable) but validates HS256
# --------------------------------------------------------------------------- #
class _Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def server_bind(self):
        TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name, self.server_port = host, port


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _token(self):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        # Also accept the token from a `session` cookie.
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session" and value:
                return value
        return None

    def do_GET(self):
        if urlsplit(self.path).path.startswith("/.well-known"):
            return self._send("{}", 404)
        token = self._token()
        if not token:
            return self._send("Login required", 401)
        try:
            alg = pyjwt.get_unverified_header(token).get("alg")
        except Exception:
            return self._send("Bad token", 401)
        if alg == "none":
            # Vulnerable: signature not verified, exp not enforced.
            claims = pyjwt.decode(
                token, options={"verify_signature": False, "verify_exp": False}
            )
            return self._send(f"Welcome {claims.get('user', '?')} - dashboard")
        if alg == "HS256":
            try:
                claims = pyjwt.decode(token, SECRET, algorithms=["HS256"])
            except Exception:
                return self._send("Invalid token", 401)
            return self._send(f"Welcome {claims.get('user', '?')} - dashboard")
        return self._send("Unsupported alg", 401)


class _StrictHandler(_VulnHandler):
    def do_GET(self):
        token = self._token()
        if not token:
            return self._send("Login required", 401)
        try:
            claims = pyjwt.decode(token, SECRET, algorithms=["HS256"])
        except Exception:
            return self._send("Invalid token", 401)
        return self._send(f"Welcome {claims.get('user', '?')} - dashboard")


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output())
    Services.register("logger", logging.getLogger("test"))
    Services.register("datastore", Datastore("sitadel/data"))
    yield
    Services.services.pop("findings", None)


def _serve(handler):
    server = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def _run(site, token, cookie=False):
    req = SingleRequest(timeout=5)
    if cookie:
        req.set_authenticator(Authenticator.from_options(
            headers=None, login_url=None, login_data=None,
            logged_in_check="Welcome"))
        req.session.cookies.set("session", token)
    else:
        req.set_authenticator(Authenticator.from_options(
            bearer=token, logged_in_check="Welcome"))
    Services.register("request_factory", req)
    Jwt().process(site, [site])


def test_alg_none_weak_secret_and_exp_detected(capsys):
    server, site = _serve(_VulnHandler)
    try:
        _run(site, _valid_token())
    finally:
        server.shutdown()
        server.server_close()
    out = capsys.readouterr().out
    if "alg:none" not in out:
        raise AssertionError("alg:none acceptance must be reported")
    if "weak/guessable HMAC secret" not in out:
        raise AssertionError("weak secret must be reported")
    if "'exp' claim is not enforced" not in out:
        raise AssertionError("unenforced exp must be reported")


def test_cookie_borne_token_is_tested(capsys):
    server, site = _serve(_VulnHandler)
    try:
        _run(site, _valid_token(), cookie=True)
    finally:
        server.shutdown()
        server.server_close()
    out = capsys.readouterr().out
    if "alg:none" not in out or "cookie 'session'" not in out:
        raise AssertionError("cookie-borne JWT must be discovered and tested")


def test_strict_server_produces_no_bypass_findings(capsys):
    server, site = _serve(_StrictHandler)
    try:
        _run(site, _valid_token())
    finally:
        server.shutdown()
        server.server_close()
    out = capsys.readouterr().out
    # A correctly-validating server must not yield alg:none / kid bypass.
    if "alg:none" in out or "kid' path traversal" in out:
        raise AssertionError("no bypass findings on a strict validator")
    # The weak secret is still a real offline finding, independent of replay.
    if "weak/guessable HMAC secret" not in out:
        raise AssertionError("offline weak-secret detection is unaffected")


def test_no_token_no_op(capsys):
    server, site = _serve(_VulnHandler)
    try:
        req = SingleRequest(timeout=5)  # no authenticator, no token
        Services.register("request_factory", req)
        Jwt().process(site, [site])
    finally:
        server.shutdown()
        server.server_close()
    out = capsys.readouterr().out
    if "No JWT found" not in out:
        raise AssertionError("must no-op cleanly when no token is present")
