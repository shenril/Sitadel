"""Passive secret scan over crawler-cached page bodies."""
import logging

import pytest

from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("secrets"))
    Services.register("findings", Findings())
    yield
    for k in ("output", "logger", "findings", "page_bodies", "request_factory", "cancel"):
        Services.services.pop(k, None)


def _run(bodies):
    Services.register("page_bodies", bodies)
    from sitadel.modules.attacks.other.secrets import Secrets
    Secrets().process("http://ex.com/", [])
    return Services.get("findings").all()


def test_aws_key_is_flagged_and_redacted():
    findings = _run({"http://ex.com/app.js": "var k='AKIAIOSFODNN7EXAMPLE';"})
    hit = [f for f in findings if "AWS" in (f.parameter or "")]
    if not hit:
        raise AssertionError("AWS key must be flagged")
    if "AKIAIOSFODNN7EXAMPLE" in (hit[0].evidence or ""):
        raise AssertionError("the raw secret must be redacted in evidence")


def test_private_key_block_is_flagged():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc...\n-----END RSA PRIVATE KEY-----"
    if not any("Private key" in (f.parameter or "") for f in _run({"http://ex.com/x": body})):
        raise AssertionError("private key block must be flagged")


def test_clean_page_no_findings():
    if _run({"http://ex.com/": "<html>nothing secret here</html>"}):
        raise AssertionError("a clean page must not produce findings")


def test_fallback_fetches_when_no_cache(monkeypatch):
    # No page_bodies registered -> the scanner fetches via request_factory.
    class _Resp:
        text = "token = 'AIzaSyA1234567890123456789012345678901234'"
        status_code = 200

    class _Req:
        def send(self, url, method="GET", payload=None, headers=None, cookies=None):
            return _Resp()

    Services.register("request_factory", _Req())
    from sitadel.modules.attacks.other.secrets import Secrets
    Secrets().process("http://ex.com/", [])
    if not any("Google" in (f.parameter or "") for f in Services.get("findings").all()):
        raise AssertionError("fallback fetch path should scan and flag")
