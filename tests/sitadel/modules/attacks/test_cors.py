"""CORS check: reflected/wildcard origin with credentials is flagged correctly."""
import logging

import pytest

from sitadel.report import Findings, Severity
from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, headers):
        self.headers = headers


class _FakeRequest:
    """Returns canned CORS headers regardless of URL."""

    def __init__(self, headers):
        self._headers = headers

    def send(self, url, method="GET", payload=None, headers=None, cookies=None):
        return _Resp(dict(self._headers))


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("cors"))
    Services.register("findings", Findings())
    yield
    for key in ("output", "logger", "findings", "request_factory"):
        Services.services.pop(key, None)


def _run(cors_headers):
    Services.register("request_factory", _FakeRequest(cors_headers))
    from sitadel.modules.attacks.other.cors import Cors
    Cors().process("http://ex.com/", [])
    return Services.get("findings").all()


def test_reflected_origin_with_credentials_is_high():
    findings = _run({
        "Access-Control-Allow-Origin": "https://evil.example",
        "Access-Control-Allow-Credentials": "true",
    })
    if not findings or findings[0].severity != Severity.HIGH:
        raise AssertionError("reflected origin + credentials must be HIGH")


def test_reflected_origin_without_credentials_is_medium():
    findings = _run({"Access-Control-Allow-Origin": "https://evil.example"})
    if not findings or findings[0].severity != Severity.MEDIUM:
        raise AssertionError("reflected origin only must be MEDIUM")


def test_wildcard_with_credentials_flagged():
    findings = _run({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    if not findings:
        raise AssertionError("wildcard + credentials must be reported")


def test_strict_cors_produces_no_finding():
    findings = _run({"Access-Control-Allow-Origin": "https://trusted.example"})
    if findings:
        raise AssertionError("origin that is not reflected must not be flagged")


def test_no_cors_headers_no_finding():
    if _run({}):
        raise AssertionError("absent CORS headers must not be flagged")
