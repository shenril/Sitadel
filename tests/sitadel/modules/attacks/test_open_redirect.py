"""Open-redirect: taint targeting + Location-based detection (no real network)."""
import logging

import pytest

from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, status_code, location=None):
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}


class _FakeRequest:
    def __init__(self, resp):
        self._resp = resp

    def send(self, url, method="GET", payload=None, headers=None,
             cookies=None, allow_redirects=None):
        return self._resp


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("or"))
    Services.register("findings", Findings())
    yield
    for k in ("output", "logger", "findings", "request_factory"):
        Services.services.pop(k, None)


def test_taint_only_redirect_style_params():
    from sitadel.modules.attacks.other.open_redirect import (
        _taint_redirect_params, _MARKER_HOST,
    )
    out = _taint_redirect_params("http://ex.com/p?next=/home&q=1", "//%s/" % _MARKER_HOST)
    if out is None or _MARKER_HOST not in out or "q=1" not in out:
        raise AssertionError("redirect param must be tainted, others preserved")
    # No redirect-style param -> skipped.
    if _taint_redirect_params("http://ex.com/p?q=1", "x") is not None:
        raise AssertionError("URL without a redirect param must be skipped")


def _run(resp, url="http://ex.com/go?next=/home"):
    from sitadel.modules.attacks.other.open_redirect import OpenRedirect
    Services.register("request_factory", _FakeRequest(resp))
    OpenRedirect().process("http://ex.com/", [url])
    return Services.get("findings").all()


def test_redirect_to_marker_is_flagged():
    from sitadel.modules.attacks.other.open_redirect import _MARKER_HOST
    findings = _run(_Resp(302, "https://%s/" % _MARKER_HOST))
    if not findings:
        raise AssertionError("redirect to the marker host must be flagged")


def test_same_site_redirect_not_flagged():
    if _run(_Resp(302, "https://ex.com/home")):
        raise AssertionError("a same-site redirect must not be flagged")


def test_no_location_not_flagged():
    if _run(_Resp(200, None)):
        raise AssertionError("a 200 with no Location must not be flagged")
