"""Rate limiter spacing and in-scope host enforcement (#73)."""
import logging
import time

import pytest
import requests

from sitadel.request.request import SingleRequest, _RateLimiter
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _output():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("rl"))
    yield
    for k in ("output", "logger"):
        Services.services.pop(k, None)


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
def test_rate_limiter_spaces_requests():
    rl = _RateLimiter(rate=20)  # 0.05s between slots
    start = time.monotonic()
    for _ in range(5):
        rl.acquire()
    elapsed = time.monotonic() - start
    # 5 slots at 20/s reserve times 0, .05, .10, .15, .20 -> >= ~0.2s.
    if elapsed < 0.18:
        raise AssertionError("limiter did not space requests: %.3fs" % elapsed)


def test_rate_limiter_zero_is_noop():
    rl = _RateLimiter(rate=0)
    start = time.monotonic()
    for _ in range(100):
        rl.acquire()
    if time.monotonic() - start > 0.05:
        raise AssertionError("rate=0 must not block")


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
class _FakeSession:
    cookies = requests.cookies.RequestsCookieJar()

    def __init__(self, final_url):
        self._final_url = final_url
        self.calls = 0

    def send(self, prepped, **kwargs):
        self.calls += 1

        class _R:
            status_code = 200
            text = "ok"
            headers = {}
            url = self._final_url
        return _R()


def _req(**kw):
    r = SingleRequest(**kw)
    return r


def test_target_host_is_in_scope_by_default():
    r = _req(url="http://target.test/")
    if r.scope_hosts != {"target.test"}:
        raise AssertionError(r.scope_hosts)


def test_off_host_request_is_skipped():
    r = _req(url="http://target.test/")
    r.session = _FakeSession("http://evil.test/")
    if r.send(url="http://evil.test/x") is not None:
        raise AssertionError("off-host request must be skipped")
    if r.session.calls != 0:
        raise AssertionError("no HTTP should be sent for an out-of-scope URL")


def test_in_scope_request_is_sent():
    r = _req(url="http://target.test/")
    r.session = _FakeSession("http://target.test/x")
    resp = r.send(url="http://target.test/x")
    if resp is None or r.session.calls != 1:
        raise AssertionError("in-scope request must be sent")


def test_ssrf_style_payload_to_target_is_in_scope():
    # Destination is the target; the internal IP lives in the query (payload).
    r = _req(url="http://target.test/")
    r.session = _FakeSession("http://target.test/proxy?url=http://127.0.0.1/")
    resp = r.send(url="http://target.test/proxy?url=http://127.0.0.1/")
    if resp is None or r.session.calls != 1:
        raise AssertionError("SSRF probe to the target must NOT be scoped out")


def test_followed_redirect_off_host_is_discarded():
    # The request goes to the target but the chain ends off-host -> discard.
    r = _req(url="http://target.test/")
    r.session = _FakeSession("http://evil.test/landing")
    if r.send(url="http://target.test/r") is not None:
        raise AssertionError("off-host redirect result must be discarded")


def test_extra_scope_host_is_allowed():
    r = _req(url="http://target.test/", scope_hosts=["api.target.test"])
    r.session = _FakeSession("http://api.target.test/x")
    if r.send(url="http://api.target.test/x") is None:
        raise AssertionError("explicitly allowed host must be in scope")


def test_urlless_construction_is_unrestricted():
    # Back-compat: no target url => no scope restriction (used by tests).
    r = _req()
    if r.scope_hosts:
        raise AssertionError("url-less construction must be unrestricted")
