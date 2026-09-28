"""In-band SSRF: metadata reachability + fetch-error differential (no real net)."""
import logging

import pytest

from sitadel.report import Findings, Severity
from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200


class _FakeReq:
    """Canned responses keyed on the injected value in the sent URL.

    mode: 'metadata' | 'error' | 'clean' | 'fp' (error also in baseline).
    """

    def __init__(self, mode):
        self.mode = mode

    def send(self, url, method="GET", payload=None, headers=None, cookies=None,
             allow_redirects=None):
        if "169.254.169.254" in url or "metadata.google" in url:
            return _Resp("instance-id: i-0abc ami-id: ami-1 iam/info") \
                if self.mode == "metadata" else _Resp("request blocked")
        if "127.0.0.1" in url:  # closed-port probe
            if self.mode in ("error", "fp"):
                return _Resp("Fetch failed: Connection refused")
            return _Resp("ok")
        # baseline (example.com) and everything else
        if self.mode == "fp":
            return _Resp("Fetch failed: Connection refused")  # error also baseline
        return _Resp("ok")


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("ssrf"))
    Services.register("findings", Findings())
    yield
    for k in ("output", "logger", "findings", "request_factory", "cancel"):
        Services.services.pop(k, None)


def test_taint_only_ssrf_params():
    from sitadel.modules.attacks.other.ssrf import _taint_params
    out = _taint_params("http://h/p?url=x&q=1", "http://127.0.0.1:9/")
    if out is None or "127.0.0.1" not in out or "q=1" not in out:
        raise AssertionError
    if _taint_params("http://h/p?q=1", "x") is not None:
        raise AssertionError("URL without an SSRF param must be skipped")


def _run(mode, url="http://h/proxy?url=http://a.test/"):
    Services.register("request_factory", _FakeReq(mode))
    from sitadel.modules.attacks.other.ssrf import Ssrf
    Ssrf().process("http://h/", [url])
    return Services.get("findings").all()


def test_metadata_reachability_is_critical():
    findings = _run("metadata")
    if not findings or findings[0].severity != Severity.CRITICAL:
        raise AssertionError("metadata reachability must be CRITICAL SSRF")


def test_fetch_error_differential_flags_indicator():
    findings = _run("error")
    if not findings or "Potential SSRF" not in findings[0].title:
        raise AssertionError("closed-port fetch error should flag an SSRF indicator")


def test_no_finding_when_error_also_in_baseline():
    if _run("fp"):
        raise AssertionError("error present in baseline too -> differential must suppress")


def test_clean_endpoint_no_finding():
    if _run("clean"):
        raise AssertionError("no metadata markers and no fetch error -> no finding")


def test_no_ssrf_param_is_noop():
    if _run("metadata", url="http://h/page?id=1"):
        raise AssertionError("no SSRF-shaped param -> no requests, no findings")


def test_fetch_error_signatures_cover_common_clients():
    from sitadel.modules.attacks.other.ssrf import _FETCH_ERROR_SIGNATURES as R
    # Phrasings emitted by aiohttp, requests/urllib3, curl/PHP, Go, Node.
    for msg in ("Cannot connect to host 127.0.0.1:9 ssl:default [Connect call failed]",
                "Failed to establish a new connection: Connection refused",
                "cURL error 7: Failed to connect to 127.0.0.1 port 9",
                "dial tcp 127.0.0.1:9: connect: connection refused",
                "connect ECONNREFUSED 127.0.0.1:9"):
        if not R.search(msg):
            raise AssertionError("fetch-error signature missed: %r" % msg)
