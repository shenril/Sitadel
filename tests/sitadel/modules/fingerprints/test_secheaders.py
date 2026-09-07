"""Security-header audit: missing/weak headers are reported, strong ones aren't."""
import logging

import pytest
from requests.structures import CaseInsensitiveDict

from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("secheaders"))
    Services.register("findings", Findings())
    yield
    for key in ("output", "logger", "findings"):
        Services.services.pop(key, None)


def _run(headers):
    from sitadel.modules.fingerprints.header.secheaders import SecurityHeaders
    SecurityHeaders().process(CaseInsensitiveDict(headers), "")
    return [f.title for f in Services.get("findings").all()]


def test_all_missing_reports_each_header():
    titles = _run({})
    for token in ("Content-Security-Policy", "Strict-Transport-Security",
                  "X-Content-Type-Options", "Referrer-Policy",
                  "Permissions-Policy", "X-Frame-Options"):
        if not any(token in t for t in titles):
            raise AssertionError("missing %s not reported" % token)


def test_strong_headers_produce_no_findings():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-Frame-Options": "DENY",
    }
    if _run(headers):
        raise AssertionError("strong headers should produce no findings")


def test_weak_hsts_and_csp_and_nosniff_flagged():
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "Strict-Transport-Security": "max-age=100",
        "X-Content-Type-Options": "foo",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-Frame-Options": "DENY",
    }
    titles = _run(headers)
    if not any("unsafe-inline" in t for t in titles):
        raise AssertionError("weak CSP not flagged")
    if not any("max-age" in t for t in titles):
        raise AssertionError("weak HSTS not flagged")
    if not any("nosniff" in t for t in titles):
        raise AssertionError("weak X-Content-Type-Options not flagged")


def test_case_insensitive_header_names():
    # Headers present under different casing must be recognized (no false miss).
    headers = CaseInsensitiveDict({"content-security-policy": "default-src 'self'"})
    from sitadel.modules.fingerprints.header.secheaders import SecurityHeaders
    SecurityHeaders().process(headers, "")
    titles = [f.title for f in Services.get("findings").all()]
    if any("Content-Security-Policy header is not set" in t for t in titles):
        raise AssertionError("case-insensitive lookup failed")
