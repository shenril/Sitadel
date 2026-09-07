"""Security-header audit — issue #72.

Passive check: inspects the recon response's headers (no extra request) and
reports missing or weak security headers. Runs in the fingerprint phase like the
other ``header/*`` modules; findings are emitted through ``output.finding`` with
``finding_type="security_headers"`` so they self-enrich from the knowledge base.

The audit is data-driven: presence rules and weak-value rules live in small
module-level tables so the checks read as a list, not a wall of ``if``s.
"""
import re

from sitadel.modules.fingerprints import FingerprintPlugin
from sitadel.utils.container import Services

# Headers whose mere absence is worth reporting, with the guidance shown.
_MISSING_RULES = [
    ("Content-Security-Policy",
     "Content-Security-Policy header is not set (no XSS/data-injection defence-in-depth)."),
    ("Strict-Transport-Security",
     "Strict-Transport-Security header is not set (HTTPS is not enforced by the browser)."),
    ("X-Content-Type-Options",
     "X-Content-Type-Options header is not set (MIME-sniffing is not disabled)."),
    ("Referrer-Policy",
     "Referrer-Policy header is not set (referrer may leak to third parties)."),
    ("Permissions-Policy",
     "Permissions-Policy header is not set (browser features are not restricted)."),
    ("X-Frame-Options",
     "X-Frame-Options header is not set (page may be framed — clickjacking risk)."),
]

_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.I)
# Six months, the commonly recommended minimum for HSTS.
_HSTS_MIN = 15552000


def _weak_hsts(value):
    m = _HSTS_MAX_AGE.search(value or "")
    if not m or int(m.group(1)) < _HSTS_MIN:
        return ("Strict-Transport-Security max-age is missing or below ~180 days: "
                "%r" % value)
    if "includesubdomains" not in (value or "").lower():
        return "Strict-Transport-Security is set without includeSubDomains: %r" % value
    return None


def _weak_csp(value):
    lowered = (value or "").lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return ("Content-Security-Policy allows 'unsafe-inline'/'unsafe-eval', "
                "weakening XSS protection.")
    return None


def _weak_xcto(value):
    if (value or "").strip().lower() != "nosniff":
        return "X-Content-Type-Options is set but not to 'nosniff': %r" % value
    return None


# Weak-value rules: only evaluated when the header IS present.
_WEAK_RULES = [
    ("Strict-Transport-Security", _weak_hsts),
    ("Content-Security-Policy", _weak_csp),
    ("X-Content-Type-Options", _weak_xcto),
]


class SecurityHeaders(FingerprintPlugin):
    def process(self, headers, content):
        output = Services.get("output")
        # ``headers`` is a requests CaseInsensitiveDict, so ``get`` is case-safe.
        # ``parameter`` carries the header name so each header is a distinct
        # finding (the report de-duplicates on plugin+url+parameter, and these
        # findings share plugin and a null url).
        for name, message in _MISSING_RULES:
            if headers.get(name) is None:
                output.finding(message, finding_type="security_headers",
                               plugin="SecurityHeaders", parameter=name)
        for name, predicate in _WEAK_RULES:
            value = headers.get(name)
            if value is not None:
                message = predicate(value)
                if message:
                    output.finding(message, finding_type="security_headers",
                                   plugin="SecurityHeaders", parameter=name)
