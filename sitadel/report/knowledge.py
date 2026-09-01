"""Remediation and standards knowledge base for findings.

A small, data-only table keyed by *finding type* (the attack plugin's name,
lowercased). Each entry supplies sane defaults for a finding's severity,
confidence, and the standards mapping (CWE, OWASP Top-10, OWASP WSTG) plus
remediation guidance. The output bridge (``lib/utils/output.py``) uses this to
enrich findings *incrementally*: any field a plugin passes explicitly wins;
anything it omits is filled from here so existing single-string
``output.finding("text")`` calls still gain severity and context for free.

Keys are matched case-insensitively. Lookup also tolerates a plugin
``__repr__`` such as ``Injection`` (the package name) by falling back to a
substring scan, so enrichment degrades gracefully rather than failing when a
plugin reports under a coarse label.
"""

from __future__ import annotations

from sitadel.report.report import Severity

# finding-type -> defaults. Only include keys that add value; everything else
# falls through to ``_DEFAULT``.
KNOWLEDGE: dict[str, dict] = {
    "sql": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-INPV-05",
        "remediation": (
            "Use parameterized queries / prepared statements and an ORM; never "
            "concatenate user input into SQL. Apply least-privilege database "
            "accounts and validate/whitelist input."
        ),
    },
    "xss": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-INPV-01",
        "remediation": (
            "Context-aware output encoding on all reflected/stored data, a "
            "restrictive Content-Security-Policy, and framework auto-escaping. "
            "Validate input and avoid injecting untrusted data into the DOM."
        ),
    },
    "html": {
        "severity": Severity.MEDIUM,
        "confidence": "tentative",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-CLNT-03",
        "remediation": (
            "Encode user input before rendering it as HTML and sanitize markup "
            "with an allow-list to prevent HTML injection."
        ),
    },
    "php": {
        "severity": Severity.CRITICAL,
        "confidence": "firm",
        "cwe": "CWE-94",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-INPV-11",
        "remediation": (
            "Never pass user input to eval()/include with dynamic paths. Disable "
            "dangerous functions and validate input against a strict allow-list."
        ),
    },
    "rfi": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-98",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-INPV-11",
        "remediation": (
            "Disable remote file inclusion (allow_url_include=Off), avoid "
            "user-controlled include paths, and use an allow-list of local "
            "resources."
        ),
    },
    "ldap": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-90",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-INPV-06",
        "remediation": (
            "Escape LDAP special characters, use parameterized LDAP APIs, and "
            "validate input before building distinguished names or filters."
        ),
    },
    "xpath": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-643",
        "owasp": "A03:2021-Injection",
        "wstg": "WSTG-INPV-09",
        "remediation": (
            "Use parameterized XPath queries and escape/validate user input "
            "before embedding it in XPath expressions."
        ),
    },
    "idor": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-639",
        "owasp": "A01:2021-Broken Access Control",
        "wstg": "WSTG-ATHZ-04",
        "remediation": (
            "Enforce object-level authorization on every request; verify the "
            "authenticated user owns or may access the referenced object. Use "
            "unpredictable identifiers as defence in depth, not as the control."
        ),
    },
    "access_control": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-284",
        "owasp": "A01:2021-Broken Access Control",
        "wstg": "WSTG-ATHZ-02",
        "remediation": (
            "Enforce access control server-side by default-deny; check function- "
            "and object-level permissions on every protected route."
        ),
    },
    "websocket": {
        "severity": Severity.LOW,
        "confidence": "firm",
        "cwe": "CWE-1385",
        "owasp": "A05:2021-Security Misconfiguration",
        "wstg": "WSTG-CLNT-10",
        "remediation": (
            "Authenticate the WebSocket handshake and validate the Origin header "
            "against an allow-list; do not expose sensitive channels without "
            "authorization on the upgrade request."
        ),
    },
    "cswsh": {
        "severity": Severity.HIGH,
        "confidence": "firm",
        "cwe": "CWE-1385",
        "owasp": "A01:2021-Broken Access Control",
        "wstg": "WSTG-CLNT-10",
        "remediation": (
            "Strictly validate the Origin header on the WebSocket handshake with "
            "an allow-list and bind each connection to a per-session CSRF token; "
            "reject handshakes from unexpected origins."
        ),
    },
    "jwt": {
        "severity": Severity.CRITICAL,
        "confidence": "firm",
        "cwe": "CWE-347",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "wstg": "WSTG-SESS-10",
        "remediation": (
            "Reject 'alg':'none', pin the expected signing algorithm server-side, "
            "verify signatures with the correct key type, enforce exp/nbf/iss/aud, "
            "and use a strong random secret for HMAC."
        ),
    },
}

_DEFAULT: dict = {
    "severity": Severity.INFO,
    "confidence": "tentative",
    "cwe": None,
    "owasp": None,
    "wstg": None,
    "remediation": None,
}


def lookup(finding_type: str | None) -> dict:
    """Return the knowledge entry for ``finding_type`` (or defaults).

    Matching is case-insensitive and tolerant: an exact key wins; otherwise a
    known key contained in the token (e.g. ``"Sql"`` inside ``"sql injection"``)
    is used. Unknown types get the neutral default.
    """
    if not finding_type:
        return dict(_DEFAULT)
    key = str(finding_type).strip().lower()
    if key in KNOWLEDGE:
        return dict(KNOWLEDGE[key])
    for known, entry in KNOWLEDGE.items():
        if known in key:
            return dict(entry)
    return dict(_DEFAULT)
