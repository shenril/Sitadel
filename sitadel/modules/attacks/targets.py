"""Injectable-target model shared by every injection surface.

A :class:`Target` is a uniform description of *something to inject into* — an
HTML query string, an HTML form, or an API endpoint that takes a JSON/XML/form
body. The injection ``AttackPlugin``s consume ``Target``s instead of raw URL
strings, so the same detection logic reaches query parameters and request
bodies alike. Producers (the crawler, the API-discovery step, and eventually
the HTML-forms step in #70) all emit ``Target``s.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.sax.saxutils import escape as _xml_escape

# Body encodings we know how to taint. ``None`` means "GET query string".
BODY_FORMATS = ("form", "json", "xml")

_CONTENT_TYPE = {
    "form": "application/x-www-form-urlencoded",
    "json": "application/json",
    "xml": "application/xml",
}


@dataclass
class Target:
    """A single injectable request.

    ``body_format`` is ``None`` for a GET query-string target (parameters live
    in ``url``); otherwise it is one of :data:`BODY_FORMATS` and ``params`` maps
    parameter names to sample values that get replaced by the payload.

    ``fixed`` holds parameters that must be sent **verbatim** rather than
    tainted — hidden/CSRF form fields captured at crawl time. They are merged
    into the query or body alongside the tainted ``params`` so a token-protected
    form is submitted with its token intact (see the HTML-forms producer, #70).
    """

    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body_format: str | None = None
    params: dict = field(default_factory=dict)
    fixed: dict = field(default_factory=dict)

    def describe(self) -> str:
        if self.body_format:
            return f"{self.method} {self.url} ({self.body_format} body)"
        return self.url


def taint_url(url: str, payload: str, fixed=()) -> str | None:
    """Rebuild ``url`` with each query parameter value replaced by ``payload``.

    Parameter names listed in ``fixed`` keep their existing value (used for
    hidden/CSRF fields of a GET form); every other value is tainted. Returns
    ``None`` when there are no query parameters to inject into.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    fixed = set(fixed)
    tainted = [
        (name, value if name in fixed else payload) for name, value in pairs
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(tainted), parts.fragment)
    )


def taint_body(params: dict, payload: str, body_format: str, fixed: dict = None) -> str:
    """Encode ``params`` with every value replaced by ``payload``.

    Supports ``json`` (object), ``xml`` (``<root>`` with a child per param) and
    ``form`` (url-encoded). Values in ``params`` are payload-tainted so the
    injection reaches each field at once (like ``taint_url``); ``fixed`` fields
    (hidden/CSRF) are merged in **verbatim** so token-protected forms submit a
    valid token.
    """
    fixed = fixed or {}
    names = list(params)
    if not names and not fixed:
        names = ["input"]
    if body_format == "json":
        data = {name: payload for name in names}
        data.update(fixed)
        return json.dumps(data)
    if body_format == "xml":
        body = "".join(
            f"<{name}>{_xml_escape(payload)}</{name}>" for name in names
        )
        body += "".join(
            f"<{name}>{_xml_escape(str(value))}</{name}>"
            for name, value in fixed.items()
        )
        return f"<root>{body}</root>"
    if body_format == "form":
        data = {name: payload for name in names}
        data.update(fixed)
        return urlencode(data)
    raise ValueError(f"unknown body_format: {body_format}")


def taint_target(target: Target, payload: str) -> dict | None:
    """Return ``SingleRequest.send`` kwargs that inject ``payload`` into ``target``.

    ``None`` is returned when there is nothing to inject (a GET target with no
    query parameters), so callers skip it exactly as the URL-only code did.
    """
    if target.body_format in BODY_FORMATS:
        body = taint_body(target.params, payload, target.body_format, target.fixed)
        headers = dict(target.headers)
        headers.setdefault("Content-Type", _CONTENT_TYPE[target.body_format])
        method = target.method if target.method != "GET" else "POST"
        return {
            "url": target.url,
            "method": method,
            "payload": body,
            "headers": headers,
        }
    tainted = taint_url(target.url, payload, fixed=target.fixed.keys())
    if tainted is None:
        return None
    return {
        "url": tainted,
        "method": target.method or "GET",
        "payload": None,
        "headers": dict(target.headers) or None,
    }
