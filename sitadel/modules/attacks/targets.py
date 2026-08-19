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
    """

    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body_format: str | None = None
    params: dict = field(default_factory=dict)

    def describe(self) -> str:
        if self.body_format:
            return f"{self.method} {self.url} ({self.body_format} body)"
        return self.url


def taint_url(url: str, payload: str) -> str | None:
    """Rebuild ``url`` with every query parameter value replaced by ``payload``.

    Returns ``None`` when there are no query parameters to inject into.
    """
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query))
    if not params:
        return None
    tainted = {name: payload for name in params}
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(tainted), parts.fragment)
    )


def taint_body(params: dict, payload: str, body_format: str) -> str:
    """Encode ``params`` with every value replaced by ``payload``.

    Supports ``json`` (object), ``xml`` (``<root>`` with a child per param) and
    ``form`` (url-encoded). Values are payload-tainted so the injection reaches
    each field in turn-agnostic fashion (all fields at once, like ``taint_url``).
    """
    names = list(params) or ["input"]
    if body_format == "json":
        return json.dumps({name: payload for name in names})
    if body_format == "xml":
        body = "".join(
            f"<{name}>{_xml_escape(payload)}</{name}>" for name in names
        )
        return f"<root>{body}</root>"
    if body_format == "form":
        return urlencode({name: payload for name in names})
    raise ValueError(f"unknown body_format: {body_format}")


def taint_target(target: Target, payload: str) -> dict | None:
    """Return ``SingleRequest.send`` kwargs that inject ``payload`` into ``target``.

    ``None`` is returned when there is nothing to inject (a GET target with no
    query parameters), so callers skip it exactly as the URL-only code did.
    """
    if target.body_format in BODY_FORMATS:
        body = taint_body(target.params, payload, target.body_format)
        headers = dict(target.headers)
        headers.setdefault("Content-Type", _CONTENT_TYPE[target.body_format])
        method = target.method if target.method != "GET" else "POST"
        return {
            "url": target.url,
            "method": method,
            "payload": body,
            "headers": headers,
        }
    tainted = taint_url(target.url, payload)
    if tainted is None:
        return None
    return {
        "url": tainted,
        "method": target.method or "GET",
        "payload": None,
        "headers": dict(target.headers) or None,
    }
