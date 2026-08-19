"""API-first discovery: turn an OpenAPI/Swagger spec (or a live REST prefix)
into injectable :class:`Target`s.

Sitadel otherwise only sees targets that appear in HTML ``<a>``/``<form>``
tags, so API surfaces are invisible. This producer ingests a spec — the
authoritative list of endpoints, methods and body parameters — and probes a
few well-known REST prefixes, emitting ``Target``s that the existing injection
plugins consume (query strings *and* JSON/XML/form bodies).

The parser is intentionally forgiving: a spec it cannot fully understand yields
fewer targets rather than an error, and a target with no discovered parameters
still gets a single ``input`` field so body injection has something to taint.
"""

from __future__ import annotations

import json
from urllib.parse import urlencode, urljoin, urlsplit

from sitadel.modules.attacks.targets import Target

# Well-known locations a spec is commonly served from.
SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
)

# REST prefixes to probe when no spec is found.
REST_PREFIXES = ("/api", "/api/v1", "/api/v2", "/rest")

_BODY_METHODS = ("post", "put", "patch", "delete")
_HTTP_METHODS = ("get",) + _BODY_METHODS

# content-type substring -> Target body_format
_CT_FORMATS = (
    ("application/json", "json"),
    ("application/xml", "xml"),
    ("text/xml", "xml"),
    ("x-www-form-urlencoded", "form"),
)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _parse_spec(body: str):
    """Parse a spec body as JSON, falling back to YAML. Returns a dict or None."""
    try:
        doc = json.loads(body)
    except Exception:
        try:
            import yaml
            doc = yaml.safe_load(body)
        except Exception:
            return None
    if not isinstance(doc, dict):
        return None
    if ("openapi" in doc or "swagger" in doc) and isinstance(doc.get("paths"), dict):
        return doc
    return None


def _resolve_ref(doc: dict, ref: str):
    """Resolve a local ``#/...`` JSON pointer within ``doc``."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _schema_params(doc: dict, schema, _depth=0) -> dict:
    """Return ``{property_name: sample_value}`` for a (possibly $ref'd) schema."""
    if not isinstance(schema, dict) or _depth > 5:
        return {}
    if "$ref" in schema:
        return _schema_params(doc, _resolve_ref(doc, schema["$ref"]), _depth + 1)
    props = schema.get("properties")
    if isinstance(props, dict):
        return {name: "1" for name in props}
    # allOf / oneOf / anyOf: merge the first that yields properties.
    for combiner in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(combiner, []) or []:
            params = _schema_params(doc, sub, _depth + 1)
            if params:
                return params
    return {}


def _base_url(doc: dict, origin: str) -> str:
    """Best-effort base URL from an OpenAPI ``servers`` or Swagger ``basePath``."""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url", "") if isinstance(servers[0], dict) else ""
        if url:
            return url if url.startswith("http") else urljoin(origin + "/", url.lstrip("/"))
    base_path = doc.get("basePath")  # Swagger 2.0
    if isinstance(base_path, str) and base_path:
        return origin.rstrip("/") + "/" + base_path.strip("/")
    return origin


def _endpoint_url(base: str, path: str, query: dict) -> str:
    # Substitute path templates ({id}) with a sample value.
    concrete = []
    for segment in path.split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            concrete.append("1")
        else:
            concrete.append(segment)
    url = base.rstrip("/") + "/" + "/".join(concrete).lstrip("/")
    if query:
        url += "?" + urlencode(query)
    return url


def _body_format(op: dict, doc: dict):
    """Return (body_format, params) for an operation's request body, or (None, {})."""
    # OpenAPI 3 requestBody.
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        if "$ref" in request_body:
            request_body = _resolve_ref(doc, request_body["$ref"]) or {}
        content = request_body.get("content", {})
        for ct_sub, fmt in _CT_FORMATS:
            for ctype, media in content.items():
                if ct_sub in ctype and isinstance(media, dict):
                    return fmt, _schema_params(doc, media.get("schema", {}))
    # Swagger 2.0 body / formData parameters.
    body_params, form_params = {}, {}
    for param in op.get("parameters", []) or []:
        if not isinstance(param, dict):
            continue
        loc = param.get("in")
        if loc == "body":
            body_params.update(_schema_params(doc, param.get("schema", {})))
        elif loc == "formData":
            form_params[param.get("name", "input")] = "1"
    if body_params:
        return "json", body_params
    if form_params:
        return "form", form_params
    return None, {}


def _query_params(op: dict) -> dict:
    query = {}
    for param in op.get("parameters", []) or []:
        if isinstance(param, dict) and param.get("in") == "query":
            query[param.get("name", "q")] = "1"
    return query


def targets_from_spec(doc: dict, origin: str) -> list[Target]:
    """Build the list of injectable :class:`Target`s described by ``doc``."""
    base = _base_url(doc, origin)
    targets: list[Target] = []
    for path, item in doc.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            query = _query_params(op)
            url = _endpoint_url(base, path, query)
            body_format, params = (None, {})
            if method in _BODY_METHODS:
                body_format, params = _body_format(op, doc)
            targets.append(
                Target(
                    url=url,
                    method=method.upper(),
                    body_format=body_format,
                    params=params,
                )
            )
    return targets


def discover(start_url, request, profile=None, force=False, output=None):
    """Discover API targets for ``start_url``.

    Fetches a spec from the well-known locations; on success returns the
    endpoints as ``Target``s and marks ``profile.api_type = "rest"``. When no
    spec is found, probes a few REST prefixes so at least the API style is
    recorded. Returns a list of ``Target`` (possibly empty).
    """
    origin = _origin(start_url)

    for path in SPEC_PATHS:
        try:
            resp = request.send(url=origin + path, method="GET")
        except Exception:
            continue
        if resp is None or resp.status_code != 200 or not resp.text:
            continue
        doc = _parse_spec(resp.text)
        if doc is None:
            continue
        targets = targets_from_spec(doc, origin)
        if profile is not None:
            profile.api_type = "rest"
        if output is not None:
            output.info(
                "API spec found at %s: %d endpoint(s) enumerated"
                % (path, len(targets))
            )
        return targets

    # No spec: probe common REST prefixes just to detect an API surface.
    for prefix in REST_PREFIXES:
        try:
            resp = request.send(url=origin + prefix, method="GET")
        except Exception:
            continue
        if resp is None:
            continue
        ctype = resp.headers.get("Content-Type", "") if resp.headers else ""
        if resp.status_code < 500 and "json" in ctype.lower():
            if profile is not None:
                profile.api_type = "rest"
            if output is not None:
                output.info(
                    "REST surface detected at %s (no spec; body injection needs "
                    "a spec to enumerate parameters)" % prefix
                )
            break
    return []
