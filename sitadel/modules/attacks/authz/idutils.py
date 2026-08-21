"""Shared helpers for the authorization (access-control) attack plugins."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Query parameter names that usually reference an object.
ID_PARAMS = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id",
    "pid", "oid", "num", "no", "doc", "docid", "file", "fileid", "order",
    "order_id", "invoice", "item", "item_id", "profile", "record",
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def object_refs(url):
    """Return references to object identifiers in ``url``.

    Each reference is ``(location, key, value)`` where location is ``"query"``
    (key = parameter name) or ``"path"`` (key = the path segment itself).
    """
    parts = urlsplit(url)
    refs = []
    for key, value in parse_qsl(parts.query):
        if key.lower() in ID_PARAMS or value.isdigit() or UUID_RE.match(value):
            refs.append(("query", key, value))
    for segment in parts.path.split("/"):
        if segment.isdigit() or UUID_RE.match(segment):
            refs.append(("path", segment, segment))
    return refs


def replace_id(url, location, key, new_value):
    """Return ``url`` with the identified object id replaced by ``new_value``."""
    parts = urlsplit(url)
    if location == "query":
        params = parse_qsl(parts.query)
        params = [(k, str(new_value) if k == key else v) for k, v in params]
        query = urlencode(params)
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
        )
    # path segment
    segments = [str(new_value) if s == key else s for s in parts.path.split("/")]
    return urlunsplit(
        (parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment)
    )


def similar(a, b, tolerance=0.1):
    """True when two response bodies are of comparable, non-trivial size."""
    if not a or not b:
        return False
    la, lb = len(a), len(b)
    longest = max(la, lb)
    if longest < 50:
        return False
    return abs(la - lb) / longest <= tolerance


def different(a, b):
    """True when two response bodies clearly differ (distinct objects)."""
    if not a or not b:
        return False
    return a != b and len(b) > 50
