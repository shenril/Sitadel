import json
import re

from sitadel.modules.fingerprints import FingerprintPlugin
from sitadel.utils.container import Services


def match_signatures(signatures, headers, content):
    """Return {tech: category} for every signature that matches.

    ``signatures`` follows a compact Wappalyzer-style schema per technology:
    ``category`` plus any of ``headers`` (name -> value regex),
    ``cookies`` (regex on Set-Cookie), ``html`` (regex on the body),
    ``meta`` (name -> content regex) and ``script`` (regex on the body).
    The upstream Wappalyzer ``technologies.json`` can be dropped in with a
    thin adapter — the matching model is intentionally the same.
    """
    header_items = {str(k).lower(): str(v) for k, v in dict(headers).items()}
    set_cookie = header_items.get("set-cookie", "")
    detected = {}

    def search(pattern, text):
        try:
            return re.search(pattern, text, re.I) is not None
        except re.error:
            return False

    for tech, sig in signatures.items():
        category = sig.get("category", "technology")
        hit = False
        for name, pattern in sig.get("headers", {}).items():
            value = header_items.get(name.lower())
            if value is not None and search(pattern, value):
                hit = True
                break
        if not hit and "cookies" in sig and search(sig["cookies"], set_cookie):
            hit = True
        if not hit and "html" in sig and search(sig["html"], content):
            hit = True
        if not hit and "script" in sig and search(sig["script"], content):
            hit = True
        if not hit:
            for name, pattern in sig.get("meta", {}).items():
                meta_re = (
                    r'<meta[^>]+name=["\']%s["\'][^>]+content=["\'][^"\']*%s'
                    % (re.escape(name), pattern)
                )
                if search(meta_re, content):
                    hit = True
                    break
        if hit:
            detected[tech] = category
    return detected


class Wappalyzer(FingerprintPlugin):
    """Signature-based technology detection feeding the TargetProfile."""

    def process(self, headers, content):
        output = Services.get("output")
        try:
            datastore = Services.get("datastore")
            with datastore.open("fingerprints.json", "r") as fh:
                signatures = json.load(fh)
        except Exception:
            return None

        detected = match_signatures(signatures, headers, content or "")
        if not detected:
            return None

        try:
            profile = Services.get("profile")
        except NameError:
            profile = None

        for tech, category in sorted(detected.items()):
            if profile is not None:
                profile.add(category, tech)
            output.finding(f"Technology detected: {tech} ({category})")
        # The profile carries the structured result; nothing to return.
        return None
