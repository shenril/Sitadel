import base64
from urllib.parse import urljoin, urlparse

from lib.modules.fingerprints import FingerprintPlugin
from lib.utils.container import Services


class Favicon(FingerprintPlugin):
    """Compute the MurmurHash3 favicon hash (Shodan/`http.favicon.hash`).

    The hash is a compact, WAF/CDN-resilient identifier that can be pivoted on
    (e.g. Shodan ``http.favicon.hash:``) and matched against known-technology
    hash tables.
    """

    def process(self, headers, content):
        try:
            import mmh3
        except ImportError:
            return None  # optional dependency; degrade silently

        request = Services.get("request_factory")
        base = request.url
        if not base or not urlparse(base).scheme:
            return None

        try:
            resp = request.send(url=urljoin(base, "/favicon.ico"), method="GET")
        except Exception:
            return None
        if resp is None or resp.status_code != 200 or not resp.content:
            return None

        # Shodan convention: mmh3 over the base64 (with newlines) of the icon.
        encoded = base64.encodebytes(resp.content)
        favicon_hash = mmh3.hash(encoded)

        try:
            profile = Services.get("profile")
            if profile is not None:
                profile.add("favicon_hash", str(favicon_hash))
        except NameError:
            pass
        return f"favicon hash {favicon_hash}"
