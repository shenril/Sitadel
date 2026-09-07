"""Open-redirect check — issue #72.

Injects an off-site marker into redirect-style query parameters and inspects the
``Location`` header **without following it** (via ``send(allow_redirects=False)``)
— following a redirect to an unreachable marker host would raise and lose the
signal. An endpoint that reflects the marker host into ``Location`` redirects to
attacker-controlled destinations.

Bespoke (not ``run_injection``) so it can send no-follow and taint only
redirect-style parameters, which bounds requests and cuts false positives.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin

# Query parameters commonly used to carry a redirect destination.
_REDIRECT_PARAMS = {
    "url", "uri", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "return", "returnurl", "return_url", "returnto", "return_to", "next",
    "dest", "destination", "continue", "goto", "target", "to", "u", "r",
    "out", "view", "image_url", "go", "checkout_url", "callback",
}

# Off-site marker. A well-formed, attacker-looking host we can recognize in a
# Location header; it need not resolve since redirects are not followed.
_MARKER_HOST = "sitadel-oob.example"
_MARKERS = ("https://%s/" % _MARKER_HOST, "//%s/" % _MARKER_HOST)

_REDIRECT_STATUS = {301, 302, 303, 307, 308}


def _taint_redirect_params(url, marker):
    """Rebuild ``url`` with redirect-style params set to ``marker``.

    Returns ``None`` when the URL carries no redirect-style parameter, so the
    endpoint is skipped (bounds requests and noise).
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(name.lower() in _REDIRECT_PARAMS for name, _ in pairs):
        return None
    tainted = [
        (name, marker if name.lower() in _REDIRECT_PARAMS else value)
        for name, value in pairs
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(tainted), parts.fragment)
    )


class OpenRedirect(AttackPlugin):
    level = Risk.NOISY

    def _check(self, output, request, url):
        for marker in _MARKERS:
            tainted = _taint_redirect_params(url, marker)
            if tainted is None:
                return  # no redirect-style param on this URL
            resp = request.send(url=tainted, method="GET", payload=None,
                                headers=None, allow_redirects=False)
            if resp is None:
                continue
            location = resp.headers.get("Location")
            if (resp.status_code in _REDIRECT_STATUS and location
                    and urlsplit(location).netloc == _MARKER_HOST):
                # Report the parameters that carried the marker.
                params = [n for n, _ in parse_qsl(urlsplit(url).query)
                          if n.lower() in _REDIRECT_PARAMS]
                output.finding(
                    "Open redirect: endpoint redirects to an external "
                    "attacker-controlled URL at %s" % url,
                    url=url, plugin="OpenRedirect",
                    parameter=",".join(params) or None,
                    evidence="injected %s -> Location: %s" % (marker, location),
                    finding_type="open_redirect",
                )
                return  # one finding per endpoint is enough

    def _cancelled(self):
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking for open redirects..")
        # Only URLs carrying a redirect-style parameter are worth probing.
        targets = [
            url for url in (crawled_urls or [])
            if _taint_redirect_params(str(url), _MARKERS[0]) is not None
        ]
        if not targets:
            return

        def scan(url):
            if self._cancelled():
                return
            try:
                self._check(output, request, str(url))
            except Exception as e:
                logger.error(e)
                output.debug("Open-redirect error on %s: %s" % (url, e))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan, url) for url in targets]
            try:
                for future in as_completed(futures):
                    if self._cancelled():
                        executor.shutdown(cancel_futures=True)
                        break
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise
