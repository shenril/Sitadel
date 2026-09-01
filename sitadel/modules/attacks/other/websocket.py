"""WebSocket discovery + Cross-Site WebSocket Hijacking (CSWSH) — issue #46.

Probes the target for WebSocket endpoints (servers that answer the HTTP Upgrade
handshake with ``101 Switching Protocols``) and tests each confirmed endpoint for
CSWSH by replaying the handshake with a foreign ``Origin``. At risk level
DANGEROUS it additionally sends a random message frame to observe whether the
endpoint stays open or closes on unexpected input (the reporter's follow-up ask).

All WebSocket I/O goes through :class:`sitadel.request.ws.WsClient`, which maps
Sitadel's request settings (proxy/UA/timeout/verify) onto ``websocket-client``;
this module never touches the library directly. Candidates come from a curated
path wordlist (``data/websocket.txt``) joined to the target host, plus any crawled
URL whose path hints at a WebSocket surface — bounded, per the single-target model
(the original issue's "hostname list" does not fit a single-target scanner).
"""
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlsplit, urlunsplit

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.request.ws import FOREIGN_ORIGIN, WsClient
from sitadel.utils.container import Services
from .. import AttackPlugin

# URLs whose path hints at a WebSocket surface are probed in addition to the
# wordlist. Compiled once (hot enough over a large crawl); models idutils.UUID_RE.
_WS_HINT = re.compile(r"ws|socket|cable|graphql|signalr|hub|stream", re.I)

# http(s) -> ws(s)
_SCHEME_MAP = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}


def _to_ws(url: str) -> str | None:
    """Rewrite an http(s)/ws(s) URL to its ws(s) form, or None if unsupported."""
    parts = urlsplit(url)
    scheme = _SCHEME_MAP.get(parts.scheme.lower())
    if scheme is None or not parts.netloc:
        return None
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


class WebSocket(AttackPlugin):
    # Discovery + CSWSH are handshake-only; the message-liveness probe is gated
    # to DANGEROUS inside process() since it sends data frames.
    level = Risk.NOISY

    def _candidates(self, start_url, crawled_urls):
        """Bounded, de-duplicated ws(s) URLs to probe (wordlist + crawl hints)."""
        candidates = []
        seen = set()

        def add(ws_url):
            if not ws_url:
                return
            parts = urlsplit(ws_url)
            key = (parts.netloc, parts.path)
            if key not in seen:
                seen.add(key)
                candidates.append(ws_url)

        datastore = Services.get("datastore")
        try:
            with datastore.open("websocket.txt", "r") as db:
                paths = [x.strip() for x in db.readlines() if x.strip()]
        except OSError:
            paths = ["/", "/ws", "/socket.io/?EIO=4&transport=websocket"]
        for path in paths:
            add(_to_ws(urljoin(str(start_url), path)))

        for url in crawled_urls or []:
            if _WS_HINT.search(urlsplit(str(url)).path or ""):
                add(_to_ws(str(url)))

        return candidates

    def _discover(self, client, url):
        """Return True and report a finding when ``url`` is a WebSocket endpoint."""
        output = Services.get("output")
        try:
            conn = client.connect(url)
        except client.bad_status_exception:
            return False
        except Exception:
            # Not a WebSocket endpoint (connection refused, non-WS server, ...).
            return False
        try:
            output.finding(
                "WebSocket endpoint found at %s" % url,
                url=url,
                plugin="WebSocket",
                evidence="101 Switching Protocols",
                finding_type="websocket",
            )
            return True
        finally:
            self._close(conn)

    def _check_cswsh(self, client, url):
        """Report a CSWSH finding when the endpoint accepts a foreign Origin."""
        output = Services.get("output")
        try:
            conn = client.connect(url, origin=FOREIGN_ORIGIN)
        except client.bad_status_exception:
            return  # Origin was rejected — the endpoint validates it.
        except Exception:
            return
        try:
            output.finding(
                "Cross-Site WebSocket Hijacking (CSWSH): endpoint accepts a "
                "foreign Origin at %s" % url,
                url=url,
                plugin="WebSocket",
                parameter="Origin",
                evidence="Origin: %s accepted" % FOREIGN_ORIGIN,
                finding_type="cswsh",
            )
        finally:
            self._close(conn)

    def _probe_liveness(self, client, url):
        """Send a random message and note whether the endpoint stays open.

        Only called at risk DANGEROUS (sends a data frame). Reports whether the
        server keeps the connection open on unexpected input or closes it.
        """
        output = Services.get("output")
        try:
            conn = client.connect(url)
        except Exception:
            return
        try:
            message = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            conn.send(message)
            try:
                conn.recv()
            except Exception:
                pass
            still_open = getattr(conn, "connected", False)
            if still_open:
                output.finding(
                    "WebSocket endpoint stays open on arbitrary input at %s "
                    "(no message validation)" % url,
                    url=url,
                    plugin="WebSocket",
                    parameter="message",
                    evidence="sent random frame; connection remained open",
                    finding_type="websocket",
                )
            else:
                output.info(
                    "WebSocket endpoint closed on invalid input at %s "
                    "(validates messages)" % url
                )
        finally:
            self._close(conn)

    @staticmethod
    def _close(conn):
        try:
            conn.close()
        except Exception:
            pass

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        logger = Services.get("logger")

        output.info("Checking for WebSocket endpoints (discovery + CSWSH)..")
        try:
            client = WsClient.from_services()
        except RuntimeError as err:
            output.info(str(err))
            return

        candidates = self._candidates(start_url, crawled_urls)
        if not candidates:
            return

        confirmed = []

        def scan(url):
            if self._cancelled():
                return
            try:
                if self._discover(client, url):
                    confirmed.append(url)
                    self._check_cswsh(client, url)
            except Exception as e:
                logger.error(e)
                output.debug("WebSocket probe error on %s: %s" % (url, e))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan, url) for url in candidates]
            try:
                for future in as_completed(futures):
                    if self._cancelled():
                        executor.shutdown(cancel_futures=True)
                        break
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise

        # Active message-liveness test only at the DANGEROUS risk level.
        if settings.risk >= Risk.DANGEROUS:
            for url in confirmed:
                if self._cancelled():
                    break
                try:
                    self._probe_liveness(client, url)
                except Exception as e:
                    logger.error(e)

    @staticmethod
    def _cancelled():
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False
