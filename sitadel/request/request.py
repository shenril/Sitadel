from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

import urllib3
from requests import ConnectionError, Request, RequestException, Session, Timeout
from requests.adapters import HTTPAdapter
from requests.utils import dict_from_cookiejar

from sitadel.utils.container import Services
from . import ragent as ragent

# Sized to the attack phase's bounded thread pools so connections are reused.
_POOL_SIZE = 20


class _RateLimiter:
    """Global request spacer: at most ``rate`` requests/second across all threads.

    ``rate <= 0`` disables it (``acquire`` is a no-op), preserving full throughput.
    Each caller reserves the next time slot under a short lock, then sleeps outside
    the lock until the slot — so N worker threads are paced to one request every
    ``1/rate`` seconds without serializing the lock during the wait.
    """

    def __init__(self, rate: float):
        self.rate = float(rate or 0)
        self._interval = 1.0 / self.rate if self.rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(self._next, now)
            self._next = slot + self._interval
        wait = slot - time.monotonic()
        if wait > 0:
            time.sleep(wait)


class SingleRequest:
    def __init__(
        self,
        url: str | None = None,
        agent: str = "Sitadel",
        proxy: str | None = None,
        redirect: bool = True,
        timeout: int | None = None,
        random_agent: bool = False,
        verify: bool = False,
        rate_limit: float = 0.0,
        scope_hosts: set | list | None = None,
    ):
        self.url = url
        self.agent = agent
        self.proxy = proxy
        self.redirect = redirect
        self.timeout = timeout
        self.random_agent = random_agent
        self.verify = verify
        # Optional authentication context (headers + a shared cookie jar).
        self.authenticator = None

        # Global rate limiter shared by every request this factory sends.
        self.rate_limit = float(rate_limit or 0)
        self._limiter = _RateLimiter(self.rate_limit)

        # In-scope hosts. Defaults to the target's host so probes (and followed
        # redirects) never wander off-target; an empty set means "unrestricted"
        # (used by direct, url-less construction in tests). Explicit extra hosts
        # are added for multi-host targets.
        hosts = {h.lower() for h in (scope_hosts or []) if h}
        if url:
            target_host = urlsplit(url).hostname
            if target_host:
                hosts.add(target_host.lower())
        self.scope_hosts = hosts

        # Reuse one pooled session (keep-alive) across every request instead of
        # opening a fresh TCP/TLS connection per call.
        self.session = Session()
        adapter = HTTPAdapter(pool_connections=_POOL_SIZE, pool_maxsize=_POOL_SIZE)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _in_scope(self, url: str) -> bool:
        """Whether ``url``'s host is in scope. Empty scope => unrestricted."""
        if not self.scope_hosts:
            return True
        host = (urlsplit(url).hostname or "").lower()
        # No parseable host (relative/opaque) is treated as in-scope — it can
        # only resolve against the in-scope base.
        return (host in self.scope_hosts) if host else True

    def set_authenticator(self, authenticator):
        self.authenticator = authenticator

    def login(self):
        """Run the configured login flow, populating the session cookie jar."""
        if self.authenticator is not None and self.authenticator.has_login:
            return self.authenticator.login(self.session, self.verify, self.timeout)
        return None

    def send(self, url, method="GET", payload=None, headers=None, cookies=None,
             allow_redirects=None, _retry=True):
        output = Services.get("output")
        # ``allow_redirects`` defaults to the instance's ``redirect`` setting;
        # callers pass ``False`` to inspect a redirect (e.g. the open-redirect
        # check reads the Location header without following it off-site).
        follow = self.redirect if allow_redirects is None else allow_redirects
        # Scope gate: never initiate a request to an out-of-scope host (the
        # destination is what matters — an SSRF/open-redirect payload points
        # inward but the request itself still targets the in-scope host).
        if not self._in_scope(url):
            output.debug("Skipping out-of-scope request: %s" % url)
            return None
        prepped = self.prepare_request(url, method, payload, headers, cookies)
        # File-only trace of every request the scan makes. Since all attack
        # modules send their probes through here, this records exactly which
        # patterns/payloads were tested (visible in sitadel.log at -v).
        output.trace(
            "REQUEST %s %s%s"
            % (method.upper(), url, f" data={payload}" if payload else "")
        )
        # Honor the global rate limit (no-op when unset) before going on the wire.
        self._limiter.acquire()
        try:
            resp = self.session.send(
                prepped,
                timeout=self.timeout,
                proxies={"http": self.proxy, "https": self.proxy, "ftp": self.proxy},
                allow_redirects=follow,
                verify=self.verify,
            )
            # A redirect chain may have landed off-scope; never let off-host
            # content feed detection — discard it like a skipped request.
            if resp is not None and self.scope_hosts and not self._in_scope(resp.url):
                output.debug("Discarding out-of-scope redirect to %s" % resp.url)
                return None
            # If the session dropped (login page returned), re-authenticate once
            # and retry so a mid-scan session expiry doesn't silently degrade to
            # unauthenticated requests.
            if _retry and self.authenticator is not None \
                    and self.authenticator.looks_logged_out(resp):
                self.authenticator.login(self.session, self.verify, self.timeout)
                return self.send(url, method, payload, headers, cookies,
                                 allow_redirects=allow_redirects, _retry=False)
            return resp
        except Timeout:
            # requests raises requests.exceptions.Timeout (a RequestException),
            # not the builtin TimeoutError, so it must be caught explicitly.
            output.error(f"Timeout error on the URL: {url}")
        except ConnectionError as err:
            output.error(f"Connection error on the URL: {url}\n {err}\n")
        except RequestException as err:
            output.error(f"Error while trying to contact the website:\n {err}\n")
        # On any handled error return None so callers can degrade gracefully
        # (a single failing request must never abort the whole scan).
        return None

    def prepare_request(self, url, method, payload, headers, cookies):
        payload = payload or {}
        # Start from the authentication headers (e.g. Authorization) so every
        # request carries them, then layer any per-call headers on top.
        auth_headers = dict(self.authenticator.headers) if self.authenticator else {}
        auth_headers.update(headers or {})
        headers = auth_headers

        # Merge the session cookie jar (populated at login) with any per-call
        # cookie so authenticated sessions persist across requests.
        jar = dict_from_cookiejar(self.session.cookies)
        if cookies is not None:
            jar[cookies] = ""
        cookies = jar or None

        headers["User-Agent"] = (
            ragent.RandomUserAgent() if self.random_agent else self.agent
        )

        method = method.upper()
        # GET carries no body; every other method forwards the payload as data.
        match method:
            case "GET":
                request = Request(
                    method=method, url=url, headers=headers, cookies=cookies
                )
            case _:
                request = Request(
                    method=method,
                    url=url,
                    data=payload,
                    headers=headers,
                    cookies=cookies,
                )
        return request.prepare()
