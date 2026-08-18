from __future__ import annotations

import urllib3
from requests import ConnectionError, Request, RequestException, Session, Timeout
from requests.adapters import HTTPAdapter
from requests.utils import dict_from_cookiejar

from lib.utils.container import Services
from . import ragent as ragent

# Sized to the attack phase's bounded thread pools so connections are reused.
_POOL_SIZE = 20


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
    ):
        self.url = url
        self.agent = agent
        self.proxy = proxy
        self.redirect = redirect
        self.timeout = timeout
        self.random_agent = random_agent
        self.verify = verify
        self.ruagent = ragent.RandomUserAgent()
        # Optional authentication context (headers + a shared cookie jar).
        self.authenticator = None

        # Reuse one pooled session (keep-alive) across every request instead of
        # opening a fresh TCP/TLS connection per call.
        self.session = Session()
        adapter = HTTPAdapter(pool_connections=_POOL_SIZE, pool_maxsize=_POOL_SIZE)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def set_authenticator(self, authenticator):
        self.authenticator = authenticator

    def login(self):
        """Run the configured login flow, populating the session cookie jar."""
        if self.authenticator is not None and self.authenticator.has_login:
            return self.authenticator.login(self.session, self.verify, self.timeout)
        return None

    def send(self, url, method="GET", payload=None, headers=None, cookies=None,
             _retry=True):
        output = Services.get("output")
        prepped = self.prepare_request(url, method, payload, headers, cookies)
        try:
            resp = self.session.send(
                prepped,
                timeout=self.timeout,
                proxies={"http": self.proxy, "https": self.proxy, "ftp": self.proxy},
                allow_redirects=self.redirect,
                verify=self.verify,
            )
            # If the session dropped (login page returned), re-authenticate once
            # and retry so a mid-scan session expiry doesn't silently degrade to
            # unauthenticated requests.
            if _retry and self.authenticator is not None \
                    and self.authenticator.looks_logged_out(resp):
                self.authenticator.login(self.session, self.verify, self.timeout)
                return self.send(url, method, payload, headers, cookies,
                                 _retry=False)
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
