"""A thin WebSocket transport adapter for the WebSocket attack module.

The rest of Sitadel funnels HTTP through the pooled ``requests`` session held by
``request_factory`` (proxy, auth, cookies, TLS-verify, request logging all
centralized there). The WebSocket protocol cannot ride that session, so this one
adapter wraps ``websocket-client`` and forwards the settings that *do* map onto a
WebSocket connection — proxy, user-agent, timeout, TLS-verify — reading them from
the registered ``request_factory``. Every attempt is mirrored to ``output.trace``
so the "every probe is logged" invariant the HTTP layer maintains also holds here.

Intentional exceptions (documented, not oversights): the pooled ``requests``
Session and the form-login cookie jar have no WebSocket analogue and are not
forwarded. If the target needs cookie-authenticated WebSockets, that is a future
enhancement.

The ``websocket-client`` import is deferred to :meth:`WsClient.from_services` so a
source checkout that has not reinstalled dependencies does not break the whole
attack loader at import time; a missing library raises a clear ``RuntimeError``
the caller turns into a graceful skip.
"""
from __future__ import annotations

import ssl
from urllib.parse import urlsplit

from sitadel.utils.container import Services

# A foreign origin used for the CSWSH check: an endpoint that still completes the
# handshake with this Origin does not validate the request origin.
FOREIGN_ORIGIN = "https://evil.example"


class WsClient:
    """Maps Sitadel request settings onto ``websocket-client`` connections."""

    def __init__(self, websocket_module, agent, proxy, timeout, verify):
        self._ws = websocket_module
        self.agent = agent
        self.proxy = proxy
        self.timeout = timeout
        self.verify = verify

    @classmethod
    def from_services(cls) -> "WsClient":
        """Build an adapter from the registered ``request_factory`` settings.

        Raises ``RuntimeError`` when ``websocket-client`` is not installed so the
        attack module can report a clean skip instead of crashing the scan.
        """
        try:
            import websocket  # websocket-client (deferred, see module docstring)
        except ImportError as err:  # pragma: no cover - exercised via monkeypatch
            raise RuntimeError(
                "websocket-client is not installed; skipping WebSocket checks. "
                "Install it with: pip install websocket-client"
            ) from err

        request = Services.get("request_factory")
        return cls(
            websocket_module=websocket,
            agent=getattr(request, "agent", "Sitadel"),
            proxy=getattr(request, "proxy", None),
            timeout=getattr(request, "timeout", None) or 15,
            verify=getattr(request, "verify", False),
        )

    def _proxy_parts(self):
        """Return (host, port) for the configured proxy, or (None, None)."""
        if not self.proxy:
            return None, None
        parts = urlsplit(self.proxy if "://" in self.proxy else "//" + self.proxy)
        return parts.hostname, parts.port

    def connect(self, url: str, origin: str | None = None):
        """Open a WebSocket connection, returning the live connection.

        A successful return means the server completed the ``101 Switching
        Protocols`` handshake. Non-101 responses raise
        ``websocket.WebSocketBadStatusException``; other transport failures raise
        the library's connection errors. Callers close the returned connection.
        """
        try:
            Services.get("output").trace(
                "WS CONNECT %s origin=%s" % (url, origin or "-")
            )
        except NameError:
            pass

        header = ["User-Agent: %s" % self.agent]
        sslopt = None if self.verify else {"cert_reqs": ssl.CERT_NONE}
        proxy_host, proxy_port = self._proxy_parts()
        return self._ws.create_connection(
            url,
            timeout=self.timeout,
            header=header,
            origin=origin,
            sslopt=sslopt,
            http_proxy_host=proxy_host,
            http_proxy_port=proxy_port,
        )

    @property
    def bad_status_exception(self):
        """The exception raised on a non-101 handshake response."""
        return self._ws.WebSocketBadStatusException
