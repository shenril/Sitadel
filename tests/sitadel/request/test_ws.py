"""WsClient maps Sitadel request settings onto websocket-client connections."""
import ssl

import pytest

from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _FakeWs:
    """Stand-in for the websocket-client module capturing create_connection."""

    class WebSocketBadStatusException(Exception):
        pass

    def __init__(self):
        self.calls = []

    def create_connection(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return object()


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output())
    yield
    Services.services.pop("output", None)
    Services.services.pop("request_factory", None)


def _client(fake, **req_kwargs):
    from sitadel.request.ws import WsClient
    Services.register("request_factory", SingleRequest(**req_kwargs))
    rf = Services.get("request_factory")
    return WsClient(
        websocket_module=fake,
        agent=rf.agent,
        proxy=rf.proxy,
        timeout=rf.timeout or 15,
        verify=rf.verify,
    )


def test_verify_off_disables_cert_checks():
    fake = _FakeWs()
    _client(fake, agent="UA", verify=False).connect("ws://t/x")
    _, kwargs = fake.calls[0]
    if kwargs["sslopt"] != {"cert_reqs": ssl.CERT_NONE}:
        raise AssertionError
    if "User-Agent: UA" not in kwargs["header"]:
        raise AssertionError


def test_verify_on_keeps_default_ssl():
    fake = _FakeWs()
    _client(fake, verify=True).connect("wss://t/x")
    _, kwargs = fake.calls[0]
    if kwargs["sslopt"] is not None:
        raise AssertionError


def test_proxy_is_forwarded():
    fake = _FakeWs()
    _client(fake, proxy="http://127.0.0.1:8080").connect("ws://t/x")
    _, kwargs = fake.calls[0]
    if kwargs["http_proxy_host"] != "127.0.0.1" or kwargs["http_proxy_port"] != 8080:
        raise AssertionError


def test_origin_is_passed_through():
    fake = _FakeWs()
    _client(fake).connect("ws://t/x", origin="https://evil.example")
    _, kwargs = fake.calls[0]
    if kwargs["origin"] != "https://evil.example":
        raise AssertionError


def test_from_services_reads_request_factory():
    from sitadel.request.ws import WsClient
    Services.register(
        "request_factory", SingleRequest(agent="Z", timeout=7, verify=False)
    )
    client = WsClient.from_services()
    if client.agent != "Z" or client.timeout != 7:
        raise AssertionError
