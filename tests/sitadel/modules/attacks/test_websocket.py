"""WebSocket discovery / CSWSH / liveness plugin behaviour (no real network)."""
import logging

import pytest

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("test-ws"))
    Services.register("datastore", Datastore("sitadel/data"))
    Services.register("findings", Findings())
    yield
    for key in ("output", "logger", "datastore", "findings", "cancel"):
        Services.services.pop(key, None)


class _Conn:
    def __init__(self, recv_raises=False, connected=True):
        self.connected = connected
        self._recv_raises = recv_raises
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)

    def recv(self):
        if self._recv_raises:
            raise OSError("closed")
        return "pong"

    def close(self):
        self.connected = False


class _BadStatus(Exception):
    pass


class _FakeClient:
    """Stand-in WsClient: connects only for URLs in ``live``."""

    bad_status_exception = _BadStatus

    def __init__(self, live, cross_origin_ok=None, conn_factory=None):
        self.live = set(live)
        self.cross_origin_ok = set(cross_origin_ok or [])
        self.conn_factory = conn_factory or (lambda: _Conn())

    def connect(self, url, origin=None):
        if origin is not None:
            if url in self.cross_origin_ok:
                return self.conn_factory()
            raise _BadStatus("origin rejected")
        if url in self.live:
            return self.conn_factory()
        raise _BadStatus("not a websocket")


def _titles():
    return [f.title for f in Services.get("findings").all()]


def _new_plugin(monkeypatch, client):
    from sitadel.modules.attacks.other import websocket as mod
    monkeypatch.setattr(mod.WsClient, "from_services", classmethod(lambda cls: client))
    return mod.WebSocket()


def test_discovery_reports_only_live_endpoints(monkeypatch):
    settings.risk = Risk.NOISY
    live = ["ws://ex.com/ws"]
    plugin = _new_plugin(monkeypatch, _FakeClient(live=live))
    plugin.process("http://ex.com/", [])
    found = [t for t in _titles() if "WebSocket endpoint found" in t]
    if not found or not any("/ws" in t for t in found):
        raise AssertionError("live endpoint must be reported")


def test_cswsh_reported_only_when_foreign_origin_accepted(monkeypatch):
    settings.risk = Risk.NOISY
    url = "ws://ex.com/ws"
    plugin = _new_plugin(
        monkeypatch, _FakeClient(live=[url], cross_origin_ok=[url])
    )
    plugin.process("http://ex.com/", [])
    if not any("CSWSH" in t for t in _titles()):
        raise AssertionError("CSWSH must be reported when foreign origin accepted")


def test_no_cswsh_when_origin_rejected(monkeypatch):
    settings.risk = Risk.NOISY
    url = "ws://ex.com/ws"
    plugin = _new_plugin(monkeypatch, _FakeClient(live=[url], cross_origin_ok=[]))
    plugin.process("http://ex.com/", [])
    if any("CSWSH" in t for t in _titles()):
        raise AssertionError("no CSWSH when origin is validated")


def test_missing_library_skips_cleanly(monkeypatch):
    settings.risk = Risk.NOISY
    from sitadel.modules.attacks.other import websocket as mod

    def _raise(cls):
        raise RuntimeError("websocket-client is not installed")

    monkeypatch.setattr(mod.WsClient, "from_services", classmethod(_raise))
    mod.WebSocket().process("http://ex.com/", [])  # must not raise
    if _titles():
        raise AssertionError("no findings should be produced when lib missing")


@pytest.mark.dangerous
def test_liveness_probe_runs_only_at_risk_dangerous(monkeypatch):
    url = "ws://ex.com/ws"
    settings.risk = Risk.DANGEROUS
    plugin = _new_plugin(
        monkeypatch,
        _FakeClient(live=[url], conn_factory=lambda: _Conn(connected=True)),
    )
    plugin.process("http://ex.com/", [])
    if not any("stays open" in t for t in _titles()):
        raise AssertionError("liveness note expected at risk DANGEROUS")
