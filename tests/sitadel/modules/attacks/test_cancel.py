"""Cooperative cancellation: when the shared 'cancel' event is set (the TUI
quit path), the injection runner performs no probes, so the scan can unwind
promptly instead of hanging the process."""
import logging
import threading

from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output
from sitadel.report import Findings


class _CountingRequest:
    def __init__(self):
        self.sends = 0

    def send(self, **kwargs):
        self.sends += 1

        class _Resp:
            status_code = 200
            text = "ok"

        return _Resp()


def _register(cancelled: bool):
    stub = _CountingRequest()
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("test"))
    Services.register("datastore", Datastore("sitadel/data"))
    Services.register("findings", Findings())
    Services.register("request_factory", stub)
    ev = threading.Event()
    if cancelled:
        ev.set()
    Services.register("cancel", ev)
    return stub


def _cleanup():
    for key in ("cancel", "request_factory", "findings", "api_targets"):
        Services.services.pop(key, None)


def test_injection_makes_no_probes_when_cancelled():
    stub = _register(cancelled=True)
    try:
        from sitadel.modules.attacks.injection.sql import Sql
        Sql().process("http://h/", ["http://h/p?id=1"])
        if stub.sends != 0:
            raise AssertionError("a cancelled scan must not send probes")
    finally:
        _cleanup()


def test_injection_probes_when_not_cancelled():
    stub = _register(cancelled=False)
    try:
        from sitadel.modules.attacks.injection.sql import Sql
        Sql().process("http://h/", ["http://h/p?id=1"])
        if stub.sends == 0:
            raise AssertionError("an active scan must send probes")
    finally:
        _cleanup()
