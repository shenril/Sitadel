"""Concurrency must not change results: the findings set is identical whether
modules run sequentially or concurrently over the shared pool, and no finding is
lost to a race (Findings.add is locked)."""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from sitadel.modules.attacks import AttackPlugin
from sitadel.report import Findings
from sitadel.report.report import _signature
from sitadel.utils.container import Services
from sitadel.utils.output import Output


# NB: deliberately NOT an AttackPlugin subclass — the IPlugin metaclass would
# register it into the global plugin registry and break the launcher tests.
# run_pool uses no instance state, so it is invoked via AttackPlugin.run_pool.
class _Emitter:
    """A fake module that emits one deterministic finding per item via run_pool."""

    def __init__(self, name, n):
        self._name = name
        self._n = n

    def process(self, start_url, crawled_urls):
        output = Services.get("output")

        def work(i):
            output.finding(
                "%s finding %d" % (self._name, i),
                url="http://t/%s/%d" % (self._name, i),
                plugin=self._name, parameter="p%d" % i,
            )

        AttackPlugin.run_pool(self, range(self._n), work)


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("conc"))
    yield
    for k in ("output", "logger", "findings", "scan_pool"):
        Services.services.pop(k, None)


def _sigs():
    return {_signature(f) for f in Services.get("findings").all()}


def test_sequential_vs_concurrent_findings_identical():
    modules = lambda: [_Emitter("a", 40), _Emitter("b", 40), _Emitter("c", 40)]

    # Sequential: one module at a time, local pools, no shared executor.
    Services.register("findings", Findings())
    Services.services.pop("scan_pool", None)
    for m in modules():
        m.process("http://t/", [])
    seq = _sigs()

    # Concurrent: shared pool + a driver running process() in parallel.
    Services.register("findings", Findings())
    pool = ThreadPoolExecutor(max_workers=8)
    Services.register("scan_pool", pool)
    drv = ThreadPoolExecutor(max_workers=3)
    for f in as_completed([drv.submit(m.process, "http://t/", []) for m in modules()]):
        f.result()
    drv.shutdown(wait=True)
    pool.shutdown(wait=True)
    con = _sigs()

    if len(seq) != 120:
        raise AssertionError("expected 120 distinct findings, got %d" % len(seq))
    if seq != con:
        raise AssertionError("concurrency changed the findings set")


def test_findings_add_is_thread_safe():
    # Many threads adding distinct findings: none lost (the add lock holds).
    Services.register("findings", Findings())
    out = Services.get("output")

    def add(i):
        out.finding("f%d" % i, url="http://t/%d" % i, plugin="x", parameter="p%d" % i)

    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(add, range(500)))
    if len(Services.get("findings").all()) != 500:
        raise AssertionError("a concurrent add was lost")
