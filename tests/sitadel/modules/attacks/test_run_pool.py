"""The shared pool runner: fallback, shared-pool reuse, and cancellation."""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from sitadel.modules.attacks import AttackPlugin
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("rp"))
    yield
    for k in ("output", "logger", "scan_pool", "cancel"):
        Services.services.pop(k, None)


def _runner():
    # A bare AttackPlugin instance: instantiation does not register a plugin
    # (the IPlugin metaclass only registers at class definition), and run_pool
    # uses no instance state.
    return AttackPlugin()


def test_runs_all_items_without_shared_pool():
    seen = []
    lock = threading.Lock()

    def worker(i):
        with lock:
            seen.append(i)

    _runner().run_pool(range(50), worker)
    if sorted(seen) != list(range(50)):
        raise AssertionError("every item must run on the local fallback pool")


def test_uses_shared_pool_and_does_not_close_it():
    pool = ThreadPoolExecutor(max_workers=4)
    Services.register("scan_pool", pool)
    seen = []
    lock = threading.Lock()
    _runner().run_pool(range(20), lambda i: (lock.acquire(), seen.append(i), lock.release()))
    if sorted(seen) != list(range(20)):
        raise AssertionError("items must run on the shared pool")
    # The shared pool must still be usable afterwards (run_pool must not shut it).
    fut = pool.submit(lambda: 42)
    if fut.result(timeout=2) != 42:
        raise AssertionError("run_pool must not shut down the shared pool")
    pool.shutdown(wait=True)


def test_cancellation_stops_scheduling():
    ev = threading.Event()
    ev.set()
    Services.register("cancel", ev)
    seen = []
    lock = threading.Lock()

    def worker(i):
        with lock:
            seen.append(i)

    # Cancelled before start: run_pool returns promptly; most items are dropped.
    _runner().run_pool(range(500), worker)
    if len(seen) >= 500:
        raise AssertionError("cancellation should drop queued work")
