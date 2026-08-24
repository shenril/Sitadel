"""A tiny, thread-safe event layer decoupling scan producers from front-ends.

Producers (the crawler, the attack runner, ``Output``) publish typed events to
an :class:`EventBus`; a consumer drains them. The default CLI front-end ignores
the bus entirely (it is only registered in ``--tui`` mode), so this stays a
non-breaking addition: when no bus is registered, ``Output`` behaves exactly as
before.

The bus is a plain ``queue.Queue`` under the hood, which is safe to publish to
from any thread. That matters because the attack phase runs in a
``ThreadPoolExecutor``: worker threads publish here, and the Textual UI drains
the queue from its own event loop via a timer — no ``call_from_thread`` gymnastics
needed at every call site.
"""
from __future__ import annotations

import queue
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- #
# Event types
# --------------------------------------------------------------------------- #
@dataclass
class Phase:
    """The scan moved to a new phase (fingerprint / crawl / attack / done)."""

    name: str


@dataclass
class Log:
    """A human-readable log line (mirrors ``Output.info``/``error``)."""

    level: str  # "info" | "error"
    text: str


@dataclass
class PageDiscovered:
    """The crawler found a new in-scope URL."""

    url: str
    is_form: bool = False


@dataclass
class PageTesting:
    """An attack module is currently probing this URL/endpoint."""

    url: str


@dataclass
class FindingAdded:
    """A finding was reported. Carries the raw fields the UI needs to render."""

    title: str
    severity: str
    url: str | None = None
    plugin: str | None = None
    parameter: str | None = None
    evidence: str | None = None
    confidence: str | None = None
    cwe: str | None = None
    remediation: str | None = None


@dataclass
class ScanFinished:
    """The scan engine finished (report already written)."""

    findings: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Bus
# --------------------------------------------------------------------------- #
class EventBus:
    """Thread-safe fan-in queue. Producers ``publish``; a consumer ``drain``s."""

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()

    def publish(self, event: Any) -> None:
        self._q.put(event)

    def drain(self) -> list[Any]:
        """Return every queued event, oldest first, leaving the queue empty."""
        items: list[Any] = []
        while True:
            try:
                items.append(self._q.get_nowait())
            except queue.Empty:
                break
        return items
