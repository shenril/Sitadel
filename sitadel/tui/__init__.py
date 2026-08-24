"""Optional Textual TUI front-end for Sitadel (issue #76).

Kept in its own package so the ``textual`` dependency is only imported when the
``--tui`` flag is used; the default CLI path never touches this module.
"""
from __future__ import annotations

import threading

from sitadel.utils.events import EventBus


def run_tui(scan_fn, bus: EventBus, target: str,
            cancel: threading.Event | None = None) -> None:
    """Launch the dashboard, running ``scan_fn`` in a background worker thread.

    ``scan_fn`` is the full scan engine (fingerprint → crawl → attack → report);
    it publishes events to ``bus`` as it runs. ``cancel`` is set when the user
    quits so the scan can unwind cooperatively. This blocks until the user quits.
    """
    from sitadel.tui.app import SitadelApp

    SitadelApp(scan_fn=scan_fn, bus=bus, target=target, cancel=cancel).run()
