"""The Textual dashboard app: header, crawl tree, live findings feed, footer.

Concurrency model (see issue #76): Textual owns the main asyncio loop. The scan
engine is blocking (it runs the async crawler via ``asyncio.run`` and the attack
phase in a ``ThreadPoolExecutor``), so it runs in a Textual **thread worker**.
Producers publish to a thread-safe :class:`EventBus`; a Textual interval timer
drains the bus on the UI loop and mutates widgets — so no widget is ever touched
from a worker thread.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Static, Tree

from sitadel.utils.events import (
    FindingAdded,
    Log,
    PageDiscovered,
    PageTesting,
    Phase,
    ScanFinished,
)

# Severity → (label colour, rank). Rank drives the ordered counters line.
_SEV = {
    "critical": ("red", 4),
    "high": ("dark_orange", 3),
    "medium": ("yellow", 2),
    "low": ("cyan", 1),
    "info": ("grey62", 0),
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


class SitadelApp(App):
    CSS = """
    #progress { height: 3; padding: 0 1; background: $panel; color: $text; }
    #status   { height: 1; padding: 0 1; color: $text-muted; }
    #tree     { width: 42%; border-right: solid $primary; }
    #findings { width: 1fr; }
    Tree > .tree--guides { color: $primary-darken-2; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "toggle_theme", "Theme"),
    ]

    def __init__(self, scan_fn, bus, target: str) -> None:
        super().__init__()
        self._scan_fn = scan_fn
        self._bus = bus
        self._target = target
        self._start = time.monotonic()
        self._phase = "starting"
        self._crawled = 0
        self._testing_url: str | None = None
        self._last_log = ""
        self._done = False
        self._counts = {s: 0 for s in _SEV_ORDER}
        # path (no query) → Tree node, for building the tree and marking tests.
        self._url_nodes: dict[str, object] = {}
        self._testing_node = None

    # ---------------------------------------------------------------- layout #
    def compose(self) -> ComposeResult:
        yield Static(id="progress")
        yield Static(id="status")
        with Horizontal():
            yield Tree("/", id="tree")
            yield DataTable(id="findings", zebra_stripes=True, cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Sitadel"
        table = self.query_one("#findings", DataTable)
        table.add_columns("Sev", "Title", "URL", "Plugin", "Param")
        tree = self.query_one("#tree", Tree)
        tree.root.expand()
        self._render_progress()
        self._render_status("Launching scan…")
        # Elapsed clock + bus drain, both on the UI loop.
        self.set_interval(1.0, self._render_progress)
        self.set_interval(0.1, self._drain)
        # Run the (blocking) scan engine off the UI loop.
        self.run_worker(self._run_scan, thread=True, exclusive=True)

    # --------------------------------------------------------------- worker #
    def _run_scan(self) -> None:
        findings = 0
        try:
            self._scan_fn()
        except Exception as err:  # keep the UI alive; surface the error
            self._bus.publish(Log("error", f"Scan aborted: {err}"))
        finally:
            self._bus.publish(ScanFinished(findings=findings))

    # ---------------------------------------------------------- bus drain #
    def _drain(self) -> None:
        for event in self._bus.drain():
            if isinstance(event, FindingAdded):
                self._on_finding(event)
            elif isinstance(event, PageDiscovered):
                self._on_page(event)
            elif isinstance(event, PageTesting):
                self._on_testing(event)
            elif isinstance(event, Phase):
                self._phase = event.name
                self._render_progress()
            elif isinstance(event, Log):
                self._last_log = event.text
                self._render_status(event.text)
            elif isinstance(event, ScanFinished):
                self._done = True
                self._phase = "done ✓"
                self._testing_url = None
                self._clear_testing_marker()
                self._render_progress()
                self._render_status("Scan finished — press q to quit.")

    # --------------------------------------------------------- rendering #
    def _render_progress(self) -> None:
        elapsed = int(time.monotonic() - self._start)
        clock = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        line1 = Text.assemble(
            ("Sitadel ", "bold"),
            (f"{self._target}", "bold cyan"),
            ("   ⏱ ", "dim"),
            (clock, "bold"),
            ("   phase: ", "dim"),
            (self._phase, "bold magenta"),
            (f"   crawled {self._crawled}", "green"),
        )
        counts = Text("  ")
        for sev in _SEV_ORDER:
            colour = _SEV[sev][0]
            counts.append(f"{self._counts[sev]} {sev}  ", style=colour)
        testing = self._testing_url or "—"
        counts.append(f"│ testing: {testing}", style="dim")
        self.query_one("#progress", Static).update(Text.assemble(line1, "\n", counts))

    def _render_status(self, text: str) -> None:
        self.query_one("#status", Static).update(Text(text, style="dim"))

    # --------------------------------------------------------- handlers #
    def _on_finding(self, ev: FindingAdded) -> None:
        sev = (ev.severity or "info").lower()
        if sev not in self._counts:
            sev = "info"
        self._counts[sev] += 1
        colour = _SEV[sev][0]
        table = self.query_one("#findings", DataTable)
        # Keep the title compact: first line only.
        title = (ev.title or "").splitlines()[0][:60]
        table.add_row(
            Text(sev.upper(), style=f"bold {colour}"),
            Text(title),
            Text(_short_url(ev.url), style="cyan"),
            Text(ev.plugin or "", style="dim"),
            Text(ev.parameter or "", style="yellow"),
        )
        table.move_cursor(row=table.row_count - 1)
        self._render_progress()

    def _on_page(self, ev: PageDiscovered) -> None:
        self._add_path(ev.url)
        self._crawled += 1

    def _on_testing(self, ev: PageTesting) -> None:
        self._testing_url = _short_url(ev.url)
        node = self._url_nodes.get(_path_key(ev.url))
        if node is not None:
            self._clear_testing_marker()
            self._testing_node = node
            self._set_node_label(node, testing=True)
        self._render_progress()

    # ------------------------------------------------------- tree build #
    def _add_path(self, url: str) -> None:
        key = _path_key(url)
        if key in self._url_nodes:
            return
        tree = self.query_one("#tree", Tree)
        parts = urlsplit(url)
        segments = [s for s in parts.path.split("/") if s]
        parent = tree.root
        cumulative = ""
        for seg in segments[:-1]:
            cumulative += "/" + seg
            child = self._url_nodes.get(cumulative)
            if child is None:
                child = parent.add(seg, expand=True)
                self._url_nodes[cumulative] = child
            parent = child
        label = segments[-1] if segments else "/"
        if parts.query:
            label = f"{label}?{parts.query}"
        leaf = parent.add_leaf(label)
        self._url_nodes[key] = leaf
        self._leaf_label(leaf, label)

    def _leaf_label(self, node, base: str) -> None:
        node._sitadel_base = base  # type: ignore[attr-defined]
        node.set_label(Text(base))

    def _set_node_label(self, node, testing: bool) -> None:
        base = getattr(node, "_sitadel_base", None)
        if base is None:
            return
        if testing:
            node.set_label(Text.assemble((base, "bold"), ("  ◀ testing", "bold red")))
        else:
            node.set_label(Text(base))

    def _clear_testing_marker(self) -> None:
        if self._testing_node is not None:
            self._set_node_label(self._testing_node, testing=False)
            self._testing_node = None

    # --------------------------------------------------------- actions #
    def action_toggle_theme(self) -> None:
        self.theme = (
            "textual-light" if self.theme == "textual-dark" else "textual-dark"
        )


def _path_key(url: str) -> str:
    """A stable per-endpoint key: path only (query variants collapse)."""
    return urlsplit(url).path or "/"


def _short_url(url: str | None) -> str:
    if not url:
        return ""
    parts = urlsplit(url)
    tail = parts.path or "/"
    if parts.query:
        tail = f"{tail}?{parts.query}"
    return tail[:50]
