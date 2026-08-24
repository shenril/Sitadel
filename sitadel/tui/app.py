"""The Textual dashboard app: header, crawl tree, grouped findings tree, footer.

Concurrency model (see issue #76): Textual owns the main asyncio loop. The scan
engine is blocking (it runs the async crawler via ``asyncio.run`` and the attack
phase in a ``ThreadPoolExecutor``), so it runs in a Textual **thread worker**.
Producers publish to a thread-safe :class:`EventBus`; a Textual interval timer
drains the bus on the UI loop and mutates widgets — so no widget is ever touched
from a worker thread.

The findings pane groups findings by a cleaned title: each group is one node
showing severity + plugin + a live occurrence count, expandable to the distinct
(relative) URLs where the issue was seen. A severity filter (``f``) narrows the
pane to a single level.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Static, Tree

from sitadel.utils.events import (
    FindingAdded,
    Log,
    PageDiscovered,
    PageTesting,
    Phase,
    ScanFinished,
)

# Severity → colour. Order drives the counters line and the filter cycle.
_SEV = {
    "critical": "red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "cyan",
    "info": "grey62",
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
# Filter cycle: None (all) → each severity → back to None.
_FILTERS = [None] + _SEV_ORDER


class SitadelApp(App):
    CSS = """
    #progress { height: 3; padding: 0 1; background: $panel; color: $text; }
    #status   { height: 1; padding: 0 1; color: $text-muted; }
    #tree     { width: 42%; border-right: solid $primary; }
    #findings { width: 1fr; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f", "cycle_filter", "Filter severity"),
        ("d", "toggle_theme", "Theme"),
    ]

    def __init__(self, scan_fn, bus, target: str) -> None:
        super().__init__()
        self._scan_fn = scan_fn
        self._bus = bus
        self._target = target
        self._start = time.monotonic()
        self._end: float | None = None
        self._phase = "starting"
        self._crawled = 0
        self._testing_url: str | None = None
        self._done = False
        self._filter: str | None = None
        self._counts = {s: 0 for s in _SEV_ORDER}
        # Crawl-tree: path (no query) → node, for building + marking tests.
        self._url_nodes: dict[str, object] = {}
        self._testing_node = None
        # Findings model, independent of the widget so the pane can be rebuilt
        # on filter change. label → {severity, plugin, count, urls, node}.
        self._groups: dict[str, dict] = {}

    # ---------------------------------------------------------------- layout #
    def compose(self) -> ComposeResult:
        yield Static(id="progress")
        yield Static(id="status")
        with Horizontal():
            yield Tree("Crawl tree", id="tree")
            yield Tree("Findings", id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Sitadel"
        self.query_one("#tree", Tree).root.expand()
        self.query_one("#findings", Tree).root.expand()
        self._render_progress()
        self._render_status("Launching scan…")
        # Elapsed clock + bus drain, both on the UI loop.
        self.set_interval(1.0, self._render_progress)
        self.set_interval(0.1, self._drain)
        # Run the (blocking) scan engine off the UI loop.
        self.run_worker(self._run_scan, thread=True, exclusive=True)

    # --------------------------------------------------------------- worker #
    def _run_scan(self) -> None:
        try:
            self._scan_fn()
        except Exception as err:  # keep the UI alive; surface the error
            self._bus.publish(Log("error", f"Scan aborted: {err}"))
        finally:
            self._bus.publish(ScanFinished())

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
                self._render_status(event.text)
            elif isinstance(event, ScanFinished):
                self._end = time.monotonic()
                self._done = True
                self._phase = "done ✓"
                self._testing_url = None
                self._clear_testing_marker()
                self._render_progress()
                self._render_status("Scan finished — press q to quit.")

    # --------------------------------------------------------- rendering #
    def _render_progress(self) -> None:
        end = self._end if self._end is not None else time.monotonic()
        elapsed = int(end - self._start)
        clock = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        line1 = Text.assemble(
            ("Sitadel ", "bold"),
            (self._target, "bold cyan"),
            ("   ⏱ ", "dim"),
            (clock, "bold"),
            ("   phase: ", "dim"),
            (self._phase, "bold magenta"),
            (f"   crawled {self._crawled}", "green"),
        )
        counts = Text("  ")
        for sev in _SEV_ORDER:
            counts.append(f"{self._counts[sev]} {sev}  ", style=_SEV[sev])
        counts.append(f"│ filter: {self._filter or 'all'}", style="bold")
        testing = self._testing_url or "—"
        counts.append(f"  │ testing: {testing}", style="dim")
        self.query_one("#progress", Static).update(Text.assemble(line1, "\n", counts))

    def _render_status(self, text: str) -> None:
        self.query_one("#status", Static).update(Text(text, style="dim"))

    # --------------------------------------------------------- findings #
    def _on_finding(self, ev: FindingAdded) -> None:
        sev = (ev.severity or "info").lower()
        if sev not in self._counts:
            sev = "info"
        self._counts[sev] += 1

        label = _group_label(ev.title)
        group = self._groups.get(label)
        if group is None:
            group = {
                "severity": sev,
                "plugin": ev.plugin or "",
                "count": 0,
                "urls": {},  # relative-url → parameter (for de-dup + display)
                "node": None,
            }
            self._groups[label] = group
        group["count"] += 1
        # Collapse to the endpoint (path only) + parameter: the finding URL is
        # the payload-tainted attack URL, so many payloads on one endpoint would
        # otherwise show as many distinct rows. (endpoint, param) is the natural
        # per-URL identity — matching the report's de-duplication.
        endpoint = _endpoint(ev.url)
        if endpoint:
            group["urls"][(endpoint, ev.parameter or "")] = True

        if self._passes_filter(group):
            self._sync_group_node(label, group)
        self._render_progress()

    def _passes_filter(self, group: dict) -> bool:
        return self._filter is None or group["severity"] == self._filter

    def _sync_group_node(self, label: str, group: dict) -> None:
        """Create or refresh a group node and its URL children incrementally."""
        tree = self.query_one("#findings", Tree)
        if group["node"] is None:
            group["node"] = tree.root.add(_group_text(label, group), expand=False)
        else:
            group["node"].set_label(_group_text(label, group))
        node = group["node"]
        # Add any (endpoint, param) children not yet shown.
        shown = {getattr(c, "_sitadel_url", None) for c in node.children}
        for (endpoint, param) in group["urls"]:
            if (endpoint, param) in shown:
                continue
            child = node.add_leaf(_url_text(endpoint, param))
            child._sitadel_url = (endpoint, param)  # type: ignore[attr-defined]

    def _rebuild_findings(self) -> None:
        """Full rebuild of the findings pane (used on filter change)."""
        tree = self.query_one("#findings", Tree)
        tree.root.remove_children()
        for group in self._groups.values():
            group["node"] = None
        for label, group in self._groups.items():
            if self._passes_filter(group):
                self._sync_group_node(label, group)

    # ------------------------------------------------------- crawl tree #
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
        leaf._sitadel_base = label  # type: ignore[attr-defined]
        leaf.set_label(Text(label))
        self._url_nodes[key] = leaf

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
    def action_cycle_filter(self) -> None:
        idx = _FILTERS.index(self._filter)
        self._filter = _FILTERS[(idx + 1) % len(_FILTERS)]
        self._rebuild_findings()
        self._render_progress()

    def action_toggle_theme(self) -> None:
        self.theme = (
            "textual-light" if self.theme == "textual-dark" else "textual-dark"
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _group_label(title: str | None) -> str:
    """A stable group key from a finding title.

    Findings from the injection modules embed the URL and payload in the title
    (``"… vulnerable to XSS at http://… Injection: …"``). Cutting the ``at
    <url>`` tail collapses the per-URL/per-payload variants into one class, so
    the pane groups by issue type rather than exploding one row per payload.
    """
    first = (title or "").splitlines()[0] if title else ""
    for sep in (" at http", " at /"):
        idx = first.find(sep)
        if idx != -1:
            first = first[:idx]
            break
    # Drop the verbose lead-in the injection modules share so the group label
    # is just the vulnerability class (e.g. "Cross Site Scripting (XSS)").
    for lead in (
        "That site may be vulnerable to ",
        "That site is may be vulnerable to ",
    ):
        if first.startswith(lead):
            first = first[len(lead):]
            break
    return first.strip() or "finding"


def _group_text(label: str, group: dict) -> Text:
    sev = group["severity"]
    colour = _SEV.get(sev, "grey62")
    text = Text.assemble(
        (f"{sev.upper():8} ", f"bold {colour}"),
        (label, "bold"),
    )
    if group["plugin"]:
        text.append(f"  [{group['plugin']}]", style="dim")
    text.append(f"  ({group['count']})", style=colour)
    return text


def _url_text(rel: str, param: str) -> Text:
    text = Text(rel, style="cyan")
    if param:
        text.append(f"  · {param}", style="yellow")
    return text


def _path_key(url: str) -> str:
    """A stable per-endpoint key: path only (query variants collapse)."""
    return urlsplit(url).path or "/"


def _short_url(url: str | None) -> str:
    """Relative URL only (path + query), for display."""
    if not url:
        return ""
    parts = urlsplit(url)
    tail = parts.path or "/"
    if parts.query:
        tail = f"{tail}?{parts.query}"
    return tail


def _endpoint(url: str | None) -> str:
    """Relative endpoint (path only) — drops the payload-carrying query."""
    if not url:
        return ""
    return urlsplit(url).path or "/"
