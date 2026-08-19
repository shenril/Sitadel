from __future__ import annotations

import html as _html
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from urllib.parse import urlsplit, urlunsplit


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single scan finding reported by a plugin.

    Beyond the core ``title``/``severity``/``url``, findings carry triage
    metadata: ``confidence`` (how sure the detection is), captured
    ``evidence`` (payload + matched marker), a standards mapping
    (``cwe``/``owasp``/``wstg``), ``remediation`` guidance, and an
    ``occurrences`` count maintained by :class:`Findings` when the same issue
    is reported for many URLs. Every field except ``title`` is optional so
    plugins can enrich incrementally.
    """

    title: str
    severity: Severity = Severity.INFO
    url: str | None = None
    parameter: str | None = None
    evidence: str | None = None
    confidence: str | None = None
    plugin: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    wstg: str | None = None
    remediation: str | None = None
    occurrences: int = 1
    # Extra URLs (beyond ``url``) where the same de-duplicated issue was seen.
    other_urls: list[str] = field(default_factory=list)


def _normalize_url(url: str | None) -> str:
    """Collapse a URL to scheme+host+path (drop query/fragment).

    Dedup treats ``/item?id=1`` and ``/item?id=2`` as the same endpoint so the
    same issue crawled across many parameter values reports once. The injected
    ``parameter`` still distinguishes findings on the same path.
    """
    if not url:
        return ""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _signature(finding: Finding) -> tuple[str, str, str]:
    """Stable dedup key: (type, normalized-url, parameter).

    ``type`` prefers the plugin name (stable per attack class) and falls back
    to the title so findings without a plugin still de-duplicate sanely.
    """
    ftype = (finding.plugin or finding.title or "").strip().lower()
    return (ftype, _normalize_url(finding.url), (finding.parameter or ""))


class Findings:
    """Collector for findings, registered in the Services container.

    De-duplicates on insert: repeats of the same (type, endpoint, parameter)
    collapse into the first finding with an incremented ``occurrences`` count,
    so the same issue across 50 crawled URLs is one entry, not 50.
    """

    def __init__(self):
        self._items: list[Finding] = []
        self._index: dict[tuple[str, str, str], Finding] = {}

    def add(self, finding: Finding) -> None:
        sig = _signature(finding)
        existing = self._index.get(sig)
        if existing is not None:
            existing.occurrences += 1
            # Keep a bounded trail of the distinct URLs the issue was seen on.
            is_new_url = bool(finding.url) and finding.url != existing.url
            if is_new_url and finding.url not in existing.other_urls:
                if len(existing.other_urls) < 20:
                    existing.other_urls.append(finding.url)
            return
        self._index[sig] = finding
        self._items.append(finding)

    def all(self) -> list[Finding]:
        return list(self._items)

    def __len__(self) -> int:
        return len(self._items)


def _to_dict(finding: Finding) -> dict:
    data = asdict(finding)
    data["severity"] = (
        finding.severity.value
        if isinstance(finding.severity, Severity)
        else finding.severity
    )
    return data


def to_json(findings: list[Finding]) -> str:
    return json.dumps([_to_dict(f) for f in findings], indent=2)


# SARIF level per severity (SARIF only knows note/warning/error).
_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def to_sarif(findings: list[Finding]) -> str:
    results = []
    rules: dict[str, dict] = {}
    for f in findings:
        severity = f.severity if isinstance(f.severity, Severity) else Severity.INFO
        rule_id = f.plugin or f.title

        # Register one rule per rule_id, carrying remediation + standards.
        if rule_id not in rules:
            rule: dict = {"id": rule_id, "name": rule_id}
            if f.remediation:
                rule["help"] = {"text": f.remediation}
            props = {}
            if f.cwe:
                props["cwe"] = f.cwe
            if f.owasp:
                props["owasp"] = f.owasp
            if f.wstg:
                props["wstg"] = f.wstg
            tags = [t for t in (f.cwe, f.owasp, f.wstg) if t]
            if tags:
                props["tags"] = tags
            if props:
                rule["properties"] = props
            rules[rule_id] = rule

        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f.title},
        }
        props = {}
        if f.confidence:
            props["confidence"] = f.confidence
        if f.occurrences and f.occurrences > 1:
            props["occurrences"] = f.occurrences
        if f.evidence:
            props["evidence"] = f.evidence
        if props:
            result["properties"] = props
        if f.url:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": f.url}}}
            ]
        results.append(result)
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "Sitadel", "rules": list(rules.values())}
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _std_cell(finding: Finding) -> str:
    parts = [p for p in (finding.cwe, finding.owasp, finding.wstg) if p]
    return _html.escape(" / ".join(parts))


def to_html(findings: list[Finding]) -> str:
    rows = []
    for f in findings:
        severity = f.severity.value if isinstance(f.severity, Severity) else f.severity
        occ = str(f.occurrences) if f.occurrences and f.occurrences > 1 else ""
        cells = [
            _html.escape(severity or ""),
            _html.escape(f.confidence or ""),
            _html.escape(f.title or ""),
            _html.escape(f.url or ""),
            _html.escape(f.parameter or ""),
            occ,
            _html.escape(f.evidence or ""),
            _std_cell(f),
            _html.escape(f.remediation or ""),
        ]
        sev_class = f"sev-{severity}" if severity else ""
        rows.append(
            f'<tr class="{sev_class}">'
            + "".join(f"<td>{c}</td>" for c in cells)
            + "</tr>"
        )
    body = "\n".join(rows) or '<tr><td colspan="9">No findings</td></tr>'
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Sitadel report</title>"
        "<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top}"
        "th{background:#222;color:#fff}"
        ".sev-critical td:first-child{background:#b60205;color:#fff}"
        ".sev-high td:first-child{background:#d93f0b;color:#fff}"
        ".sev-medium td:first-child{background:#fbca04}"
        ".sev-low td:first-child{background:#c2e0c6}"
        "</style></head><body>"
        f"<h1>Sitadel report</h1><p>{len(findings)} finding(s)</p>"
        "<table><thead><tr><th>Severity</th><th>Confidence</th><th>Title</th>"
        "<th>URL</th><th>Parameter</th><th>Count</th><th>Evidence</th>"
        "<th>CWE / OWASP / WSTG</th><th>Remediation</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
        "</body></html>"
    )


_SERIALIZERS = {"json": to_json, "sarif": to_sarif, "html": to_html}


def write_report(findings: list[Finding], fmt: str, path: str) -> None:
    """Serialize ``findings`` in ``fmt`` and write to ``path``."""
    serializer = _SERIALIZERS[fmt]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(serializer(findings))
