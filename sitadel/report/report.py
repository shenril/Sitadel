from __future__ import annotations

import html as _html
import json
from dataclasses import asdict, dataclass
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single scan finding reported by a plugin."""

    title: str
    severity: Severity = Severity.INFO
    url: str | None = None
    parameter: str | None = None
    evidence: str | None = None
    confidence: str | None = None
    plugin: str | None = None
    cwe: str | None = None


class Findings:
    """Collector for findings, registered in the Services container."""

    def __init__(self):
        self._items: list[Finding] = []

    def add(self, finding: Finding) -> None:
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
    for f in findings:
        severity = f.severity if isinstance(f.severity, Severity) else Severity.INFO
        result = {
            "ruleId": f.plugin or f.title,
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f.title},
        }
        if f.url:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": f.url}}}
            ]
        results.append(result)
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {"tool": {"driver": {"name": "Sitadel"}}, "results": results}
        ],
    }
    return json.dumps(doc, indent=2)


def to_html(findings: list[Finding]) -> str:
    rows = []
    for f in findings:
        severity = f.severity.value if isinstance(f.severity, Severity) else f.severity
        cells = [
            _html.escape(severity or ""),
            _html.escape(f.title or ""),
            _html.escape(f.url or ""),
            _html.escape(f.evidence or ""),
        ]
        rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    body = "\n".join(rows) or '<tr><td colspan="4">No findings</td></tr>'
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Sitadel report</title>"
        "<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:left}"
        "th{background:#222;color:#fff}</style></head><body>"
        f"<h1>Sitadel report</h1><p>{len(findings)} finding(s)</p>"
        "<table><thead><tr><th>Severity</th><th>Title</th><th>URL</th>"
        f"<th>Evidence</th></tr></thead><tbody>{body}</tbody></table>"
        "</body></html>"
    )


_SERIALIZERS = {"json": to_json, "sarif": to_sarif, "html": to_html}


def write_report(findings: list[Finding], fmt: str, path: str) -> None:
    """Serialize ``findings`` in ``fmt`` and write to ``path``."""
    serializer = _SERIALIZERS[fmt]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(serializer(findings))
