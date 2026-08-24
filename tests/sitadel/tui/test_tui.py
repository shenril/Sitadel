"""TUI plumbing tests that don't require driving the Textual app: the risk
level is announced to the bus, and the detail-modal renderer surfaces the
finding's triage fields. Textual-dependent bits are skipped when textual is
not installed (it is an optional 'tui' extra)."""
import pytest

from sitadel.cli import Sitadel
from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from sitadel.utils.events import EventBus, RiskLevel


def test_announce_risk_publishes_level():
    bus = EventBus()
    Services.register("events", bus)
    settings.risk = Risk.DANGEROUS
    try:
        Sitadel()._announce_risk()
        events = bus.drain()
    finally:
        Services.services.pop("events", None)
    risk = [e for e in events if isinstance(e, RiskLevel)]
    if not risk or risk[0].name != "DANGEROUS" or risk[0].value != 2:
        raise AssertionError("risk level must be announced to the bus")


def test_detail_text_includes_triage_fields():
    pytest.importorskip("textual")
    from sitadel.tui.app import _detail_text
    group = {
        "severity": "high", "plugin": "Sql", "confidence": "firm",
        "cwe": "CWE-89", "count": 9, "urls": {("/product", "id"): True},
        "evidence": "payload=' | matched=MySQL Injection",
        "remediation": "Use parameterized queries / prepared statements.",
    }
    plain = _detail_text("MySQL Injection", group).plain
    for token in ("MySQL Injection", "Sql", "firm", "CWE-89", "/product",
                  "payload=", "Use parameterized"):
        if token not in plain:
            raise AssertionError(f"detail modal missing {token!r}")
