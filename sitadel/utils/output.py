from __future__ import annotations

import logging

from colorama import Fore, Style

from sitadel.report import Finding, Severity
from sitadel.report.knowledge import lookup as _lookup_knowledge
from sitadel.utils.container import Services
from sitadel.utils.events import FindingAdded, Log


class Output:
    r = Fore.RED
    g = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    c = Fore.CYAN
    e = Style.RESET_ALL

    def __init__(self, level: int = 0, quiet: bool = False):
        # ``level`` is the -v count; it gates how much reaches the console.
        self.level = level
        # ``quiet`` suppresses stdout (used by the TUI front-end, which owns the
        # screen and renders findings/logs itself from the event bus). The file
        # logger and the event bus are unaffected, so nothing is lost.
        self.quiet = quiet
        # File logging is owned by the ``sitadelLog`` logger. Every console
        # message is mirrored there, and ``trace`` adds file-only detail, so
        # the log file is always a superset of stdout.
        self.logger = logging.getLogger("sitadelLog")

    @staticmethod
    def _bus():
        """The registered event bus, or ``None`` in plain CLI mode."""
        try:
            return Services.get("events")
        except NameError:
            return None

    def finding(self, value: str, severity: Severity | None = None,
                url: str | None = None, plugin: str | None = None,
                parameter: str | None = None, evidence: str | None = None,
                confidence: str | None = None, cwe: str | None = None,
                owasp: str | None = None, wstg: str | None = None,
                remediation: str | None = None,
                finding_type: str | None = None) -> None:
        r"""Report a finding: print it, log it, and record it for the report.

        Only ``value`` is required, so legacy ``finding("text")`` calls keep
        working. Any triage field a plugin omits is filled from the
        remediation/standards knowledge base (keyed by ``finding_type`` or the
        ``plugin`` name), so even single-string findings gain a sane severity,
        confidence, and CWE/OWASP/WSTG mapping. Explicit arguments always win.
        """
        if not self.quiet:
            print(f"{self.g}[+]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info("FINDING: %s", value)

        # Enrich from the knowledge base and build the Finding once; it feeds
        # both the report collector and the live event stream.
        kb = _lookup_knowledge(finding_type or plugin)

        def pick(explicit, key):
            return explicit if explicit is not None else kb.get(key)

        finding = Finding(
            title=value,
            severity=pick(severity, "severity") or Severity.INFO,
            url=url,
            parameter=parameter,
            evidence=evidence,
            confidence=pick(confidence, "confidence"),
            plugin=plugin,
            cwe=pick(cwe, "cwe"),
            owasp=pick(owasp, "owasp"),
            wstg=pick(wstg, "wstg"),
            remediation=pick(remediation, "remediation"),
        )

        # Record for report generation, when a collector is registered.
        try:
            collector = Services.get("findings")
        except NameError:
            collector = None
        if collector is not None:
            collector.add(finding)

        # Publish to the live UI (TUI). No-op in plain CLI mode.
        bus = self._bus()
        if bus is not None:
            sev = (
                finding.severity.value
                if isinstance(finding.severity, Severity)
                else finding.severity
            )
            bus.publish(
                FindingAdded(
                    title=finding.title,
                    severity=sev or "info",
                    url=finding.url,
                    plugin=finding.plugin,
                    parameter=finding.parameter,
                    evidence=finding.evidence,
                    confidence=finding.confidence,
                    cwe=finding.cwe,
                    remediation=finding.remediation,
                )
            )

    def error(self, value: str) -> None:
        if not self.quiet:
            print(f"{self.r}[-]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.error(value)
        bus = self._bus()
        if bus is not None:
            bus.publish(Log("error", value))

    def info(self, value: str) -> None:
        if not self.quiet:
            print(f"{self.y}[i]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info(value)
        bus = self._bus()
        if bus is not None:
            bus.publish(Log("info", value))

    def debug(self, value: str) -> None:
        # Debug is the -vvv tier: printed to the console only at -vvv, but
        # always forwarded to the file logger (which keeps it when the file
        # handler is at DEBUG, i.e. also -vvv).
        if self.level >= 3 and not self.quiet:
            print(f"{self.c}[d]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.debug(value)

    def trace(self, value: str) -> None:
        """File-only detail — never printed, even at high verbosity.

        Used for the high-volume records that would drown the console but are
        valuable in the log: every URL the crawler discovered and every
        payload/pattern the attack modules test. These land in ``sitadel.log``
        only when the file handler is at DEBUG (i.e. any ``-v``).
        """
        self.logger.debug(value)
