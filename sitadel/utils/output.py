from __future__ import annotations

import logging

from colorama import Fore, Style

from sitadel.report import Finding, Severity
from sitadel.report.knowledge import lookup as _lookup_knowledge
from sitadel.utils.container import Services


class Output:
    r = Fore.RED
    g = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    c = Fore.CYAN
    e = Style.RESET_ALL

    def __init__(self, level: int = 0):
        # ``level`` is the -v count; it gates how much reaches the console.
        self.level = level
        # File logging is owned by the ``sitadelLog`` logger. Every console
        # message is mirrored there, and ``trace`` adds file-only detail, so
        # the log file is always a superset of stdout.
        self.logger = logging.getLogger("sitadelLog")

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
        print(f"{self.g}[+]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info("FINDING: %s", value)
        # Also record the finding for report generation, when a collector is
        # registered. Console output above is emitted unconditionally.
        try:
            collector = Services.get("findings")
        except NameError:
            collector = None
        if collector is not None:
            kb = _lookup_knowledge(finding_type or plugin)

            def pick(explicit, key):
                return explicit if explicit is not None else kb.get(key)

            collector.add(
                Finding(
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
            )

    def error(self, value: str) -> None:
        print(f"{self.r}[-]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.error(value)

    def info(self, value: str) -> None:
        print(f"{self.y}[i]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info(value)

    def debug(self, value: str) -> None:
        # Debug is the -vvv tier: printed to the console only at -vvv, but
        # always forwarded to the file logger (which keeps it when the file
        # handler is at DEBUG, i.e. also -vvv).
        if self.level >= 3:
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
