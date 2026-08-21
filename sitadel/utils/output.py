from __future__ import annotations

import logging

from colorama import Fore, Style

from sitadel.report import Finding, Severity
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

    def finding(self, value: str, severity: Severity = Severity.INFO,
                url: str | None = None, plugin: str | None = None) -> None:
        print(f"{self.g}[+]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info("FINDING: %s", value)
        # Also record the finding for report generation, when a collector is
        # registered. Console output above is emitted unconditionally.
        try:
            collector = Services.get("findings")
        except NameError:
            collector = None
        if collector is not None:
            collector.add(
                Finding(title=value, severity=severity, url=url, plugin=plugin)
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
