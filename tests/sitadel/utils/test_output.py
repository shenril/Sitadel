import os

from sitadel.report import Findings, Severity
from sitadel.utils.container import Services
from sitadel.utils.logs import setup_logging
from sitadel.utils.output import Output


def test_finding_prints_without_collector(capsys):
    # No "findings" collector registered: still prints, no crash.
    Services.services.pop("findings", None)
    Output().finding("standalone finding")
    captured = capsys.readouterr()
    if "standalone finding" not in captured.out:
        raise AssertionError


def test_finding_prints_and_records_when_collector_registered(capsys):
    collector = Findings()
    Services.register("findings", collector)
    try:
        Output().finding("recorded finding", severity=Severity.HIGH,
                         url="http://host/x", plugin="Demo")
        captured = capsys.readouterr()
        # Console output preserved (stdout still shows findings).
        if "recorded finding" not in captured.out:
            raise AssertionError
        # And it was captured for the report.
        if len(collector) != 1:
            raise AssertionError
        item = collector.all()[0]
        if item.title != "recorded finding" or item.severity != Severity.HIGH:
            raise AssertionError
    finally:
        Services.services.pop("findings", None)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_console_messages_are_mirrored_to_the_log_file(tmp_path, capsys):
    logfile = os.path.join(str(tmp_path), "sitadel.log")
    # -vv puts the file at INFO so info() and finding() are captured.
    logger = setup_logging(verbosity=2, logfile=logfile)
    out = Output(level=2)

    out.info("progress-line")
    out.finding("a-finding")
    out.error("an-error")
    for handler in logger.handlers:
        handler.flush()

    content = _read(logfile)
    # Everything printed to the console is also in the log file.
    if "progress-line" not in content:
        raise AssertionError("info() must be mirrored to the log file")
    if "FINDING: a-finding" not in content:
        raise AssertionError("finding() must be mirrored to the log file")
    if "an-error" not in content:
        raise AssertionError("error() must be mirrored to the log file")


def test_trace_goes_to_file_only_never_console(tmp_path, capsys):
    logfile = os.path.join(str(tmp_path), "sitadel.log")
    # -vvv puts the file at DEBUG so trace() records are captured.
    logger = setup_logging(verbosity=3, logfile=logfile)
    # Even at high console verbosity, trace() must never print.
    out = Output(level=99)

    out.trace("tested-payload-xyz")
    for handler in logger.handlers:
        handler.flush()

    captured = capsys.readouterr()
    if "tested-payload-xyz" in captured.out:
        raise AssertionError("trace() must never reach the console")
    if "tested-payload-xyz" not in _read(logfile):
        raise AssertionError("trace() must be written to the log file")
