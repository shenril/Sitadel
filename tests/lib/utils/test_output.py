from lib.report import Findings, Severity
from lib.utils.container import Services
from lib.utils.output import Output


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
