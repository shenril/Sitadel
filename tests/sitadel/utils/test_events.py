"""Event-layer contract: the bus is a no-op unless registered, and Output
publishes findings/logs to it while ``quiet`` suppresses stdout. No Textual
dependency is exercised here — this covers the non-breaking plumbing only.
"""
from sitadel.utils.container import Services
from sitadel.utils.events import EventBus, FindingAdded, Log
from sitadel.utils.output import Output


def _reset():
    Services.services.pop("events", None)
    Services.services.pop("findings", None)


def test_output_without_bus_is_unchanged(capsys):
    _reset()
    Output().finding("hello", url="http://h/x", plugin="Sql")
    out = capsys.readouterr().out
    if "hello" not in out:
        raise AssertionError("CLI mode must still print findings")


def test_output_publishes_finding_and_log(capsys):
    _reset()
    bus = EventBus()
    Services.register("events", bus)
    try:
        out = Output(quiet=True)
        out.finding("SQLi here", severity=None, url="http://h/p", plugin="Sql",
                    parameter="id")
        out.info("crawling")
        events = bus.drain()
    finally:
        _reset()

    # quiet mode prints nothing to stdout
    if capsys.readouterr().out.strip():
        raise AssertionError("quiet Output must not write to stdout")

    findings = [e for e in events if isinstance(e, FindingAdded)]
    logs = [e for e in events if isinstance(e, Log)]
    if len(findings) != 1:
        raise AssertionError("expected exactly one FindingAdded event")
    if findings[0].plugin != "Sql" or findings[0].parameter != "id":
        raise AssertionError("finding fields must reach the event")
    if not any(log.text == "crawling" for log in logs):
        raise AssertionError("info() must publish a Log event")


def test_bus_drain_is_fifo_and_empties():
    bus = EventBus()
    bus.publish(Log("info", "a"))
    bus.publish(Log("info", "b"))
    drained = bus.drain()
    if [e.text for e in drained] != ["a", "b"]:
        raise AssertionError("drain must return events oldest-first")
    if bus.drain():
        raise AssertionError("drain must leave the queue empty")
