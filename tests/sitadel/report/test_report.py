import json
import os

from sitadel.report import (
    Finding,
    Findings,
    Severity,
    to_html,
    to_json,
    to_sarif,
    write_report,
)


def _sample():
    return [
        Finding(title="SQL Injection", severity=Severity.HIGH,
                url="http://host/p?id=1", evidence="MySQL error", plugin="Sql"),
        Finding(title="Missing CSP header", severity=Severity.LOW,
                url="http://host/"),
    ]


def test_collector_add_and_all():
    coll = Findings()
    if len(coll) != 0:
        raise AssertionError
    coll.add(_sample()[0])
    if len(coll) != 1 or coll.all()[0].title != "SQL Injection":
        raise AssertionError


def test_to_json_is_valid_and_serializes_severity():
    data = json.loads(to_json(_sample()))
    if len(data) != 2:
        raise AssertionError
    if data[0]["severity"] != "high":  # enum serialized to its string value
        raise AssertionError
    if data[0]["title"] != "SQL Injection":
        raise AssertionError


def test_to_sarif_is_valid():
    doc = json.loads(to_sarif(_sample()))
    if doc["version"] != "2.1.0":
        raise AssertionError
    if doc["runs"][0]["tool"]["driver"]["name"] != "Sitadel":
        raise AssertionError
    if len(doc["runs"][0]["results"]) != 2:
        raise AssertionError


def test_to_html_contains_findings():
    out = to_html(_sample())
    if "SQL Injection" not in out or "Missing CSP header" not in out:
        raise AssertionError


def test_write_report(tmp_path):
    path = os.path.join(str(tmp_path), "report.json")
    write_report(_sample(), "json", path)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if len(data) != 2:
        raise AssertionError


def test_dedup_collapses_same_issue_across_urls():
    coll = Findings()
    # Same plugin + endpoint + parameter, only the query value differs: one
    # finding with an occurrence count, plus the extra URLs recorded.
    for i in range(5):
        coll.add(Finding(title="SQLi", plugin="Sql", parameter="id",
                         url=f"http://host/item?id={i}"))
    if len(coll) != 1:
        raise AssertionError("repeats must collapse to a single finding")
    item = coll.all()[0]
    if item.occurrences != 5:
        raise AssertionError("occurrences must count every repeat")
    if item.url != "http://host/item?id=0":
        raise AssertionError("first seen URL is kept as representative")
    if len(item.other_urls) != 4:
        raise AssertionError("distinct extra URLs must be recorded")


def test_dedup_keeps_distinct_types_and_params_separate():
    coll = Findings()
    coll.add(Finding(title="SQLi", plugin="Sql", parameter="id",
                     url="http://host/item?id=1"))
    coll.add(Finding(title="SQLi", plugin="Sql", parameter="name",
                     url="http://host/item?name=x"))  # different param
    coll.add(Finding(title="XSS", plugin="Xss", parameter="id",
                     url="http://host/item?id=1"))     # different type
    coll.add(Finding(title="SQLi", plugin="Sql", parameter="id",
                     url="http://host/other?id=1"))    # different endpoint
    if len(coll) != 4:
        raise AssertionError("distinct type/param/endpoint must not collapse")


def test_json_serializes_enriched_fields():
    f = Finding(title="SQLi", severity=Severity.HIGH, plugin="Sql",
                cwe="CWE-89", owasp="A03:2021-Injection", wstg="WSTG-INPV-05",
                remediation="Use prepared statements", occurrences=3)
    data = json.loads(to_json([f]))[0]
    for key in ("cwe", "owasp", "wstg", "remediation", "occurrences",
                "confidence", "parameter"):
        if key not in data:
            raise AssertionError(f"{key} must be serialized")
    if data["occurrences"] != 3 or data["cwe"] != "CWE-89":
        raise AssertionError


def test_sarif_carries_rule_help_and_standards():
    f = Finding(title="SQLi", severity=Severity.HIGH, plugin="Sql",
                url="http://host/x", cwe="CWE-89",
                owasp="A03:2021-Injection", wstg="WSTG-INPV-05",
                remediation="Use prepared statements")
    doc = json.loads(to_sarif([f]))
    driver = doc["runs"][0]["tool"]["driver"]
    rules = driver["rules"]
    if not rules or rules[0]["id"] != "Sql":
        raise AssertionError("a rule must be registered per rule id")
    if rules[0]["help"]["text"] != "Use prepared statements":
        raise AssertionError("remediation must land in rule.help")
    if "CWE-89" not in rules[0]["properties"]["tags"]:
        raise AssertionError("standards must be exposed as rule tags")
    result = doc["runs"][0]["results"][0]
    if result["level"] != "error":  # high -> error
        raise AssertionError


def test_html_shows_evidence_remediation_and_count():
    f = Finding(title="SQLi", severity=Severity.HIGH, url="http://host/x",
                evidence="MySQL syntax error", remediation="Use prepared statements",
                cwe="CWE-89", occurrences=7)
    out = to_html([f])
    for needle in ("MySQL syntax error", "Use prepared statements", "CWE-89", "7"):
        if needle not in out:
            raise AssertionError(f"HTML must show {needle!r}")
