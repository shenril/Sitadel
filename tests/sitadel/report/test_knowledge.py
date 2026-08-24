from sitadel.report import Severity
from sitadel.report.knowledge import lookup


def test_lookup_exact_key():
    entry = lookup("sql")
    if entry["severity"] != Severity.HIGH or entry["cwe"] != "CWE-89":
        raise AssertionError


def test_lookup_is_case_insensitive():
    if lookup("SQL")["cwe"] != lookup("sql")["cwe"]:
        raise AssertionError


def test_lookup_substring_fallback():
    # A coarse label containing a known key still resolves.
    entry = lookup("sql injection")
    if entry["cwe"] != "CWE-89":
        raise AssertionError


def test_lookup_unknown_returns_neutral_default():
    entry = lookup("totally-unknown-type")
    if entry["severity"] != Severity.INFO or entry["cwe"] is not None:
        raise AssertionError


def test_lookup_none():
    entry = lookup(None)
    if entry["severity"] != Severity.INFO:
        raise AssertionError


def test_lookup_returns_a_copy():
    # Mutating a returned entry must not corrupt the shared table.
    entry = lookup("sql")
    entry["cwe"] = "mutated"
    if lookup("sql")["cwe"] != "CWE-89":
        raise AssertionError
