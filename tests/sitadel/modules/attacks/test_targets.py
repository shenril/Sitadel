import json

from sitadel.modules.attacks.targets import (
    Target,
    taint_body,
    taint_target,
    taint_url,
)


def test_taint_url_replaces_all_params_or_none():
    tainted = taint_url("http://h/p?id=1&q=2", "X")
    if "id=X" not in tainted or "q=X" not in tainted:
        raise AssertionError
    if taint_url("http://h/p", "X") is not None:
        raise AssertionError


def test_taint_body_json():
    body = taint_body({"a": "1", "b": "1"}, "P", "json")
    data = json.loads(body)
    if data != {"a": "P", "b": "P"}:
        raise AssertionError


def test_taint_body_xml_escapes():
    body = taint_body({"user": "1"}, "<x>&", "xml")
    if "<user>" not in body or "&lt;x&gt;&amp;" not in body:
        raise AssertionError


def test_taint_body_form():
    body = taint_body({"a": "1", "b": "1"}, "P", "form")
    if body not in ("a=P&b=P", "b=P&a=P"):
        raise AssertionError


def test_taint_body_defaults_to_input_when_no_params():
    if json.loads(taint_body({}, "P", "json")) != {"input": "P"}:
        raise AssertionError


def test_taint_target_get_query():
    t = Target(url="http://h/p?id=1")
    kw = taint_target(t, "P")
    if kw["method"] != "GET" or "id=P" not in kw["url"] or kw["payload"] is not None:
        raise AssertionError


def test_taint_target_get_without_params_is_skipped():
    if taint_target(Target(url="http://h/p"), "P") is not None:
        raise AssertionError


def test_taint_target_json_body_sets_content_type_and_method():
    t = Target(url="http://h/login", method="POST", body_format="json",
               params={"username": "1", "password": "1"})
    kw = taint_target(t, "P")
    if kw["method"] != "POST":
        raise AssertionError
    if kw["headers"]["Content-Type"] != "application/json":
        raise AssertionError
    if json.loads(kw["payload"]) != {"username": "P", "password": "P"}:
        raise AssertionError


def test_taint_target_body_defaults_get_to_post():
    # A body target whose method is left as GET is promoted to POST.
    t = Target(url="http://h/x", body_format="json", params={"a": "1"})
    if taint_target(t, "P")["method"] != "POST":
        raise AssertionError


def test_describe():
    if Target(url="http://h/p?id=1").describe() != "http://h/p?id=1":
        raise AssertionError
    d = Target(url="http://h/x", method="POST", body_format="json").describe()
    if d != "POST http://h/x (json body)":
        raise AssertionError
