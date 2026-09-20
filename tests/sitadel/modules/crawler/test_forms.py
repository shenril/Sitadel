"""HTML form discovery: _extract_forms turns <form>s into injectable Targets."""
from sitadel.modules.crawler.crawler import _extract_forms, form_signature


def _forms(html, base="http://ex.com/page", host="ex.com"):
    return _extract_forms(base, html, host)


def test_post_form_becomes_form_body_target_with_csrf_fixed():
    html = """
    <form action="/login" method="post">
      <input name="user" type="text">
      <input name="pass" type="password">
      <input name="csrf" type="hidden" value="tok123">
      <input type="submit" value="Go">
    </form>"""
    forms = _forms(html)
    if len(forms) != 1:
        raise AssertionError(f"expected 1 form, got {len(forms)}")
    t = forms[0]
    if t.method != "POST" or t.body_format != "form":
        raise AssertionError
    if t.url != "http://ex.com/login":
        raise AssertionError(t.url)
    if set(t.params) != {"user", "pass"} or t.fixed != {"csrf": "tok123"}:
        raise AssertionError((t.params, t.fixed))


def test_get_form_bakes_fields_into_query():
    html = '<form action="/search"><input name="q"><input name="csrf" type="hidden" value="z"></form>'
    t = _forms(html)[0]
    if t.method != "GET" or t.body_format is not None:
        raise AssertionError
    if "q=" not in t.url or "csrf=z" not in t.url:
        raise AssertionError(t.url)
    if set(t.params) != {"q"} or t.fixed != {"csrf": "z"}:
        raise AssertionError


def test_action_defaults_to_page_url():
    t = _forms('<form method="post"><input name="x"></form>')[0]
    if t.url != "http://ex.com/page":
        raise AssertionError(t.url)


def test_multipart_and_file_forms_are_skipped():
    if _forms('<form method="post" enctype="multipart/form-data"><input name="x"></form>'):
        raise AssertionError("multipart form must be skipped")
    if _forms('<form method="post"><input name="f" type="file"></form>'):
        raise AssertionError("file-upload form must be skipped")


def test_form_with_only_hidden_fields_is_skipped():
    if _forms('<form method="post"><input name="csrf" type="hidden" value="t"></form>'):
        raise AssertionError("form with no injectable field must be skipped")


def test_offsite_action_is_skipped():
    if _forms('<form action="http://evil.com/x" method="post"><input name="q"></form>'):
        raise AssertionError("off-host form action must be skipped")


def test_form_signature_collapses_duplicates():
    html = '<form action="/s" method="post"><input name="q"></form>'
    a = form_signature(_forms(html)[0])
    b = form_signature(_forms(html)[0])
    if a != b:
        raise AssertionError
