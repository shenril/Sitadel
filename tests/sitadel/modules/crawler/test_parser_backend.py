"""Guard against the selectolax Modest-backend removal (issue #109).

selectolax 1.0 dropped the Modest backend, so importing ``selectolax.parser``
raises at import time. The crawler and the form-login authenticator must use the
Lexbor backend. These tests fail loudly if either regresses to the dead backend.
"""
import importlib
import inspect

from selectolax.lexbor import LexborHTMLParser


def test_crawler_and_auth_import_cleanly():
    # Would raise ImportError under selectolax 1.0 if the Modest backend returned.
    importlib.import_module("sitadel.modules.crawler.crawler")
    importlib.import_module("sitadel.request.auth")


def test_modules_use_lexbor_not_modest():
    from sitadel.modules.crawler import crawler
    from sitadel.request import auth
    for module in (crawler, auth):
        src = inspect.getsource(module)
        if "selectolax.parser" in src:
            raise AssertionError(
                "%s still imports the removed Modest backend" % module.__name__
            )
        if "selectolax.lexbor" not in src:
            raise AssertionError(
                "%s must use the Lexbor backend" % module.__name__
            )


def test_lexbor_parses_csrf_input_like_auth():
    # Mirrors the exact call Authenticator uses to read a CSRF token.
    html = '<form><input name="csrf" type="hidden" value="tok123"></form>'
    node = LexborHTMLParser(html).css_first('input[name="csrf"]')
    if node is None or node.attributes.get("value", "") != "tok123":
        raise AssertionError("Lexbor must parse the CSRF input like the old backend")
