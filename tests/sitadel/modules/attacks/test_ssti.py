"""SSTI detector: evaluated product flags; reflected literal does not."""
import logging

import pytest

from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, text):
        self.text = text


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("request_factory", object())
    Services.register("logger", logging.getLogger("ssti"))
    yield
    for k in ("output", "request_factory", "logger"):
        Services.services.pop(k, None)


def test_evaluated_product_is_detected():
    from sitadel.modules.attacks.injection.ssti import Ssti
    # 31*37 = 1147; payload carries the expression, response the product only.
    if Ssti().detect(_Resp("result: 1147"), "{{31*37}}") != \
            "Server-Side Template Injection":
        raise AssertionError("evaluated product must be detected")


def test_reflected_literal_is_not_detected():
    from sitadel.modules.attacks.injection.ssti import Ssti
    # The payload is echoed verbatim (not evaluated) -> no finding.
    if Ssti().detect(_Resp("you searched for {{31*37}}"), "{{31*37}}") is not None:
        raise AssertionError("a reflected literal must not be detected")


def test_clean_response_is_not_detected():
    from sitadel.modules.attacks.injection.ssti import Ssti
    if Ssti().detect(_Resp("nothing here"), "{{31*37}}") is not None:
        raise AssertionError("a clean response must not be detected")
