"""Path traversal detector: file signatures flag; clean responses do not."""
import logging

import pytest

from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, text):
        self.text = text


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("request_factory", object())
    Services.register("datastore", Datastore("sitadel/data"))
    Services.register("logger", logging.getLogger("trav"))
    yield
    for k in ("output", "request_factory", "datastore", "logger"):
        Services.services.pop(k, None)


def test_passwd_signature_detected():
    from sitadel.modules.attacks.injection.traversal import Traversal
    body = "root:x:0:0:root:/root:/bin/bash\n"
    if Traversal().detect(_Resp(body), "../../etc/passwd") != "Path Traversal / LFI":
        raise AssertionError("/etc/passwd signature must be detected")


def test_win_ini_signature_detected():
    from sitadel.modules.attacks.injection.traversal import Traversal
    if Traversal().detect(_Resp("[fonts]\nfoo=bar"), "..\\win.ini") is None:
        raise AssertionError("win.ini signature must be detected")


def test_clean_response_not_detected():
    from sitadel.modules.attacks.injection.traversal import Traversal
    if Traversal().detect(_Resp("<html>hello</html>"), "../../etc/passwd") is not None:
        raise AssertionError("a clean response must not be detected")
