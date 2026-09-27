"""In-band XXE: builds a DOCTYPE/entity body and detects reflected file reads."""
import logging

import pytest

from sitadel.report import Findings
from sitadel.modules.attacks.targets import Target
from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200


class _VulnRequest:
    """Simulates a vulnerable XML parser: resolves the SYSTEM file entity and
    reflects the file contents (only for the /etc/passwd payload)."""

    def send(self, url, method="GET", payload=None, headers=None, cookies=None,
             allow_redirects=None):
        if payload and 'SYSTEM "file:///etc/passwd"' in payload:
            return _Resp("welcome root:x:0:0:root:/root:/bin/bash")
        return _Resp("no entities here")


class _SafeRequest:
    def send(self, url, method="GET", payload=None, headers=None, cookies=None,
             allow_redirects=None):
        return _Resp("all input echoed literally: &xxe;")


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("xxe"))
    Services.register("findings", Findings())
    yield
    for k in ("output", "logger", "findings", "request_factory", "api_targets",
              "form_targets", "cancel"):
        Services.services.pop(k, None)


def test_build_body_wraps_doctype_and_references_entity():
    from sitadel.modules.attacks.injection.xxe import Xxe
    t = Target(url="http://h/x", method="POST", body_format="xml",
               params={"name": "1"})
    body = Xxe._build_body(t, "file:///etc/passwd")
    if "<!DOCTYPE root [" not in body or 'ENTITY xxe SYSTEM "file:///etc/passwd"' not in body:
        raise AssertionError("body must declare the external entity")
    if "<name>&xxe;</name>" not in body:
        raise AssertionError("entity must be referenced in the target's field")


def _run(request):
    Services.register("request_factory", request)
    Services.register("api_targets", [
        Target(url="http://h/api/xml", method="POST", body_format="xml",
               params={"data": "1"}),
    ])
    from sitadel.modules.attacks.injection.xxe import Xxe
    Xxe().process("http://h/", [])
    return Services.get("findings").all()


def test_reflected_file_read_is_flagged():
    findings = _run(_VulnRequest())
    if not findings or findings[0].plugin != "Xxe":
        raise AssertionError("reflected /etc/passwd must be reported as XXE")


def test_non_reflecting_endpoint_not_flagged():
    if _run(_SafeRequest()):
        raise AssertionError("an endpoint that does not resolve the entity must not fire")


def test_no_xml_targets_is_noop():
    Services.register("request_factory", _VulnRequest())
    from sitadel.modules.attacks.injection.xxe import Xxe
    Xxe().process("http://h/", ["http://h/?id=1"])  # only a GET url, no xml target
    if Services.get("findings").all():
        raise AssertionError("no XML targets -> no findings")
