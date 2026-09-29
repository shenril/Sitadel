"""Exposed-file probing: signature confirmation, soft-404 safety."""
import logging
from urllib.parse import urlsplit

import pytest

from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeReq:
    """mode: 'git' | 'soft404' | 'backup'."""

    def __init__(self, mode):
        self.mode = mode

    def send(self, url, method="GET", payload=None, headers=None, cookies=None):
        path = urlsplit(url).path
        if self.mode == "soft404":
            return _Resp(200, "<html>page not found</html>")
        # Sites that serve real 404s:
        if path.endswith(".git/HEAD") and self.mode == "git":
            return _Resp(200, "ref: refs/heads/main\n")
        if path.endswith("/backup.sql") and self.mode == "backup":
            return _Resp(200, "CREATE TABLE users (id INT, password TEXT);")
        return _Resp(404, "not found")


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("exposure"))
    Services.register("datastore", Datastore("sitadel/data"))
    Services.register("findings", Findings())
    yield
    for k in ("output", "logger", "datastore", "findings", "request_factory", "cancel"):
        Services.services.pop(k, None)


def _run(mode):
    Services.register("request_factory", _FakeReq(mode))
    from sitadel.modules.attacks.other.exposure import Exposure
    Exposure().process("http://ex.com/app/", [])
    return Services.get("findings").all()


def test_git_head_signature_is_flagged():
    findings = _run("git")
    if not any(".git/HEAD" in (f.parameter or "") for f in findings):
        raise AssertionError("exposed .git/HEAD must be flagged")


def test_soft_404_site_produces_no_findings():
    if _run("soft404"):
        raise AssertionError("a soft-404 site must not false-positive")


def test_generic_backup_flagged_only_when_real_404s():
    findings = _run("backup")
    if not any("backup.sql" in (f.parameter or "") for f in findings):
        raise AssertionError("exposed backup.sql must be flagged on a real-404 site")
