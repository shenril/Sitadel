"""build_targets extends the crawled URLs with registered form_targets."""
import pytest

from sitadel.modules.attacks import AttackPlugin
from sitadel.modules.attacks.targets import Target
from sitadel.utils.container import Services


@pytest.fixture(autouse=True)
def _clean():
    yield
    for k in ("api_targets", "form_targets"):
        Services.services.pop(k, None)


def test_form_targets_are_included():
    form = Target(url="http://h/login", method="POST", body_format="form",
                  params={"user": ""})
    Services.register("form_targets", [form])
    targets = AttackPlugin.build_targets(["http://h/?id=1"])
    if not any(t.body_format == "form" and t.url == "http://h/login" for t in targets):
        raise AssertionError("form target must be included in build_targets")
    # The crawled URL is still present as a GET target.
    if not any(t.url == "http://h/?id=1" for t in targets):
        raise AssertionError


def test_no_form_targets_is_fine():
    targets = AttackPlugin.build_targets(["http://h/?id=1"])
    if len(targets) != 1:
        raise AssertionError
