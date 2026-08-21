import pytest
import logging

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.modules.attacks import AttackPlugin, Attacks
from sitadel.utils.container import Services
from sitadel.utils.output import Output
from sitadel.utils.datastore import Datastore
from sitadel.request.request import SingleRequest


def test_attack_plugin():
    f = AttackPlugin()
    if f.level != Risk.NOISY:
        raise AssertionError

    if not hasattr(f, "process"):
        raise AssertionError

    with pytest.raises(NotImplementedError):
        f.process(start_url=None, crawled_urls=None)

    if f.__repr__() != "Modules":
        raise AssertionError


def test_new_attack_plugin():
    settings.risk = Risk.NOISY

    before = len(AttackPlugin.plugins)

    class DangerousAttackPlugin(AttackPlugin):
        level = Risk.DANGEROUS

        def process(self, start_url, crawled_urls):
            pass

    class GoodAttackPlugin(AttackPlugin):
        level = Risk.NO_DANGER

        def process(self, start_url, crawled_urls):
            pass

    # Both plugins are registered unconditionally at definition time.
    if len(AttackPlugin.plugins) != before + 2:
        raise AssertionError
    if DangerousAttackPlugin not in AttackPlugin.plugins:
        raise AssertionError
    if GoodAttackPlugin not in AttackPlugin.plugins:
        raise AssertionError

    # Risk filtering is applied at run time via enabled(): at NOISY risk the
    # DANGEROUS plugin is excluded while the NO_DANGER one is kept.
    enabled = AttackPlugin.enabled()
    if DangerousAttackPlugin in enabled:
        raise AssertionError
    if GoodAttackPlugin not in enabled:
        raise AssertionError


def test_taint_url():
    from urllib.parse import parse_qsl, urlsplit

    payload = "1' OR '1'='1"

    # Every query parameter value is replaced by the payload, with proper
    # separators, and the original path/fragment are preserved.
    tainted = AttackPlugin.taint_url("http://host/path?id=1&q=2#frag", payload)
    parts = urlsplit(tainted)
    if parts.path != "/path" or parts.fragment != "frag":
        raise AssertionError
    values = dict(parse_qsl(parts.query))
    if set(values.keys()) != {"id", "q"}:
        raise AssertionError
    if any(v != payload for v in values.values()):
        raise AssertionError

    # URLs without a query string yield nothing to inject into.
    if AttackPlugin.taint_url("http://host/path", payload) is not None:
        raise AssertionError


def test_attack_launcher():
    # Add services container for running
    Services.register("output", Output())
    Services.register("logger", logging.getLogger("sitadelLog"))

    f = Attacks(None, None)
    if not hasattr(f, "run"):
        raise AssertionError


@pytest.mark.dangerous
def test_current_plugins():
    test_url = "http://localhost"
    settings.from_yaml("tests/sitadel/config/test_attack_config.yml")
    Services.register("datastore", Datastore(settings.datastore))
    Services.register("logger", logging.getLogger("sitadelLog"))
    Services.register("output", Output())
    Services.register("request_factory", SingleRequest(url=test_url, agent="Sitadel"))
    plugins = settings.attack_plugins
    Attacks(test_url, [test_url]).run(plugins)
