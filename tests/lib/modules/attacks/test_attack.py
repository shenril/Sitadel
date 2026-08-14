import pytest
import logging

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.attacks import AttackPlugin, Attacks
from lib.utils.container import Services
from lib.utils.output import Output
from lib.utils.datastore import Datastore
from lib.request.request import SingleRequest


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

    class DangerousAttackPlugin(AttackPlugin):
        level = Risk.DANGEROUS

        def process(self, start_url, crawled_urls):
            pass

    dangerous = DangerousAttackPlugin()
    if dangerous is None:
        raise AssertionError
    if dangerous.level != Risk.DANGEROUS:
        raise AssertionError
    if dangerous.plugins != []:
        raise AssertionError

    class GoodAttackPlugin(AttackPlugin):
        level = Risk.NO_DANGER

        def process(self, start_url, crawled_urls):
            pass

    good = GoodAttackPlugin()
    if good is None:
        raise AssertionError
    if good.level != Risk.NO_DANGER:
        raise AssertionError
    if good.plugins == []:
        raise AssertionError
    if id(good.plugins[0]) != id(GoodAttackPlugin):
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
    settings.from_yaml("tests/lib/config/test_attack_config.yml")
    Services.register("datastore", Datastore(settings.datastore))
    Services.register("logger", logging.getLogger("sitadelLog"))
    Services.register("output", Output())
    Services.register("request_factory", SingleRequest(url=test_url, agent="Sitadel"))
    plugins = settings.attack_plugins
    Attacks(test_url, [test_url]).run(plugins)
