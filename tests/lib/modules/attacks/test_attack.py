import pytest
import logging

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.attacks import AttackPlugin, Attacks
from lib.utils.container import Services
from lib.utils.output import Output
from lib.utils.datastore import Datastore
from lib.request.request import Request


def test_attack_plugin():
    f = AttackPlugin()
    assert f.level == Risk.NOISY

    assert hasattr(f, 'process')

    with pytest.raises(NotImplementedError):
        f.process(start_url=None, crawled_urls=None)

    assert f.__repr__() == "Modules"


def test_new_attack_plugin():
    settings.risk = Risk.NOISY

    class DangerousAttackPlugin(AttackPlugin):
        level = Risk.DANGEROUS

        def process(self, start_url, crawled_urls):
            pass

    dangerous = DangerousAttackPlugin()
    assert dangerous is not None
    assert dangerous.level == Risk.DANGEROUS
    assert dangerous.plugins == []

    class GoodAttackPlugin(AttackPlugin):
        level = Risk.NO_DANGER

        def process(self, start_url, crawled_urls):
            pass

    good = GoodAttackPlugin()
    assert good is not None
    assert good.level == Risk.NO_DANGER
    assert good.plugins != []
    assert id(good.plugins[0]) == id(GoodAttackPlugin)


def test_attack_launcher():
    # Add services container for running
    Services.register("output", Output())

    f = Attacks(None, None)
    assert hasattr(f, 'run')

@pytest.mark.dangerous
def test_current_plugins():
    test_url="http://example.com"
    settings.from_yaml("tests/lib/config/test_attack_config.yml")
    Services.register("datastore", Datastore(settings.datastore))
    Services.register("logger", logging.getLogger("sitadelLog"))
    Services.register("output", Output())
    Services.register("request_factory",Request(url=test_url, agent="Sitadel"))
    plugins = settings.attack_plugins
    Attacks(test_url, None).run(plugins)