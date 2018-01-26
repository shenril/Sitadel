import pytest

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.attacks import AttackPlugin, Attacks


def test_attack_plugin():
    f = AttackPlugin()
    assert f.level == Risk.NOISY

    assert hasattr(f, 'process')

    with pytest.raises(NotImplementedError):
        f.process(output=None, datastore=None, request=None)

    assert f.__repr__() == "Modules"


def test_new_attack_plugin():
    settings.risk = Risk.NOISY

    class DangerousAttackPlugin(AttackPlugin):
        level = Risk.DANGEROUS

        def process(self, output, datastore, request):
            pass

    dangerous = DangerousAttackPlugin()
    assert dangerous is not None
    assert dangerous.level == Risk.DANGEROUS
    assert dangerous.plugins == []

    class GoodAttackPlugin(AttackPlugin):
        level = Risk.NO_DANGER

        def process(self, output, datastore, request):
            pass

    good = GoodAttackPlugin()
    assert good is not None
    assert good.level == Risk.NO_DANGER
    assert good.plugins != []
    assert id(good.plugins[0]) == id(GoodAttackPlugin)


def test_attack_launcher():
    f = Attacks(None, None, None, None, None, None, None, None)
    assert hasattr(f, 'run')
