import pytest
import logging

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.fingerprints import FingerprintPlugin, Fingerprints
from lib.utils.container import Services
from lib.utils.output import Output
from lib.utils.datastore import Datastore
from lib.request.request import Request


def test_fingerprint_plugin():
    f = FingerprintPlugin()
    assert f.level == Risk.NO_DANGER

    assert hasattr(f, 'process')

    with pytest.raises(NotImplementedError):
        f.process(headers=None, content=None)

    assert f.__repr__() == "Modules"


def test_new_fingerprint_plugin():
    settings.risk = Risk.NOISY

    class DangerousFingerPrintPlugin(FingerprintPlugin):
        level = Risk.DANGEROUS

        def process(self, headers, content):
            pass

    dangerous = DangerousFingerPrintPlugin()
    assert dangerous is not None
    assert dangerous.level == Risk.DANGEROUS
    assert dangerous.plugins == []

    class GoodFingerPrintPlugin(FingerprintPlugin):
        level = Risk.NO_DANGER

        def process(self, headers, content):
            pass

    good = GoodFingerPrintPlugin()
    assert good is not None
    assert good.level == Risk.NO_DANGER
    assert good.plugins != []
    assert id(good.plugins[0]) == id(GoodFingerPrintPlugin)


def test_fingerprint_launcher():
    f = Fingerprints(None, None, None, None, None, None)
    assert hasattr(f, 'run')

@pytest.mark.dangerous
def test_current_plugins():
    test_url="http://localhost"
    settings.from_yaml("tests/lib/config/test_fingerprint_config.yml")
    Services.register("logger", logging.getLogger("sitadelLog"))
    Services.register("output", Output())
    Services.register("request_factory",SingleRequest(url=test_url, agent="Sitadel"))
    plugins = settings.fingerprint_plugins
    Fingerprints(agent="Sitadel",proxy=None,redirect=None,timeout=None,url=test_url,cookie=None).run(plugins)