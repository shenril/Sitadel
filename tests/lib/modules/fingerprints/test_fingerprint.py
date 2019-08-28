import pytest
import logging

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.fingerprints import FingerprintPlugin, Fingerprints
from lib.utils.container import Services
from lib.utils.output import Output
from lib.request.request import SingleRequest


def test_fingerprint_plugin():
    f = FingerprintPlugin()
    if f.level != Risk.NO_DANGER:
        raise AssertionError

    if not hasattr(f, "process"):
        raise AssertionError

    with pytest.raises(NotImplementedError):
        f.process(headers=None, content=None)

    if f.__repr__() != "Modules":
        raise AssertionError


def test_new_fingerprint_plugin():
    settings.risk = Risk.NOISY

    class DangerousFingerPrintPlugin(FingerprintPlugin):
        level = Risk.DANGEROUS

        def process(self, headers, content):
            pass

    dangerous = DangerousFingerPrintPlugin()
    if dangerous is None:
        raise AssertionError
    if dangerous.level != Risk.DANGEROUS:
        raise AssertionError
    if dangerous.plugins != []:
        raise AssertionError

    class GoodFingerPrintPlugin(FingerprintPlugin):
        level = Risk.NO_DANGER

        def process(self, headers, content):
            pass

    good = GoodFingerPrintPlugin()
    if good is None:
        raise AssertionError
    if good.level != Risk.NO_DANGER:
        raise AssertionError
    if good.plugins == []:
        raise AssertionError
    if id(good.plugins[0]) != id(GoodFingerPrintPlugin):
        raise AssertionError


def test_fingerprint_launcher():
    Services.register("output", Output())
    Services.register("request_factory", SingleRequest())
    f = Fingerprints(None, None)
    if not hasattr(f, "run"):
        raise AssertionError


@pytest.mark.dangerous
def test_current_plugins():
    test_url = "http://localhost"
    settings.from_yaml("tests/lib/config/test_fingerprint_config.yml")
    Services.register("logger", logging.getLogger("sitadelLog"))
    Services.register("output", Output())
    Services.register("request_factory", SingleRequest(url=test_url, agent="Sitadel"))
    plugins = settings.fingerprint_plugins
    Fingerprints(
        url=test_url,
        cookie=None,
    ).run(plugins)

