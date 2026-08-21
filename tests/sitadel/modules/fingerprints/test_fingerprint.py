import pytest
import logging

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.modules.fingerprints import FingerprintPlugin, Fingerprints
from sitadel.utils.container import Services
from sitadel.utils.output import Output
from sitadel.request.request import SingleRequest


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

    before = len(FingerprintPlugin.plugins)

    class DangerousFingerPrintPlugin(FingerprintPlugin):
        level = Risk.DANGEROUS

        def process(self, headers, content):
            pass

    class GoodFingerPrintPlugin(FingerprintPlugin):
        level = Risk.NO_DANGER

        def process(self, headers, content):
            pass

    # Both plugins are registered unconditionally at definition time.
    if len(FingerprintPlugin.plugins) != before + 2:
        raise AssertionError
    if DangerousFingerPrintPlugin not in FingerprintPlugin.plugins:
        raise AssertionError
    if GoodFingerPrintPlugin not in FingerprintPlugin.plugins:
        raise AssertionError

    # Risk filtering is applied at run time via enabled(): at NOISY risk the
    # DANGEROUS plugin is excluded while the NO_DANGER one is kept.
    enabled = FingerprintPlugin.enabled()
    if DangerousFingerPrintPlugin in enabled:
        raise AssertionError
    if GoodFingerPrintPlugin not in enabled:
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
    settings.from_yaml("tests/sitadel/config/test_fingerprint_config.yml")
    Services.register("logger", logging.getLogger("sitadelLog"))
    Services.register("output", Output())
    Services.register("request_factory", SingleRequest(url=test_url, agent="Sitadel"))
    plugins = settings.fingerprint_plugins
    Fingerprints(
        url=test_url,
        cookie=None,
    ).run(plugins)

