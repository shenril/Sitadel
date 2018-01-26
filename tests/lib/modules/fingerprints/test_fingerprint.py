import pytest

from lib.config import settings
from lib.config.settings import Risk
from lib.modules.fingerprints import FingerprintPlugin, Fingerprints


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
