from lib.model import TargetProfile
from lib.modules.attacks import AttackPlugin


class _PhpOnly(AttackPlugin):
    requires = {"lang": "php"}

    def process(self, start_url, crawled_urls):
        pass


def test_applies_to_fail_open_and_contradiction():
    php = _PhpOnly()

    # No profile at all -> run.
    if php.applies_to(None) is not True:
        raise AssertionError

    # Profile present but language unknown -> still run (fail-open).
    empty = TargetProfile()
    if php.applies_to(empty) is not True:
        raise AssertionError

    # Language detected as PHP -> run.
    php_profile = TargetProfile()
    php_profile.add("lang", "PHP")
    if php.applies_to(php_profile) is not True:
        raise AssertionError

    # Language positively detected as something else -> skip.
    py_profile = TargetProfile()
    py_profile.add("lang", "Python")
    if php.applies_to(py_profile) is not False:
        raise AssertionError


def test_default_plugin_applies_everywhere():
    class _Any(AttackPlugin):
        def process(self, start_url, crawled_urls):
            pass

    profile = TargetProfile()
    profile.add("lang", "Python")
    if _Any().applies_to(profile) is not True:
        raise AssertionError
