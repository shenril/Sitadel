from lib.utils import manager


def test_manager():
    ma = manager
    if not hasattr(ma, "attacks"):
        raise AssertionError
    if not hasattr(ma, "crawl"):
        raise AssertionError
    if not hasattr(ma, "fingerprints"):
        raise AssertionError
