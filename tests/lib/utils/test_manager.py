from lib.utils import manager


def test_manager():
    ma = manager
    assert hasattr(ma, 'attacks')
    assert hasattr(ma, 'crawl')
    assert hasattr(ma, 'fingerprints')
