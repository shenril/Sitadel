import pytest

from lib.utils.container import Services


def test_container():
    Services.register("datastore", "hello")
    assert Services.get("datastore") == "hello"

    a = "singleton"

    Services.register("singleton", a)
    assert Services.get("singleton") == a


def test_bad_service():
    with pytest.raises(NameError):
        Services.get("example")

    Services.register("example", "test")
    assert Services.get("example") is not None
