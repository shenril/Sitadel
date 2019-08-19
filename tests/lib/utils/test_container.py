import pytest

from lib.utils.container import Services


def test_container():
    Services.register("datastore", "hello")
    if Services.get("datastore") != "hello":
        raise AssertionError

    a = "singleton"

    Services.register("singleton", a)
    if Services.get("singleton") != a:
        raise AssertionError


def test_bad_service():
    with pytest.raises(NameError):
        Services.get("example")

    Services.register("example", "test")
    if Services.get("example") is None:
        raise AssertionError
