import pytest

from sitadel.utils.container import ServiceNotFound, Services


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


def test_missing_service_raises_service_not_found():
    Services.services.pop("nope", None)
    with pytest.raises(ServiceNotFound):
        Services.get("nope")


def test_service_not_found_is_a_name_error():
    # The many ``except NameError`` "is it registered?" guards must keep
    # catching the more specific exception.
    if not issubclass(ServiceNotFound, NameError):
        raise AssertionError
