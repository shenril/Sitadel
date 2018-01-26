import os

import pytest

from lib.config import settings


def test_config_exception():
    with pytest.raises(NameError):
        settings.test = 3


def test_valid_config_value():
    settings.dns_resolver = "2.2.2.2"
    assert settings.dns_resolver == "2.2.2.2"


def test_singleton_config():
    settings.dns_resolver = "9.9.9.9"
    assert settings.dns_resolver == "9.9.9.9"
    settings.dns_resolver = "2.2.2.2"
    assert settings.dns_resolver == "2.2.2.2"
    assert settings == settings


def test_bad_filepath_config_file():
    with pytest.raises(FileNotFoundError):
        settings.from_yaml("conf.yml")


def test_yaml_config_file():
    settings.from_yaml(os.path.join(os.path.dirname(__file__), 'good-config.yml'))
    assert settings.dns_resolver == "8.8.8.8"
    assert settings.plugins[0] == "test-plugin"
    with pytest.raises(IndexError):
        assert settings.plugins[1]
