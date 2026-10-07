"""Shared test fixtures.

Isolates the process-global ``Settings.cfg`` so a config a test loads (via
``Settings.from_yaml``) cannot leak into later tests. Without this, one test
calling ``from_yaml`` permanently rewrites ``settings.datastore`` for the rest of
the pytest process, which (combined with plugins that bind ``datastore`` as an
import-time class attribute) made the ``dangerous`` suite order-dependent and
caused cross-test FileNotFoundError failures. See the datastore-leak issue.
"""
import copy

import pytest

from sitadel.config.settings import Settings


@pytest.fixture(autouse=True)
def _isolate_settings():
    snapshot = copy.deepcopy(Settings.cfg)
    try:
        yield
    finally:
        Settings.cfg = snapshot
