"""The compiled injection detectors (Tier 1 C1) must preserve behaviour:
known DB/LDAP error strings still map to the right label, and clean responses
return None."""
import logging

import pytest

from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("test"))
    Services.register("request_factory", object())
    Services.register("datastore", object())
    yield
    for key in ("request_factory", "datastore"):
        Services.services.pop(key, None)


def test_sql_dberror_labels():
    from sitadel.modules.attacks.injection.sql import Sql
    sql = Sql()
    if sql.dberror("You have an error in your SQL syntax; near") != "MySQL Injection":
        raise AssertionError
    if sql.dberror("Microsoft OLE DB Provider for SQL Server") != "MSSQL-Based Injection":
        raise AssertionError
    if sql.dberror("PostgreSQL query failed: bad") != "PostgreSQL Injection":
        raise AssertionError
    if sql.dberror("a perfectly ordinary page") is not None:
        raise AssertionError


def test_ldap_errors_label():
    from sitadel.modules.attacks.injection.ldap import LDAP
    ldap = LDAP()
    if ldap.errors("javax.naming.NameNotFoundException: bad") != "LDAP Injection":
        raise AssertionError
    if ldap.errors("nothing suspicious here") is not None:
        raise AssertionError
