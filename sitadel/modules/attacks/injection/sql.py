import re
from sitadel.utils.container import Services
from sitadel.config.settings import Risk
from .. import AttackPlugin

# DB-error signatures, compiled once at import (the detector runs on every
# response — per payload × target — so pre-compiling keeps the hot path cheap).
_DB_ERRORS = [
    (re.compile(
        r"supplied argument is not a valid MySQL|Column count doesn\'t match value count at row|mysql_fetch_array()|on MySQL result index|You have an error in your SQL syntax;|You have an error in your SQL syntax near|MySQL server version for the right syntax to use|\[MySQL]\[ODBC|Column count doesn\'t match|valid MySQL result|MySqlClient."
    ), "MySQL Injection"),
    (re.compile(
        r"System.Data.OleDb.OleDbException|\[Microsoft]\[ODBC SQL Server Driver]|\[Macromedia]\[SQLServer JDBC Driver]|SqlException|System.Data.SqlClient.SqlException|Unclosed quotation mark after the character string|mssql_query()|Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|Sintaxis incorrecta cerca de|Syntax error in string in query expression|Unclosed quotation mark before the character string|Data type mismatch in criteria expression.|ADODB.Field (0x800A0BCD)|the used select statements have different number of columns"
    ), "MSSQL-Based Injection"),
    (re.compile(
        r"java.sql.SQLException|java.sql.SQLSyntaxErrorException|org.hibernate.QueryException: unexpected char:|org.hibernate.QueryException: expecting \'"
    ), "Java.SQL Injection"),
    (re.compile(
        r"PostgreSQL query failed:|supplied argument is not a valid PostgreSQL result|pg_query() \[:|pg_exec() \[:|valid PostgreSQL result|Npgsql.|PostgreSQL query failed: ERROR: parser:"
    ), "PostgreSQL Injection"),
    (re.compile(r"\[IBM]\[CLI Driver]\[DB2/6000]|DB2 SQL error"), "DB2 Injection"),
    (re.compile(
        r"<b>Warning</b>: ibase_|Unexpected end of command in statement|Dynamic SQL Error"
    ), "Interbase Injection"),
    (re.compile(r"Sybase message:"), "Sybase Injection"),
    (re.compile(r"Oracle error"), "Oracle Injection"),
    (re.compile(
        r"SQLite/JDBCDriver|System.Data.SQLite.SQLiteException|SQLITE_ERROR|SQLite.Exception"
    ), "SQLite Injection"),
]


class Sql(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def dberror(self, data):
        for pattern, label in _DB_ERRORS:
            if pattern.search(data):
                return label
        return None

    def detect(self, resp, payload):
        return self.dberror(resp.text)

    def process(self, start_url, crawled_urls):
        self.output.info("Checking sql injection...")
        with self.datastore.open("sql.txt", "r") as db:
            payloads = [x.rstrip("\n") for x in db]
        # One bounded pool over every injectable target (GET query + API
        # JSON/XML/form bodies); detection is unchanged across surfaces.
        self.run_injection(payloads, crawled_urls, self.detect)
