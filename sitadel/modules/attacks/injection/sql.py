import re
from sitadel.utils.container import Services
from sitadel.config.settings import Risk
from .. import AttackPlugin


class Sql(AttackPlugin):
    level = Risk.DANGEROUS
    output = Services.get("output")
    request = Services.get("request_factory")
    datastore = Services.get("datastore")
    logger = Services.get("logger")

    def dberror(self, data):
        if re.search(
            r"supplied argument is not a valid MySQL|Column count doesn\'t match value count at row|mysql_fetch_array()|on MySQL result index|You have an error in your SQL syntax;|You have an error in your SQL syntax near|MySQL server version for the right syntax to use|\[MySQL]\[ODBC|Column count doesn\'t match|valid MySQL result|MySqlClient.",
            data,
        ):
            return "MySQL Injection"
        if re.search(
            r"System.Data.OleDb.OleDbException|\[Microsoft]\[ODBC SQL Server Driver]|\[Macromedia]\[SQLServer JDBC Driver]|SqlException|System.Data.SqlClient.SqlException|Unclosed quotation mark after the character string|mssql_query()|Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|Sintaxis incorrecta cerca de|Syntax error in string in query expression|Unclosed quotation mark before the character string|Data type mismatch in criteria expression.|ADODB.Field (0x800A0BCD)|the used select statements have different number of columns",
            data,
        ):
            return "MSSQL-Based Injection"
        if re.search(
            r"java.sql.SQLException|java.sql.SQLSyntaxErrorException|org.hibernate.QueryException: unexpected char:|org.hibernate.QueryException: expecting \'",
            data,
        ):
            return "Java.SQL Injection"
        if re.search(
            r"PostgreSQL query failed:|supplied argument is not a valid PostgreSQL result|pg_query() \[:|pg_exec() \[:|valid PostgreSQL result|Npgsql.|PostgreSQL query failed: ERROR: parser:",
            data,
        ):
            return "PostgreSQL Injection"
        if re.search(r"\[IBM]\[CLI Driver]\[DB2/6000]|DB2 SQL error", data):
            return "DB2 Injection"
        if re.search(
            r"<b>Warning</b>: ibase_|Unexpected end of command in statement|Dynamic SQL Error",
            data,
        ):
            return "Interbase Injection"
        if re.search(r"Sybase message:", data):
            return "Sybase Injection"
        if re.search(r"Oracle error", data):
            return "Oracle Injection"
        if re.search(
            r"SQLite/JDBCDriver|System.Data.SQLite.SQLiteException|SQLITE_ERROR|SQLite.Exception",
            data,
        ):
            return "SQLite Injection"
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
