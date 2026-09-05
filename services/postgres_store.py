"""PostgreSQL implementation of the control plane's small DB-API surface.

Only the SQL dialect differences used by our repositories are translated here.
No provider payloads or arbitrary client SQL reach this adapter.
"""

import re
import sqlite3
from typing import Any

LOCK_ID = 714_901_386


def placeholders(statement: str) -> str:
    """Translate qmark parameters without changing quoted SQL literals."""
    parts = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", statement)
    return "".join(
        part.replace("%", "%%").replace("?", "%s") if index % 2 == 0
        else part.replace("%", "%%")
        for index, part in enumerate(parts)
    )


def translate(statement: str) -> tuple[str, bool]:
    normalized = " ".join(statement.split()).rstrip(";")
    if normalized.upper() == "BEGIN IMMEDIATE":
        return f"SELECT pg_advisory_xact_lock({LOCK_ID})", False
    if normalized.upper() == "PRAGMA JOURNAL_MODE=WAL":
        return "SELECT 'postgresql' AS journal_mode", False
    if normalized.upper() == "PRAGMA TABLE_INFO(USERS)":
        return (
            "SELECT column_name AS name FROM information_schema.columns "
            "WHERE table_schema = 'multillm' AND table_name = 'users'",
            False,
        )
    if "FROM sqlite_master" in normalized:
        if normalized != "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'":
            raise ValueError("Unsupported schema query")
        return (
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'multillm' AND table_name = 'users'",
            False,
        )
    if normalized.upper().startswith("PRAGMA "):
        raise ValueError("Unsupported PostgreSQL repository operation")
    statement = re.sub(
        r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", statement
    )
    # SQLite REAL holds doubles; PostgreSQL REAL is single precision and would
    # round epoch timestamps enough to break login lockout windows.
    if normalized.upper().startswith("CREATE TABLE"):
        statement = re.sub(r"\bREAL\b", "DOUBLE PRECISION", statement)
    if normalized.upper().startswith("INSERT OR IGNORE "):
        statement = statement.replace("INSERT OR IGNORE", "INSERT", 1).rstrip().rstrip(";")
        statement += " ON CONFLICT DO NOTHING"
    inserted_id = normalized.upper().startswith("INSERT INTO REQUEST_USAGE ")
    if inserted_id:
        statement = statement.rstrip().rstrip(";") + " RETURNING id"
    return statement, inserted_id


class Cursor:
    def __init__(self, cursor: Any, inserted_id: bool = False):
        self._cursor = cursor
        self.rowcount = cursor.rowcount
        self.lastrowid = cursor.fetchone()["id"] if inserted_id else None

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self):
        return iter(self._cursor)


class PostgresConnection:
    dialect = "postgresql"

    def __init__(self, database_url: str):
        try:
            import psycopg
            from psycopg.rows import dict_row

            self._driver = psycopg
            self._connection = psycopg.connect(
                database_url, row_factory=dict_row, connect_timeout=5,
                options="-c statement_timeout=10000 -c lock_timeout=5000",
            )
            # Match SQLite's serialized control-plane writes, including first
            # schema initialization and cross-process quota admission.
            self._connection.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_ID,))
            self._connection.execute("CREATE SCHEMA IF NOT EXISTS multillm")
            self._connection.execute("SET search_path TO multillm, pg_catalog")
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise sqlite3.OperationalError("PostgreSQL control-plane connection failed") from None

    def execute(self, statement: str, parameters=()):
        sql, inserted_id = translate(statement)
        try:
            cursor = self._connection.execute(
                placeholders(sql) if parameters else sql,
                parameters or None,
            )
            return Cursor(cursor, inserted_id)
        except self._driver.IntegrityError:
            raise sqlite3.IntegrityError("Control-plane constraint violation") from None
        except self._driver.Error:
            raise sqlite3.OperationalError("PostgreSQL control-plane operation failed") from None

    def executemany(self, statement: str, parameters):
        result = None
        for values in parameters:
            result = self.execute(statement, values)
        return result

    def commit(self):
        try:
            self._connection.commit()
        except self._driver.Error:
            raise sqlite3.OperationalError("PostgreSQL control-plane commit failed") from None

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if error_type is None:
            self.commit()
        else:
            self.rollback()
