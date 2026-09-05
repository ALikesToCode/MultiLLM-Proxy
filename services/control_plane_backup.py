"""Encrypted, operator-only backups; restores only populate empty databases."""

import json
import math
import os
import sqlite3
from contextlib import ExitStack, closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from services.sqlite_store import connect, storage_path

MAX_BACKUP_BYTES = 32 * 1024 * 1024
TABLES = {
    "users": ("auth", "username api_key_hash api_key_prefix scopes is_admin created_at last_login last_used_at last_used_ip created_by rotated_at revoked_at"),
    "model_overrides": ("models", "model_id status"),
    "auto_routes": ("models", "route_id updated_at"),
    "auto_route_candidates": ("models", "route_id priority model_id"),
    "request_usage": ("limits", "id created_at identity key_prefix provider remote_addr input_tokens output_tokens estimated_tokens stream"),
    "login_attempts": ("limits", "identity_hash failures window_started locked_until updated_at"),
    "connection_profiles": ("workbench", "id owner name settings created_at"),
    "comparison_results": ("workbench", "id owner created_at data"),
}
STORES = {
    "auth": ("AUTH_DB_PATH", "auth.sqlite3"),
    "models": ("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3"),
    "limits": ("RATE_LIMIT_DB_PATH", "rate_limits.sqlite3"),
    "workbench": ("CONNECTION_PROFILES_DB_PATH", "workbench.sqlite3"),
}


def _connections(stack, *, source=False):
    if os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip():
        connection = stack.enter_context(closing(connect(Path("unused"))))
        return dict.fromkeys(STORES, connection)
    connections = {}
    for name, (variable, filename) in STORES.items():
        path = storage_path(variable, filename)
        if source:
            if not path.exists():
                connections[name] = None
                continue
            connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
        else:
            connection = connect(path)
        connections[name] = stack.enter_context(closing(connection))
    return connections


def _exists(connection, table):
    if connection is None:
        return False
    if getattr(connection, "dialect", "sqlite") == "postgresql":
        query = "SELECT 1 FROM information_schema.tables WHERE table_schema = 'multillm' AND table_name = ?"
    else:
        query = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
    return connection.execute(query, (table,)).fetchone() is not None


def capture():
    tables = {}
    with ExitStack() as stack:
        connections = _connections(stack, source=True)
        for table, (store, fields) in TABLES.items():
            connection = connections[store]
            if not _exists(connection, table):
                tables[table] = []
                continue
            # Both identifiers originate only in the fixed TABLES definition.
            rows = connection.execute(f"SELECT {', '.join(fields.split())} FROM {table}").fetchall()  # nosec B608
            tables[table] = [dict(row) for row in rows]
    return {"format": "multillm-control-plane", "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(), "tables": tables}


def validate(document):
    if not isinstance(document, dict) or document.get("format") != "multillm-control-plane" or document.get("version") != 1:
        raise ValueError("Unsupported backup format")
    tables = document.get("tables")
    if not isinstance(tables, dict) or set(tables) != set(TABLES):
        raise ValueError("Backup table inventory does not match")
    for table, (_, fields) in TABLES.items():
        rows = tables[table]
        if not isinstance(rows, list) or len(rows) > 100_000:
            raise ValueError("Invalid backup row count")
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(fields.split()):
                raise ValueError("Invalid backup columns")
            if any(value is not None and type(value) not in (str, int, float) for value in row.values()):
                raise ValueError("Invalid backup field type")
            if any(isinstance(value, float) and not math.isfinite(value) for value in row.values()):
                raise ValueError("Invalid backup numeric value")
    return {table: len(rows) for table, rows in tables.items()}


def write_backup(path: Path, key: bytes):
    cipher = Fernet(key)
    document = capture()
    counts = validate(document)
    raw = json.dumps(document, allow_nan=False).encode()
    if len(raw) > MAX_BACKUP_BYTES:
        raise ValueError("Backup exceeds the size limit; use database-native backup tooling")
    encrypted = cipher.encrypt(raw)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(encrypted)
        target.flush()
        os.fsync(target.fileno())
    return counts


def read_backup(path: Path, key: bytes):
    if path.stat().st_size > MAX_BACKUP_BYTES * 2:
        raise ValueError("Backup exceeds the size limit")
    try:
        raw = Fernet(key).decrypt(path.read_bytes())
        if len(raw) > MAX_BACKUP_BYTES:
            raise ValueError("Backup exceeds the size limit")
        document = json.loads(raw)
    except (InvalidToken, UnicodeError, json.JSONDecodeError):
        raise ValueError("Backup authentication or format validation failed") from None
    validate(document)
    return document


def _initialize(connections):
    from services.auth_service import AuthService
    from services.login_attempt_service import LoginAttemptService
    from services.model_registry import ModelRegistry
    from services.rate_limit_service import RateLimitService
    from services.connection_profiles import WorkbenchStore

    AuthService._create_users_table(connections["auth"])
    AuthService._ensure_users_indexes(connections["auth"])
    ModelRegistry._ensure_storage(connections["models"])
    RateLimitService._ensure_storage(connections["limits"])
    LoginAttemptService._ensure_storage(connections["limits"])
    WorkbenchStore.ensure(connections["workbench"])
    connections["models"].execute("CREATE TABLE IF NOT EXISTS auto_routes (route_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL)")
    connections["models"].execute("""CREATE TABLE IF NOT EXISTS auto_route_candidates (
        route_id TEXT NOT NULL REFERENCES auto_routes(route_id) ON DELETE CASCADE,
        priority INTEGER NOT NULL, model_id TEXT NOT NULL,
        PRIMARY KEY (route_id, priority), UNIQUE (route_id, model_id))""")


def restore_empty(document):
    """Offline migration into an empty destination; never merge or replace users."""
    counts = validate(document)
    with ExitStack() as stack:
        connections = _connections(stack)
        unique = list(dict.fromkeys(connections.values()))
        try:
            for connection in unique:
                connection.execute("BEGIN IMMEDIATE")
            for table, (store, _) in TABLES.items():
                connection = connections[store]
                if _exists(connection, table) and connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():  # nosec B608
                    raise ValueError("Destination is not empty; restore refused")
            _initialize(connections)
            for table, (store, fields) in TABLES.items():
                columns = fields.split()
                sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"  # nosec B608
                connections[store].executemany(sql, [tuple(row[column] for column in columns) for row in document["tables"][table]])
            if getattr(connections["limits"], "dialect", "sqlite") == "postgresql":
                connections["limits"].execute("SELECT setval(pg_get_serial_sequence('request_usage', 'id'), COALESCE(MAX(id), 0) + 1, false) FROM request_usage")
            for connection in unique:
                connection.commit()
        except Exception:
            for connection in unique:
                connection.rollback()
            raise
    return counts
