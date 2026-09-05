import os
import sqlite3
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from services.control_plane_backup import (
    capture, read_backup, restore_empty, validate, write_backup,
)
from services.postgres_store import placeholders, translate
from services.sqlite_store import connect


@pytest.fixture
def storage(tmp_path):
    with patch.dict(os.environ, {
        "CONTROL_PLANE_DATABASE_URL": "",
        "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"),
        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"),
        "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3"),
        "CONNECTION_PROFILES_DB_PATH": str(tmp_path / "workbench.sqlite3"),
    }):
        document = capture()
        document["tables"]["model_overrides"] = [{"model_id": "example:model", "status": "disabled"}]
        restore_empty(document)
        yield tmp_path


def test_backup_encrypted_owner_only_and_no_overwrite(storage):
    key = Fernet.generate_key()
    path = storage / "test.control-plane-backup"
    write_backup(path, key)
    assert b"example:model" not in path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_backup(path, key)["tables"]["model_overrides"][0]["status"] == "disabled"
    with pytest.raises(FileExistsError):
        write_backup(path, key)
    with pytest.raises(ValueError, match="authentication"):
        read_backup(path, Fernet.generate_key())


def test_restore_refuses_existing_data(storage):
    document = capture()
    with pytest.raises(ValueError, match="not empty"):
        restore_empty(document)
    assert capture()["tables"] == document["tables"]


def test_backup_rejects_unrecognized_columns(storage):
    document = capture()
    document["tables"]["model_overrides"][0]["api_key"] = "synthetic"
    with pytest.raises(ValueError, match="columns"):
        validate(document)


def test_postgres_placeholders_and_narrow_dialect_translation():
    assert placeholders("SELECT '?', \"?\", ?, '100%' ") == "SELECT '?', \"?\", %s, '100%%' "
    assert "pg_advisory_xact_lock" in translate("BEGIN IMMEDIATE")[0]
    assert "BIGSERIAL" in translate("CREATE TABLE example(id INTEGER PRIMARY KEY AUTOINCREMENT)")[0]
    assert "DOUBLE PRECISION" in translate("CREATE TABLE example(ts REAL NOT NULL)")[0]
    assert translate("INSERT OR IGNORE INTO example (id) VALUES (?)")[0].endswith("ON CONFLICT DO NOTHING")
    with pytest.raises(ValueError):
        translate("PRAGMA user_version=5")


def test_configured_postgres_fails_closed_without_local_file(storage):
    path = storage / "must-not-exist.sqlite3"
    with patch.dict(os.environ, {"CONTROL_PLANE_DATABASE_URL": "invalid-synthetic-dsn"}):
        with pytest.raises(sqlite3.OperationalError, match="connection failed") as error:
            connect(path)
    assert "invalid-synthetic" not in str(error.value)
    assert not path.exists()


def test_postgres_backend_round_trip_when_test_database_is_configured():
    database_url = os.environ.get("TEST_CONTROL_PLANE_DATABASE_URL")
    if not database_url:
        pytest.skip("Requires an isolated PostgreSQL test database")
    from services.model_registry import ModelRegistry
    from services.auto_route_service import AutoRouteService
    from services.rate_limit_service import RateLimitService
    from services.login_attempt_service import LoginAttemptService
    from services.auth_service import AuthService
    from services.connection_profiles import WorkbenchStore

    with patch.dict(os.environ, {"CONTROL_PLANE_DATABASE_URL": database_url}):
        AuthService._ensure_storage()
        ModelRegistry.disable_model("opencode:storage-probe")
        assert ModelRegistry._status_overrides()["opencode:storage-probe"] == "disabled"
        assert AutoRouteService.list_routes()
        decision = RateLimitService.reserve_request_slot("openai", None, "192.0.2.50", {"max_tokens": 1})
        assert decision.allowed and decision.metadata["reservation_id"] > 0
        now = 1788572345.125
        LoginAttemptService.record_failure("192.0.2.50", "synthetic", now=now)
        with connect(Path("unused")) as connection:
            row = connection.execute("SELECT window_started FROM login_attempts").fetchone()
            assert row["window_started"] == now
        assert capture()["tables"]["request_usage"]
        profile = dict(name="PostgreSQL probe", kind="roleplay", provider="nanogpt", model="z-ai/glm-5.3-flash",
                       mode="pinned", effort="high", billing="subscription-only", fallback="none", memory="off", recovery="off")
        identifier = WorkbenchStore.save_profile("storage-probe-owner", profile)
        assert any(item["id"] == identifier for item in WorkbenchStore.profiles("storage-probe-owner"))
        assert WorkbenchStore.profiles("another-storage-owner") == []
        assert capture()["tables"]["connection_profiles"]
