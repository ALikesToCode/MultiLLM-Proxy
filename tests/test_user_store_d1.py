"""Dashboard accounts in D1 survive Container restarts and never fall back to local SQLite."""

from unittest.mock import patch

import pytest

from error_handlers import APIError
from services import user_store
from services.auth_service import AuthService
from services.intelligence_d1_store import PrivateIntelligenceError


class FakeUsersDomain:
    """The Worker's fixed account operations, held in memory."""

    def __init__(self):
        self.rows, self.calls, self.down = {}, [], False

    def __call__(self, payload, *, endpoint):
        assert endpoint == "users"
        operation = payload["operation"]
        self.calls.append(operation)
        if self.down:
            raise PrivateIntelligenceError(503, "storage_unavailable")
        if operation == "list":
            names = sorted(name for name in self.rows if payload["after"] is None or name > payload["after"])
            return {"version": 1, "users": [dict(self.rows[name]) for name in names[:payload["limit"]]]}
        if operation == "get":
            row = self.rows.get(payload["username"])
            return {"version": 1, "user": dict(row) if row else None}
        if operation == "by_prefix":
            return {"version": 1, "users": [dict(row) for _, row in sorted(self.rows.items())
                                            if row["api_key_prefix"] == payload["prefix"] and row["revoked_at"] is None]}
        if operation == "upsert":
            assert set(payload["user"]) == set(user_store.USER_FIELDS)
            self.rows[payload["user"]["username"]] = dict(payload["user"])
            return {"version": 1, "stored": True}
        if operation == "delete":
            return {"version": 1, "deleted": self.rows.pop(payload["username"], None) is not None}
        if operation == "touch":
            row = self.rows.get(payload["username"])
            if row:
                row.update(last_used_at=payload["last_used_at"], last_used_ip=payload["last_used_ip"])
            return {"version": 1, "updated": row is not None}
        raise AssertionError(operation)


@pytest.fixture
def d1(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.sqlite3"))
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-d1-admin-key")
    domain = FakeUsersDomain()
    monkeypatch.setattr(user_store, "request_private_intelligence", domain)
    restart(monkeypatch)
    yield domain
    assert not (tmp_path / "auth.sqlite3").exists(), "D1 mode never creates a local account database"


def restart(monkeypatch):
    """A new Container: empty process memory, then normal startup."""
    monkeypatch.setattr(AuthService, "_storage_path", None)
    monkeypatch.setattr(AuthService, "_users", {})
    monkeypatch.setattr(AuthService, "_api_key_prefix_index", {})
    AuthService.initialize()


def create(username, scopes):
    with patch.object(AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
        return AuthService.create_user(username, scopes=scopes)["api_key"]


def test_accounts_and_the_admin_survive_a_container_restart(d1, monkeypatch):
    assert d1.rows["admin"]["is_admin"] == 1
    key = create("agent", ["knowledge:read"])
    restart(monkeypatch)
    user = AuthService.verify_api_key(key, "203.0.113.5")
    assert user["username"] == "agent" and user["scopes"] == ["knowledge:read"]
    assert AuthService.verify_api_key("synthetic-d1-admin-key")["is_admin"] is True
    assert AuthService.verify_api_key(key + "x") is None
    assert AuthService.count_users() == 2


def test_rotation_revocation_and_deletion_apply_to_every_container(d1, monkeypatch):
    key = create("agent", ["chat", "models"])
    with patch.object(AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
        rotated = AuthService.rotate_api_key("agent")["api_key"]
    restart(monkeypatch)
    assert AuthService.verify_api_key(key) is None
    assert AuthService.verify_api_key(rotated)["username"] == "agent"
    with patch.object(AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
        AuthService.delete_user("agent")
    assert AuthService.verify_api_key(rotated) is None


def test_usage_writes_are_throttled_and_advisory(d1):
    key = create("agent", ["chat"])
    d1.calls.clear()
    for _ in range(3):
        assert AuthService.verify_api_key(key, "203.0.113.5")
    assert d1.calls.count("touch") == 1
    assert d1.rows["agent"]["last_used_ip"] == "203.0.113.5"
    original = FakeUsersDomain.__call__

    def fail_touch(self, payload, *, endpoint):
        if payload["operation"] == "touch":
            raise PrivateIntelligenceError(503, "storage_unavailable")
        return original(self, payload, endpoint=endpoint)

    with patch.object(FakeUsersDomain, "__call__", fail_touch):
        assert AuthService.verify_api_key(key, "198.51.100.7")["username"] == "agent"


def test_outages_fail_closed_and_startup_recovers_the_admin(d1, monkeypatch):
    key = create("agent", ["chat"])
    d1.down = True
    with pytest.raises(APIError) as caught:
        AuthService.verify_api_key(key)
    assert caught.value.status_code == 503
    d1.rows.clear()
    restart(monkeypatch)
    d1.down = False
    assert AuthService.verify_api_key("synthetic-d1-admin-key")["username"] == "admin"
    assert d1.rows["admin"]["is_admin"] == 1


def test_account_lists_are_paged_and_rows_are_validated(d1):
    for index in range(user_store.PAGE_SIZE + 3):
        d1.rows[f"user{index:03d}"] = dict(d1.rows["admin"], username=f"user{index:03d}", is_admin=0)
    assert len(user_store.list_users()) == user_store.PAGE_SIZE + 4
    d1.rows["broken"] = dict(d1.rows["admin"], username="broken", is_admin=True)
    with pytest.raises(APIError):
        user_store.list_users()


def test_backend_names_are_explicit(monkeypatch):
    for value, expected in (("", False), ("sql", False), ("D1", True)):
        monkeypatch.setenv("AUTH_STORAGE_BACKEND", value)
        assert user_store.using_d1() is expected
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "postgres")
    with pytest.raises(RuntimeError):
        user_store.using_d1()
