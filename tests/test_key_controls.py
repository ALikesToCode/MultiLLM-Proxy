"""Per-key controls: validation, model allowlists, expiry and client address ranges."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from error_handlers import APIError
from services import key_controls


def test_validation_normalizes_every_control():
    controls = key_controls.validate({
        "daily_budget_usd": "5", "monthly_budget_usd": 50.123456789,
        "allowed_models": ["Auto:*", "free:*", "openai:gpt-4.1", "free:*"],
        "allowed_ips": "203.0.113.7\n198.51.100.0/24, 2001:db8::/32 ::ffff:192.0.2.1",
        "expires_at": "2026-10-01T12:00",
    })
    assert controls == {
        "daily_budget_usd": 5.0, "monthly_budget_usd": 50.123457,
        "allowed_models": "auto:*,free:*,openai:gpt-4.1",
        "allowed_ips": "203.0.113.7/32,198.51.100.0/24,2001:db8::/32,192.0.2.1/32",
        "expires_at": "2026-10-01T12:00:00+00:00",
    }
    assert key_controls.validate({}) == key_controls.empty()
    assert key_controls.validate({"allowed_models": [], "allowed_ips": "", "daily_budget_usd": None}) == key_controls.empty()


@pytest.mark.parametrize("payload", [
    {"daily_budget_usd": -1}, {"daily_budget_usd": True}, {"monthly_budget_usd": "lots"},
    {"daily_budget_usd": float("nan")}, {"allowed_models": ["openai:gpt 4"]}, {"allowed_models": "x" * 300},
    {"allowed_models": [1]}, {"allowed_ips": ["not-an-ip"]}, {"allowed_ips": ["10.0.0.0/33"]},
    {"expires_at": "tomorrow"}, {"expires_at": 5}, {"api_key": "x"},
    {"allowed_models": [f"m{index}:*" for index in range(65)]},
])
def test_validation_refuses_malformed_controls(payload):
    with pytest.raises(APIError) as error:
        key_controls.validate(payload)
    assert error.value.status_code == 400


def test_model_patterns_match_whole_ids_with_wildcards():
    user = {"allowed_models": "auto:*,free:*,openai:gpt-4.1,openrouter:meta-llama/*"}
    for model in ("auto:image", "AUTO:chat", "free:text", "openai:gpt-4.1", "openrouter:meta-llama/llama-4:free"):
        assert key_controls.model_allowed(user, model), model
    for model in ("openai:gpt-4.1-mini", "openai:gpt-4", "gguu:gpt-image-2", "", None, "xauto:image"):
        assert not key_controls.model_allowed(user, model), model
    assert key_controls.model_allowed({"allowed_models": None}, "anything:at-all")
    assert key_controls.model_allowed({"allowed_models": ["gguu:*"]}, "gguu:grok-imagine")
    assert key_controls.provider_allowed({"allowed_models": "openai:*"}, "openai")
    assert not key_controls.provider_allowed({"allowed_models": "openai:gpt-4.1"}, "openai")
    assert key_controls.provider_allowed({"allowed_models": "*"}, "groq")


def test_expiry_uses_utc_and_unreadable_values_expire():
    now = datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    assert not key_controls.expired({"expires_at": None}, now)
    assert not key_controls.expired({"expires_at": (now + timedelta(seconds=1)).isoformat()}, now)
    assert key_controls.expired({"expires_at": now.isoformat()}, now)
    assert key_controls.expired({"expires_at": "2026-09-26T13:00:00+02:00"}, now)
    assert key_controls.expired({"expires_at": "garbage"}, now)


def test_address_ranges_cover_ipv4_ipv6_and_mapped_clients():
    user = {"allowed_ips": ["203.0.113.0/24", "2001:db8::/32"]}
    assert key_controls.ip_allowed(user, "203.0.113.9")
    assert key_controls.ip_allowed(user, "::ffff:203.0.113.9")
    assert key_controls.ip_allowed(user, "2001:db8::5")
    for address in ("203.0.114.1", "2001:db9::1", "", None, "garbage"):
        assert not key_controls.ip_allowed(user, address), address
    assert key_controls.ip_allowed({"allowed_ips": None}, None)


def test_client_address_trusts_cf_connecting_ip_only_behind_the_worker(monkeypatch):
    request = SimpleNamespace(headers={"CF-Connecting-IP": "198.51.100.4"}, remote_addr="10.0.0.2")
    monkeypatch.delenv("MULTILLM_TRUST_PROXY_HEADERS", raising=False)
    assert key_controls.client_ip(request) == "10.0.0.2"
    monkeypatch.setenv("MULTILLM_TRUST_PROXY_HEADERS", "true")
    assert key_controls.client_ip(request) == "198.51.100.4"
    request.headers = {"CF-Connecting-IP": "198.51.100.4, 10.0.0.1"}
    assert key_controls.client_ip(request) == "10.0.0.2", "a malformed header falls back to the peer"


def test_sqlite_accounts_keep_controls_through_rotation_and_backups(tmp_path, monkeypatch):
    from unittest.mock import patch

    from services.auth_service import AuthService
    from services.control_plane_backup import capture, restore_empty, validate

    paths = {name: str(tmp_path / f"{name}.sqlite3") for name in ("auth", "models", "limits", "workbench")}
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "sql")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-controls-admin-key")
    for variable, name in (("AUTH_DB_PATH", "auth"), ("MODEL_REGISTRY_DB_PATH", "models"),
                           ("RATE_LIMIT_DB_PATH", "limits"), ("CONNECTION_PROFILES_DB_PATH", "workbench")):
        monkeypatch.setenv(variable, paths[name])
    monkeypatch.setattr(AuthService, "_storage_path", None)
    monkeypatch.setattr(AuthService, "_users", {})
    monkeypatch.setattr(AuthService, "_api_key_prefix_index", {})
    AuthService.initialize()
    with patch.object(AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
        AuthService.create_user("agent", scopes=["chat"])
        AuthService.set_key_controls("agent", {"daily_budget_usd": 3, "allowed_models": ["free:*"]})
        with pytest.raises(APIError, match="break-glass|cannot expire"):
            AuthService.set_key_controls("admin", {"expires_at": "2099-01-01T00:00:00Z"})
        key = AuthService.rotate_api_key("agent")["api_key"]
    user = AuthService.verify_api_key(key)
    assert (user["daily_budget_usd"], user["allowed_models"]) == (3.0, ["free:*"])

    document = capture()
    [row] = [item for item in document["tables"]["users"] if item["username"] == "agent"]
    assert row["daily_budget_usd"] == 3.0 and row["allowed_models"] == "free:*"
    for item in document["tables"]["users"]:
        for name in key_controls.CONTROL_FIELDS:
            item.pop(name)
    validate(document)  # A backup from before the controls existed still validates.
    target = tmp_path / "restored"
    target.mkdir()
    for variable, name in (("AUTH_DB_PATH", "auth"), ("MODEL_REGISTRY_DB_PATH", "models"),
                           ("RATE_LIMIT_DB_PATH", "limits"), ("CONNECTION_PROFILES_DB_PATH", "workbench")):
        monkeypatch.setenv(variable, str(target / f"{name}.sqlite3"))
    restore_empty(document)
    monkeypatch.setattr(AuthService, "_storage_path", None)
    restored = AuthService.get_user_record("agent")
    assert restored["scopes"] == ["chat"] and restored["daily_budget_usd"] is None


def test_stored_values_are_read_defensively():
    row = {"daily_budget_usd": 2, "monthly_budget_usd": "9", "allowed_models": "", "allowed_ips": "10.0.0.0/8",
           "expires_at": None}
    assert key_controls.from_storage(row) == {"daily_budget_usd": 2.0, "monthly_budget_usd": None,
                                              "allowed_models": None, "allowed_ips": "10.0.0.0/8", "expires_at": None}
    assert key_controls.public(row)["allowed_ips"] == ["10.0.0.0/8"]
