from copy import deepcopy
from unittest.mock import patch
import pytest
from werkzeug.security import generate_password_hash
from error_handlers import APIError
from services.auth_service import AuthService
from services.intelligence_auth import KEY_NAMESPACE, verify_integration_key

KEY = "mllm_intelligence_" + "a" * 48
OTHER = "mllm_intelligence_" + "b" * 48


@pytest.fixture
def durable(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    record = {
        "id": "integration:omni",
        "scopes": ["chat", "models"],
        "credentialVersion": 1,
        "createdAt": "2026-09-22T00:00:00Z",
        "revokedAt": None,
        "keyPrefix": KEY[: len(KEY_NAMESPACE) + 16],
        "keyHash": generate_password_hash(KEY),
    }

    def lookup(payload, *, endpoint):
        assert endpoint == "auth"
        return {
            "version": 1,
            "principal": deepcopy(record)
            if payload["keyPrefix"] == record["keyPrefix"]
            else None,
        }

    with patch(
        "services.intelligence_d1_store.request_private_intelligence",
        side_effect=lookup,
    ) as rpc:
        yield record, rpc


def test_replacement_rotation_and_revocation(durable, tmp_path):
    record, rpc = durable
    with patch.object(AuthService, "_storage_path", tmp_path / "fresh.sqlite3"):
        assert AuthService.verify_api_key(KEY)["username"] == "integration:omni"
        assert not (tmp_path / "fresh.sqlite3").exists()
        record.update(
            keyPrefix=OTHER[: len(KEY_NAMESPACE) + 16],
            keyHash=generate_password_hash(OTHER),
            credentialVersion=2,
        )
        assert AuthService.verify_api_key(KEY) is None
        assert AuthService.verify_api_key(OTHER)["is_admin"] is False
        record["revokedAt"] = "2026-09-22T01:00:00Z"
        assert AuthService.verify_api_key(OTHER) is None
        assert AuthService.verify_api_key(OTHER) is None
        assert rpc.call_count == 5


def test_knowledge_scopes_are_durable_integration_scopes(durable, tmp_path):
    record, _ = durable
    record["scopes"] = ["knowledge:read", "knowledge:manage"]
    with patch.object(AuthService, "_storage_path", tmp_path / "fresh.sqlite3"):
        assert AuthService.verify_api_key(KEY)["scopes"] == ["knowledge:read", "knowledge:manage"]


@pytest.mark.parametrize(
    "change",
    [
        {"scopes": ["admin"]},
        {"id": "admin"},
        {"credentialVersion": True},
        {"is_admin": True},
    ],
)
def test_malformed_or_escalated_principal_fails_closed(durable, change):
    record, _ = durable
    record.update(change)
    with pytest.raises(APIError) as caught:
        verify_integration_key(KEY)
    assert caught.value.status_code == 503


def test_outage_never_falls_back(durable):
    _, rpc = durable
    rpc.side_effect = RuntimeError("private transport details")
    with patch.object(AuthService, "_load_users_by_api_key_prefix") as local:
        with pytest.raises(APIError) as caught:
            AuthService.verify_api_key(KEY)
        assert caught.value.status_code == 503
        assert "private transport" not in str(caught.value)
        local.assert_not_called()


def test_disabled_backend_does_not_authenticate_reserved_key(monkeypatch):
    monkeypatch.delenv("INTELLIGENCE_STORAGE_BACKEND", raising=False)
    with patch.object(AuthService, "_load_users_by_api_key_prefix") as local:
        assert AuthService.verify_api_key(KEY) is None
        local.assert_not_called()


@pytest.mark.parametrize("method", ["create_user", "delete_user", "rotate_api_key"])
def test_local_management_cannot_shadow_durable_principal(method):
    with patch.object(
        AuthService, "_require_admin", return_value={"username": "admin"}
    ):
        with pytest.raises(APIError) as caught:
            getattr(AuthService, method)("integration:omni")
        assert caught.value.status_code == 403
        assert caught.value.payload["error"] == "integration_management_required"


def test_wrong_secret_with_same_prefix_is_denied(durable):
    assert AuthService.verify_api_key(KEY[: len(KEY_NAMESPACE) + 16] + "z" * 32) is None


def test_existing_environment_admin_authentication_is_unchanged(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", KEY)
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    row = {
        "api_key_hash": generate_password_hash(KEY),
        "is_admin": True,
        "revoked_at": None,
    }
    with (
        patch.object(AuthService, "_load_user_by_username", return_value=row),
        patch.object(AuthService, "_update_key_usage"),
        patch.object(
            AuthService, "_public_user", return_value={"id": "admin", "is_admin": True}
        ),
        patch.object(AuthService, "_users", {"admin": row}),
    ):
        assert AuthService.verify_api_key(KEY)["is_admin"] is True
