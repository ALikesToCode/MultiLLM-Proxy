"""Snapshot routes use only scoped configuration and private durable storage."""
import importlib
import json
from unittest import TestCase
from unittest.mock import patch

from flask import url_for

import pytest

from error_handlers import APIError
from services import auto_route_d1, intelligence_d1_store
from services.intelligence_d1_store import PrivateIntelligenceError


checks = TestCase()


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SECRET_KEY", "synthetic-snapshot-session")
    monkeypatch.setenv("JWT_SECRET", "synthetic-snapshot-jwt")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-snapshot-admin")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.sqlite3"))
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "models.sqlite3"))
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "limits.sqlite3"))
    monkeypatch.delenv("CONFIG_SNAPSHOTS_ENABLED", raising=False)
    with patch("config.load_runtime_env"), patch("env_loader.load_runtime_env"), \
            patch("services.usage_ledger.start"), patch("requests.Session.send", side_effect=AssertionError("No network")):
        module = importlib.import_module("app")
        with patch.object(module, "load_runtime_env"):
            app = module.create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with patch.object(module.AuthService, "is_authenticated", return_value=True), \
                patch.object(module.AuthService, "get_current_user", return_value={"username": "operator", "is_admin": True}):
            yield app.test_client()


def test_disabled_registered_paths_are_404_without_storage(client, monkeypatch):
    with patch.object(intelligence_d1_store, "request_private_intelligence") as private:
        for method, path in [("get", ""), ("post", ""), ("get", "/" + "a" * 32 + "/diff"),
                             ("post", "/" + "a" * 32 + "/apply")]:
            checks.assertEqual(getattr(client, method)('/admin/config/snapshots' + path, json={}).status_code, 404)
        private.assert_not_called()


def test_enabled_requires_admin(client, monkeypatch):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    with patch("services.auth_service.AuthService.get_current_user", return_value={"is_admin": False}), \
            patch.object(intelligence_d1_store, "request_private_intelligence") as private:
        checks.assertEqual(client.get('/admin/config/snapshots').status_code, 403)
        private.assert_not_called()


def test_missing_storage_returns_clear_json_503(client, monkeypatch):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    with patch.object(intelligence_d1_store, "request_private_intelligence",
                      side_effect=PrivateIntelligenceError(503, "storage_unavailable")):
        response = client.get("/admin/config/snapshots")
    checks.assertEqual(response.status_code, 503)
    checks.assertEqual(response.json['error'], 'config_snapshot_storage_unavailable')


CONFIG = {"routes": [{"route_id": "auto:review", "candidates": ["openai:model-a"]}]}


def test_registered_create_diff_apply_use_private_adapter(client, monkeypatch):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    identifier = "a" * 32
    replies = [{"version": 1, "snapshot": {"id": identifier, "domain": "auto_routes", "base_revision": 0, "created_at": "2026-10-09T00:00:00Z", "created_by": "a" * 64, "size_bytes": 80}},
               {"version": 1, "id": "a" * 32, "domain": "auto_routes", "base_revision": 0, "next_offset": None, "current_revision": 0, "changes": [{"route_id": "auto:review", "before": [], "after": ["openai:model-a"]}]},
               {"version": 1, "applied": True, "revision": 1, "application_id": "b" * 32}]
    with patch.object(intelligence_d1_store, "request_private_intelligence", side_effect=replies) as private, \
            patch.object(auto_route_d1, "reset_cache") as reset:
        created = client.post("/admin/config/snapshots", json={"domain": "auto_routes", "base_revision": 0, "configuration": CONFIG})
        checks.assertEqual(created.status_code, 201)
        diff = client.get(f"/admin/config/snapshots/{identifier}/diff")
        checks.assertEqual(diff.status_code, 200)
        applied = client.post(f"/admin/config/snapshots/{identifier}/apply", json={"current_revision": 0, "confirm": True})
        checks.assertTrue(applied.status_code == 200 and applied.json['revision'] == 1)
        reset.assert_called_once()
    checks.assertEqual([call.kwargs['endpoint'] for call in private.call_args_list], ['auto_routes'] * 3)
    checks.assertEqual(private.call_args_list[0].args[0]['operation'], 'snapshot_create')
    checks.assertEqual(len(private.call_args.args[0]['actor']), 64)
    checks.assertNotIn('operator', json.dumps(private.call_args.args))


@pytest.mark.parametrize("extra", ["api_key", "gateway_key", "headers", "prompts", "connections", "env", "provider_keys"])
def test_secrets_and_unapproved_fields_never_reach_storage(client, monkeypatch, extra):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    configuration = {**CONFIG, extra: "synthetic-private-value"}
    with patch.object(intelligence_d1_store, "request_private_intelligence") as private:
        response = client.post("/admin/config/snapshots", json={"domain": "auto_routes", "base_revision": 0, "configuration": configuration})
        checks.assertEqual(response.status_code, 400)
        checks.assertNotIn('synthetic-private-value', response.get_data(as_text=True))
        private.assert_not_called()


@pytest.mark.parametrize("body", [{}, {"confirm": "true", "current_revision": 0}, {"confirm": True},
                                   {"confirm": True, "current_revision": False}])
def test_apply_requires_literal_confirmation_and_revision(client, monkeypatch, body):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    with patch.object(intelligence_d1_store, "request_private_intelligence") as private:
        checks.assertEqual(client.post('/admin/config/snapshots/' + 'a' * 32 + '/apply', json=body).status_code, 409)
        private.assert_not_called()


def test_conflict_and_uncertain_apply_do_not_claim_success(client, monkeypatch):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    for error, status in [(PrivateIntelligenceError(409, "revision_conflict"), 409), (RuntimeError("private detail"), 503)]:
        with patch.object(intelligence_d1_store, "request_private_intelligence", side_effect=error) as private, \
                patch.object(auto_route_d1, "reset_cache") as reset:
            result = client.post("/admin/config/snapshots/" + "a" * 32 + "/apply", json={"confirm": True, "current_revision": 0})
        checks.assertTrue(result.status_code == status and 'private detail' not in result.get_data(as_text=True))
        checks.assertEqual(private.call_count, 1)
        reset.assert_not_called()


def test_default_save_payload_and_cache_are_unchanged(monkeypatch):
    monkeypatch.delenv("CONFIG_SNAPSHOTS_ENABLED", raising=False)
    auto_route_d1.reset_cache()
    with patch.object(intelligence_d1_store, "request_private_intelligence", return_value={"version": 1, "stored": True}) as private:
        auto_route_d1.save_route("auto:x", ["openai:model"], "2026-10-09T00:00:00Z")
    checks.assertEqual(private.call_args.args[0], {'operation': 'put', 'route_id': 'auto:x', 'candidates': ['openai:model'], 'updated_at': '2026-10-09T00:00:00Z'})
    checks.assertEqual(auto_route_d1.stored_routes()['auto:x'][0], ('openai:model',))
    auto_route_d1.reset_cache()


def test_limits_and_secret_model_ids():
    from services.config_snapshots import validate_configuration
    for config in [{"routes": []}, {"routes": CONFIG["routes"] * 201},
                   {"routes": [{"route_id": "auto:x", "candidates": ["openai:sk-syntheticsecret123"]}]},
                   {"routes": [{"route_id": "auto:x", "candidates": ["openai:model"], "api_key": "synthetic"}]}]:
        with pytest.raises(APIError):
            validate_configuration(config, {"openai": "https://synthetic.invalid"})
    checks.assertEqual(validate_configuration(CONFIG, {'openai': 'https://synthetic.invalid'}), CONFIG)


def test_disabled_paths_are_404_even_with_csrf_enabled(client):
    client.application.config["WTF_CSRF_ENABLED"] = True
    checks.assertEqual(client.post('/admin/config/snapshots', json={}).status_code, 404)


def test_enabled_apply_keeps_csrf_protection(client, monkeypatch):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    client.application.config["WTF_CSRF_ENABLED"] = True
    with patch.object(intelligence_d1_store, "request_private_intelligence") as private:
        checks.assertEqual(client.post('/admin/config/snapshots/' + 'a' * 32 + '/apply', json={'confirm': True, 'current_revision': 0}).status_code, 400)
        private.assert_not_called()


def test_diff_reviews_effective_seeded_defaults(client, monkeypatch):
    from services.auto_route_service import DEFAULT_AUTO_ROUTES
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    result = {"version": 1, "id": "a" * 32, "domain": "auto_routes", "base_revision": 0, "next_offset": None, "current_revision": 0, "changes": [{"route_id": "auto:image", "before": [], "after": ["openai:model"]}]}
    with patch.object(intelligence_d1_store, "request_private_intelligence", return_value=result):
        response = client.get("/admin/config/snapshots/" + "a" * 32 + "/diff")
    checks.assertEqual(response.json['changes'][0]['before'], list(DEFAULT_AUTO_ROUTES['auto:image']))


@pytest.mark.parametrize("result", [{"version": 1}, {"version": 1, "api_key": "synthetic-private-value"}])
def test_partial_or_secret_storage_response_is_not_success(client, monkeypatch, result):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    with patch.object(intelligence_d1_store, "request_private_intelligence", return_value=result):
        response = client.post("/admin/config/snapshots", json={"domain": "auto_routes", "base_revision": 0, "configuration": CONFIG})
    checks.assertEqual(response.status_code, 503)
    checks.assertNotIn("synthetic-private-value", response.get_data(as_text=True))


def test_unauthenticated_review_does_not_reach_storage(client, monkeypatch):
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    with patch("services.auth_service.AuthService.is_authenticated", return_value=False), \
            patch.object(intelligence_d1_store, "request_private_intelligence") as private:
        response = client.get("/admin/config/snapshots")
    checks.assertEqual(response.status_code, 302)
    with client.application.test_request_context():
        checks.assertEqual(response.headers["Location"], url_for("login", next="/admin/config/snapshots"))
    private.assert_not_called()
