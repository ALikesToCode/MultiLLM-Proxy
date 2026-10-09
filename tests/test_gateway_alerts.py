"""Content-free alerts use registered admin paths and private, injected state."""
import importlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from services import gateway_alerts as alerts

MIGRATION = "0022_gateway_alerts.sql"
DESTINATION = "https://hooks.example/recipient-private"
BODY = {"revision": 0, "destination": DESTINATION, "rules": [
    {"kind": "spend", "period": "day", "budget_usd": 10},
    {"kind": "unknown_price", "period": "day"},
    {"kind": "provider_circuit", "provider": "openai"},
    {"kind": "pool_exhaustion", "provider": "openai"},
]}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_ALERT_WEBHOOK_ALLOWLIST", '["https://hooks.example"]')
    monkeypatch.setenv("CONFIG_REVISION_SYNC_ENABLED", "false")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setattr(alerts, "_warned", set())
    monkeypatch.setattr("requests.Session.send", Mock(side_effect=AssertionError("No network")))


@pytest.fixture
def client(monkeypatch, tmp_path):
    for name, value in {"FLASK_SECRET_KEY": "synthetic-alert-session", "JWT_SECRET": "synthetic-alert-jwt",
                        "ADMIN_API_KEY": "synthetic-alert-admin", "CONTROL_PLANE_DATABASE_URL": "",
                        "AUTH_STORAGE_BACKEND": "sql", "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"),
                        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"),
                        "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3")}.items():
        monkeypatch.setenv(name, value)
    with patch("config.load_runtime_env"), patch("env_loader.load_runtime_env"), patch("services.usage_ledger.start"):
        module = importlib.import_module("app")
        with patch.object(module, "load_runtime_env"):
            app = module.create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    core = importlib.import_module("routes.core")
    route = importlib.import_module("routes.alerts")
    monkeypatch.setattr(core.AuthService, "is_authenticated", lambda: True)
    monkeypatch.setattr(route.AuthService, "is_authenticated", lambda: True)
    monkeypatch.setattr(route.AuthService, "get_current_user", lambda: {"is_admin": True})
    return app.test_client()


def status(revision=0, rules=None):
    return {"version": 1, "revision": revision, "rules": rules or [], "webhook_configured": bool(revision),
            "events": []}


@pytest.mark.parametrize("value", ["", "false", "invalid", "no", "0"])
def test_disabled_registered_routes_do_not_touch_storage(client, monkeypatch, value):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", value)
    private = Mock(side_effect=AssertionError("Storage touched"))
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    for method in ("GET", "POST"):
        response = client.open("/admin/alerts", method=method, json={})
        assert response.status_code == 404
        assert response.headers["Cache-Control"] == "no-store"
    private.assert_not_called()
    assert client.get("/healthz").json["status"] == "healthy"


def test_enabled_registered_config_defaults_and_private_status(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    normalized = alerts.validate_rules(BODY["rules"], {"openai"})
    assert normalized[0]["thresholds"] == [85, 100]
    private = Mock(side_effect=[status(), status(1, normalized)])
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    assert client.get("/admin/alerts").json == status()
    saved = client.post("/admin/alerts", json=BODY)
    assert saved.status_code == 200
    assert saved.json == status(1, normalized)
    assert private.call_args.args == ("alerts", "configure")
    assert private.call_args.kwargs["configuration"]["destination"] == DESTINATION
    assert "recipient-private" not in saved.get_data(as_text=True)


def test_admin_authorization_and_csrf_are_preserved(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    route = importlib.import_module("routes.alerts")
    monkeypatch.setattr(route.AuthService, "get_current_user", lambda: {"is_admin": False})
    private = Mock()
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    assert client.get("/admin/alerts").status_code == 403
    assert client.post("/admin/alerts", json=BODY).status_code == 403
    private.assert_not_called()
    client.application.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/admin/alerts", json=BODY).status_code == 400


@pytest.mark.parametrize("backend", ["", "sql", "d1"])
def test_enabled_missing_state_fails_closed(client, monkeypatch, backend):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", backend)
    monkeypatch.setattr(alerts.control_state_d1, "call", Mock(side_effect=RuntimeError("private-secret")))
    response = client.get("/admin/alerts")
    assert response.status_code == 503
    assert response.json["error"]["code"] == "gateway_alert_storage_unavailable"
    assert "private-secret" not in response.get_data(as_text=True)


@pytest.mark.parametrize("destination", ["http://hooks.example/a", "https://evil.example/a",
    "https://hooks.example@localhost/a", "https://127.0.0.1/a", "https://169.254.169.254/a",
    "https://[::1]/a", "https://hooks.example/a?secret=x", "https://hooks.example/a#fragment",
    "https://hooks.example\\@evil.example/a", "https://hooks.example/\nsecret"])
def test_ssrf_rejects_before_private_storage(client, monkeypatch, destination):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    private = Mock()
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    response = client.post("/admin/alerts", json={**BODY, "destination": destination})
    assert response.status_code == 400
    private.assert_not_called()


@pytest.mark.parametrize("value", ["", "[]", "invalid", '["https://localhost"]', '["https://127.0.0.1"]'])
def test_allowlist_empty_or_malformed_prevents_configuration(client, monkeypatch, value, caplog):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("GATEWAY_ALERT_WEBHOOK_ALLOWLIST", value)
    for _ in range(2):
        assert client.post("/admin/alerts", json=BODY).status_code == (400 if value in {"", "[]"} else 404)
    assert "localhost" not in caplog.text
    assert sum("Invalid gateway alert setting" in r.message for r in caplog.records) <= 1


@pytest.mark.parametrize("rules", [[{"kind": "spend", "budget_usd": 0}],
    [{"kind": "spend", "period": "day", "budget_usd": float("nan")}],
    [{"kind": "spend", "period": "day", "budget_usd": 1, "thresholds": [True]}],
    [{"kind": "provider_circuit", "provider": "private-key"}],
    [{"kind": "unknown_price", "period": "day", "prompt": "private-content"}], BODY["rules"] * 6])
def test_invalid_or_content_bearing_rules_are_rejected(rules):
    with pytest.raises(alerts.AlertError):
        alerts.validate_rules(rules, {"openai"})


def test_registered_response_validation_never_exposes_private_fields(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setattr(alerts.control_state_d1, "call", Mock(return_value={**status(), "secret": "private-secret"}))
    response = client.get("/admin/alerts")
    assert response.status_code == 503
    assert "private-secret" not in response.get_data(as_text=True)


def test_collector_reads_only_aggregate_usage_and_observed_health(monkeypatch):
    rules = alerts.validate_rules(BODY["rules"], {"openai"})
    rows = [{"day": "2026-10-09", "requests": 10, "priced_requests": 6, "cost_usd": 9,
             "principal": "private-person", "prompt": "private-content"}]
    store = Mock()
    store.summary.return_value = rows
    states = {"openai": {"circuit_open": True, "pool_exhausted": True, "consecutive_failures": 0}}
    observations = alerts.collect_observations(rules, usage=store, health=lambda _: states,
                                               now=1791504000)
    assert [row["value"] for row in observations] == [9, 40, 1, 1]
    assert observations[0]["basis"] == "gateway_cost_estimate"
    assert observations[1]["basis"] == "unknown_price_coverage"
    text = json.dumps(observations)
    assert "private" not in text
    assert all(call.kwargs.get("principal") is None for call in store.summary.call_args_list)


def test_observer_is_inert_when_disabled_and_does_not_start_probes(monkeypatch):
    private, collect = Mock(), Mock()
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    assert alerts.observe(collect=collect) == {"queued": 0}
    private.assert_not_called()
    collect.assert_not_called()


def test_enabled_observer_uses_config_revision_and_injected_collector(monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    rules = alerts.validate_rules(BODY["rules"], {"openai"})
    private = Mock(side_effect=[status(1, rules), {"version": 1, "queued": 2}])
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    collect = Mock(return_value=[{"rule_id": rules[0]["id"], "value": 9,
                                 "basis": "gateway_cost_estimate", "window": "2026-10-09"}])
    assert alerts.observe(collect=collect) == {"version": 1, "queued": 2}
    assert private.call_args.kwargs["revision"] == 1
    collect.assert_called_once_with(rules)


def test_additive_migration_rehearsal_keeps_old_rows():
    with sqlite3.connect(":memory:") as db:
        db.executescript("CREATE TABLE old_rows (value TEXT); INSERT INTO old_rows VALUES ('existing');")
        sql = (Path(__file__).resolve().parents[1] / "intelligence-migrations" / MIGRATION).read_text()
        db.executescript(sql)
        db.executescript(sql)
        assert db.execute("SELECT value FROM old_rows").fetchone() == ("existing",)
        assert {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} >= {
            "gateway_alert_rules", "gateway_alert_events"}


def test_fractional_configuration_identity_matches_worker():
    rule = alerts.validate_rules([{"kind": "spend", "period": "month", "budget_usd": 0.000001,
                                  "thresholds": [0.001, 85.5, 100.0]}], {"openai"})[0]
    assert rule["id"] == "f699ee8b115fb123a1f3f9504e7004a9123d853c7886c9c767c4066f5e648d61"


def test_enabled_unauthenticated_admin_path_is_json_401(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    route = importlib.import_module("routes.alerts")
    monkeypatch.setattr(route.AuthService, "is_authenticated", lambda: False)
    response = client.get("/admin/alerts")
    assert response.status_code == 401
    assert response.json["error"]["code"] == "authentication_required"


def test_default_raw_body_headers_and_callback_order_are_unchanged(monkeypatch):
    from flask import Flask, Response, request
    from services.gateway_extensions import register_gateway_extensions
    called = []
    app = Flask(__name__)
    register_gateway_extensions(app, callbacks=(lambda _: called.append("first"), lambda _: called.append("second")))
    assert called == ["first", "second"]
    app.add_url_rule("/v1/raw", "raw", lambda: Response(request.get_data(), headers={"X-Test": "original"}), methods=["POST"])
    response = app.test_client().post("/v1/raw", data=b'raw\x00content')
    assert response.data == b'raw\x00content'
    assert response.headers["X-Test"] == "original"
    assert "Cache-Control" not in response.headers


def test_passive_health_and_pool_counts_never_probe(monkeypatch):
    health = importlib.import_module("services.health_checks")
    resilience = importlib.import_module("services.resilience_service")
    route_health = importlib.import_module("services.route_health")
    monkeypatch.setattr(resilience.ResilienceService, "snapshot", lambda *args, **kwargs: {"state": "open"})
    monkeypatch.setattr(route_health.RouteHealth, "snapshot", lambda *args: {"consecutive_failures": 3, "last_failure_at": 100})
    result = health.passive_alert_health({"openai"}, pools=lambda _: (2, 0), now=101)
    assert result == {"openai": {"circuit_open": True, "pool_exhausted": True, "consecutive_failures": 3}}
    assert health.passive_alert_health({"openai"}, pools=lambda _: (0, 0), now=4000)["openai"] == {
        "circuit_open": True, "pool_exhausted": False, "consecutive_failures": 0}


def test_observation_failure_does_not_change_free_health_results(monkeypatch):
    health = importlib.import_module("services.health_checks")
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setattr(health.AutoRouteService, "list_routes", lambda: [])
    monkeypatch.setattr(alerts, "observe", Mock(side_effect=alerts.AlertError("gateway_alert_storage_unavailable", 503)))
    proxy = Mock(side_effect=AssertionError("No provider requests"))
    result = health.run_free_checks({}, Mock(), proxy, now=100)
    assert result == {"checked_at": health.iso_time(100), "results": []}
    proxy.assert_not_called()


@pytest.mark.parametrize("period", [[], {}, 1, None])
def test_malformed_period_is_json_400_before_storage(client, monkeypatch, period):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    private = Mock()
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    response = client.post("/admin/alerts", json={**BODY, "rules": [
        {"kind": "spend", "period": period, "budget_usd": 10}]})
    assert response.status_code == 400
    private.assert_not_called()


def test_oversized_registered_configuration_is_413_before_storage(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    private = Mock(side_effect=AssertionError("Storage touched"))
    monkeypatch.setattr(alerts.control_state_d1, "call", private)
    response = client.post("/admin/alerts", json={**BODY, "destination": "https://hooks.example/" + "a" * 8192})
    assert response.status_code == 413
    assert response.json["error"]["code"] == "gateway_alert_too_large"
    assert response.headers["Cache-Control"] == "no-store"
    private.assert_not_called()


def test_registered_revision_conflict_is_json_409(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_ALERTS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    failure = alerts.control_state_d1.intelligence_d1_store.PrivateIntelligenceError(409, "gateway_alert_revision_conflict")
    monkeypatch.setattr(alerts.control_state_d1, "call", Mock(side_effect=failure))
    response = client.post("/admin/alerts", json=BODY)
    assert response.status_code == 409
    assert response.json["error"]["code"] == "gateway_alert_revision_conflict"
