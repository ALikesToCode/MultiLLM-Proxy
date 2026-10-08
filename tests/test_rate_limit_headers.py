"""Admission snapshots and response advice without provider quota disclosure."""

import sys
from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask, Response, g

from middleware import rate_limit_headers as advice
from services import rate_limit_d1
from services.rate_limit_service import RateLimitService

USER = {"username": "private-principal", "api_key_prefix": "private-prefix"}
NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
PREFIX = "X-MultiLLM-RateLimit-"


@pytest.fixture(autouse=True)
def limits(monkeypatch, tmp_path):
    monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "limits.sqlite3"))
    monkeypatch.setenv("RATE_LIMIT_RPM", "2")
    monkeypatch.setenv("OPENAI_RATE_LIMIT_RPM", "2")
    monkeypatch.setenv("RATE_LIMIT_TPM", "200000")
    monkeypatch.setenv("DAILY_REQUEST_LIMIT", "10000")
    pin_storage_and_clock(monkeypatch, NOW)


def loaded_namespaces(*names):
    """Every loaded copy of these modules: other suites pop and re-import them."""
    namespaces = {id(vars(advice)): vars(advice), id(vars(rate_limit_d1)): vars(rate_limit_d1)}
    service = RateLimitService.reserve_request_slot.__func__.__globals__
    namespaces[id(service)] = service
    for name in names:
        module = sys.modules.get(name)
        if module is not None:
            namespaces[id(vars(module))] = vars(module)
    return namespaces.values()


def pin_storage_and_clock(monkeypatch, when):
    for namespace in loaded_namespaces(
            "services.rate_limit_service", "middleware.rate_limit_headers", "services.rate_limit_d1"):
        if "_utcnow" in namespace:
            monkeypatch.setitem(namespace, "_utcnow", lambda: when)
        if "active" in namespace and namespace.get("__name__", "").endswith("rate_limit_d1"):
            monkeypatch.setitem(namespace, "active", lambda: False)


def reserve():
    return RateLimitService.reserve_request_slot("openai", USER, "203.0.113.8")


def minimal_app():
    app = Flask(__name__)
    advice.register_rate_limit_headers(app)

    @app.route("/v1/chat/completions", methods=["POST"])
    @app.route("/openai/v1/chat/completions", methods=["POST"])
    def chat():
        g.authenticated_user = USER
        decision = reserve()
        response = Response(b"provider-body", status=decision.status_code)
        response.headers["X-RateLimit-Remaining"] = "provider-private"
        response.headers["RateLimit-Limit"] = "provider-limit"
        if not decision.allowed:
            response.headers["Retry-After"] = str(decision.retry_after)
        return response

    return app


@pytest.mark.parametrize("value", [None, "", "false", "0", "no", "off", "malformed-private-value"])
def test_disabled_is_byte_for_byte_unchanged(value, monkeypatch, caplog):
    if value is None:
        monkeypatch.delenv("RATE_LIMIT_HEADERS_ENABLED", raising=False)
    else:
        monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", value)
    decision = reserve()
    assert "rate_limit_advice" not in decision.metadata
    client = minimal_app().test_client()
    response = client.post("/v1/chat/completions")
    assert response.data == b"provider-body"
    assert not any(name.startswith(PREFIX) for name in response.headers.keys())
    assert "malformed-private-value" not in caplog.text


def test_malformed_flag_warns_once_without_value(monkeypatch, caplog):
    monkeypatch.setattr(advice, "_warned_invalid", False)
    monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", "private-bad-flag")
    assert not advice.enabled() and not advice.enabled()
    assert sum("RATE_LIMIT_HEADERS_ENABLED" in record.message for record in caplog.records) == 1
    assert "private-bad-flag" not in caplog.text


def test_allowed_and_denied_snapshots_and_precise_retry(monkeypatch):
    first = reserve()
    assert first.metadata["rate_limit_advice"] == {"limit": 2, "remaining": 1, "reset": 60}
    pin_storage_and_clock(monkeypatch, NOW + timedelta(seconds=17))
    second = reserve()
    denied = reserve()
    assert second.metadata["rate_limit_advice"] == {"limit": 2, "remaining": 0, "reset": 43}
    assert denied.metadata["rate_limit_advice"] == second.metadata["rate_limit_advice"]
    assert denied.retry_after == 43 and denied.status_code == 429
    assert first.metadata["rate_limit_advice"]["remaining"] == 1


def test_snapshot_is_stable_across_finalization_and_later_admission(monkeypatch):
    app = minimal_app()
    with app.test_request_context("/v1/chat/completions"):
        g.authenticated_user = USER
        first = reserve()
        reserve()
        pin_storage_and_clock(monkeypatch, NOW + timedelta(seconds=10))
        finalized = RateLimitService.finalize_request_slot(
            first.metadata["reservation_id"], "openai", USER, b"{}", {}, "203.0.113.8")
        assert finalized.allowed
        response = advice.apply_rate_limit_headers(Response("ok"))
        assert response.headers[PREFIX + "Remaining"] == "1"
        assert response.headers[PREFIX + "Reset"] == "60"
        assert not any(value in str(response.headers) for value in USER.values())


def test_registered_middleware_preserves_provider_headers_and_raw_bytes():
    client = minimal_app().test_client()
    allowed = client.post("/v1/chat/completions")
    assert allowed.headers[PREFIX + "Remaining"] == "1"
    assert allowed.headers["X-RateLimit-Remaining"] == "provider-private"
    assert allowed.headers["RateLimit-Limit"] == "provider-limit"
    assert allowed.data == b"provider-body"
    denied = client.post("/v1/chat/completions")
    assert denied.status_code == 200
    denied = client.post("/v1/chat/completions")
    assert denied.status_code == 429 and denied.headers["Retry-After"] == "60"
    assert denied.headers[PREFIX + "Remaining"] == "0"
    raw = client.post("/openai/v1/chat/completions")
    assert raw.data == b"provider-body"
    assert not any(name.startswith(PREFIX) for name in raw.headers.keys())


def test_upstream_retry_after_and_unknown_fields_are_preserved():
    app = minimal_app()
    with app.test_request_context("/v1/chat/completions"):
        g.authenticated_user = USER
        reserve()
        response = Response("upstream throttle", status=429, headers={"Retry-After": "upstream-date"})
        assert advice.apply_rate_limit_headers(response).headers["Retry-After"] == "upstream-date"
    assert advice.snapshot_headers({"limit": None, "remaining": None, "reset": None}) == {}
    assert advice.snapshot_headers({"limit": 0, "remaining": 0, "reset": 0}) == {}
    assert advice.snapshot_headers({"limit": 3, "remaining": 0}) == {PREFIX + "Limit": "3", PREFIX + "Remaining": "0"}
    assert advice.snapshot_headers({"limit": True, "remaining": "2", "reset": float("inf")}) == {}


def test_unlimited_omits_all_advice(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    response = minimal_app().test_client().post("/v1/chat/completions")
    assert not any(name.startswith(PREFIX) for name in response.headers.keys())
    assert "rate_limit_advice" not in reserve().metadata


@pytest.mark.parametrize("kind,limit,window", [("DAILY_REQUEST_LIMIT", 1, 86400), ("RATE_LIMIT_TPM", 1, 60)])
def test_binding_daily_and_token_denials(kind, limit, window, monkeypatch):
    monkeypatch.setenv(kind, str(limit))
    payload = {"max_tokens": 1}
    first = RateLimitService.enforce_request("openai", USER, b"{}", payload, "203.0.113.8")
    assert first.allowed
    denied = RateLimitService.enforce_request("openai", USER, b"{}", payload, "203.0.113.8")
    assert denied.status_code == 429
    assert denied.metadata["rate_limit_advice"] == {"limit": limit, "remaining": 0, "reset": window}
    assert denied.retry_after == window


def test_d1_uses_known_counts_without_inventing_reset(monkeypatch):
    monkeypatch.setattr(rate_limit_d1, "active", lambda: True)
    monkeypatch.setattr(rate_limit_d1, "identity_key", lambda _: "synthetic-hash")
    monkeypatch.setattr(rate_limit_d1.control_state_d1, "ensure_running", lambda: None)
    monkeypatch.setattr(rate_limit_d1.control_state_d1, "wake", lambda: None)
    rate_limit_d1.reset()
    try:
        assert reserve().metadata["rate_limit_advice"] == {"limit": 2, "remaining": 1}
        assert reserve().allowed
        assert reserve().metadata["rate_limit_advice"] == {"limit": 2, "remaining": 0}
    finally:
        rate_limit_d1.reset()


def test_usage_registered_route_default_and_bounded_snapshot(monkeypatch):
    from routes import usage
    from flask_wtf.csrf import CSRFProtect
    app = Flask(__name__)
    app.config["WTF_CSRF_ENABLED"] = False
    monkeypatch.setattr(usage, "api_authenticate_only", lambda **_: lambda view: view)
    monkeypatch.setattr(usage, "usage_history", lambda *args, **kwargs: {})
    monkeypatch.setattr(usage.BudgetService, "status", lambda _: {})
    monkeypatch.setattr(usage.key_controls, "public", lambda _: {
        "allowed_models": None, "allowed_ips": None, "expires_at": None})
    @app.before_request
    def authenticate():
        g.authenticated_user = USER
    usage.register_usage_routes(app, CSRFProtect())
    client = app.test_client()
    monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", "false")
    before = client.get("/v1/usage").data
    assert "rate_limits" not in client.get("/v1/usage").json
    monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", "")
    assert client.get("/v1/usage").data == before
    monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", "true")
    reserve()
    payload = client.get("/v1/usage").json
    assert payload["rate_limits"] == {"openai": {"limit": 2, "remaining": 1, "reset": 60}}
    assert "private-prefix" not in str(payload["rate_limits"])


def test_admin_usage_registered_route_includes_selected_principal_snapshot(monkeypatch):
    from routes import usage
    from flask_wtf.csrf import CSRFProtect
    app = Flask(__name__)
    monkeypatch.setattr(usage, "api_authenticate_only", lambda **_: lambda view: view)
    monkeypatch.setattr(usage, "login_required", lambda view: view)
    monkeypatch.setattr(usage, "usage_history", lambda *args, **kwargs: {})
    monkeypatch.setattr(usage.AuthService, "get_current_user", lambda: {"username": "admin", "is_admin": True})
    monkeypatch.setattr(usage.AuthService, "get_user_record", lambda _: USER)
    monkeypatch.setattr(usage.BudgetService, "status", lambda _: {})
    monkeypatch.setattr(usage.key_controls, "public", lambda _: {})
    monkeypatch.setattr(usage.usage_ledger.LEDGER, "stats", lambda: {})
    usage.register_usage_routes(app, CSRFProtect())
    reserve()
    payload = app.test_client().get("/usage/data?principal=private-principal").json
    assert payload["rate_limits"] == {"openai": {"limit": 2, "remaining": 1, "reset": 60}}


def test_gateway_denial_fills_only_missing_retry_and_requires_authentication():
    app = minimal_app()
    with app.test_request_context("/v1/chat/completions"):
        reserve()
        reserve()
        reserve()
        response = Response("denied", status=429)
        assert not any(name.startswith(PREFIX) for name in advice.apply_rate_limit_headers(response).headers.keys())
        g.authenticated_user = USER
        decorated = advice.apply_rate_limit_headers(response)
        assert decorated.headers["Retry-After"] == "60"


def test_sqlite_concurrent_admission_snapshots_are_atomic():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4) as pool:
        decisions = list(pool.map(lambda _: reserve(), range(4)))
    assert sum(decision.allowed for decision in decisions) == 2
    assert sorted(decision.metadata["rate_limit_advice"]["remaining"] for decision in decisions) == [0, 0, 0, 1]


def test_real_managed_chat_route_with_mounted_middleware(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "load_runtime_env", lambda: None)
    for name, value in {
        "ADMIN_API_KEY": "synthetic-admin-key", "FLASK_SECRET_KEY": "synthetic-session-secret",
        "JWT_SECRET": "synthetic-jwt-secret", "OPENCODE_GO_API_KEY": "synthetic-provider-key",
        "OPENCODE_API_KEY": "synthetic-provider-key", "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"),
        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"),
        "PROVIDER_CATALOG_AUTO_REFRESH": "false", "OPENCODE_RATE_LIMIT_RPM": "2",
    }.items():
        monkeypatch.setenv(name, value)
    from app import create_app
    from tests.unified_api_test_case import UnifiedApiTestCase
    from unittest.mock import patch
    app = create_app()
    pin_storage_and_clock(monkeypatch, NOW)
    app.config["WTF_CSRF_ENABLED"] = False
    advice.register_rate_limit_headers(app)
    client = app.test_client()
    with patch("app.ProxyService.make_request", return_value=UnifiedApiTestCase._chat_response()) as upstream:
        for remaining in ("1", "0"):
            response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer synthetic-admin-key"},
                                   json={"model": "opencode:glm-5.2", "messages": [{"role": "user", "content": "hi"}]})
            assert response.status_code == 200
            assert response.headers[PREFIX + "Remaining"] == remaining
        refused = client.post("/v1/chat/completions", headers={"Authorization": "Bearer synthetic-admin-key"},
                              json={"model": "opencode:glm-5.2", "messages": [{"role": "user", "content": "hi"}]})
        assert refused.status_code == 429 and refused.headers["Retry-After"] == "60"
        assert upstream.call_count == 2
        usage = client.get("/v1/usage", headers={"Authorization": "Bearer synthetic-admin-key"})
        assert usage.status_code == 200 and usage.json["rate_limits"]["opencode"]["remaining"] == 0


def test_disabled_never_queries_expiry_or_usage(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_HEADERS_ENABLED", "false")
    def unexpected(*args, **kwargs):
        raise AssertionError("disabled advice must not inspect counters")
    monkeypatch.setattr(advice, "_reset_seconds", unexpected)
    assert reserve().allowed
    assert advice.usage_snapshot(USER) == {}


def test_usage_snapshot_reports_binding_daily_counter(monkeypatch):
    monkeypatch.setenv("DAILY_REQUEST_LIMIT", "1")
    reserve()
    assert advice.usage_snapshot(USER) == {"openai": {"limit": 1, "remaining": 0, "reset": 86400}}


def test_usage_snapshot_is_bounded_and_read_only():
    from contextlib import closing
    with closing(RateLimitService._connect()) as connection:
        RateLimitService._ensure_storage(connection)
        connection.executemany(
            "INSERT INTO request_usage (created_at, identity, provider) VALUES (?, ?, ?)",
            [(NOW.isoformat(), USER["username"], f"provider-{index:02}") for index in range(40)],
        )
        connection.commit()
    snapshot = advice.usage_snapshot(USER)
    assert len(snapshot) == 32
    assert list(snapshot) == [f"provider-{index:02}" for index in range(32)]
    with closing(RateLimitService._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM request_usage").fetchone()[0] == 40


def test_missing_usage_storage_and_tables_are_omitted(tmp_path):
    assert advice.usage_snapshot(USER) == {}
    from contextlib import closing
    with closing(RateLimitService._connect()) as connection:
        connection.execute("CREATE TABLE unrelated (value INTEGER)")
        connection.commit()
    assert advice.usage_snapshot(USER) == {}


@pytest.mark.parametrize("snapshot", [
    {"limit": 3, "remaining": 4, "reset": 86401},
    {"limit": 3, "remaining": -1, "reset": 0},
    {"limit": 3, "remaining": True, "reset": "60"},
])
def test_invalid_optional_fields_are_omitted(snapshot):
    assert advice.snapshot_headers(snapshot) == {PREFIX + "Limit": "3"}
