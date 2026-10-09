"""Registered authentication hooks compose deadlines, durable claims and admission."""
import importlib
import os
from unittest.mock import Mock, patch

import pytest
from flask import Flask, Response, g, request

from tests.test_managed_idempotency import Authority
from tests.unified_api_test_case import UnifiedApiTestCase

FLAGS = ("MANAGED_IDEMPOTENCY_ENABLED", "CONTENT_RETENTION_ENABLED", "ADMISSION_ENABLED",
         "CONFIG_REVISION_SYNC_ENABLED", "RATE_LIMIT_HEADERS_ENABLED", "USAGE_RESERVATIONS_ENABLED",
         "GATEWAY_ALERTS_ENABLED", "GENERATION_CACHE_SHARED_ENABLED", "PROMPT_CACHE_AFFINITY_ENABLED",
         "OUTPUT_SCHEMA_VALIDATION_ENABLED", "PROTOCOL_EXTRAS_ENABLED", "SESSION_TIERS_ENABLED")
BODY = {"model": "auto:test", "messages": [{"role": "user", "content": "hello"}]}


@pytest.fixture
def harness(monkeypatch, tmp_path):
    modules = {name: importlib.import_module(name) for name in (
        "services.gateway_extensions", "services.generation_deadline", "middleware.idempotency",
        "services.idempotency_store", "services.reservation_store", "services.budget_service",
        "services.request_accounting", "services.retention_policy", "services.control_state_d1",
        "services.intelligence_d1_store")}
    for name in FLAGS:
        monkeypatch.setenv(name, "false")
    for name, value in {"INTELLIGENCE_STORAGE_BACKEND": "", "GENERATION_DEADLINE_MAX_MS": "",
                        "USAGE_HOLD_REVIEW_AFTER_SECONDS": "", "USAGE_LEDGER_ENABLED": "false",
                        "CONTENT_RETENTION_POLICY_JSON": "{}", "CONTROL_PLANE_DATABASE_URL": "",
                        "USAGE_DB_PATH": str(tmp_path / "usage.sqlite3"),
                        "MODEL_PRICING_USD_PER_MILLION": "{}", "SECRET_SCAN_DEFAULT": "off"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(modules["services.reservation_store"], "_store", None)
    monkeypatch.setattr(importlib.import_module("requests").sessions.Session, "send",
                        Mock(side_effect=AssertionError("No network")))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    registrar = modules["services.gateway_extensions"]
    registrar.register_gateway_extensions(app, callbacks=registrar.gateway_callbacks())
    authority = Authority()
    app.extensions["managed_idempotency_store"] = modules["services.idempotency_store"].IdempotencyStore(authority)
    app.extensions["managed_idempotency_policy_revision"] = lambda body: "revision-1"
    lease = Mock()
    admission = Mock(acquire=Mock(return_value=lease))
    app.extensions["admission_client"] = admission
    clock = Mock(return_value=100.0)
    if "generation_deadline" in app.extensions:
        app.extensions["generation_deadline"]["clock"] = clock
    providers, reservations = Mock(), Mock()

    @app.before_request
    def authenticated():
        g.authenticated_user = {"username": "caller", "scopes": ["chat", "models"]}
        return registrar.after_authentication()

    @app.post("/v1/chat/completions")
    def completion():
        reservations()
        providers()
        if request.json.get("stream"):
            return Response(iter([b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n',
                                  b'data: [DONE]\n\n']), content_type="text/event-stream")
        middleware = modules["middleware.idempotency"]
        response = Response(b'{"choices":[{"finish_reason":"stop"}]}', content_type="application/json",
                            headers={"X-Test": "same"})
        return middleware.dispatch_with_idempotency(lambda: response, completed=lambda result: result.status_code == 200)

    @app.post("/provider/raw", endpoint="proxy")
    def raw():
        providers()
        return Response(request.get_data(), content_type="application/octet-stream", headers={"X-Test": "same"})

    @app.get("/v1/usage")
    def usage():
        return Response(b'{"object":"usage"}', content_type="application/json")

    def enable():
        for name in FLAGS:
            monkeypatch.setenv(name, "true")
        monkeypatch.setenv("ADMISSION_LIMITS_JSON", '{"principal":1}')
        monkeypatch.setenv("GENERATION_CACHE_BACKEND", "d1-r2")
    return app, modules, authority, admission, lease, clock, providers, reservations, enable


@pytest.mark.parametrize("path,body", [("/v1/chat/completions", BODY),
    ("/v1/chat/completions", {**BODY, "stream": True}), ("/provider/raw", None),
    ("/v1/usage", None), ("/admin/alerts", None)])
def test_all_flags_off_preserve_response_bytes_headers_and_storage(harness, path, body):
    app, _, authority, admission, _, _, _, _, _ = harness
    client = app.test_client()
    kwargs = {"json": body} if body else {"data": b"\x00\xffraw"} if path == "/provider/raw" else {}
    kwargs["headers"] = {"X-MultiLLM-Internal-Deadline-Ms": "1"}
    method = "GET" if path in {"/v1/usage", "/admin/alerts"} else "POST"
    response = client.open(path, method=method, **kwargs)
    actual = response.status_code, response.data, list(response.headers)
    response.close()
    hooks = app.extensions["gateway_after_authentication"]
    app.extensions["gateway_after_authentication"] = [hook for hook in hooks
        if hook.__name__ not in {"generation_deadline_hook", "idempotency_request_hook"}]
    response = client.open(path, method=method, **kwargs)
    assert (response.status_code, response.data, list(response.headers)) == actual
    assert response.status_code == (404 if path == "/admin/alerts" else 200)
    response.close()
    assert authority.calls == []
    admission.acquire.assert_not_called()


def test_named_hook_order_and_replay_bypass_all_work(harness):
    app, _, authority, admission, lease, _, provider, reservation, enable = harness
    enable()
    assert [hook.__name__ for hook in app.extensions["gateway_after_authentication"]] == [
        "request_policy_hook", "prompt_injection_request_hook", "spillover_hook", "pii_request_hook",
        "responses_state_hook", "generation_deadline_hook", "latency_slo_request_hook", "idempotency_request_hook", "admit"]
    client = app.test_client()
    headers = {"Idempotency-Key": "one"}
    first = client.post("/v1/chat/completions", json=BODY, headers=headers)
    replay = client.post("/v1/chat/completions", json=BODY, headers=headers)
    assert first.status_code == replay.status_code == 200 and first.data == replay.data
    assert replay.headers["X-MultiLLM-Idempotency"] == "replayed"
    assert admission.acquire.call_count == lease.release.call_count == provider.call_count == reservation.call_count == 1
    assert [call["operation"] for call in authority.calls] == ["claim", "handoff", "complete", "claim"]


def test_expired_deadline_returns_504_before_claim_or_admission(harness, monkeypatch):
    app, modules, authority, admission, _, clock, provider, reservation, enable = harness
    enable()
    clock.side_effect = [100.0, 102.0] + [102.0] * 10
    deadline = modules["services.generation_deadline"]
    monkeypatch.setattr(deadline.threading.Timer, "start", lambda self: None)
    response = app.test_client().post("/v1/chat/completions", json=BODY,
        headers={"Idempotency-Key": "one", deadline.PUBLIC_HEADER: "1000"})
    assert response.status_code == 504 and response.json["error"]["code"] == "generation_deadline_exceeded"
    assert authority.calls == []
    admission.acquire.assert_not_called()
    provider.assert_not_called()
    reservation.assert_not_called()


def test_zero_retention_never_stores_replay(harness):
    app, _, authority, admission, _, _, provider, _, enable = harness
    enable()
    headers = {"Idempotency-Key": "one", "X-MultiLLM-Retention": "zero"}
    client = app.test_client()
    assert client.post("/v1/chat/completions", json=BODY, headers=headers).status_code == 200
    response = client.post("/v1/chat/completions", json=BODY, headers=headers)
    assert response.status_code == 409 and response.json["error"]["code"] == "outcome_unknown"
    assert not any("response" in call for call in authority.calls)
    assert admission.acquire.call_count == provider.call_count == 1


@pytest.mark.parametrize("name,url", [("alerts", "http://intelligence.internal/v1/state/alerts"),
                                     ("reservations", "http://intelligence.internal/v1/reservations")])
def test_pinned_private_endpoints(harness, name, url):
    assert harness[1]["services.intelligence_d1_store"]._ENDPOINTS[name] == url


def test_d1_reservations_select_private_store_without_sqlite(harness, monkeypatch):
    _, modules, *_ = harness
    storage = modules["services.reservation_store"]
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    sqlite = Mock(side_effect=AssertionError("No SQLite in D1 mode"))
    monkeypatch.setattr(storage, "SqlReservationStore", sqlite)
    private = Mock(side_effect=RuntimeError("private detail"))
    monkeypatch.setattr(modules["services.control_state_d1"], "call", private)
    store = storage.get_store()
    assert isinstance(store, storage.D1ReservationStore)
    with pytest.raises(storage.ReservationError, match="usage_reservations_unavailable"):
        store.summary("caller")
    assert private.call_args.args == ("reservations", "summary")
    sqlite.assert_not_called()


def test_deadline_and_admission_keep_one_cancellation_owner(harness, monkeypatch):
    app, modules, _, admission, _, _, _, _, enable = harness
    enable()
    deadline = modules["services.generation_deadline"]
    monkeypatch.setattr(deadline.threading.Timer, "start", lambda self: None)
    def acquire(identity, on_lost):
        assert on_lost.__self__ is g.gateway_cancellation
        assert g.generation_deadline._cancellations[0].__self__ is g.gateway_cancellation
        return None
    admission.acquire.side_effect = acquire
    response = app.test_client().post("/v1/chat/completions", json=BODY, headers={deadline.PUBLIC_HEADER: "1000"})
    assert response.status_code == 200


def test_pre_dispatch_failure_releases_durable_hold(harness, monkeypatch):
    _, modules, *_ = harness
    storage = modules["services.reservation_store"]
    store = storage.get_store()
    storage.configure_store(store)
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    row = store.reserve("a" * 32, "caller", .1, 1, None, 0, 0)
    modules["services.budget_service"].BudgetService.complete(row["id"], {"status": 504, "cost_usd": None})
    settled = store.get(row["id"])
    assert settled["state"] == "settled" and settled["basis"] == "released" and settled["cost_usd"] == 0


@pytest.mark.parametrize("change,code,status", [({}, "request_in_progress", 409),
    ({"messages": []}, "idempotency_key_conflict", 422)])
def test_claim_refusals_skip_admission_reservation_and_provider(harness, change, code, status):
    app, _, authority, admission, _, _, provider, reservation, enable = harness
    enable()
    client = app.test_client()
    headers = {"Idempotency-Key": "one"}
    assert client.post("/v1/chat/completions", json=BODY, headers=headers).status_code == 200
    if not change:
        next(iter(authority.rows.values()))["status"] = "pending"
    admission.acquire.reset_mock()
    provider.reset_mock()
    reservation.reset_mock()
    result = client.post("/v1/chat/completions", json={**BODY, **change}, headers=headers)
    assert result.status_code == status and result.json["error"]["code"] == code
    admission.acquire.assert_not_called()
    provider.assert_not_called()
    reservation.assert_not_called()


def test_expiry_during_claim_still_precedes_admission(harness, monkeypatch):
    app, modules, _, admission, _, clock, provider, reservation, enable = harness
    enable()
    deadline = modules["services.generation_deadline"]
    monkeypatch.setattr(deadline.threading.Timer, "start", lambda self: None)
    store = app.extensions["managed_idempotency_store"]
    original = store.claim
    def claim(*args):
        result = original(*args)
        clock.return_value = 102.0
        return result
    monkeypatch.setattr(store, "claim", claim)
    result = app.test_client().post("/v1/chat/completions", json=BODY,
        headers={"Idempotency-Key": "one", deadline.PUBLIC_HEADER: "1000"})
    assert result.status_code == 504 and result.json["error"]["code"] == "generation_deadline_exceeded"
    admission.acquire.assert_not_called()
    provider.assert_not_called()
    reservation.assert_not_called()


def test_d1_mode_rejects_previously_injected_sqlite(harness, monkeypatch):
    storage = harness[1]["services.reservation_store"]
    storage.configure_store(storage.get_store())
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    with pytest.raises(storage.ReservationError, match="usage_reservations_unavailable"):
        storage.get_store()


def test_default_transport_verifier_rejects_caller_headers(harness):
    app, modules, *_ = harness
    with app.test_request_context(headers={"X-MultiLLM-External-Origin": "https://example.invalid",
            "X-MultiLLM-Internal-Deadline-Ms": "1", "Authorization": "Bearer synthetic"}):
        g.authenticated_user = {"username": "caller", "is_admin": True}
        assert modules["services.gateway_extensions"].verified_internal_transport() is False


def test_route_limits_are_lazy_and_bound_opted_in_deadlines(harness, monkeypatch):
    app, modules, *_ = harness
    registrar = modules["services.gateway_extensions"]
    policy = Mock(return_value={"deadline_ms": 2000})
    monkeypatch.setattr(importlib.import_module("services.intelligence_store").IntelligenceStore, "policy", policy)
    with app.test_request_context("/v1/chat/completions", json={"model": "auto:intelligence"}):
        assert registrar.generation_limits_ms() == ()
    policy.assert_not_called()
    deadline = modules["services.generation_deadline"]
    with app.test_request_context("/v1/chat/completions", json={"routing": {"deadline_ms": 500}},
            headers={deadline.PUBLIC_HEADER: "3000"}):
        limits = registrar.generation_limits_ms()
        result = deadline.deadline_from_headers(request.headers, limits_ms=limits, clock=lambda: 0)
        assert limits == (2000, 500) and result.remaining_ms() == 500


def test_d1_reservation_transport_returns_valid_private_summary(harness, monkeypatch):
    _, modules, *_ = harness
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    summary = {"day_seeded": False, "month_seeded": False, "held_usd": 0,
               "spent_today_usd": 0, "spent_this_month_usd": 0, "reserved": 0,
               "dispatched": 0, "unknown": 0, "needs_review": 0}
    private = Mock(return_value={"version": 1, "summary": summary})
    monkeypatch.setattr(modules["services.control_state_d1"], "call", private)
    assert modules["services.reservation_store"].get_store().summary("caller") == summary
    private.assert_called_once_with("reservations", "summary", principal="caller")


def test_registration_occurs_once(harness):
    app, modules, *_ = harness
    registrar = modules["services.gateway_extensions"]
    before = tuple(app.extensions["gateway_after_authentication"])
    registrar.register_gateway_extensions(app, callbacks=registrar.gateway_callbacks())
    assert tuple(app.extensions["gateway_after_authentication"]) == before


def test_dispatched_deadline_failure_keeps_unknown_hold(harness, monkeypatch):
    _, modules, *_ = harness
    storage = modules["services.reservation_store"]
    store = storage.get_store()
    storage.configure_store(store)
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    row = store.reserve("a" * 32, "caller", .1, 1, None, 0, 0)
    budget = modules["services.budget_service"].BudgetService
    budget.mark_dispatched(row["id"])
    budget.complete(row["id"], {"status": 504, "cost_usd": None, "cost_basis": None})
    assert store.get(row["id"])["state"] == "unknown"
    assert store.summary("caller")["held_usd"] == .1


class RegistrarRoutesTest(UnifiedApiTestCase):
    def setUp(self):
        self.settings = patch.dict(os.environ, {**{name: "false" for name in FLAGS},
            "GENERATION_DEADLINE_MAX_MS": "", "INTELLIGENCE_STORAGE_BACKEND": "",
            "CONTROL_PLANE_DATABASE_URL": "", "RESPONSE_CACHE_ENABLED": "false",
            "USAGE_LEDGER_ENABLED": "false", "NANOGPT_API_KEY": ""})
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.loader = patch("config.load_runtime_env")
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.env_loader = patch("env_loader.load_runtime_env")
        self.env_loader.start()
        self.addCleanup(self.env_loader.stop)
        self.ledger = patch.object(importlib.import_module("services.usage_ledger"), "start")
        self.ledger.start()
        self.addCleanup(self.ledger.stop)
        super().setUp()
        self.network = patch("requests.sessions.Session.send", side_effect=AssertionError("No network"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def test_actual_registered_routes_match_legacy_registration_with_flags_off(self):
        registrar = importlib.import_module("services.gateway_extensions")
        from middleware.admission import register_admission
        from middleware.rate_limit_headers import register_rate_limit_headers
        legacy_callbacks = (registrar.register_retention, register_admission,
                            registrar.register_cooldown_errors, register_rate_limit_headers)
        with patch.object(self.app_module, "load_runtime_env"), \
                patch.object(self.app_module, "gateway_callbacks", return_value=legacy_callbacks):
            legacy = self.app_module.create_app()
        legacy.config.update(WTF_CSRF_ENABLED=False, IMAGE_RELAY_CATALOG_AUTO_REFRESH=False)
        headers = {"Authorization": "Bearer admin-test-key", "X-Request-ID": "registrar-test"}
        for path, streaming in (("/v1/chat/completions", False), ("/v1/chat/completions", True),
                                ("/opencode/v1/chat/completions", False), ("/v1/usage", False),
                                ("/admin/alerts", False)):
            def upstream(*args, **kwargs):
                response = self._chat_response()
                if streaming:
                    response.headers["Content-Type"] = "text/event-stream"
                    response.iter_lines = lambda *args, **kwargs: iter([
                        b'data: {"choices":[{"delta":{"content":"ok"}}]}', b'data: [DONE]'])
                    response.close = Mock()
                return response
            outputs = []
            with patch.object(self.app_module.ProxyService, "make_request", side_effect=upstream), \
                    patch.object(importlib.import_module("routes.unified").time, "time", return_value=1000), \
                    patch.object(importlib.import_module("route_helpers").time, "perf_counter", return_value=1000), \
                    patch.object(importlib.import_module("error_handlers").secrets, "token_urlsafe", return_value="fixed"):
                for client in (self.client, legacy.test_client()):
                    if path in {"/v1/usage", "/admin/alerts"}:
                        result = client.get(path, headers=headers)
                    else:
                        result = client.post(path, headers=headers, json={"model": "opencode:test"
                            if path.startswith("/v1/") else "test", "messages": [], "stream": streaming})
                    outputs.append((result.status_code, result.data, list(result.headers)))
                    result.close()
            assert outputs[0] == outputs[1]
            assert outputs[0][0] == (404 if path == "/admin/alerts" else 200)
