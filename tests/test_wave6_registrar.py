"""Registered canary decisions, bounded private state and immutable receipt wiring."""
import importlib
import json
import os
from types import SimpleNamespace
from unittest.mock import Mock, patch
from collections import OrderedDict

import pytest
from flask import Flask, Response, g, request
from flask_wtf.csrf import CSRFProtect

from tests.test_managed_idempotency import Authority
from tests.unified_api_test_case import UnifiedApiTestCase

ORDER = ["request_policy_hook", "prompt_injection_request_hook", "spillover_hook", "pii_request_hook",
         "responses_state_hook", "context_canary_request_hook", "generation_deadline_hook",
         "latency_slo_request_hook", "idempotency_request_hook", "admit"]
FLAGS = {"HEDGED_REQUESTS_ENABLED": "true", "REALTIME_ENABLED": "true", "LATENCY_SLO_MODE": "reject",
         "STREAM_COST_BREAKER_ENABLED": "true", "LEARNED_COOLDOWN_MODE": "apply",
         "CONTEXT_CANARY_MODE": "block", "USAGE_RECEIPTS_ENABLED": "true",
         "ENTERPRISE_PREVIEW_ENABLED": "true"}
BODY = {"model": "auto:test", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 100}
RECEIPT_PATHS = ("/v1/usage/receipts/" + "a" * 64, "/v1/usage/receipt-keys")


@pytest.fixture
def harness(monkeypatch, tmp_path):
    modules = {name: importlib.import_module(name) for name in (
        "services.gateway_extensions", "services.idempotency_store", "middleware.idempotency",
        "services.latency_slo", "services.intelligence_d1_store", "services.reservation_store",
        "services.usage_receipts", "routes.usage_receipts")}
    for name in FLAGS:
        monkeypatch.setenv(name, "off" if name.endswith("MODE") else "false")
    for name in ("MANAGED_IDEMPOTENCY_ENABLED", "ADMISSION_ENABLED", "CONFIG_REVISION_SYNC_ENABLED",
                 "CONTENT_RETENTION_ENABLED", "PII_REDACTION_ENABLED", "BATCH_SPILLOVER_ENABLED",
                 "HOSTED_RESPONSES_ENABLED", "RATE_LIMIT_HEADERS_ENABLED", "USAGE_RESERVATIONS_ENABLED",
                 "GATEWAY_ALERTS_ENABLED", "USAGE_LEDGER_ENABLED", "SESSION_TIERS_ENABLED"):
        monkeypatch.setenv(name, "false")
    for name, value in {"PROMPT_INJECTION_MODE": "off", "INTELLIGENCE_STORAGE_BACKEND": "",
        "CONTROL_PLANE_DATABASE_URL": "", "GENERATION_DEADLINE_MAX_MS": "",
        "SECRET_SCAN_DEFAULT": "off", "USAGE_DB_PATH": str(tmp_path / "usage.sqlite3"),
        "ADMISSION_LIMITS_JSON": '{"principal":1}', "CONTENT_RETENTION_POLICY_JSON": "{}",
        "CONTEXT_CANARY_POLICY_JSON": '{"keys":["key-7"]}',
        "LATENCY_SLO_MIN_SAMPLES": "1", "LATENCY_SLO_MAX_MODELS": "128",
        "LATENCY_SLO_POLICY_JSON": '{"routes":{"/v1/chat/completions":{"deadline_ms":1000}}}'}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(importlib.import_module("requests").sessions.Session, "send",
                        Mock(side_effect=AssertionError("No network")))
    app = Flask(__name__)
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    csrf = CSRFProtect(app)
    registrar = modules["services.gateway_extensions"]
    registrar.register_gateway_extensions(app, callbacks=registrar.gateway_callbacks(csrf=csrf))
    modules["routes.usage_receipts"].register_usage_receipt_routes(app, csrf)
    authority = Authority()
    app.extensions["managed_idempotency_store"] = modules["services.idempotency_store"].IdempotencyStore(authority)
    app.extensions["managed_idempotency_policy_revision"] = lambda body: "fixed-policy"
    admission = Mock(acquire=Mock(return_value=Mock()))
    app.extensions["admission_client"] = admission
    providers, reservations, states = [], [], []
    user = {"id": "key-7", "username": "alice", "scopes": ["chat", "models"]}

    @app.before_request
    def authenticated():
        if request.path in {"/v1/chat/completions", "/v1/messages", "/v1/responses",
                            "/intelligence/v1/chat/completions", "/openai/v1/chat/completions"}:
            g.authenticated_user = user
            return registrar.after_authentication()
        return None

    @app.after_request
    def capture_state(response):
        states.append(dict(g.__dict__))
        return response

    def completion():
        def upstream():
            reservations.append(True)
            providers.append(request.get_json())
            return Response(b'{"choices":[{"finish_reason":"stop"}]}',
                            content_type="application/json", headers={"X-Test": "same"})
        return modules["middleware.idempotency"].dispatch_with_idempotency(
            upstream, completed=lambda response: response.status_code == 200)

    for index, path in enumerate(("/v1/chat/completions", "/v1/messages", "/v1/responses",
                                 "/intelligence/v1/chat/completions", "/openai/v1/chat/completions")):
        app.add_url_rule(path, f"generation_{index}", completion, methods=["POST"])
    return SimpleNamespace(app=app, modules=modules, authority=authority, admission=admission,
        providers=providers, reservations=reservations, states=states, user=user)


def test_off_preserves_generation_bytes_headers_and_no_storage(harness):
    h = harness
    client = h.app.test_client()
    response = client.post("/v1/chat/completions", json=BODY)
    actual = response.status_code, response.data, list(response.headers)
    assert [hook.__name__ for hook in h.app.extensions["gateway_after_authentication"]] == ORDER
    h.app.extensions["gateway_after_authentication"] = [hook for hook in
        h.app.extensions["gateway_after_authentication"] if hook.__name__ != "context_canary_request_hook"]
    baseline = client.post("/v1/chat/completions", json=BODY)
    assert (baseline.status_code, baseline.data, list(baseline.headers)) == actual
    assert response.status_code == 200 and h.providers == [BODY, BODY]
    assert all("context_canary_scope" not in state for state in h.states)
    assert h.authority.calls == []
    h.admission.acquire.assert_not_called()


@pytest.mark.parametrize("path", RECEIPT_PATHS)
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST"])
def test_off_receipts_return_json_404_before_authentication(harness, monkeypatch, path, method):
    routes = harness.modules["routes.usage_receipts"]
    auth = routes.api_authenticate_only.__globals__["AuthService"]
    verify = Mock(side_effect=AssertionError("Disabled receipt authentication"))
    store = Mock(side_effect=AssertionError("Disabled receipt storage"))
    monkeypatch.setattr(auth, "verify_api_key", verify)
    monkeypatch.setattr(harness.modules["services.usage_receipts"], "open_store", store)
    result = harness.app.test_client().open(path, method=method,
        headers={"Authorization": "Bearer synthetic"})
    assert result.status_code == 404
    assert result.headers["Cache-Control"] == "no-store"
    assert result.content_type == "application/json"
    if method != "HEAD":
        assert result.json["error"]["code"] == "not_found"
    verify.assert_not_called()
    store.assert_not_called()


def test_all_flags_on_order_and_candidate_registrar(harness, monkeypatch):
    for name, value in FLAGS.items():
        monkeypatch.setenv(name, value)
    h = harness
    assert [hook.__name__ for hook in h.app.extensions["gateway_after_authentication"]] == ORDER
    assert callable(h.app.extensions.get("latency_slo_candidate_policy"))
    h.modules["services.gateway_extensions"].register_gateway_extensions(h.app,
        callbacks=h.modules["services.gateway_extensions"].gateway_callbacks())
    assert [hook.__name__ for hook in h.app.extensions["gateway_after_authentication"]] == ORDER


@pytest.mark.parametrize("path,protocol", [("/v1/chat/completions", "chat"), ("/v1/messages", "messages"),
    ("/v1/responses", "responses"), ("/intelligence/v1/chat/completions", "chat")])
def test_canary_scope_preserves_caller_body(harness, monkeypatch, path, protocol):
    monkeypatch.setenv("CONTEXT_CANARY_MODE", "block")
    response = harness.app.test_client().post(path, json=BODY)
    assert response.status_code == 200 and harness.providers == [BODY]
    assert harness.states[-1]["context_canary_scope"] == {
        "route": path, "key_scope": "key-7", "protocol": protocol}
    assert not any("marker" in key or key == "context_canary_context" for key in harness.states[-1])


@pytest.mark.parametrize("raw", [False, True])
def test_canary_unmatched_and_passthrough_set_nothing(harness, monkeypatch, raw):
    monkeypatch.setenv("CONTEXT_CANARY_MODE", "block")
    if not raw:
        harness.user["id"] = "other"
    path = "/openai/v1/chat/completions" if raw else "/v1/chat/completions"
    result = harness.app.test_client().post(path, json=BODY)
    assert result.status_code == 200 and harness.providers == [BODY]
    assert "context_canary_scope" not in harness.states[-1]


def test_canary_opt_in_does_not_change_idempotency_fingerprint(harness, monkeypatch):
    monkeypatch.setenv("MANAGED_IDEMPOTENCY_ENABLED", "true")
    client = harness.app.test_client()
    first = client.post("/v1/chat/completions", json=BODY, headers={"Idempotency-Key": "same"})
    monkeypatch.setenv("CONTEXT_CANARY_MODE", "block")
    replay = client.post("/v1/chat/completions", json=BODY, headers={"Idempotency-Key": "same"})
    assert first.status_code == replay.status_code == 200 and first.data == replay.data
    assert replay.headers["X-MultiLLM-Idempotency"] == "replayed"
    assert harness.providers == [BODY]


def test_all_flags_on_slo_rejection_precedes_every_acquisition(harness, monkeypatch):
    h = harness
    for name, value in FLAGS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("MANAGED_IDEMPOTENCY_ENABLED", "true")
    monkeypatch.setenv("ADMISSION_ENABLED", "true")
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    slo = h.modules["services.latency_slo"]
    observations = slo.admit_candidates.__kwdefaults__["observations"]
    monkeypatch.setattr(observations, "_models", OrderedDict())
    observations.record("openai:slow", ttft_ms=100, tokens_per_second=1, now=100)
    h.app.extensions["latency_slo"]["clock"] = lambda: 100
    h.app.extensions["latency_slo_candidate_policy"] = lambda body: [{"model": "openai:slow"}]
    response = h.app.test_client().post("/v1/chat/completions", json=BODY,
        headers={"Idempotency-Key": "never-claimed"})
    assert response.status_code == 503 and response.json["error"]["code"] == "latency_slo_predicted_miss"
    assert "context_canary_scope" not in h.states[-1]
    assert h.authority.calls == [] and h.providers == [] and h.reservations == []
    h.admission.acquire.assert_not_called()


def test_enabled_receipt_reads_keep_owner_and_missing_storage_boundary(harness, monkeypatch):
    h = harness
    receipts = h.modules["services.usage_receipts"]
    monkeypatch.setenv("USAGE_RECEIPTS_ENABLED", "true")
    objects = h.modules["routes.usage_receipts"].api_authenticate_only.__globals__
    monkeypatch.setattr(objects["AuthService"], "verify_api_key", lambda key, address: {
        "username": key, "scopes": ["models"]})
    accounting = objects["request_accounting"]
    monkeypatch.setattr(accounting, "check_key_controls", lambda user: None)
    monkeypatch.setattr(accounting, "begin", lambda: None)
    monkeypatch.setattr(accounting, "finish", lambda response: response)
    monkeypatch.setitem(objects, "authorize_integration_route", lambda user: None)
    item = {"record_hash": "a" * 64, "record": {"cost_usd": .2, "cost_basis": "provider"}}
    store = SimpleNamespace(get=lambda principal, identity: item if principal == "alice" and
        identity == "a" * 64 else None, keys=lambda: [{"key_id": "reviewed"}])
    monkeypatch.setattr(receipts, "open_store", lambda: store)
    client = h.app.test_client()
    assert client.get(RECEIPT_PATHS[0], headers={"Authorization": "Bearer alice"}).json == item
    assert client.get(RECEIPT_PATHS[0], headers={"Authorization": "Bearer bob"}).status_code == 404
    assert client.get(RECEIPT_PATHS[1], headers={"Authorization": "Bearer alice"}).json == {
        "keys": [{"key_id": "reviewed"}]}
    monkeypatch.setattr(receipts, "open_store", Mock(side_effect=receipts.ReceiptError()))
    result = client.get(RECEIPT_PATHS[1], headers={"Authorization": "Bearer alice"})
    assert result.status_code == 503 and result.json["error"]["code"] == "usage_receipts_unavailable"


@pytest.mark.parametrize("failure", [False, True])
def test_reconciliation_receipt_is_unique_and_cannot_change_commit(harness, monkeypatch, tmp_path, failure):
    reservations = harness.modules["services.reservation_store"]
    receipts = harness.modules["services.usage_receipts"]
    store = reservations.SqlReservationStore(tmp_path / "reconciliation.sqlite3")
    identity, event = "a" * 32, "d" * 32
    store.reserve(identity, "alice", .1, 1, None, 0, 0)
    store.transition(identity, 0, "dispatched", transition_id="b" * 32)
    store.transition(identity, 1, "unknown", transition_id="c" * 32)
    monkeypatch.setenv("USAGE_RECEIPTS_ENABLED", "true")
    rows = []
    def append(principal, event_id, record):
        assert store.get(identity)["state"] == "reconciled"
        rows.append((principal, event_id, receipts.checked_record(record)))
        if failure:
            raise RuntimeError("private receipt failure")
    monkeypatch.setattr(receipts, "open_store", lambda: SimpleNamespace(append=append))
    kwargs = dict(admin=True, reason="provider_receipt", evidence="provider_123", transition_id=event)
    result = reservations.reconcile(store, identity, 2, .2, **kwargs)
    repeated = reservations.reconcile(store, identity, 2, .2, **kwargs)
    assert result["applied"] is True and repeated["applied"] is False
    assert result["reservation"] == repeated["reservation"] == store.get(identity)
    assert rows == [("alice", event, {"reservation_id": identity, "settlement_id": identity, "state": "reconciled",
        "cost_usd": .2, "cost_basis": "provider", "input_tokens": None, "output_tokens": None})]


@pytest.mark.parametrize("endpoint,url,limit", [
    ("learned-cooldown", "http://intelligence.internal/v1/state/learned-cooldown", 4096),
    ("usage-receipts", "http://intelligence.internal/v1/managed-state/usage-receipts", 131072)])
def test_private_transports_are_pinned_and_bounded(harness, monkeypatch, endpoint, url, limit):
    private = harness.modules["services.intelligence_d1_store"]
    calls = []
    def submit(target, body, stopped, deadline, results, slots, statuses, timeout):
        calls.append((target, len(body)))
        results.put_nowait((True, {"version": 1}))
        slots.release()
    monkeypatch.setattr(private, "_submit", submit)
    overhead = len(json.dumps({"data": "", "version": 1}, separators=(",", ":")).encode())
    assert private.request_private_intelligence({"data": "x" * (limit - overhead)}, endpoint=endpoint) == {"version": 1}
    assert calls == [(url, limit)]
    for destination, length in ((endpoint, limit - overhead + 1), (url, 0),
                                ("https://external.invalid", 0)):
        with pytest.raises(private.GatewayError):
            private.request_private_intelligence({"data": "x" * length}, endpoint=destination)
    assert calls == [(url, limit)]


class RegisteredRoutesTest(UnifiedApiTestCase):
    def setUp(self):
        self.settings = patch.dict(os.environ, {**{name: "" for name in FLAGS},
            "CONFIG_REVISION_SYNC_ENABLED": "false", "USAGE_LEDGER_ENABLED": "false",
            "NANOGPT_API_KEY": "", "INTELLIGENCE_STORAGE_BACKEND": ""})
        self.settings.start()
        self.addCleanup(self.settings.stop)
        loader = patch("env_loader.load_runtime_env")
        loader.start()
        self.addCleanup(loader.stop)
        config_loader = patch("config.load_runtime_env")
        config_loader.start()
        self.addCleanup(config_loader.stop)
        network = patch("requests.sessions.Session.send", side_effect=AssertionError("No network"))
        network.start()
        self.addCleanup(network.stop)
        super().setUp()

    def test_real_app_mounts_receipts_once_and_preserves_existing_routes(self):
        rules = [rule.rule for rule in self.app.url_map.iter_rules()]
        for route in ("/v1/usage/receipts/<id>", "/v1/usage/receipt-keys", "/admin/enterprise/preview",
                      "/v1/responses/<response_id>", "/v1/batches", "/v1/context/pages/<page_id>"):
            assert rules.count(route) == 1
        for path in RECEIPT_PATHS:
            result = self.client.get(path)
            assert result.status_code == 404 and result.headers["Cache-Control"] == "no-store"

    def test_real_managed_chat_matches_canary_hook_removed_when_off(self):
        hooks = self.app.extensions["gateway_after_authentication"]
        outputs = []
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=lambda *args, **kwargs:
                self._chat_response()), patch.object(importlib.import_module("routes.unified").time,
                "time", return_value=1000), patch.object(importlib.import_module("route_helpers").time,
                "perf_counter", return_value=1000):
            for remove_hook in (False, True):
                if remove_hook:
                    self.app.extensions["gateway_after_authentication"] = [hook for hook in hooks
                        if hook.__name__ != "context_canary_request_hook"]
                result = self.client.post("/v1/chat/completions", json={"model": "opencode:test", "messages": []},
                    headers={"Authorization": "Bearer admin-test-key", "X-Request-ID": "same"})
                outputs.append((result.status_code, result.data, list(result.headers)))
        assert outputs[0] == outputs[1] and outputs[0][0] == 200
