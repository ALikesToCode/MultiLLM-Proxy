"""Content-free predictions and pre-dispatch admission with synthetic observations."""
import copy
import json
from unittest.mock import Mock

import pytest
from flask import Flask, Response, g

from services import latency_slo as slo
from services import gateway_extensions as extensions
from services import generation_deadline as gd
from services import intelligence_policy as ip
from services.intelligence_contract import ChatRequest
from services.route_health import RouteHealth

NOW = 1800000000.0
A, B, C = "openai:slow", "openai:fast", "openai:other"


def environment(mode="reject", required=False, **changes):
    return {"LATENCY_SLO_MODE": mode, "LATENCY_SLO_POLICY_JSON": json.dumps({
        "routes": {"/v1/chat/completions": {"deadline_ms": 5000, "require_coverage": required},
                   "auto:intelligence": {"deadline_ms": 5000, "require_coverage": required}}}), **changes}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    for name in slo.ENV_KEYS:
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("GENERATION_DEADLINE_MAX_MS", "")
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "off")
    slo._warned.clear()
    RouteHealth.reset()
    yield
    RouteHealth.reset()


def measured(store, model=A, ttft=1000, rate=10, count=20, now=NOW):
    for _ in range(count):
        store.record(model, ttft_ms=ttft, tokens_per_second=rate, now=now)


def choice(model=A, tier=1, **changes):
    return {"model": model, "quality_tier": tier, "enabled": True, "entitled": True,
            "privacy_allowed": True, "billing": "free", "capabilities": [],
            "context_window": 32768, "max_output_tokens": 4096, **changes}


def decide(store, candidates=None, mode="reject", required=False, output=100, auto=True):
    settings = slo.load_settings(environment(mode, required))
    rule = settings.rule_for(route="auto:intelligence")
    return slo.admit_candidates(candidates or [choice()], settings=settings, rule=rule,
                                output_tokens=output, auto=auto, observations=store, now=NOW)


def test_sparse_stale_and_invalid_pairs_are_unknown():
    store = slo.ObservationWindow()
    measured(store, count=19)
    prediction = store.predict(A, 100, min_samples=20, now=NOW)
    assert prediction["status"] == "prediction_unknown"
    assert prediction["samples"] == 19 and prediction["coverage"] == .95
    store.record(A, ttft_ms=None, tokens_per_second=10, now=NOW)
    store.record(A, ttft_ms=100, tokens_per_second=0, now=NOW)
    assert store.predict(A, 100, min_samples=20, now=NOW)["samples"] == 19
    measured(store, now=NOW - 901)
    assert store.predict(A, 100, min_samples=20, now=NOW + 901)["samples"] == 0


def test_empirical_p95_and_output_bound():
    store = slo.ObservationWindow()
    measured(store, count=18, ttft=100, rate=100)
    store.record(A, ttft_ms=2000, tokens_per_second=100, now=NOW - 1)
    store.record(A, ttft_ms=9000, tokens_per_second=100, now=NOW - 1)
    small = store.predict(A, 100, min_samples=20, now=NOW)
    large = store.predict(A, 1000, min_samples=20, now=NOW)
    assert small["predicted_ms"] == 3000 and large["predicted_ms"] == 12000
    assert small["observation_age_ms"] == 0 and small["coverage"] == 1
    assert slo.requested_output({}) == 1024
    assert slo.requested_output({"max_tokens": 100, "max_completion_tokens": 50}) == 50
    for value in [True, 0, -1, "100", 131073]:
        assert slo.requested_output({"max_tokens": value}) is None


def test_window_and_model_caps_concurrent_and_read_only():
    from concurrent.futures import ThreadPoolExecutor
    store = slo.ObservationWindow(max_models=2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: store.record(A, ttft_ms=1, tokens_per_second=10, now=NOW), range(1100)))
    assert store.predict(A, 1, min_samples=20, now=NOW)["samples"] == 1000
    measured(store, B)
    measured(store, C)
    assert store.predict(A, 1, min_samples=20, now=NOW)["samples"] == 0
    assert len(store._models) == 2
    before = copy.deepcopy(store._models)
    store.predict(C, 1, min_samples=20, now=NOW)
    assert store._models == before


def test_unknown_policy_and_explicit_model_preserved():
    store = slo.ObservationWindow()
    assert decide(store).prediction["status"] == "prediction_unknown"
    with pytest.raises(slo.LatencySLOError) as error:
        decide(store, required=True)
    assert error.value.code == "latency_slo_unavailable"
    measured(store)
    measured(store, B, rate=100)
    with pytest.raises(slo.LatencySLOError) as error:
        decide(store, [choice(), choice(B)], mode="reroute", auto=False)
    assert error.value.code == "latency_slo_predicted_miss"


def test_reroute_only_already_eligible_same_approved_tier():
    store = slo.ObservationWindow()
    measured(store)
    measured(store, B, rate=100)
    measured(store, C, rate=100)
    candidates = [choice(), choice(C, tier=2), choice(B)]
    original = copy.deepcopy(candidates)
    decision = decide(store, candidates, mode="reroute")
    assert decision.candidates == [choice(B)] and decision.action == "reroute"
    assert candidates == original
    with pytest.raises(slo.LatencySLOError):
        decide(store, candidates[:2], mode="reroute")
    assert decide(store, output=10).action == "pass"


@pytest.mark.parametrize("change", [
    {"LATENCY_SLO_MODE": "private-bad"}, {"LATENCY_SLO_MIN_SAMPLES": "0"},
    {"LATENCY_SLO_MAX_MODELS": "513"}, {"LATENCY_SLO_POLICY_JSON": "[]"},
    {"LATENCY_SLO_POLICY_JSON": '{"routes":{"x":{"deadline_ms":true}}}'},
    {"LATENCY_SLO_POLICY_JSON": '{"routes":{"x":{"deadline_ms":10,"extra":1}}}'},
    {"LATENCY_SLO_POLICY_JSON": '{"routes":{},"routes":{}}'},
    {"LATENCY_SLO_POLICY_JSON": '{"keys":{"x":{"deadline_ms":1,"require_coverage":"yes"}}}'},
])
def test_invalid_settings_disable_once_without_values(change, caplog):
    for _ in range(2):
        assert slo.load_settings(environment(**change)).mode == "off"
    assert len(caplog.records) == 1
    assert "private-bad" not in caplog.text


def test_empty_defaults_and_tightest_route_key_rule():
    assert slo.load_settings({name: "" for name in slo.ENV_KEYS}).mode == "off"
    settings = slo.load_settings(environment(LATENCY_SLO_POLICY_JSON=json.dumps({
        "routes": {"auto:intelligence": {"deadline_ms": 5000}},
        "keys": {"caller": {"deadline_ms": 1000, "require_coverage": True}}})))
    rule = settings.rule_for(route="auto:intelligence", key_id="caller")
    assert rule.deadline_ms == 1000 and rule.require_coverage
    assert settings.rule_for(route="other", key_id="other") is None


def test_route_health_records_paired_measurements_only_when_on(monkeypatch):
    RouteHealth.record_speed(A, ttft_ms=100, tokens_per_second=100, now=NOW)
    assert slo.observations.predict(A, 100, min_samples=1, now=NOW)["samples"] == 0
    for name, value in environment().items():
        monkeypatch.setenv(name, value)
    for _ in range(20):
        RouteHealth.record_speed(A, ttft_ms=100, tokens_per_second=100, now=NOW)
    assert slo.observations.predict(A, 100, min_samples=20, now=NOW)["predicted_ms"] == 1100
    assert "latency_slo" not in RouteHealth.snapshot(A)
    assert all("latency_slo" not in row["state"] for row in RouteHealth.dirty_rows(100))


def registered_app(monkeypatch, env, candidates=None, clock=lambda: NOW):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    app = Flask(__name__)
    gd.register_generation_deadline(app, clock=clock)
    slo.register_latency_slo(app, is_managed=extensions.managed_generation_request,
                             candidates=lambda body: candidates, clock=clock)
    claims, handoffs = [], []
    def idempotency_request_hook():
        claims.append(True)
    extensions.register_authenticated_hook(app, idempotency_request_hook)
    @app.before_request
    def authenticated():
        g.authenticated_user = {"id": "caller", "username": "caller"}
        return extensions.after_authentication()
    @app.post("/v1/chat/completions")
    @app.post("/openai/v1/chat/completions")
    def generate():
        handoffs.append(True)
        return Response(b'{"untouched":true}', headers={"X-Test": "unchanged"}, content_type="application/json")
    return app, claims, handoffs


def test_registered_rejection_before_claim_or_handoff_and_fixed_order(monkeypatch):
    measured(slo.observations)
    app, claims, handoffs = registered_app(monkeypatch, environment())
    response = app.test_client().post("/v1/chat/completions", json={"model": A, "max_tokens": 100})
    assert response.status_code == 503 and response.json["error"]["code"] == "latency_slo_predicted_miss"
    assert response.json["error"]["prediction"]["samples"] == 20
    assert not claims and not handoffs
    names = [hook.__name__ for hook in app.extensions["gateway_after_authentication"]]
    assert names == ["generation_deadline_hook", "latency_slo_request_hook", "idempotency_request_hook"]
    assert extensions.AUTHENTICATED_HOOK_ORDER.index("latency_slo_request_hook") == extensions.AUTHENTICATED_HOOK_ORDER.index("generation_deadline_hook") + 1
    assert extensions.register_latency_slo in extensions.gateway_callbacks()


def test_default_and_raw_responses_unchanged(monkeypatch):
    app, _, handoffs = registered_app(monkeypatch, environment(mode="off"))
    client = app.test_client()
    body = {"model": A, "max_tokens": 100}
    baseline = client.post("/v1/chat/completions", json=body)
    measured(slo.observations)
    monkeypatch.setenv("LATENCY_SLO_MODE", "reject")
    raw = client.post("/openai/v1/chat/completions", json=body)
    assert raw.data == baseline.data and raw.headers == baseline.headers
    monkeypatch.setenv("LATENCY_SLO_MODE", "")
    disabled = client.post("/v1/chat/completions", json=body)
    assert disabled.data == baseline.data and disabled.headers == baseline.headers
    assert len(handoffs) == 3


def test_registered_unknown_required_and_auto_fake_collaborator(monkeypatch):
    app, claims, handoffs = registered_app(monkeypatch, environment(required=True), [choice(), choice(B)])
    client = app.test_client()
    response = client.post("/v1/chat/completions", json={"model": "auto:intelligence", "max_tokens": 100})
    assert response.status_code == 503 and response.json["error"]["code"] == "latency_slo_unavailable"
    assert not claims and not handoffs
    measured(slo.observations)
    measured(slo.observations, B, rate=100)
    monkeypatch.setenv("LATENCY_SLO_MODE", "reroute")
    assert client.post("/v1/chat/completions", json={"model": "auto:intelligence", "max_tokens": 100}).status_code == 200


def test_prediction_does_not_extend_runtime_deadline(monkeypatch):
    clock = Mock(return_value=NOW)
    app, _, _ = registered_app(monkeypatch, environment(), clock=clock)
    measured(slo.observations, ttft=1, rate=10000)
    with app.test_request_context("/v1/chat/completions", method="POST", json={"model": A, "max_tokens": 100}, headers={gd.PUBLIC_HEADER: "1000"}):
        g.authenticated_user = {"id": "caller"}
        assert extensions.after_authentication() is None
        deadline = gd.current_deadline()
        deadline.stop()
        assert deadline.expires_at == NOW + 1
        clock.return_value = NOW + 2
        with pytest.raises(gd.GenerationDeadlineExceeded):
            gd.check_deadline()


def test_intelligence_filters_after_eligibility_without_policy_write(monkeypatch):
    configured = ip.validate_policy({"candidates": [choice(), choice(B), choice(C, entitled=False)]})
    before = copy.deepcopy(configured)
    parsed = ChatRequest.parse({"model": "auto:intelligence", "messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 100}, configured)
    monkeypatch.setattr(ip, "eligible", lambda candidate, *args: candidate["entitled"])
    for name, value in environment(mode="reroute").items():
        monkeypatch.setenv(name, value)
    measured(slo.observations, now=slo.time.time())
    measured(slo.observations, B, rate=100, now=slo.time.time())
    assert ip.select_candidates(configured, parsed, {"API_BASE_URLS": {}}) == [choice(B)]
    assert configured == before


def test_generic_auto_order_respects_pre_admission_restriction(monkeypatch):
    measured(slo.observations)
    measured(slo.observations, B, rate=100)
    app, _, _ = registered_app(monkeypatch, environment(mode="reroute"), [choice(), choice(B), choice(C, 2)])
    with app.test_request_context("/v1/chat/completions", method="POST", json={"model": "auto:test", "max_tokens": 100}):
        g.authenticated_user = {"id": "caller"}
        assert extensions.after_authentication() is None
        assert RouteHealth.order("auto:test", (A, B, C), now=NOW).candidates == (B,)


def test_missing_approved_tier_never_authorizes_generic_reroute(monkeypatch):
    measured(slo.observations)
    measured(slo.observations, B, rate=100)
    app, _, _ = registered_app(monkeypatch, environment(mode="reroute"))
    with app.test_request_context("/v1/chat/completions", method="POST", json={"model": "auto:test", "max_tokens": 100}):
        g.authenticated_user = {"id": "caller"}
        assert extensions.after_authentication() is None
        with pytest.raises(slo.LatencySLOError) as error:
            RouteHealth.order("auto:test", (A, B), now=NOW)
        assert error.value.code == "latency_slo_predicted_miss"


def test_session_tier_filter_precedes_slo_filter(monkeypatch):
    configured = ip.validate_policy({"candidates": [choice(), choice(B, 2), choice(C, 1)]})
    parsed = ChatRequest.parse({"model": "auto:intelligence", "messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 100}, configured)
    monkeypatch.setattr(ip, "eligible", lambda *args: True)
    for name, value in environment(mode="reroute").items():
        monkeypatch.setenv(name, value)
    measured(slo.observations, now=slo.time.time())
    measured(slo.observations, B, rate=100, now=slo.time.time())
    measured(slo.observations, C, rate=100, now=slo.time.time())
    tier = Mock(select=lambda choices: [candidate for candidate in choices if candidate["quality_tier"] == 1])
    assert ip.select_candidates(configured, parsed, {"API_BASE_URLS": {}}, session_tier=tier) == [choice(C)]


def test_unknown_output_cannot_underestimate_large_request():
    store = slo.ObservationWindow()
    measured(store, rate=1000000)
    with pytest.raises(slo.LatencySLOError) as error:
        decide(store, required=True, output=None)
    assert error.value.code == "latency_slo_unavailable"


def test_lane_acquisition_keeps_original_approval_before_filtering(monkeypatch):
    from services import managed_turn
    configured = ip.validate_policy({"candidates": [choice(), choice(B, 2), choice(C, 1)]})
    body = {"model": "auto:intelligence", "messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 100}
    parsed = ChatRequest.parse(body, configured)
    monkeypatch.setattr(ip, "eligible", lambda *args: True)
    app, _, _ = registered_app(monkeypatch, environment(mode="reroute"))
    measured(slo.observations)
    measured(slo.observations, B, rate=100)
    measured(slo.observations, C, rate=100)
    with app.test_request_context("/v1/chat/completions", method="POST", json=body):
        g.authenticated_user = {"id": "caller"}
        assert extensions.after_authentication() is None
        token = managed_turn._turn.set(managed_turn.ManagedTurn("chat", tier_metadata={"approved_model": A}))
        try:
            assert ip.select_candidates(configured, parsed, {}) == configured["candidates"]
            lane = Mock(select=lambda candidates: [candidate for candidate in candidates if candidate["quality_tier"] == 1])
            assert ip.select_candidates(configured, parsed, {}, session_tier=lane) == [choice(C)]
        finally:
            managed_turn._turn.reset(token)
