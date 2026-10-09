"""Managed integration with synthetic upstreams and request-local feature policy."""
import importlib
import json
import re
import threading
from unittest.mock import patch
from types import SimpleNamespace

import pytest
from flask import g

from tests.test_wave5_managed import gateway as base_gateway, body, post, enable_semantic
from tests.test_protocol_routes import RESPONSES_BODY, CHAT_STREAM, json_upstream, sse_upstream

FLAGS = {
    "CONTEXT_CANARY_MODE": "off", "CONTEXT_CANARY_POLICY_JSON": "{}",
    "LATENCY_SLO_MODE": "off", "LATENCY_SLO_POLICY_JSON": "{}",
    "HEDGED_REQUESTS_ENABLED": "false", "HEDGED_REQUESTS_POLICY_JSON": "{}",
    "STREAM_COST_BREAKER_ENABLED": "false", "LEARNED_COOLDOWN_MODE": "off",
    "USAGE_RECEIPTS_ENABLED": "false", "REALTIME_ENABLED": "false",
    "ENTERPRISE_PREVIEW_ENABLED": "false",
}


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    for name, value in FLAGS.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def gateway(base_gateway):
    base_gateway.headers["X-Request-ID"] = "managed-fixed"
    return base_gateway


@pytest.mark.parametrize("path,payload,result", [
    ("/v1/chat/completions", body(), None),
    ("/v1/messages", {"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}, None),
    ("/v1/responses", {"model": "opencode:grok-4.6", "input": "hi"}, RESPONSES_BODY),
    ("/v1/chat/completions", body(model="auto:managed-test"), None),
    ("/v1/chat/completions", body(model="opencode:kimi-k2.6", stream=True), "stream"),
])
def test_flags_off_keep_provider_and_response_bytes(gateway, monkeypatch, path, payload, result):
    monkeypatch.setattr("time.perf_counter", lambda: 1000)
    routes = importlib.import_module("services.auto_route_service").AutoRouteService
    routes.save_route("auto:managed-test", ["mimo:mimo-v2.5"], gateway.app.config["API_BASE_URLS"])
    def reply():
        return sse_upstream(CHAT_STREAM) if result == "stream" else json_upstream(result) if result else gateway._chat_response()
    first, send = post(gateway, payload, path=path, reply=reply())
    submitted = send.call_args.kwargs["data"]
    for name in FLAGS:
        monkeypatch.delenv(name, raising=False)
    second, send = post(gateway, payload, path=path, reply=reply())
    assert first.status_code == second.status_code == 200
    assert first.data == second.data and submitted == send.call_args.kwargs["data"]
    assert list(first.headers) == list(second.headers)


def enable_canary(monkeypatch, mode="log"):
    monkeypatch.setenv("CONTEXT_CANARY_MODE", mode)
    monkeypatch.setenv("CONTEXT_CANARY_POLICY_JSON", json.dumps({"routes": ["/v1/chat/completions", "/v1/messages", "/v1/responses"]}))


def marker(payload):
    match = re.search(r"Private request marker: ([0-9a-f]{32})", json.dumps(payload))
    assert match, payload
    return match[1]


@pytest.mark.parametrize("mode,status", [("log", 200), ("block", 502)])
@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/messages", "/v1/responses"])
def test_canary_annotates_dispatch_only_and_scans_real_protocol_route(gateway, monkeypatch, caplog, mode, status, path):
    enable_canary(monkeypatch, mode)
    payload = body()
    if path == "/v1/messages":
        payload = {"model": payload["model"], "messages": payload["messages"], "max_tokens": 10}
    if path == "/v1/responses":
        payload = {"model": "opencode:grok-4.6", "input": "hello"}
    submitted = []
    def provider(**kwargs):
        dispatch = json.loads(kwargs["data"])
        token = marker(dispatch)
        submitted.append(token)
        assert token not in json.dumps(importlib.import_module("flask").request.get_json())
        if path == "/v1/responses":
            reply = json.loads(json.dumps(RESPONSES_BODY))
            reply["output"][0]["content"][0]["text"] = "before " + token + " after"
            return json_upstream(reply)
        return gateway._chat_response("before " + token + " after")
    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send:
        response = gateway.client.post(path, json=payload, headers=gateway.headers)
    assert response.status_code == status, response.data
    assert send.call_count == 1
    assert submitted[0].encode() not in response.data
    assert submitted[0] not in caplog.text
    assert "context_canary_leak" in caplog.text
    if mode == "log":
        assert b"before " in response.data and b" after" in response.data


def test_canary_opt_in_bypasses_exact_shared_and_semantic_caches(gateway, monkeypatch):
    enable_semantic(monkeypatch)
    first, _ = post(gateway, headers={"X-MultiLLM-Cache": "on"})
    enable_canary(monkeypatch)
    before = len(gateway.embeddings)
    for _ in range(2):
        response, send = post(gateway, headers={"X-MultiLLM-Cache": "on"})
        assert response.status_code == 200 and send.call_count == 1
        assert marker(json.loads(send.call_args.kwargs["data"]))
        assert response.headers["X-MultiLLM-Cache"] == "bypass"
    assert len(gateway.embeddings) == before
    assert first.status_code == 200


def test_canary_preparation_error_fails_before_provider(gateway, monkeypatch):
    enable_canary(monkeypatch)
    canary = importlib.import_module("services.context_canary")
    monkeypatch.setattr(canary, "prepare_request", lambda *args, **kwargs: (_ for _ in ()).throw(canary.ContextCanaryError()))
    response, send = post(gateway)
    assert response.status_code == 502 and send.call_count == 0
    assert b"context_canary_scan_failed" in response.data


def test_candidate_policy_is_read_only_and_reuses_reviewed_eligibility(gateway, monkeypatch):
    module = importlib.import_module("services.latency_slo_candidates")
    routes = importlib.import_module("services.auto_route_service").AutoRouteService
    routes.save_route("auto:managed-test", ["mimo:mimo-v2.5", "opencode:kimi-k2.6"], gateway.app.config["API_BASE_URLS"])
    fixtures = importlib.import_module("tests.test_intelligence_policy")
    store = importlib.import_module("services.intelligence_store").IntelligenceStore
    store.seed(fixtures.policy(candidates=[fixtures.candidate("mimo:mimo-v2.5"), fixtures.candidate("opencode:kimi-k2.6", privacy_allowed=False)]))
    module.register_latency_slo_candidates(gateway.app)
    with gateway.app.test_request_context("/v1/chat/completions", method="POST", json=body(model="auto:managed-test")):
        g.authenticated_user = {"username": "caller", "allowed_models": ["*"]}
        assert gateway.app.extensions["latency_slo_candidate_policy"](body(model="auto:managed-test")) == [{"model": "mimo:mimo-v2.5", "quality_tier": 1}]


def seed_route(gateway, models):
    fixtures = importlib.import_module("tests.test_intelligence_policy")
    importlib.import_module("services.intelligence_store").IntelligenceStore.seed(
        fixtures.policy(candidates=[fixtures.candidate(model) for model in models]))
    importlib.import_module("services.auto_route_service").AutoRouteService.save_route(
        "auto:managed-test", models, gateway.app.config["API_BASE_URLS"])


@pytest.mark.parametrize("mode,status,model", [("reject", 503, None), ("reroute", 200, "opencode:kimi-k2.6")])
def test_latency_auto_admission_uses_reviewed_policy_before_claims(gateway, monkeypatch, tmp_path, mode, status, model):
    models = ["mimo:mimo-v2.5", "opencode:kimi-k2.6"]
    seed_route(gateway, models)
    monkeypatch.setenv("LATENCY_SLO_MODE", mode)
    monkeypatch.setenv("LATENCY_SLO_MIN_SAMPLES", "1")
    monkeypatch.setenv("LATENCY_SLO_POLICY_JSON", json.dumps({"routes": {"auto:managed-test": {"deadline_ms": 500, "require_coverage": True}}}))
    slo = importlib.import_module("services.latency_slo")
    slo.observations.clear()
    gateway.app.extensions["latency_slo"]["clock"] = lambda: 1000
    slo.observations.record(models[0], ttft_ms=1000, tokens_per_second=100, now=1000)
    slo.observations.record(models[1], ttft_ms=1, tokens_per_second=100, now=1000)
    enable_combined(monkeypatch)
    monkeypatch.setenv("LATENCY_SLO_MODE", mode)
    enable_claims(gateway, monkeypatch)
    store = enable_budget(gateway, monkeypatch, tmp_path, models)
    admission = importlib.import_module("tests.test_hedged_requests").Admission()
    gateway.app.extensions["admission_client"] = admission
    monkeypatch.setenv("ADMISSION_ENABLED", "true")
    canary = importlib.import_module("services.context_canary")
    with patch.object(canary, "prepare_request", wraps=canary.prepare_request) as prepare:
        response, send = post(gateway, body(model="auto:managed-test"), headers={"Idempotency-Key": "slo-admission"})
    assert response.status_code == status, response.data
    if model:
        assert send.call_count == 1 and response.headers["X-MultiLLM-Auto-Selected-Model"] == model
    else:
        assert send.call_count == prepare.call_count == 0
        assert not gateway.claims.calls and not admission.calls
        assert store.summary("caller")["held_usd"] == 0


@pytest.mark.parametrize("mode,status", [("log", 200), ("block", 502)])
def test_intelligence_transport_scans_before_internal_settlement(gateway, monkeypatch, mode, status):
    seed_route(gateway, ["mimo:mimo-v2.5"])
    enable_canary(monkeypatch, mode)
    submitted = []
    def provider(**kwargs):
        token = marker(json.loads(kwargs["data"]))
        submitted.append(token)
        fixtures = importlib.import_module("tests.intelligence_fixtures")
        return fixtures.upstream(fixtures.completion("before " + token + " after"))
    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider):
        response = gateway.client.post("/v1/chat/completions", json=body(model="auto:intelligence"), headers=gateway.headers)
    assert response.status_code == status, response.data
    assert len(submitted) == 1 and submitted[0].encode() not in response.data


def enable_claims(gateway, monkeypatch):
    monkeypatch.setenv("MANAGED_IDEMPOTENCY_ENABLED", "true")
    gateway.claims = importlib.import_module("tests.test_managed_idempotency").Authority()
    gateway.app.extensions["managed_idempotency_store"] = importlib.import_module("services.idempotency_store").IdempotencyStore(gateway.claims)


def enable_budget(gateway, monkeypatch, tmp_path, models):
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    reservations = importlib.import_module("services.reservation_store")
    store = reservations.SqlReservationStore(tmp_path / "holds.sqlite3")
    monkeypatch.setattr(reservations, "_store", store)
    gateway.app.extensions["gateway_after_authentication"].append(
        lambda: g.authenticated_user.update(username="caller", daily_budget_usd=5, monthly_budget_usd=10))
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps({model: {"input": 0, "cache_read": 0, "cache_write": 0, "output": 1} for model in models}))
    return store


def enable_combined(monkeypatch):
    for flag in ("HEDGED_REQUESTS_ENABLED", "STREAM_COST_BREAKER_ENABLED", "USAGE_RECEIPTS_ENABLED", "REALTIME_ENABLED", "ENTERPRISE_PREVIEW_ENABLED"):
        monkeypatch.setenv(flag, "true")
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", "apply")
    monkeypatch.setenv("LATENCY_SLO_MODE", "reject")
    enable_canary(monkeypatch, "block")


def test_latency_selection_cannot_restore_removed_eligibility(gateway):
    slo = importlib.import_module("services.latency_slo")
    with gateway.app.test_request_context("/v1/chat/completions"):
        g.latency_slo_context = (slo.load_settings(), slo.Rule(500, False), 10)
        g.latency_slo_eligible = [{"model": "mimo:mimo-v2.5", "quality_tier": 1}]
        g.latency_slo_decision = None
        assert slo.order_auto_candidates("auto:managed-test", ("mimo:mimo-v2.5", "opencode:kimi-k2.6")) == ("mimo:mimo-v2.5",)


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/messages", "/v1/responses"])
@pytest.mark.parametrize("first_stop", ["cost", "canary"])
def test_combined_stream_stops_once_and_keeps_ambiguous_hold(gateway, monkeypatch, tmp_path, path, first_stop):
    enable_combined(monkeypatch)
    model = "opencode:grok-4.6" if path == "/v1/responses" else "opencode:kimi-k2.6"
    store = enable_budget(gateway, monkeypatch, tmp_path, [model])
    gateway.app.extensions["gateway_after_authentication"].append(lambda: g.authenticated_user.update(max_stream_cost_microusd=14 if path == "/v1/messages" else 4))
    closes, submitted = [], []
    from tests.test_protocol_translation import chat_sse, chunk, sse
    def provider(**kwargs):
        token = marker(json.loads(kwargs["data"]))
        submitted.append(token)
        texts = ["ok", token if first_stop == "canary" else "overbudget", token]
        if path == "/v1/responses":
            frames = sse(*[("response.output_text.delta", {"type": "response.output_text.delta", "delta": text, "output_index": 0, "content_index": 0}) for text in texts],
                         ("response.completed", {"type": "response.completed", "response": RESPONSES_BODY}))
        else:
            frames = chat_sse(*[chunk({"content": text}, model="kimi-k2.6") for text in texts], chunk(finish="stop", model="kimi-k2.6"))
        reply = sse_upstream([])
        reply.raw = object()
        reply.iter_content = lambda **kwargs: iter(frames)
        reply.close = lambda: closes.append(True)
        return reply
    payload = body(model=model, stream=True)
    if path == "/v1/messages":
        payload.pop("temperature")
    elif path == "/v1/responses":
        payload = {"model": model, "input": "hello", "stream": True, "max_output_tokens": 10}
    cancellation = importlib.import_module("services.request_cancellation").RequestCancellation
    original_cancel = cancellation.cancel
    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send, \
         patch.object(cancellation, "cancel", autospec=True, side_effect=original_cancel) as cancelled:
        response = gateway.client.post(path, json=payload, headers=gateway.headers)
        data = response.get_data()
        response.close()
    assert send.call_count == 1 and closes == [True] and cancelled.call_count == 1, data
    assert submitted[0].encode() not in data and b"[DONE]" not in data
    code = b"context_canary_leak" if first_stop == "canary" else b"stream_cost_cap_exceeded"
    from tests.test_protocol_translation import parse_frames
    errors = [frame for frame in parse_frames(data.decode())
              if code.decode() in json.dumps(frame[1]) or
              (path == "/v1/messages" and first_stop == "canary" and frame[0] == "error"
               and frame[1].get("error", {}).get("message") == "Managed response inspection stopped generation")]
    assert len(errors) == 1, data
    if path == "/v1/messages":
        assert b"event: error" in data and b"event: message_stop" not in data
    elif path == "/v1/responses":
        assert b"event: response.failed" in data and b"event: response.completed" not in data
    assert store.summary("caller")["unknown"] == 1


def test_canary_scanned_replay_and_hosted_state_never_contain_marker(gateway, monkeypatch):
    enable_combined(monkeypatch)
    enable_canary(monkeypatch, "log")
    enable_claims(gateway, monkeypatch)
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
    gateway.responses = importlib.import_module("tests.test_responses_state").Authority()
    gateway.app.extensions["responses_state_store"] = importlib.import_module("services.responses_state").ResponsesStateStore(gateway.responses)
    submitted = []
    def provider(**kwargs):
        token = marker(json.loads(kwargs["data"]))
        submitted.append(token)
        reply = json.loads(json.dumps(RESPONSES_BODY))
        reply["output"][0]["content"][0]["text"] = "before " + token + " after"
        return json_upstream(reply)
    payload = {"model": "opencode:grok-4.6", "input": "hello", "gateway_state": True, "store": True}
    headers = {**gateway.headers, "Idempotency-Key": "scanned"}
    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send:
        first = gateway.client.post("/v1/responses", json=payload, headers=headers)
        second = gateway.client.post("/v1/responses", json=payload, headers=headers)
    assert first.status_code == second.status_code == 200 and send.call_count == 1
    assert first.data == second.data and second.headers["X-MultiLLM-Idempotency"] == "replayed"
    assert gateway.responses.rows and gateway.claims.rows
    assert submitted[0] not in json.dumps([list(gateway.responses.rows.values()), gateway.claims.rows, gateway.claims.calls])


@pytest.mark.parametrize("combined", [False, True])
def test_registered_hedge_isolates_canaries_and_excludes_slo_removed_models(gateway, monkeypatch, tmp_path, combined):
    models = ["mimo:mimo-v2.5", "opencode:kimi-k2.6", "mimo:mimo-v2.5-pro"]
    seed_route(gateway, models)
    if combined:
        enable_combined(monkeypatch)
    else:
        monkeypatch.setenv("HEDGED_REQUESTS_ENABLED", "true")
    enable_claims(gateway, monkeypatch)
    store = enable_budget(gateway, monkeypatch, tmp_path, models)
    gateway.app.extensions["admission_client"] = importlib.import_module("tests.test_hedged_requests").Admission()
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", json.dumps({"auto:managed-test": {"enabled": True, "delay_ms": 1, "max_duplicates": 2, "idempotent_safe": True}}))
    health = importlib.import_module("services.route_health").RouteHealth
    health.reset()
    if combined:
        monkeypatch.setenv("LATENCY_SLO_MODE", "reroute")
        monkeypatch.setenv("LATENCY_SLO_MIN_SAMPLES", "1")
        monkeypatch.setenv("LATENCY_SLO_POLICY_JSON", json.dumps({"routes": {"auto:managed-test": {"deadline_ms": 500, "require_coverage": True}}}))
        slo = importlib.import_module("services.latency_slo")
        gateway.app.extensions["latency_slo"]["clock"] = lambda: 1000
        for index, model in enumerate(models):
            slo.observations.record(model, ttft_ms=1000 if index == 0 else 1, tokens_per_second=100, now=1000)
        expected = models[1:]
    else:
        expected = models[:2]
    cancelled = threading.Event()
    sent, contexts, closes = [], [], []
    managed = importlib.import_module("services.managed_turn")
    from services.request_cancellation import bind_cancellation
    def provider(**kwargs):
        dispatch = json.loads(kwargs["data"])
        full = kwargs["api_provider"] + ":" + dispatch["model"]
        sent.append(full)
        contexts.append(managed.current_turn().canary)
        if full == expected[0]:
            reply = json_upstream({})
            bind_cancellation(reply, close_owner=lambda: (closes.append(full), cancelled.set()))
            assert cancelled.wait(2)
            raise importlib.import_module("requests").ReadTimeout("synthetic cancellation")
        return json_upstream(importlib.import_module("tests.test_hedged_requests").envelope("winner"))
    rows, receipt_rows = [], []
    accounting = importlib.import_module("services.request_accounting")
    ledger = accounting.usage_ledger.UsageLedger()
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "true")
    monkeypatch.setattr(ledger, "_ensure_thread", lambda: None)
    monkeypatch.setattr(ledger, "store", lambda: SimpleNamespace(record=lambda batch, items: rows.extend(items), totals=lambda *args: {"day_usd": 0, "month_usd": 0}))
    monkeypatch.setattr(accounting.usage_ledger, "LEDGER", ledger)
    receipts = importlib.import_module("services.usage_receipts")
    monkeypatch.setattr(receipts, "open_store", lambda: SimpleNamespace(append=lambda principal, event, record: receipt_rows.append(record)))
    learned = importlib.import_module("services.learned_cooldown")
    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send, \
         patch.object(health, "record", wraps=health.record) as observed, \
         patch.object(learned, "adjust_cooldown", wraps=learned.adjust_cooldown) as cooldown:
        response = gateway.client.post("/v1/chat/completions", json=body(model="auto:managed-test"), headers={**gateway.headers, "Idempotency-Key": "race"})
    assert response.status_code == 200, response.data
    assert send.call_count == 2 and sent == expected and closes == [expected[0]]
    assert all(call.args[0] != expected[0] for call in observed.call_args_list)
    assert ledger.flush_once() == 2
    assert len(rows) == 2 and store.summary("caller")["unknown"] == 1
    assert cooldown.call_count == 0
    assert len(receipt_rows) == (2 if combined else 0)
    if combined:
        assert contexts[0] is not contexts[1] and all(context.closed for context in contexts)
        assert contexts[0].marker != contexts[1].marker
        assert all(context.marker not in json.dumps(receipt_rows) for context in contexts)


@pytest.mark.parametrize("flag,value", [("AUTO_ROUTE_ORDERING", "health"), ("CANARY_TRAFFIC_ENABLED", "true")])
def test_early_candidates_do_not_guess_mutable_route_order(gateway, monkeypatch, flag, value):
    seed_route(gateway, ["mimo:mimo-v2.5", "opencode:kimi-k2.6"])
    monkeypatch.setenv(flag, value)
    module = importlib.import_module("services.latency_slo_candidates")
    with gateway.app.test_request_context("/v1/chat/completions", method="POST"):
        g.authenticated_user = {"username": "caller", "allowed_models": ["*"]}
        assert module.latency_slo_candidate_policy(body(model="auto:managed-test")) == []


def test_intelligence_selection_keeps_early_reroute_restriction(gateway):
    slo = importlib.import_module("services.latency_slo")
    first = {"model": "mimo:mimo-v2.5", "quality_tier": 1}
    second = {"model": "opencode:kimi-k2.6", "quality_tier": 1}
    with gateway.app.test_request_context("/v1/chat/completions"):
        g.latency_slo_context = (slo.load_settings(), slo.Rule(500, False), 10)
        g.latency_slo_decision = slo.Decision([second], "reroute", {})
        assert slo.selection_candidates([first, second], route="auto:intelligence", output_tokens=10, auto=True) == [second]


def test_canary_marker_stays_out_of_context_pages(gateway, monkeypatch):
    enable_combined(monkeypatch)
    enable_canary(monkeypatch, "log")
    monkeypatch.setenv("CONTEXT_PAGING_ENABLED", "true")
    history = importlib.import_module("tests.test_context_pages").history()
    payload = body(messages=history, capabilities=["multillm_context_retrieve"], optimization={"target_input_tokens": 700})
    result, sent = post(gateway, payload)
    token = marker(json.loads(sent.call_args.kwargs["data"]))
    assert result.status_code == 200 and gateway.pages.records
    assert token not in json.dumps([gateway.pages.records, result.json], default=str)


def test_stream_cost_flag_alone_stops_registered_stream(gateway, monkeypatch, tmp_path):
    monkeypatch.setenv("STREAM_COST_BREAKER_ENABLED", "true")
    model = "opencode:kimi-k2.6"
    store = enable_budget(gateway, monkeypatch, tmp_path, [model])
    gateway.app.extensions["gateway_after_authentication"].append(lambda: g.authenticated_user.update(max_stream_cost_microusd=4))
    from tests.test_protocol_translation import chat_sse, chunk
    reply = sse_upstream([])
    reply.raw = object()
    reply.iter_content = lambda **kwargs: iter(chat_sse(chunk({"content": "overbudget"}, model="kimi-k2.6"), chunk(finish="stop")))
    closes = []
    reply.close = lambda: closes.append(True)
    result, sent = post(gateway, body(model=model, stream=True), reply=reply)
    result.close()
    assert sent.call_count == 1 and closes == [True]
    assert b"stream_cost_cap_exceeded" in result.data and b"[DONE]" not in result.data
    assert "Private request marker" not in json.dumps(json.loads(sent.call_args.kwargs["data"]))
    assert store.summary("caller")["unknown"] == 1


def test_all_flags_never_hedge_streaming_auto_request(gateway, monkeypatch, tmp_path):
    models = ["mimo:mimo-v2.5", "opencode:kimi-k2.6"]
    seed_route(gateway, models)
    enable_combined(monkeypatch)
    enable_budget(gateway, monkeypatch, tmp_path, models)
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", json.dumps({"auto:managed-test": {"enabled": True, "delay_ms": 1, "max_duplicates": 2, "idempotent_safe": True}}))
    from tests.test_protocol_translation import chat_sse, chunk
    reply = sse_upstream([])
    reply.raw = object()
    reply.iter_content = lambda **kwargs: iter(chat_sse(chunk({"content": "ok"}), chunk(finish="stop")))
    result, sent = post(gateway, body(model="auto:managed-test", stream=True), reply=reply)
    result.close()
    assert result.status_code == 200 and sent.call_count == 1
