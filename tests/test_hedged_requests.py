"""Bounded auto races with synthetic transport, admission and durable holds."""
import importlib
import json
import os
import threading
import time
from unittest.mock import patch

import pytest
import requests
from flask import Flask, Response, g

MODELS = ("mimo:first", "opencode:second", "mimo:third")
PAYLOAD = {"model": "auto:hedge", "messages": [{"role": "user", "content": "test"}], "max_tokens": 100}
USER = {"username": "caller", "daily_budget_usd": 5.0, "monthly_budget_usd": 10.0}


def envelope(text="ok", *, tokens=True, finish="stop"):
    body = {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": finish}]}
    if tokens:
        body["usage"] = {"prompt_tokens": 10, "completion_tokens": 20}
    return body


class Lease:
    def __init__(self, identity=None):
        self.identity = identity
        self.releases = 0
        self.closed = False

    def check(self):
        assert not self.closed

    def release(self):
        if not self.closed:
            self.closed = True
            self.releases += 1


class Admission:
    def __init__(self, *, denied=False):
        self.denied = denied
        self.leases = []
        self.calls = []

    def acquire(self, identity, *, on_lost=None):
        self.calls.append(identity)
        if self.denied:
            from services.admission_leases import AdmissionError
            raise AdmissionError()
        lease = Lease(identity)
        self.leases.append(lease)
        return lease


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    global hedges, routes, accounting, reservations, budget
    hedges = importlib.import_module("services.hedged_requests")
    routes = importlib.import_module("routes.auto_routes")
    accounting = importlib.import_module("services.request_accounting")
    reservations = importlib.import_module("services.reservation_store")
    budget = importlib.import_module("services.budget_service")
    flags = {"HEDGED_REQUESTS_ENABLED": "true", "MANAGED_IDEMPOTENCY_ENABLED": "true",
             "USAGE_RESERVATIONS_ENABLED": "true", "USAGE_HOLD_REVIEW_AFTER_SECONDS": "259200",
             "INTELLIGENCE_STORAGE_BACKEND": "", "CONTROL_PLANE_DATABASE_URL": "",
             "USAGE_LEDGER_ENABLED": "false", "PROMPT_CACHE_USAGE_BUCKETS_ENABLED": "false",
             "PROMPT_CACHE_AFFINITY_ENABLED": "false", "CANARY_TRAFFIC_ENABLED": "false",
             "ADMISSION_ENABLED": "false", "MULTILLM_STREAM_PREFLIGHT": "off", "NANOGPT_API_KEY": "",
             "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"), "SESSION_TIER_MODE": "off"}
    for name, value in flags.items():
        monkeypatch.setenv(name, value)
    policy(monkeypatch)
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps(
        {model: {"input": 1000, "output": 1000} for model in MODELS}))
    monkeypatch.setattr(hedges, "_warned", set())
    store = reservations.SqlReservationStore(tmp_path / "usage.sqlite3")
    monkeypatch.setattr(reservations, "_store", store)
    rows = []
    monkeypatch.setattr(accounting.usage_ledger.LEDGER, "record", rows.append)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER, "submit", lambda row: None)
    budget.BudgetService.reset()
    routes.RouteHealth.reset()
    yield store, rows
    budget.BudgetService.reset()
    routes.RouteHealth.reset()


def policy(monkeypatch, **changes):
    config = {"enabled": True, "delay_ms": 15, "max_duplicates": 2, "idempotent_safe": True}
    config.update(changes)
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", json.dumps({"auto:hedge": config}))


def application():
    app = Flask(__name__)
    app.config.update(TESTING=True, API_TIMEOUTS={"default": (0.5, 0.5)})
    from services.auto_route_service import AutoRoute
    route = AutoRoute(id="auto:hedge", candidates=MODELS, updated_at="")
    return app, route


def run(monkeypatch, send, *, body=None, headers=None, prepare=None, admission=None):
    app, route = application()
    app.extensions["admission_client"] = admission or Admission()
    monkeypatch.setattr(routes.AutoRouteService, "get_route", lambda model: route)
    payload = {**PAYLOAD, **(body or {})}
    from services.admission_leases import AdmissionIdentity, principal_hash
    with app.test_request_context("/v1/chat/completions", method="POST", json=payload,
                                  headers={"Idempotency-Key": "stable", **(headers or {})}):
        g.authenticated_user = dict(USER)
        g.managed_idempotency_claim = object()
        g.managed_idempotency_handed_off = True
        g.gateway_generation_deadline = time.monotonic() + 1
        g.gateway_admission_lease = Lease(AdmissionIdentity(principal_hash("caller"), "auto:hedge", "original", int(time.time() * 1000) + 1000))
        assert accounting.begin() is None
        context = g.usage_context
        if prepare:
            prepare()
        response = routes.dispatch_auto_route_chat_completion(payload, validate_candidate=lambda model: None,
                                                              dispatch_candidate=send)
        accounting.finish(response)
        return response, context, app.extensions["admission_client"]


@pytest.mark.parametrize("flag", ["", "false", "0", "off", "malformed-private-value"])
def test_disabled_exact_bytes_headers_accounting_storage(monkeypatch, isolated, caplog, flag):
    store, rows = isolated
    monkeypatch.setenv("HEDGED_REQUESTS_ENABLED", flag)
    calls = []
    def send(body, model, decision):
        calls.append((body, model, decision))
        return Response(json.dumps(envelope()), content_type="application/json", headers={"X-Provider": "same"})
    original, _, _ = run(monkeypatch, send)
    counts = len(rows), store.summary("caller")["spent_today_usd"]
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", "not-json-private-value")
    second, _, _ = run(monkeypatch, send)
    assert original.data == second.data and list(original.headers) == list(second.headers)
    assert calls[0] == calls[1] and len(calls) == 2
    assert counts == (1, pytest.approx(0.03)) and len(rows) == 2
    assert store.summary("caller")["spent_today_usd"] == pytest.approx(0.06)
    assert all(row["selected_model"] == MODELS[0] for row in rows)
    assert "malformed-private-value" not in caplog.text and "not-json-private-value" not in caplog.text
    assert sum("Invalid HEDGED" in record.message for record in caplog.records) == int(flag == "malformed-private-value")


@pytest.mark.parametrize("change", [{"extra": True}, {"delay_ms": 0}, {"delay_ms": 1001}, {"delay_ms": True},
    {"delay_ms": 1.5}, {"max_duplicates": 3}, {"max_duplicates": True}, {"max_duplicates": 2.0},
    {"enabled": "true"}, {"idempotent_safe": 1}])
def test_invalid_policy_disables_whole_mapping_once(monkeypatch, caplog, change):
    policy(monkeypatch, **change)
    for _ in range(2):
        assert hedges.route_policy("auto:hedge") is None
    assert sum("Invalid HEDGED" in record.message for record in caplog.records) == 1


@pytest.mark.parametrize("raw", ["[]", "null", "private-value", '{"direct:model":{}}', '{"auto:hedge":false}'])
def test_invalid_policy_object_and_route(monkeypatch, raw, caplog):
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", raw)
    assert hedges.route_policy("auto:hedge") is None
    assert "private-value" not in caplog.text


def test_empty_policy_and_flags_use_defaults(monkeypatch):
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", "")
    assert hedges.route_policy("auto:hedge") is None
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", '{"auto:hedge":{"enabled":true,"idempotent_safe":true}}')
    settings = hedges.route_policy("auto:hedge")
    assert settings.delay_ms == 150 and settings.max_duplicates == 2


@pytest.mark.parametrize("body,prepare", [({"stream": True}, None), ({"tools": []}, None),
    ({"tool_choice": None}, None), ({"functions": []}, None), ({"function_call": None}, None),
    ({"max_tokens": None}, None), ({}, lambda: setattr(g, "managed_idempotency_claim", None)),
    ({}, lambda: setattr(g, "managed_idempotency_handed_off", False)),
    ({}, lambda: setattr(g, "authenticated_user", {"username": "unlimited"}))])
def test_ineligible_requests_keep_single_path(monkeypatch, body, prepare):
    calls = []
    response, _, admission = run(monkeypatch, lambda body, model, decision: (
        calls.append(model) or Response(json.dumps(envelope()), content_type="application/json")), body=body, prepare=prepare)
    assert response.status_code == 200 and calls == [MODELS[0]] and not admission.calls


@pytest.mark.parametrize("flag", ["MANAGED_IDEMPOTENCY_ENABLED", "USAGE_RESERVATIONS_ENABLED"])
def test_missing_enabled_dependency_keeps_single_path(monkeypatch, flag):
    monkeypatch.setenv(flag, "false")
    calls = []
    response, _, admission = run(monkeypatch, lambda body, model, decision: (
        calls.append(model) or Response(json.dumps(envelope()), content_type="application/json")))
    assert response.status_code == 200 and calls == [MODELS[0]] and not admission.calls


def test_unknown_price_rejected_only_for_otherwise_eligible_policy(monkeypatch):
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps({MODELS[0]: {"input": 1000, "output": 1000}}))
    app, route = application()
    monkeypatch.setattr(routes.AutoRouteService, "get_route", lambda model: route)
    with app.test_request_context("/v1/chat/completions", method="POST", json=PAYLOAD, headers={"Idempotency-Key": "stable"}):
        g.authenticated_user = USER
        g.managed_idempotency_claim = object()
        g.managed_idempotency_handed_off = True
        g.usage_context = accounting.UsageContext("chat", [PAYLOAD["model"]], None, USER, time.perf_counter(), time.time_ns(), input_tokens=10, output_tokens=100)
        g.usage_context.reservation = budget.BudgetService.check_and_reserve(USER, 0.11).reservation
        send = lambda *args: pytest.fail("Unpriced fanout")
        with pytest.raises(routes.APIError) as raised:
            routes.dispatch_auto_route_chat_completion(PAYLOAD, validate_candidate=lambda model: None, dispatch_candidate=send)
        assert raised.value.status_code == 503
        policy(monkeypatch, idempotent_safe=False)
        reply = routes.dispatch_auto_route_chat_completion(PAYLOAD, validate_candidate=lambda model: None,
            dispatch_candidate=lambda *args: Response(json.dumps(envelope()), content_type="application/json"))
        assert reply.status_code == 200


def test_reserve_both_before_dispatch_fast_primary_releases_unused_hold(monkeypatch, isolated):
    store, rows = isolated
    def send(body, model, decision):
        assert store.summary("caller")["reserved"] + store.summary("caller")["dispatched"] == 2
        return Response(json.dumps(envelope()), content_type="application/json")
    response, outer, admission = run(monkeypatch, send)
    assert response.headers["X-MultiLLM-Auto-Attempts"] == "1" and not admission.calls
    assert outer.finished and len(rows) == 1
    assert store.summary("caller")["held_usd"] == 0 and store.summary("caller")["spent_today_usd"] == pytest.approx(0.03)


def test_secondary_wins_cancels_loser_once_retains_unknown_hold(monkeypatch, isolated):
    store, rows = isolated
    calls, closes = [], []
    from services.request_cancellation import bind_cancellation
    def send(body, model, decision):
        calls.append((model, time.monotonic()))
        if model == MODELS[0]:
            upstream = requests.Response()
            upstream.status_code = 200
            upstream._content = b""
            owner = bind_cancellation(upstream, close_owner=lambda: closes.append(model))
            while not owner.closed:
                time.sleep(0.001)
            raise requests.ReadTimeout("synthetic interrupted provider")
        return Response(json.dumps(envelope("winner")), content_type="application/json")
    response, _, admission = run(monkeypatch, send)
    assert response.get_json() == envelope("winner") and response.headers["X-MultiLLM-Auto-Selected-Model"] == MODELS[1]
    assert len(calls) == 2 and calls[1][1] - calls[0][1] >= 0.015
    assert closes == [MODELS[0]] and admission.leases[0].releases == 1
    summary = store.summary("caller")
    assert summary["unknown"] == 1 and summary["held_usd"] > 0 and summary["spent_today_usd"] == pytest.approx(0.03)
    assert len(rows) == 2 and not any(thread.name.startswith("hedged-auto-") for thread in threading.enumerate())


@pytest.mark.parametrize("first", [envelope("", finish="stop"), envelope("partial", finish="length"),
    {"error": {"message": "provider failure"}}, {"choices": [{"message": {}, "finish_reason": "stop"}]}])
def test_invalid_fast_response_cannot_win_or_start_third(monkeypatch, first):
    calls = []
    def send(body, model, decision):
        calls.append(model)
        return Response(json.dumps(first if model == MODELS[0] else envelope("second")), content_type="application/json")
    response, _, _ = run(monkeypatch, send)
    assert calls == list(MODELS[:2]) and response.get_json() == envelope("second")


def test_both_measured_costs_survive_loser_close(monkeypatch, isolated):
    store, rows = isolated
    def send(body, model, decision):
        return Response(json.dumps(envelope("bad", finish="length") if model == MODELS[0] else envelope()), content_type="application/json")
    response, _, _ = run(monkeypatch, send)
    assert response.status_code == 200 and len(rows) == 2
    summary = store.summary("caller")
    assert summary["held_usd"] == 0 and summary["spent_today_usd"] == pytest.approx(0.06)
    assert all(row["input_tokens"] == 10 and row["output_tokens"] == 20 for row in rows)


def test_ambiguous_failures_never_dispatch_third_or_add_retry_headers(monkeypatch):
    calls = []
    def send(body, model, decision):
        calls.append(model)
        return Response('{"error":{"code":"interrupted"}}', status=503, content_type="application/json")
    response, _, _ = run(monkeypatch, send)
    assert calls == list(MODELS[:2]) and response.status_code == 503
    assert "Retry-After" not in response.headers and response.headers["X-MultiLLM-Auto-Attempts"] == "2"


def test_admission_denial_suppresses_second_and_releases_hold(monkeypatch, isolated):
    calls = []
    def send(body, model, decision):
        calls.append(model)
        time.sleep(0.04)
        return Response(json.dumps(envelope()), content_type="application/json")
    response, _, admission = run(monkeypatch, send, admission=Admission(denied=True))
    assert calls == [MODELS[0]] and len(admission.calls) == 1
    assert response.headers["X-MultiLLM-Auto-Attempts"] == "1" and isolated[0].summary("caller")["held_usd"] == 0


def test_insufficient_deadline_never_launches_duplicate(monkeypatch):
    policy(monkeypatch, delay_ms=1000)
    calls = []
    response, _, admission = run(monkeypatch, lambda body, model, decision: (
        calls.append(model) or Response(json.dumps(envelope()), content_type="application/json")))
    assert calls == [MODELS[0]] and not admission.calls and response.status_code == 200


def test_caps_that_only_fit_original_keep_single_path(monkeypatch, isolated):
    def prepare():
        g.authenticated_user["daily_budget_usd"] = 0.12
    calls = []
    response, _, admission = run(monkeypatch, lambda body, model, decision: (
        calls.append(model) or Response(json.dumps(envelope()), content_type="application/json")), prepare=prepare)
    assert response.status_code == 200 and calls == [MODELS[0]] and not admission.calls


def test_managed_submission_guard_blocks_retry_and_additional_send(monkeypatch):
    managed = importlib.import_module("services.managed_dispatch")
    from services.upstream_outcome import classify_upstream_outcome
    calls = []
    def send(body, model, decision):
        def upstream():
            calls.append(model)
            result = requests.Response()
            result.status_code = 503
            result._content = b'{"error":{}}'
            return result
        managed.execute_managed_attempt(upstream, model, "synthetic-credential")
        assert managed.retry_managed_attempt(lambda number: pytest.fail("extra retry"),
            lambda: classify_upstream_outcome(429), retry_count=0, max_retries=2, retry_delay=0) is None
        with pytest.raises(routes.APIError):
            managed.execute_managed_attempt(upstream, model, "synthetic-credential")
        return Response('{"error":{}}', status=503, content_type="application/json")
    run(monkeypatch, send)
    assert calls == list(MODELS[:2])


def test_lazy_nonstreaming_json_is_validated_before_winning(monkeypatch, isolated):
    def send(body, model, decision):
        return Response(iter([json.dumps(envelope()).encode()]), content_type="application/json")
    response, _, admission = run(monkeypatch, send)
    assert response.status_code == 200 and response.get_json() == envelope() and not admission.calls
    assert isolated[0].summary("caller")["spent_today_usd"] == pytest.approx(0.03)


def test_deadline_cancels_both_attempts_and_retains_both_holds(monkeypatch, isolated):
    calls, closes = [], []
    from services.generation_deadline import Deadline, GenerationDeadlineExceeded
    from services.request_cancellation import bind_cancellation
    def send(body, model, decision):
        calls.append(model)
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = b""
        owner = bind_cancellation(upstream, close_owner=lambda: closes.append(model))
        while not owner.closed:
            time.sleep(0.001)
        raise requests.ReadTimeout("synthetic deadline")
    with pytest.raises(GenerationDeadlineExceeded):
        run(monkeypatch, send, prepare=lambda: setattr(g, "generation_deadline", Deadline(time.monotonic() + 0.04)))
    assert calls == list(MODELS[:2]) and sorted(closes) == sorted(MODELS[:2])
    assert isolated[0].summary("caller")["unknown"] == 2
    assert not any(thread.name.startswith("hedged-auto-") for thread in threading.enumerate())


def test_request_disconnect_cancels_both_without_retry(monkeypatch, isolated):
    from services.request_cancellation import bind_cancellation
    owner = []
    timer = []
    calls = []
    def prepare():
        from services.request_cancellation import RequestCancellation
        g.gateway_cancellation = RequestCancellation()
        owner.append(g.gateway_cancellation)
    def send(body, model, decision):
        calls.append(model)
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = b""
        context = bind_cancellation(upstream, close_owner=lambda: None)
        if model == MODELS[1]:
            timer.append(threading.Timer(0.005, owner[0].cancel))
            timer[0].start()
        while not context.closed:
            time.sleep(0.001)
        raise requests.ReadTimeout("synthetic disconnect")
    try:
        with pytest.raises(routes.APIError) as raised:
            run(monkeypatch, send, prepare=prepare)
        assert raised.value.status_code == 499
    finally:
        for clock in timer:
            clock.join()
    assert calls == list(MODELS[:2]) and isolated[0].summary("caller")["unknown"] == 2


def test_no_key_and_no_policy_never_race(monkeypatch):
    calls = []
    response, _, admission = run(monkeypatch, lambda body, model, decision: (
        calls.append(model) or Response(json.dumps(envelope()), content_type="application/json")), headers={"Idempotency-Key": ""})
    assert response.status_code == 200 and calls == [MODELS[0]] and not admission.calls


def test_primary_can_win_after_second_starts_and_close_second_once(monkeypatch, isolated):
    from services.request_cancellation import bind_cancellation
    started = threading.Event()
    closes = []
    def send(body, model, decision):
        if model == MODELS[0]:
            assert started.wait(0.5)
            return Response(json.dumps(envelope()), content_type="application/json")
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = b""
        owner = bind_cancellation(upstream, close_owner=lambda: closes.append(model))
        started.set()
        while not owner.closed:
            time.sleep(0.001)
        raise requests.ReadTimeout("synthetic cancellation")
    response, _, admission = run(monkeypatch, send)
    assert response.headers["X-MultiLLM-Auto-Selected-Model"] == MODELS[0] and closes == [MODELS[1]]
    assert admission.leases[0].releases == 1 and isolated[0].summary("caller")["unknown"] == 1


def test_bad_unrelated_route_disables_policy_and_duplicate_fields_are_rejected(monkeypatch):
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", json.dumps({"auto:hedge": {
        "enabled": True, "idempotent_safe": True}, "auto:other": {"unexpected": True}}))
    assert hedges.route_policy("auto:hedge") is None
    monkeypatch.setenv("HEDGED_REQUESTS_POLICY_JSON", '{"auto:hedge":{"enabled":true,"enabled":false}}')
    assert hedges.route_policy("auto:hedge") is None


def test_large_lazy_body_is_rejected_with_unknown_hold(monkeypatch, isolated):
    def send(body, model, decision):
        return Response(iter([b"x" * (1024 * 1024 + 1)]), content_type="application/json")
    with pytest.raises(routes.APIError) as raised:
        run(monkeypatch, send)
    assert raised.value.status_code == 502 and isolated[0].summary("caller")["unknown"] == 2


def test_primary_completion_during_admission_prevents_late_duplicate(monkeypatch, isolated):
    primary = threading.Event()
    class SlowAdmission(Admission):
        def acquire(self, identity, *, on_lost=None):
            lease = super().acquire(identity, on_lost=on_lost)
            primary.set()
            time.sleep(0.02)
            return lease
    calls = []
    def send(body, model, decision):
        calls.append(model)
        assert primary.wait(0.5)
        return Response(json.dumps(envelope()), content_type="application/json")
    response, _, admission = run(monkeypatch, send, admission=SlowAdmission())
    assert calls == [MODELS[0]] and response.status_code == 200 and admission.leases[0].releases == 1
    assert isolated[0].summary("caller")["held_usd"] == 0


def test_delay_begins_at_provider_submission_after_managed_preparation(monkeypatch):
    from services.managed_turn import ManagedTurn, _turn
    from services.request_cancellation import bind_cancellation
    managed = importlib.import_module("services.managed_dispatch")
    submitted = []
    def send(body, model, decision):
        if model == MODELS[0]:
            time.sleep(0.035)
        def upstream():
            submitted.append((model, time.monotonic()))
            response = requests.Response()
            response.status_code = 200
            response._content = json.dumps(envelope()).encode()
            if model == MODELS[0]:
                owner = bind_cancellation(response, close_owner=lambda: None)
                while not owner.closed:
                    time.sleep(0.001)
                raise requests.ReadTimeout("synthetic cancelled generation")
            return response
        raw = managed.execute_managed_attempt(upstream, model, "synthetic-credential")
        return Response(raw.content, content_type="application/json")
    token = _turn.set(ManagedTurn("chat"))
    try:
        response, _, _ = run(monkeypatch, send)
    finally:
        _turn.reset(token)
    assert response.status_code == 200 and [model for model, at in submitted] == list(MODELS[:2])
    assert submitted[1][1] - submitted[0][1] >= 0.015


def test_durable_dispatch_failure_stops_before_submission_and_releases_holds(monkeypatch, isolated):
    calls = []
    def unavailable(reservation):
        raise reservations.ReservationError()
    monkeypatch.setattr(budget.BudgetService, "mark_dispatched", unavailable)
    with pytest.raises(routes.APIError) as raised:
        run(monkeypatch, lambda *args: calls.append(args))
    assert raised.value.status_code == 503 and not calls
    assert isolated[0].summary("caller")["held_usd"] == 0
    assert not any(thread.name.startswith("hedged-auto-") for thread in threading.enumerate())


def test_durable_hold_read_failure_is_controlled_before_dispatch(monkeypatch, isolated):
    calls = []
    def prepare():
        def unavailable(identity):
            raise reservations.ReservationError()
        monkeypatch.setattr(isolated[0], "get", unavailable)
    with pytest.raises(routes.APIError) as raised:
        run(monkeypatch, lambda *args: calls.append(args), prepare=prepare)
    assert raised.value.status_code == 503 and not calls


from tests.unified_api_test_case import UnifiedApiTestCase


class RegisteredHedgeTests(UnifiedApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()
        from services.auto_route_service import AutoRouteService
        from services.idempotency_store import IdempotencyStore
        from tests.test_managed_idempotency import Authority
        self.authority = Authority()
        self.app.extensions["managed_idempotency_store"] = IdempotencyStore(self.authority)
        self.app.extensions["admission_client"] = Admission()
        self.app.extensions["gateway_after_authentication"].append(lambda: g.authenticated_user.update(USER))
        self.models = ("mimo:mimo-v2.5", "opencode:glm-5.2", "mimo:mimo-v2.5-pro")
        AutoRouteService.save_route("auto:hedge", list(self.models), self.app.config["API_BASE_URLS"])
        os.environ["MODEL_PRICING_USD_PER_MILLION"] = json.dumps(
            {model: {"input": 1000, "output": 1000} for model in self.models})
        os.environ["CONTEXT_CACHE_SHARED_ENABLED"] = "false"
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = False
        self.headers = {"Authorization": "Bearer admin-test-key", "Idempotency-Key": "registered"}

    def test_registered_two_attempts_account_and_replay_without_new_dispatch(self):
        from services.request_cancellation import bind_cancellation
        sent, closes = [], []
        def send(**kwargs):
            sent.append(kwargs["api_provider"])
            response = requests.Response()
            response.status_code = 200
            response.headers["Content-Type"] = "application/json"
            if kwargs["api_provider"] == "mimo":
                response._content = b""
                owner = bind_cancellation(response, close_owner=lambda: closes.append("mimo"))
                while not owner.closed:
                    time.sleep(0.001)
                raise requests.ReadTimeout("synthetic interrupted loser")
            response._content = json.dumps(envelope()).encode()
            return response
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=send):
            first = self.client.post("/v1/chat/completions", json=PAYLOAD, headers=self.headers)
            replay = self.client.post("/v1/chat/completions", json=PAYLOAD, headers=self.headers)
        assert first.status_code == replay.status_code == 200
        assert first.data == replay.data and replay.headers["X-MultiLLM-Idempotency"] == "replayed"
        assert first.headers["X-MultiLLM-Auto-Selected-Model"] == self.models[1]
        assert first.headers["X-MultiLLM-Auto-Attempts"] == "2" and sent == ["mimo", "opencode"]
        assert closes == ["mimo"]
        summary = reservations.get_store().summary("caller")
        assert summary["unknown"] == 1 and summary["spent_today_usd"] == pytest.approx(0.03)

    def test_registered_ambiguous_race_blocks_replay_and_third_candidate(self):
        def send(**kwargs):
            response = requests.Response()
            response.status_code = 503
            response.headers["Content-Type"] = "application/json"
            response._content = b'{"error":{"code":"interrupted"}}'
            return response
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=send) as upstream:
            first = self.client.post("/v1/chat/completions", json=PAYLOAD, headers=self.headers)
            retry = self.client.post("/v1/chat/completions", json=PAYLOAD, headers=self.headers)
        assert first.status_code == 503 and retry.status_code == 409 and upstream.call_count == 2
        assert reservations.get_store().summary("caller")["unknown"] == 2
