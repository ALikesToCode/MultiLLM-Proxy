"""Hosted continuation through registered routes with synthetic storage and transports."""
import copy
import importlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from services import responses_state as state
from tests.unified_api_test_case import UnifiedApiTestCase


BODY = {"id": "resp_provider", "object": "response", "status": "completed", "model": "grok-4.6",
        "output": [{"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "lookup",
                    "arguments": '{"q":"one"}', "status": "completed"}],
        "usage": {"input_tokens": 4, "output_tokens": 2}}


class Authority:
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.fail = None

    def __call__(self, body):
        self.calls.append(copy.deepcopy(body))
        operation = body["operation"]
        if operation == self.fail:
            raise OSError("private storage detail")
        if operation == "probe":
            result = {"ready": True}
        else:
            key = (body["owner"], body["id"])
            if operation == "get":
                row = self.rows.get(key)
                result = {"state": copy.deepcopy(row) if row and row["expires_at"] > state.now() and row.get("status") != "failed" else None}
            elif operation == "delete":
                row = self.rows.pop(key, None)
                result = {"deleted": bool(row and row["expires_at"] > state.now())}
            elif operation == "fail":
                row = self.rows.get(key)
                if row:
                    row["status"] = "failed"
                result = {"failed": row is not None}
            else:
                self.rows.setdefault(key, {name: copy.deepcopy(body[name]) for name in
                    ("id", "owner", "provider", "model", "parent_id", "policy_revision", "depth", "document")})
                self.rows[key]["expires_at"] = state.now() + state.TTL_SECONDS
                result = {"stored": True}
        return {"version": 1, "result": result}


@pytest.fixture
def gateway(monkeypatch):
    for name in ("HOSTED_RESPONSES_ENABLED", "CONTENT_RETENTION_ENABLED", "MANAGED_IDEMPOTENCY_ENABLED",
                 "ADMISSION_ENABLED", "CONFIG_REVISION_SYNC_ENABLED", "USAGE_RESERVATIONS_ENABLED",
                 "PROTOCOL_EXTRAS_ENABLED", "SESSION_TIERS_ENABLED", "PROMPT_CACHE_AFFINITY_ENABLED"):
        monkeypatch.setenv(name, "false")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("NANOGPT_API_KEY", "")
    with patch("config.load_runtime_env"), patch("requests.sessions.Session.request", side_effect=AssertionError("live HTTP forbidden")):
        fixture = UnifiedApiTestCase()
        fixture.setUp()
        authority = Authority()
        fixture.app.extensions["responses_state_store"] = state.ResponsesStateStore(authority)
        fixture.authority = authority
        fixture.headers = {"Authorization": "Bearer admin-test-key", "X-Request-ID": "responses-state-test"}
        fixture.route = importlib.import_module("routes.unified")
        try:
            yield fixture
        finally:
            fixture.tearDown()


def upstream(body=BODY, status=200):
    import requests
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    return response


def post(gateway, monkeypatch, changes=None, result=BODY, *, enabled=True):
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true" if enabled else "false")
    body = {"model": "opencode:grok-4.6", "input": "one", "store": True, "gateway_state": True, **(changes or {})}
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=upstream(result)) as send:
        response = gateway.client.post("/v1/responses", json=body, headers=gateway.headers)
        response.get_data()
    return response, send


@pytest.mark.parametrize("flag", ["false", "", "off", "malformed"])
def test_disabled_post_preserves_provider_bytes_options_headers_and_storage(gateway, monkeypatch, flag):
    monkeypatch.setattr(gateway.route.time, "perf_counter", lambda: 1000)
    monkeypatch.setattr(gateway.route.time, "time", lambda: 1000)
    hooks = gateway.app.extensions["gateway_after_authentication"]
    from routes.responses_state import responses_state_hook, finish_hosted_response
    hook_index = hooks.index(responses_state_hook)
    hooks.remove(responses_state_hook)
    finalizers = gateway.app.after_request_funcs[None]
    finalizer_index = finalizers.index(finish_hosted_response)
    finalizers.remove(finish_hosted_response)
    body = {"model": "opencode:grok-4.6", "input": "one", "store": True,
            "gateway_state": True, "previous_response_id": "resp_native"}
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=upstream()):
        baseline = gateway.client.post("/v1/responses", json=body, headers=gateway.headers)
        baseline.get_data()
    hooks.insert(hook_index, responses_state_hook)
    finalizers.insert(finalizer_index, finish_hosted_response)
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", flag)
    body = {"model": "opencode:grok-4.6", "input": "one", "store": True,
            "gateway_state": True, "previous_response_id": "resp_native"}
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=upstream()) as send:
        response = gateway.client.post("/v1/responses", json=body, headers=gateway.headers)
    assert response.status_code == 200 and response.data == json.dumps(BODY).encode()
    sent = json.loads(send.call_args.kwargs["data"])
    assert sent == {**body, "model": "grok-4.6"}
    assert gateway.authority.calls == []
    assert response.data == baseline.data
    assert list(response.headers) == list(baseline.headers)


def test_invalid_flag_warns_once_without_value(monkeypatch, caplog):
    state._warn_invalid_flag.cache_clear()
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "private-invalid-value")
    assert not state.enabled() and not state.enabled()
    assert caplog.text.count("Invalid HOSTED_RESPONSES_ENABLED") == 1
    assert "private-invalid-value" not in caplog.text


def test_enabled_without_opt_in_and_native_parent_are_unchanged(gateway, monkeypatch):
    response, send = post(gateway, monkeypatch, {"gateway_state": False, "previous_response_id": "resp_native"})
    assert response.data == json.dumps(BODY).encode() and response.status_code == 200
    assert json.loads(send.call_args.kwargs["data"])["previous_response_id"] == "resp_native"
    assert gateway.authority.calls == []


def test_store_get_continue_preserve_tool_item_order_and_metadata(gateway, monkeypatch):
    first, send = post(gateway, monkeypatch)
    assert first.status_code == 200 and first.json["id"].startswith(state.ID_PREFIX)
    payload = json.loads(send.call_args.kwargs["data"])
    assert "gateway_state" not in payload and payload["store"] is False
    response_id = first.json["id"]
    stored = gateway.client.get(f"/v1/responses/{response_id}", headers=gateway.headers)
    assert stored.json == first.json and stored.headers["Cache-Control"] == "no-store"
    tool_result = {"type": "function_call_output", "call_id": "call_1", "output": "answer"}
    second, send = post(gateway, monkeypatch, {"previous_response_id": response_id, "input": [tool_result]})
    sent = json.loads(send.call_args.kwargs["data"])
    assert sent["input"] == [{"role": "user", "content": "one"}, *BODY["output"], tool_result]
    assert "previous_response_id" not in sent
    record = next(row for row in gateway.authority.rows.values() if row["id"] == second.json["id"])
    assert record["depth"] == 2 and record["parent_id"] == response_id
    assert record["provider"] == "opencode" and record["policy_revision"]


@pytest.mark.parametrize("kind", ["absent", "foreign", "expired"])
def test_absent_foreign_expired_parent_404_without_provider(gateway, monkeypatch, kind):
    first, _ = post(gateway, monkeypatch)
    response_id = first.json["id"]
    if kind == "absent":
        response_id = state.ID_PREFIX + "f" * 32
    else:
        row = next(iter(gateway.authority.rows.values()))
        if kind == "foreign":
            old = next(iter(gateway.authority.rows))
            gateway.authority.rows[("b" * 64, old[1])] = gateway.authority.rows.pop(old)
        else:
            row["expires_at"] = 0
    response, send = post(gateway, monkeypatch, {"previous_response_id": response_id})
    assert response.status_code == 404 and response.json["error"]["code"] == "response_not_found"
    assert send.call_count == 0
    assert gateway.client.get(f"/v1/responses/{response_id}", headers=gateway.headers).status_code == 404
    assert gateway.client.delete(f"/v1/responses/{response_id}", headers=gateway.headers).status_code == 404


def test_explicit_delete_removes_state_without_dispatch(gateway, monkeypatch):
    first, _ = post(gateway, monkeypatch)
    response_id = first.json["id"]
    response = gateway.client.delete(f"/v1/responses/{response_id}", headers=gateway.headers)
    assert response.status_code == 200 and response.json["deleted"] is True
    assert gateway.authority.rows == {}
    assert gateway.client.get(f"/v1/responses/{response_id}", headers=gateway.headers).status_code == 404


def test_disabled_get_delete_match_existing_routing_bytes(gateway, monkeypatch):
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "false")
    monkeypatch.setattr(gateway.route.time, "perf_counter", lambda: 1000)
    for method in (gateway.client.get, gateway.client.delete):
        existing = method("/v1/responses/absent/route", headers=gateway.headers)
        hosted = method("/v1/responses/" + state.ID_PREFIX + "a" * 32, headers=gateway.headers)
        assert hosted.status_code == existing.status_code == 400
        assert hosted.data == existing.data and list(hosted.headers) == list(existing.headers)
    assert gateway.authority.calls == []


@pytest.mark.parametrize("changes", [{"gateway_state": True}, {"gateway_state": False, "previous_response_id": state.ID_PREFIX + "a" * 32}])
def test_zero_retention_refuses_before_storage_and_provider(gateway, monkeypatch, changes):
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", '{"default":"zero"}')
    response, send = post(gateway, monkeypatch, changes)
    assert response.status_code == 400 and response.json["error"]["code"] == "retention_conflict"
    assert send.call_count == 0 and gateway.authority.calls == []


@pytest.mark.parametrize("failure", ["probe", "put"])
def test_storage_failure_is_visible_and_never_retried(gateway, monkeypatch, failure):
    gateway.authority.fail = failure
    response, send = post(gateway, monkeypatch)
    assert response.status_code == 503 and response.json["error"]["code"] == "responses_store_unavailable"
    assert send.call_count == (0 if failure == "probe" else 1)
    assert gateway.authority.rows == {} and b"private storage detail" not in response.data


@pytest.mark.parametrize("status", ["failed", "incomplete", "cancelled", "in_progress", None])
def test_nonterminal_and_failed_outcomes_store_nothing(gateway, monkeypatch, status):
    response, send = post(gateway, monkeypatch, result={**BODY, "status": status})
    assert send.call_count == 1 and gateway.authority.rows == {}
    assert response.status_code == 200


def test_chain_depth_and_input_size_fail_before_provider(gateway, monkeypatch):
    first, _ = post(gateway, monkeypatch)
    next(iter(gateway.authority.rows.values()))["depth"] = 16
    for changes, code in [({"previous_response_id": first.json["id"]}, "response_chain_limit"),
                          ({"input": "x" * state.MAX_STATE_BYTES}, "response_state_too_large")]:
        response, send = post(gateway, monkeypatch, changes)
        assert response.status_code == 400 and response.json["error"]["code"] == code and send.call_count == 0


def test_oversized_completed_output_has_no_replayable_body(gateway, monkeypatch):
    result = {**BODY, "output": [{"type": "message", "role": "assistant", "content": "x" * state.MAX_STATE_BYTES}]}
    response, send = post(gateway, monkeypatch, result=result)
    assert response.status_code == 502 and response.json["error"]["code"] == "response_state_too_large"
    assert send.call_count == 1 and gateway.authority.rows == {}


def test_translated_chat_completion_can_continue(gateway, monkeypatch):
    result = {"id": "chatcmpl-one", "choices": [{"message": {"role": "assistant", "content": "answer"}, "finish_reason": "stop"}]}
    response, _ = post(gateway, monkeypatch, {"model": "opencode:kimi-k2.6"}, result)
    assert response.status_code == 200 and response.json["id"].startswith(state.ID_PREFIX)
    continued, send = post(gateway, monkeypatch, {"model": "opencode:kimi-k2.6", "previous_response_id": response.json["id"], "input": "two"}, result)
    assert continued.status_code == 200
    assert [item["role"] for item in json.loads(send.call_args.kwargs["data"])["messages"]] == ["user", "assistant", "user"]


@pytest.mark.parametrize("terminal", ["completed", "incomplete", "missing"])
def test_stream_persists_only_completed_terminal_after_accounting(gateway, monkeypatch, terminal):
    import io
    import requests
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
    response = requests.Response()
    response.status_code = 200
    frames = 'event: response.created\ndata: ' + json.dumps({"type": "response.created", "response": {**BODY, "status": "in_progress"}}) + '\n\n'
    if terminal != "missing":
        frames += f'event: response.{terminal}\ndata: ' + json.dumps({"type": f"response.{terminal}", "response": {**BODY, "status": terminal}}) + '\n\n'
    response.raw = io.BytesIO(frames.encode())
    response.headers["Content-Type"] = "text/event-stream"
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=response) as send:
        streamed = gateway.client.post("/v1/responses", json={"model": "opencode:grok-4.6", "input": "one", "gateway_state": True, "store": True, "stream": True}, headers=gateway.headers, buffered=False)
        assert gateway.authority.rows == {}
        data = streamed.get_data(as_text=True)
    assert send.call_count == 1
    assert (len(gateway.authority.rows) == 1) == (terminal == "completed")
    assert "resp_provider" not in data and state.ID_PREFIX in data


def test_migration_is_additive_and_reentrant():
    db = sqlite3.connect(":memory:")
    db.executescript("CREATE TABLE old_rows (n INTEGER); INSERT INTO old_rows VALUES (7)")
    migration = Path("intelligence-migrations/0028_responses_state.sql").read_text()
    db.executescript(migration)
    db.executescript(migration)
    assert db.execute("SELECT n FROM old_rows").fetchone() == (7,)
    assert db.execute("SELECT count(*) FROM hosted_responses").fetchone() == (0,)
    db.close()


class IdempotencyAuthority:
    def __init__(self):
        self.rows, self.calls, self.lock = {}, [], threading.Lock()

    def __call__(self, body):
        with self.lock:
            self.calls.append(body["operation"])
            row = self.rows.get(body["scope"])
            if body["operation"] == "claim":
                if row is None:
                    row = {"digest": body["digest"], "owner": body["owner"], "status": "pending"}
                    self.rows[body["scope"]] = row
                    result = {"status": "claimed"}
                elif row["digest"] != body["digest"]:
                    result = {"status": "conflict"}
                elif row["status"] == "completed":
                    result = {"status": "completed", "response": row["response"]}
                else:
                    result = {"status": row["status"]}
            else:
                changed = bool(row and row["owner"] == body["owner"] and row["status"] == "pending")
                if changed and body["operation"] != "handoff":
                    row["status"] = "completed" if body["operation"] == "complete" else "unknown"
                    if row["status"] == "completed":
                        row["response"] = body["response"]
                result = {"changed": changed}
            return {"version": 1, "result": result}


@pytest.mark.parametrize("complete", [True, False])
def test_keyed_completion_replays_gateway_id_and_unknown_never_resubmits(gateway, monkeypatch, complete):
    store = importlib.import_module("services.idempotency_store")
    authority = IdempotencyAuthority()
    gateway.app.extensions["managed_idempotency_store"] = store.IdempotencyStore(authority)
    monkeypatch.setenv("MANAGED_IDEMPOTENCY_ENABLED", "true")
    gateway.headers["Idempotency-Key"] = "responses-key"
    result = BODY if complete else {**BODY, "status": "incomplete"}
    first, send = post(gateway, monkeypatch, result=result)
    assert send.call_count == 1
    second, send = post(gateway, monkeypatch, result=result)
    assert send.call_count == 0
    if complete:
        assert second.status_code == 200 and second.data == first.data
        assert second.headers["X-MultiLLM-Idempotency"] == "replayed"
        assert len(gateway.authority.rows) == 1
        assert authority.calls == ["claim", "handoff", "complete", "claim"]
    else:
        assert second.status_code == 409 and second.json["error"]["code"] == "outcome_unknown"
        assert not gateway.authority.rows


def test_concurrent_duplicate_claim_permits_one_generation(gateway, monkeypatch):
    store = importlib.import_module("services.idempotency_store")
    gateway.app.extensions["managed_idempotency_store"] = store.IdempotencyStore(IdempotencyAuthority())
    monkeypatch.setenv("MANAGED_IDEMPOTENCY_ENABLED", "true")
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
    body = {"model": "opencode:grok-4.6", "input": "one", "store": True, "gateway_state": True}
    started, release = threading.Event(), threading.Event()

    def provider(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return upstream()

    def request_response():
        with gateway.app.test_client() as client:
            response = client.post("/v1/responses", json=body,
                                   headers={**gateway.headers, "Idempotency-Key": "concurrent-key"})
            response.get_data()
            return response

    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(request_response)
            try:
                assert started.wait(5)
                second = pool.submit(request_response).result(timeout=5)
                assert second.status_code == 409 and second.json["error"]["code"] == "request_in_progress"
            finally:
                release.set()
            assert first.result(timeout=5).status_code == 200
    assert send.call_count == 1 and len(gateway.authority.rows) == 1


def test_gateway_parent_without_storage_opt_in_runs_ephemeral(gateway, monkeypatch):
    first, _ = post(gateway, monkeypatch)
    response, send = post(gateway, monkeypatch, {"gateway_state": False, "store": False,
                                               "previous_response_id": first.json["id"], "input": "two"})
    assert response.json == BODY and response.status_code == 200
    payload = json.loads(send.call_args.kwargs["data"])
    assert payload["input"] == [{"role": "user", "content": "one"}, *BODY["output"], {"role": "user", "content": "two"}]
    assert "gateway_state" not in payload and "previous_response_id" not in payload
    assert len(gateway.authority.rows) == 1


def test_parallel_tool_calls_and_results_keep_exact_boundaries(gateway, monkeypatch):
    calls = [BODY["output"][0], {**BODY["output"][0], "call_id": "call_2", "id": "fc_2"}]
    first, _ = post(gateway, monkeypatch, result={**BODY, "output": calls})
    results = [{"type": "function_call_output", "call_id": "call_2", "output": "second"},
               {"type": "function_call_output", "call_id": "call_1", "output": "first"}]
    _, send = post(gateway, monkeypatch, {"previous_response_id": first.json["id"], "input": results})
    assert json.loads(send.call_args.kwargs["data"])["input"] == [{"role": "user", "content": "one"}, *calls, *results]


def test_missing_private_backend_is_503_before_provider(gateway, monkeypatch):
    gateway.app.extensions["responses_state_store"] = state.ResponsesStateStore()
    response, send = post(gateway, monkeypatch)
    assert response.status_code == 503 and send.call_count == 0


@pytest.mark.parametrize("failure", ["cancel", "ambiguous", "deadline"])
def test_lost_or_ambiguous_outcome_is_not_stored(gateway, monkeypatch, failure):
    from flask import g
    deadline_module = importlib.import_module("services.generation_deadline")

    def provider(*args, **kwargs):
        if failure == "ambiguous":
            g.usage_context.ambiguous = True
        elif failure == "cancel":
            g.gateway_cancellation = SimpleNamespace(lost=True, contexts=[])
        else:
            g.generation_deadline = deadline_module.Deadline(0, clock=lambda: 1)
        return upstream()

    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send:
        monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
        response = gateway.client.post("/v1/responses", json={"model": "opencode:grok-4.6", "input": "one",
                                      "gateway_state": True, "store": True}, headers=gateway.headers)
        response.get_data()
    assert send.call_count == 1 and not gateway.authority.rows


def test_unknown_usage_is_recorded_before_success_is_stored(gateway, monkeypatch):
    accounting = importlib.import_module("services.request_accounting")
    observed = []
    original = accounting._record

    def record(context, status, usage, units):
        observed.append(usage)
        return original(context, status, usage, units)

    monkeypatch.setattr(accounting, "_record", record)
    response, _ = post(gateway, monkeypatch, result={**BODY, "usage": None})
    assert response.status_code == 200 and observed == [None]
    assert len(gateway.authority.rows) == 1


def test_storage_ack_after_deadline_is_not_replayable(gateway, monkeypatch):
    from flask import g
    deadline_module = importlib.import_module("services.generation_deadline")
    clock = [0.0]
    authority = gateway.authority

    def late(body):
        result = authority(body)
        if body["operation"] == "put":
            clock[0] = 2
        return result

    gateway.app.extensions["responses_state_store"] = state.ResponsesStateStore(late)
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")

    def provider(*args, **kwargs):
        g.generation_deadline = deadline_module.Deadline(1, clock=lambda: clock[0])
        return upstream({"id": "chatcmpl-deadline", "choices": [{"message": {"role": "assistant", "content": "answer"},
                         "finish_reason": "stop"}], "usage": BODY["usage"]})

    with patch.object(gateway.app_module.ProxyService, "make_request", side_effect=provider) as send:
        response = gateway.client.post("/v1/responses", json={"model": "opencode:kimi-k2.6", "input": "one",
                                      "gateway_state": True, "store": True}, headers=gateway.headers)
    assert response.status_code == 504 and send.call_count == 1
    assert next(iter(authority.rows.values()))["status"] == "failed"
    assert [body["operation"] for body in authority.calls] == ["probe", "put", "fail"]


def stream_response(chunks):
    response = upstream()
    response.raw = SimpleNamespace(close=lambda: None)
    response.headers["Content-Type"] = "text/event-stream"
    response.iter_content = lambda *args, **kwargs: iter(chunks)
    return response


def sse_event(name, body):
    return ("event: " + name + "\ndata: " + json.dumps({"type": name, "response": body}) + "\n\n").encode()


@pytest.mark.parametrize("failure", ["disconnect", "after_terminal", "done_in_content", "missing_body", "duplicate_terminal", "storage"])
def test_interrupted_or_uncommitted_stream_never_exposes_completed_event(gateway, monkeypatch, failure):
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
    created = sse_event("response.created", {**BODY, "status": "in_progress"})
    completed = sse_event("response.completed", BODY)

    def chunks():
        yield created
        yield sse_event("response.completed", None) if failure == "missing_body" else completed
        if failure == "disconnect":
            raise OSError("private transport detail")
        if failure == "after_terminal":
            yield created
        if failure == "done_in_content":
            yield sse_event("response.output_text.delta", {"text": "[DONE]"})
        if failure == "duplicate_terminal":
            yield completed

    if failure == "storage":
        gateway.authority.fail = "put"
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=stream_response(chunks())) as send:
        response = gateway.client.post("/v1/responses", json={"model": "opencode:grok-4.6", "input": "one",
            "gateway_state": True, "store": True, "stream": True}, headers=gateway.headers, buffered=False)
        data = response.get_data()
    assert send.call_count == 1 and not gateway.authority.rows
    assert b"event: error" in data and b"event: response.completed" not in data
    assert b"private transport detail" not in data


def test_client_stream_abort_before_terminal_stores_nothing(gateway, monkeypatch):
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
    chunks = [sse_event("response.created", {**BODY, "status": "in_progress"}), sse_event("response.completed", BODY)]
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=stream_response(chunks)) as send:
        response = gateway.client.post("/v1/responses", json={"model": "opencode:grok-4.6", "input": "one",
            "gateway_state": True, "store": True, "stream": True}, headers=gateway.headers, buffered=False)
        next(iter(response.response))
        response.close()
    assert send.call_count == 1 and not gateway.authority.rows


def test_fragmented_crlf_stream_preserves_completed_tool_envelope(gateway, monkeypatch):
    monkeypatch.setenv("HOSTED_RESPONSES_ENABLED", "true")
    framed = (sse_event("response.created", {**BODY, "status": "in_progress"}) + sse_event("response.completed", BODY)).replace(b"\n", b"\r\n")
    chunks = [framed[index:index + 7] for index in range(0, len(framed), 7)]
    with patch.object(gateway.app_module.ProxyService, "make_request", return_value=stream_response(chunks)):
        response = gateway.client.post("/v1/responses", json={"model": "opencode:grok-4.6", "input": "one",
            "gateway_state": True, "store": True, "stream": True}, headers=gateway.headers, buffered=False)
        data = response.get_data()
    assert data.count(b"event: response.completed") == 1
    assert next(iter(gateway.authority.rows.values()))["document"]["response"]["output"] == BODY["output"]


@pytest.mark.parametrize("changes", [{"input": [{"role": "user", "content": float("nan")}]}, {"store": False}])
def test_invalid_hosted_request_is_400_without_dispatch(gateway, monkeypatch, changes):
    response, send = post(gateway, monkeypatch, changes)
    assert response.status_code == 400 and response.json["error"]["code"] == "invalid_request"
    assert send.call_count == 0 and gateway.authority.calls == []
