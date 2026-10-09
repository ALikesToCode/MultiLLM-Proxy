"""Managed generation contracts through registered Flask routes and injected authority."""
import base64
import importlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
from flask import Flask, Response, g

from services import idempotency_store as store_module
from middleware import idempotency as middleware
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream

MIGRATION = Path("intelligence-migrations/0023_idempotency.sql")


class Authority:
    def __init__(self):
        self.rows = {}
        self.lock = threading.Lock()
        self.calls = []
        self.fail = None

    def __call__(self, body):
        with self.lock:
            self.calls.append(body)
            if self.fail == body["operation"]:
                raise requests.Timeout("private detail")
            scope, digest, owner = body["scope"], body["digest"], body["owner"]
            row = self.rows.get(scope)
            operation = body["operation"]
            if operation == "claim":
                if row is None:
                    self.rows[scope] = {"digest": digest, "owner": owner, "status": "pending"}
                    result = {"status": "claimed"}
                elif row["digest"] != digest:
                    result = {"status": "conflict"}
                elif row["status"] == "completed":
                    result = {"status": "completed", "response": row["response"]}
                else:
                    result = {"status": row["status"]}
            else:
                changed = row is not None and row["owner"] == owner and row["digest"] == digest and row["status"] == "pending"
                if changed and operation != "handoff":
                    row["status"] = "completed" if operation == "complete" else "unknown"
                    if operation == "complete":
                        row["response"] = body["response"]
                result = {"changed": changed}
            return {"version": 1, "result": result}


@pytest.fixture(autouse=True)
def pin_settings(monkeypatch):
    for name in ("MANAGED_IDEMPOTENCY_ENABLED", "CONTENT_RETENTION_POLICY_ENABLED", "ADMISSION_ENABLED", "CONFIG_REVISION_SYNC_ENABLED"):
        monkeypatch.setenv(name, "false")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("NANOGPT_API_KEY", "")


def test_registered_hook_claims_before_admission_and_dispatch():
    authority = Authority()
    app = Flask(__name__)
    middleware.register_idempotency(app, store=store_module.IdempotencyStore(authority), policy_revision=lambda body: "revision-1")
    observed = []
    app.extensions["gateway_after_authentication"].append(lambda: observed.append("admission"))
    @app.post("/v1/chat/completions")
    def managed():
        g.authenticated_user = {"username": "caller"}
        for hook in app.extensions["gateway_after_authentication"]:
            rejection = hook()
            if rejection is not None:
                return rejection
        return middleware.dispatch_with_idempotency(
            lambda: Response(b'{"choices":[1]}', content_type="application/json"),
            completed=lambda response: response.status_code == 200)
    with patch.dict("os.environ", {"MANAGED_IDEMPOTENCY_ENABLED": "true"}):
        with app.test_client() as client:
            first = client.post("/v1/chat/completions", json={"model": "auto:test"}, headers={"Idempotency-Key": "one"})
            second = client.post("/v1/chat/completions", json={"model": "auto:test"}, headers={"Idempotency-Key": "one"})
    assert first.status_code == second.status_code == 200
    assert first.data == second.data and second.headers["X-MultiLLM-Idempotency"] == "replayed"
    assert observed == ["admission"]
    assert [call["operation"] for call in authority.calls] == ["claim", "handoff", "complete", "claim"]


def test_migration_is_additive_and_preserves_existing_rows():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE old_usage (amount INTEGER)")
    db.execute("INSERT INTO old_usage VALUES (5)")
    db.executescript(MIGRATION.read_text())
    db.executescript(MIGRATION.read_text())
    assert db.execute("SELECT amount FROM old_usage").fetchone() == (5,)
    assert db.execute("SELECT count(*) FROM managed_idempotency").fetchone() == (0,)


@pytest.mark.parametrize("flag", ["", "false", "bad-value", "0", "off"])
def test_disabled_flag_and_malformed_warning_are_bounded(monkeypatch, caplog, flag):
    monkeypatch.setenv("MANAGED_IDEMPOTENCY_ENABLED", flag)
    assert not store_module.idempotency_enabled()
    assert not store_module.idempotency_enabled()
    assert "bad-value" not in caplog.text


@pytest.mark.parametrize("key", ["", "x" * 129, "has space", "newline\n", "ü"])
def test_invalid_key_is_rejected_without_storage(key):
    with pytest.raises(Exception) as raised:
        store_module.request_fingerprint("p", "POST", "/v1/chat/completions", key, {}, "r")
    assert raised.value.code == "invalid_idempotency_key"


def test_principal_path_body_and_revision_identity():
    fingerprint = store_module.request_fingerprint
    first = fingerprint("alice", "POST", "/a", "key", {"b": 1, "a": 2}, "r")
    assert first == fingerprint("alice", "POST", "/a", "key", {"a": 2, "b": 1}, "r")
    assert first[0] != fingerprint("bob", "POST", "/a", "key", {"b": 1, "a": 2}, "r")[0]
    assert first[0] != fingerprint("alice", "POST", "/b", "key", {"b": 1, "a": 2}, "r")[0]
    assert first[0] == fingerprint("alice", "POST", "/a", "key", {}, "r2")[0]
    assert first[1] != fingerprint("alice", "POST", "/a", "key", {"b": 1, "a": 2}, "r2")[1]


class ManagedIdempotencyTests(IntelligenceApiTestCase):
    def setUp(self):
        # The shared fixture must not load deployment environment files.
        with patch("config.load_runtime_env"):
            super().setUp()
        import os
        os.environ.update({"MANAGED_IDEMPOTENCY_ENABLED": "true", "INTELLIGENCE_STORAGE_BACKEND": "", "CONFIG_REVISION_SYNC_ENABLED": "false"})
        self.route = importlib.import_module("routes.intelligence")
        self.middleware = importlib.import_module("middleware.idempotency")
        self.authority = Authority()
        self.middleware.register_idempotency(self.app, store=store_module.IdempotencyStore(self.authority))
        self.headers["Idempotency-Key"] = "test-key"
        self.seed()

    def test_completed_replay_preserves_body_headers_and_only_one_provider_call(self):
        with self.requests(return_value=upstream(completion())) as send:
            first, replay = self.post(), self.post()
        assert first.status_code == replay.status_code == 200 and send.call_count == 1
        assert first.data == replay.data
        assert first.headers["Content-Type"] == replay.headers["Content-Type"]
        assert replay.headers["X-MultiLLM-Idempotency"] == "replayed"
        assert [call["operation"] for call in self.authority.calls] == ["claim", "handoff", "complete", "claim"]

    def test_body_model_and_policy_conflicts_do_not_dispatch(self):
        with self.requests(return_value=upstream(completion())) as send:
            assert self.post().status_code == 200
            for changes in ({"messages": [{"role": "user", "content": "changed"}]}, {"model": "openai:small", "routing": {}}):
                conflict = self.post(**changes)
                assert conflict.status_code == 422 and conflict.json["error"]["code"] == "idempotency_key_conflict"
            with patch.object(self.route, "load_policy", return_value={**self.route.load_policy(), "deadline_ms": 1000}):
                # The hook reads the same policy source as managed dispatch.
                conflict = self.post()
            assert conflict.status_code == 422 and send.call_count == 1

    def test_concurrent_submissions_have_one_provider_call(self):
        entered, release = threading.Event(), threading.Event()
        def generate(*args, **kwargs):
            entered.set()
            assert release.wait(3)
            return upstream(completion())
        def post():
            with self.app.test_client() as client:
                return client.post("/v1/chat/completions", headers=self.headers, json={"model": "auto:intelligence", "messages": [{"role": "user", "content": "test"}]})
        with self.requests(side_effect=generate) as send, ThreadPoolExecutor(max_workers=2) as executor:
            future = executor.submit(post)
            try:
                assert entered.wait(3)
                duplicate = post()
                assert duplicate.status_code == 409 and duplicate.json["error"]["code"] == "request_in_progress"
                assert duplicate.headers["Retry-After"] == "1"
            finally:
                release.set()
            assert future.result(3).status_code == 200
            assert send.call_count == 1

    def test_ambiguous_outcome_never_generates_again(self):
        with self.requests(side_effect=requests.Timeout("private detail")) as send:
            first, retry = self.post(), self.post()
        assert first.status_code == 502 and retry.status_code == 409 and send.call_count == 1
        assert retry.json["error"]["code"] == "outcome_unknown"
        assert "Retry-After" not in retry.headers and b"private detail" not in first.data

    def test_streaming_rejected_before_claim(self):
        with self.requests() as send:
            response = self.post(stream=True)
        assert response.status_code == 400 and response.json["error"]["code"] == "idempotency_stream_unsupported"
        assert self.authority.calls == [] and send.call_count == 0

    def test_missing_authority_fails_closed(self):
        self.authority.fail = "claim"
        with self.requests() as send:
            response = self.post()
        assert response.status_code == 503 and response.json["error"]["code"] == "idempotency_store_unavailable"
        assert send.call_count == 0

    def test_lost_handoff_ack_never_dispatches(self):
        from services.control_plane_backup import capture
        self.authority.fail = "handoff"
        with self.requests() as send:
            first, retry = self.post(), self.post()
        assert first.status_code == 503 and retry.status_code == 409 and send.call_count == 0
        assert [(row["state"], row["charged"]) for row in capture()["tables"]["intelligence_reservations"]] == [("settled", 0)]

    def test_lost_completion_or_oversized_body_blocks_retry(self):
        for failure in ("complete", None):
            self.authority.rows.clear()
            self.authority.fail = failure
            content = "ok" if failure else "x" * store_module.MAX_RESPONSE_BYTES
            with self.requests(return_value=upstream(completion(content))) as send:
                first, retry = self.post(), self.post()
            assert first.status_code == 200 and retry.status_code == 409 and send.call_count == 1
            assert retry.json["error"]["code"] == "outcome_unknown"

    def test_no_key_and_default_off_preserve_existing_contract(self):
        self.headers.pop("Idempotency-Key")
        with self.requests(return_value=upstream(completion())) as send:
            assert self.post().status_code == 200 and send.call_count == 1
        assert self.authority.calls == []
        self.headers["Idempotency-Key"] = "one"
        with patch.dict("os.environ", {"MANAGED_IDEMPOTENCY_ENABLED": "false"}), self.requests() as send:
            response = self.post()
        assert response.status_code == 400 and response.json["error"]["code"] == "idempotency_not_supported"
        assert send.call_count == 0 and self.authority.calls == []

    def test_raw_openai_header_filter_and_body_are_unchanged(self):
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post(model="openai:small")
        assert response.status_code == 200 and send.call_count == 1 and self.authority.calls == []
        assert "idempotency-key" not in {name.lower() for name in send.call_args.kwargs["headers"]}
        assert json.loads(send.call_args.kwargs["data"])["messages"] == [{"role": "user", "content": "test"}]

    def test_dedicated_route_replays_after_durable_handoff_before_provider(self):
        def generate(*args, **kwargs):
            assert [call["operation"] for call in self.authority.calls] == ["claim", "handoff"]
            return upstream(completion())
        with self.requests(side_effect=generate) as send:
            first = self.client.post("/intelligence/v1/chat/completions", headers=self.headers,
                                     json={"messages": [{"role": "user", "content": "test"}]})
            replay = self.client.post("/intelligence/v1/chat/completions", headers=self.headers,
                                      json={"messages": [{"role": "user", "content": "test"}]})
        assert first.status_code == replay.status_code == 200 and send.call_count == 1
        assert replay.data == first.data and replay.headers["X-MultiLLM-Idempotency"] == "replayed"

    def test_incomplete_success_body_never_becomes_a_replay(self):
        partial = completion()
        partial["choices"][0].pop("finish_reason")
        with self.requests(return_value=upstream(partial)) as send:
            first, retry = self.post(routing={"max_escalations": 0}), self.post(routing={"max_escalations": 0})
        assert first.status_code == 502 and retry.status_code == 409 and send.call_count == 1
        assert retry.json["error"]["code"] == "outcome_unknown"
        assert not any(call["operation"] == "complete" for call in self.authority.calls)

    def test_no_key_response_bytes_headers_and_provider_payload_match_flag_off(self):
        self.headers.pop("Idempotency-Key")
        with patch.object(self.route.time, "time", return_value=1000), patch.object(self.route.time, "perf_counter", return_value=1000), self.requests(side_effect=lambda **kwargs: upstream(completion())) as send:
            enabled = self.post()
            enabled_payload = send.call_args.kwargs["data"]
            with patch.dict("os.environ", {"MANAGED_IDEMPOTENCY_ENABLED": "false"}):
                disabled = self.post()
            disabled_payload = send.call_args.kwargs["data"]
        assert enabled.status_code == disabled.status_code == 200
        assert enabled.data == disabled.data and list(enabled.headers) == list(disabled.headers)
        assert enabled_payload == disabled_payload and self.authority.calls == []

    def test_unauthenticated_submission_never_claims(self):
        response = self.client.post("/v1/chat/completions", json={"model": "auto:intelligence"}, headers={"Idempotency-Key": "one"})
        assert response.status_code == 401 and self.authority.calls == []

    def test_retention_zero_stores_no_response(self):
        from services import retention_policy
        with patch.object(retention_policy, "request_policy", return_value=retention_policy.RetentionPolicy("zero", True, "r")), self.requests(return_value=upstream(completion())) as send:
            first, retry = self.post(), self.post()
        assert first.status_code == 200 and retry.status_code == 409 and send.call_count == 1
        assert not any("response" in call for call in self.authority.calls)


@pytest.mark.parametrize("document", [{"version": 1, "result": {"changed": 1}}, {"version": True, "result": {}}, {"version": 1, "result": {"status": "free_to_retry"}}, {"version": 1, "result": {"status": "claimed", "extra": "private"}}])
def test_malformed_authority_responses_never_authorize_dispatch(document):
    store = store_module.IdempotencyStore(lambda body: document)
    with pytest.raises(Exception) as raised:
        store.claim("a" * 64, "b" * 64)
    assert raised.value.code == "idempotency_store_unavailable"


def test_private_client_uses_fixed_no_retry_transport_and_accepts_full_response_bound(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    calls = []
    document = {"version": 1, "result": {"status": "completed", "response": {"status": 200,
        "headers": [["Content-Type", "application/json"]], "body": base64.b64encode(b"x" * store_module.MAX_RESPONSE_BYTES).decode()}}}
    class Reply:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def iter_content(self, chunk_size):
            yield json.dumps(document).encode()
    class Session:
        trust_env = True
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def mount(self, prefix, adapter):
            assert prefix == "http://" and adapter.max_retries.total == 0
        def post(self, url, **kwargs):
            calls.append((url, kwargs, self.trust_env))
            return Reply()
    monkeypatch.setattr(store_module.requests, "Session", Session)
    result = store_module.private_call({"version": 1, "operation": "claim"})
    assert result == document and len(calls) == 1
    url, options, trust_env = calls[0]
    assert url == store_module.PRIVATE_URL and not trust_env
    assert options["allow_redirects"] is False and options["stream"] is True and options["timeout"] == (2, 3)
    replay = store_module.decode_response(document["result"]["response"])
    assert len(replay.data) == store_module.MAX_RESPONSE_BYTES


def test_dispatch_wrapper_requires_explicit_completion_and_notifies_settlement():
    authority = Authority()
    notifications = []
    app = Flask(__name__)
    middleware.register_idempotency(app, store=store_module.IdempotencyStore(authority), policy_revision=lambda body: "r",
        settlement=lambda claim, state: notifications.append(state))
    @app.post("/v1/chat/completions")
    def managed():
        g.authenticated_user = {"username": "caller"}
        for hook in app.extensions["gateway_after_authentication"]:
            refusal = hook()
            if refusal is not None:
                return refusal
        return middleware.dispatch_with_idempotency(lambda: Response("unproven", status=200))
    with patch.dict("os.environ", {"MANAGED_IDEMPOTENCY_ENABLED": "true"}):
        with app.test_client() as client:
            first = client.post("/v1/chat/completions", json={"model": "auto:test"}, headers={"Idempotency-Key": "one"})
            retry = client.post("/v1/chat/completions", json={"model": "auto:test"}, headers={"Idempotency-Key": "one"})
    assert first.status_code == 200 and retry.status_code == 409
    assert retry.json["error"]["code"] == "outcome_unknown" and notifications == ["unknown"]
    assert not any("response" in call for call in authority.calls)
