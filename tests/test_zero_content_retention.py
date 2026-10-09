"""Prospective retention barriers use immutable request context."""
import json
import os
from unittest.mock import Mock, patch

import pytest
from flask import Flask, Response, g

from services.retention_policy import RetentionPolicy, resolve_policy, request_policy
from services import shadow_eval_sampling as sampling
from routes import chat_cache


@pytest.mark.parametrize("enabled", [None, "", "false", "no", "malformed"])
def test_disabled_ignores_header_and_configuration(enabled):
    env = {"CONTENT_RETENTION_POLICY_JSON": '{"default":"zero"}'}
    if enabled is not None:
        env["CONTENT_RETENTION_ENABLED"] = enabled
    assert resolve_policy(env, key_id="test-key", route="/chat", header="zero").mode == "inherit"


def test_precedence_and_frozen_context():
    env = {"CONTENT_RETENTION_ENABLED": "true", "CONTENT_RETENTION_POLICY_JSON": json.dumps({
        "keys": {"test-key": "zero"}, "routes": {"/private": "zero"}})}
    for key, route, header in [("test-key", "/chat", "inherit"), ("other", "/private", "inherit"),
                                ("other", "/chat", "zero")]:
        policy = resolve_policy(env, key_id=key, route=route, header=header)
        assert policy.mode == "zero" and policy.enabled
        with pytest.raises(AttributeError):
            policy.mode = "inherit"
    assert resolve_policy(env, key_id="other", route="/chat", header="inherit").mode == "inherit"


@pytest.mark.parametrize("raw", ["{", "[]", '{"default":"bad"}', '{"keys":[]}', '{"routes":{"/chat":5}}'])
def test_invalid_config_is_off_without_logging_values(raw, caplog):
    env = {"CONTENT_RETENTION_ENABLED": "true", "CONTENT_RETENTION_POLICY_JSON": raw}
    assert not resolve_policy(env, header="zero").enabled
    assert raw not in caplog.text


def app_fixture(monkeypatch):
    app = Flask(__name__)
    app.config["TESTING"] = True
    sampling.init_shadow_sampling(app)
    monkeypatch.setenv("RESPONSE_CACHE_POLICY_REVISION", "legacy")
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", "{}")
    chat_cache.clear()
    upstream = Mock()
    @app.before_request
    def auth():
        g.authenticated_user = {"id": "test-key", "username": "reader", "shadow_eval_rate": 0.2}
    @app.post("/v1/chat/completions")
    @chat_cache.cached_chat_completion
    def complete():
        upstream()
        return Response(json.dumps({"choices": [{"message": {"content": "fixture answer"},
            "finish_reason": "stop"}], "usage": {"total_tokens": 3}}), mimetype="application/json",
            headers={"X-MultiLLM-Auto-Selected-Model": "openai:fixture"})
    return app, upstream


def test_zero_bypasses_cache_and_sample_before_construction_preserves_old_entries(monkeypatch):
    app, upstream = app_fixture(monkeypatch)
    monkeypatch.setattr(sampling, "random", Mock(random=lambda: 0))
    submit = Mock()
    monkeypatch.setattr(sampling, "submit", submit)
    monkeypatch.setattr(sampling.random, "random", lambda: 0)
    body = {"model": "auto:test", "temperature": 0, "messages": [{"role": "user", "content": "fixture prompt"}]}
    headers = {"Authorization": "Bearer fixture-token", "X-MultiLLM-Cache": "on"}
    client = app.test_client()
    client.post("/v1/chat/completions", headers=headers, json=body)
    old = dict(chat_cache._store._entries)
    submit.reset_mock()
    before = sampling.sampling_counts()
    with patch.object(chat_cache._store, "get", side_effect=AssertionError("cache read")), \
         patch.object(chat_cache._store, "put", side_effect=AssertionError("cache write")), \
         patch.object(sampling, "make_sample", side_effect=AssertionError("content constructed")):
        response = client.post("/v1/chat/completions", headers={**headers, "X-MultiLLM-Retention": "zero"}, json=body)
    assert response.status_code == 200 and response.json["usage"] == {"total_tokens": 3}
    assert response.headers["X-MultiLLM-Cache"] == "bypass"
    assert chat_cache._store._entries == old
    submit.assert_not_called()
    assert sampling.sampling_counts() == before
    assert upstream.call_count == 2


def test_disabled_response_cache_and_sampling_unchanged(monkeypatch):
    app, _ = app_fixture(monkeypatch)
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "false")
    submit = Mock()
    monkeypatch.setattr(sampling, "submit", submit)
    monkeypatch.setattr(sampling.random, "random", lambda: 0)
    body = {"model": "auto:test", "temperature": 0, "messages": [{"role": "user", "content": "fixture prompt"}]}
    headers = {"Authorization": "Bearer fixture-token", "X-MultiLLM-Cache": "on", "X-MultiLLM-Retention": "zero"}
    reply = app.test_client().post("/v1/chat/completions", headers=headers, json=body)
    assert reply.headers["X-MultiLLM-Cache"] == "miss"
    assert "X-MultiLLM-Retention" not in reply.headers
    assert chat_cache._store.stats()["entries"] == 1
    submit.assert_called_once()


def test_zero_submit_does_not_start_thread_or_enqueue():
    with patch.object(sampling._QUEUE, "put_nowait") as enqueue, patch.object(sampling.threading, "Thread") as thread:
        sampling.submit({"content": "fixture"}, retention_policy=RetentionPolicy("zero", True))
    enqueue.assert_not_called()
    thread.assert_not_called()


def test_stream_callback_keeps_request_policy_after_context_and_config_change(monkeypatch):
    app = Flask(__name__)
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", "{}")
    submitted = []
    monkeypatch.setattr(sampling, "submit", lambda sample, **kw: submitted.append((sample, kw)))
    events = [b'data: {"choices":[{"delta":{"content":"fixture"},"finish_reason":"stop"}]}\n\n', b'data: [DONE]\n\n']
    with app.test_request_context("/v1/chat/completions", method="POST", json={"model":"auto:test", "messages":[{"content":"fixture"}]}):
        g.authenticated_user = {"id":"test-key", "shadow_eval_rate":0.2}
        g.shadow_eval_started = 0
        with patch.object(sampling.random, "random", return_value=0):
            response = sampling.sample_success(Response(iter(events), mimetype="text/event-stream",
                headers={"X-MultiLLM-Auto-Selected-Model":"openai:fixture"}))
        policy = request_policy()
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", '{"default":"zero"}')
    assert list(response.response) == events
    assert len(submitted) == 1 and submitted[0][1]["retention_policy"] == policy
    with app.test_request_context("/v1/chat/completions", method="POST", headers={"X-MultiLLM-Retention":"zero"}):
        g.authenticated_user = {"id":"test-key", "shadow_eval_rate":0.2}
        untouched = iter(events)
        private = sampling.sample_success(Response(untouched, mimetype="text/event-stream"))
    assert private.response is untouched


def test_background_persistence_uses_captured_policy(monkeypatch):
    policy = RetentionPolicy("inherit", True)
    monkeypatch.setattr(sampling, "_WORKER", Mock(is_alive=lambda: True))
    enqueue = Mock()
    monkeypatch.setattr(sampling._QUEUE, "put_nowait", enqueue)
    sampling.submit({"request": "fixture"}, retention_policy=policy)
    queued = enqueue.call_args.args[0]
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", '{"default":"zero"}')
    getter = Mock(side_effect=[queued, StopIteration])
    monkeypatch.setattr(sampling._QUEUE, "get", getter)
    monkeypatch.setattr(sampling._QUEUE, "task_done", Mock())
    with patch.object(sampling.ShadowEvalStore, "put") as persisted, pytest.raises(StopIteration):
        sampling._persist()
    persisted.assert_called_once_with({"request": "fixture"})


from tests.unified_api_test_case import UnifiedApiTestCase


class RegisteredRetentionTest(UnifiedApiTestCase):
    def setUp(self):
        for target in ("env_loader.load_runtime_env", "config.load_runtime_env"):
            loader = patch(target)
            loader.start()
            self.addCleanup(loader.stop)
        network = patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected network call"))
        network.start()
        self.addCleanup(network.stop)
        super().setUp()
        os.environ["CONTENT_RETENTION_ENABLED"] = "true"
        os.environ["CONTENT_RETENTION_POLICY_JSON"] = '{"routes":{"/v1/chat/completions":"zero"}}'
        os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "legacy"

    def test_registered_route_cannot_loosen_server_retention_and_keeps_usage(self):
        from tests.test_chat_cache import BODY, CACHED, chat_cache as cache_module, completion
        cache = cache_module()
        with patch.object(cache._store, "get", side_effect=AssertionError("cache read")), \
             patch.object(cache._store, "put", side_effect=AssertionError("cache write")), \
             patch("app.ProxyService.make_request", return_value=self._chat_response()) as upstream:
            reply = self.client.post("/v1/chat/completions", json=BODY,
                headers={**CACHED, "X-MultiLLM-Retention": "inherit"})
        assert reply.status_code == 200 and reply.headers["X-MultiLLM-Cache"] == "bypass"
        assert upstream.call_count == 1 and reply.json["usage"]
