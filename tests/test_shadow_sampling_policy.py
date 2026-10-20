"""Loaded account envelopes govern capture and queued content persistence."""
import queue
import time
from unittest.mock import Mock

import pytest
from flask import Flask, Response, g

from services.dispatch_policy import envelope
from services.key_data_guards import has_data_controls
from services.shadow_eval_contract import eligible, make_sample
from services import shadow_eval_sampling as sampling
from services.user_store import USER_FIELDS, _row


POLICIES = [
    {"official_only": None, "forced_provider_preferences": None},
    {"official_only": 0, "forced_provider_preferences": None},
    {"official_only": None, "forced_provider_preferences": '{}'},
    {"official_only": 1, "forced_provider_preferences": None},
    {"official_only": None, "forced_provider_preferences": '{"data_collection":"deny"}'},
]
PAYLOAD = {"model": "auto:synthetic", "messages": [{"role": "user", "content": "Synthetic request"}]}


def loaded_account(policy):
    from services.auth_service import AuthService
    raw = dict.fromkeys(USER_FIELDS)
    raw.update(username="synthetic", api_key_hash="synthetic", api_key_prefix="synthetic", scopes="chat",
               is_admin=0, created_at="2026-10-01T00:00:00Z", shadow_eval_rate=0.2,
               **policy, data_policy=envelope(policy))
    user = AuthService._row_to_user(_row(raw))
    assert user["data_policy"] == envelope(policy)
    return user


@pytest.fixture
def capture(monkeypatch):
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "false")
    pending = queue.Queue(maxsize=32)
    monkeypatch.setattr(sampling, "_QUEUE", pending)
    monkeypatch.setattr(sampling, "_WORKER", Mock(is_alive=Mock(return_value=True)))
    monkeypatch.setattr(sampling.random, "random", lambda: 0)
    stored = Mock()
    monkeypatch.setattr(sampling.ShadowEvalStore, "put", stored)
    return pending, stored


def drain(pending, monkeypatch):
    get = pending.get
    def next_sample():
        try:
            return get(block=False)
        except queue.Empty:
            raise StopIteration from None
    monkeypatch.setattr(pending, "get", next_sample)
    with pytest.raises(StopIteration):
        sampling._persist()


def complete(user, stream=False):
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST", json=PAYLOAD):
        g.authenticated_user = user
        g.shadow_eval_started = time.monotonic()
        if stream:
            response = Response(iter([b'data: {"choices":[{"delta":{"content":"Synthetic answer"},"finish_reason":"stop"}]}\n\n',
                                      b'data: [DONE]\n\n']), mimetype="text/event-stream")
        else:
            response = Response('{"choices":[{"message":{"content":"Synthetic answer"},"finish_reason":"stop"}]}', mimetype="application/json")
        response.headers["X-MultiLLM-Auto-Selected-Model"] = "openai:synthetic"
        assert sampling.sample_success(response) is response
    return response


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("stream", [False, True])
def test_loaded_account_sample_success_captures_and_persists_only_null_policy(policy, stream, capture, monkeypatch):
    current = loaded_account(policy)
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current)
    unrestricted = policy == POLICIES[0]
    assert has_data_controls(current) is not unrestricted
    assert eligible(PAYLOAD, current, "/v1/chat/completions", random_value=0) is unrestricted
    response = complete(current, stream)
    if stream:
        list(response.response)  # Capture finishes outside the Flask request context.
    pending, stored = capture
    assert pending.qsize() == int(unrestricted)
    drain(pending, monkeypatch)
    assert stored.call_count == int(unrestricted)
    if unrestricted:
        assert stored.call_args.args[0]["request"]["messages"] == PAYLOAD["messages"]


@pytest.mark.parametrize("stage", ["capture", "persist"])
@pytest.mark.parametrize("replacement", [*POLICIES[1:], None, {}])
def test_policy_change_or_unreadable_authority_stops_deferred_retention(stage, replacement, capture, monkeypatch):
    current = loaded_account(POLICIES[0])
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current)
    response = complete(current, stream=True)
    if stage == "persist":
        list(response.response)
    current = loaded_account(replacement) if replacement else replacement
    if stage == "capture":
        list(response.response)
    pending, stored = capture
    drain(pending, monkeypatch)
    stored.assert_not_called()


@pytest.mark.parametrize("policy", [None, {}, {"version": 1}, {"version": 0, **POLICIES[0]},
                                     {"version": 1, "official_only": None, "forced_provider_preferences": 'null'}])
def test_malformed_canonical_policy_cannot_fall_back_to_flat_nulls(policy):
    user = {"username": "synthetic", "shadow_eval_rate": 0.2, **POLICIES[0], "data_policy": policy}
    assert not eligible(PAYLOAD, user, "/v1/chat/completions", random_value=0)
    assert make_sample(PAYLOAD, user, "auto:synthetic", {"content": "Synthetic"}, "openai:synthetic", 1, {}) is None


@pytest.mark.parametrize("policy", [{}, {"version": 1}, {"version": 0, **POLICIES[0]}])
def test_account_loading_does_not_replace_malformed_envelopes_with_unrestricted_policy(policy):
    from error_handlers import APIError
    from services.auth_service import AuthService
    with pytest.raises(APIError):
        AuthService._row_to_user({"data_policy": policy})


@pytest.mark.parametrize("policy", POLICIES)
def test_gemini_override_admission_uses_canonical_non_null_policy(policy):
    from services.gemini_credentials import restricted
    with Flask(__name__).test_request_context():
        g.authenticated_user = loaded_account(policy)
        assert restricted("gemini") is (policy != POLICIES[0])
