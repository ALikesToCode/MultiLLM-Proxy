"""Controlled source content cannot reach replay candidates or judges."""

import time
from unittest.mock import Mock

import pytest
from flask import Flask, Response, g

from services.shadow_eval_contract import default_config, encoded, make_sample
from services.shadow_eval_data_policy import source_allows_replay
from services.shadow_eval_runner import evaluate, run
from services.shadow_eval_sampling import sample_success
from tests.test_shadow_eval import configured, response, sample, store  # noqa: F401

CONTROLS = [{"official_only": True}, {"forced_provider_preferences": {"data_collection": "deny"}},
            {"forced_provider_preferences": {}}]


@pytest.mark.parametrize("controls", CONTROLS)
@pytest.mark.parametrize("stream", [False, True])
def test_controlled_requests_never_enter_sampling(controls, stream, monkeypatch):
    submit = Mock()
    draw = Mock(return_value=0)
    monkeypatch.setattr("services.shadow_eval_sampling.submit", submit)
    monkeypatch.setattr("services.shadow_eval_sampling.random.random", draw)
    payload = {"model": "auto:example", "messages": [{"role": "user", "content": "Synthetic"}]}
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST", json=payload):
        g.authenticated_user = {"username": "sampled-user", "shadow_eval_rate": 0.2, **controls}
        original = Response(iter([b"data: [DONE]\n\n"]), mimetype="text/event-stream") if stream else response("Synthetic")
        assert sample_success(original, payload) is original
        if stream:
            assert list(original.response) == [b"data: [DONE]\n\n"]
    submit.assert_not_called()
    draw.assert_not_called()
    assert make_sample(payload, controls, "auto:example", {"content": "Synthetic"},
                       "openai:production", 1, {}) is None


@pytest.mark.parametrize("controls", CONTROLS)
def test_legacy_samples_from_controlled_keys_skip_candidate_and_judges(store, controls, monkeypatch):
    configured(store, max_replays_per_run=1)
    store.put(sample())
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: {"username": "sampled-user", **controls})
    dispatch = Mock()
    app = Flask(__name__)
    with app.test_request_context():
        assert run(app, dispatch, store=store) == 0
    dispatch.assert_not_called()
    assert store.results() == []


@pytest.mark.parametrize("controls", CONTROLS)
@pytest.mark.parametrize("change_after", [0, 1, 2])
def test_source_policy_rechecked_before_candidate_and_each_judge(controls, change_after, monkeypatch):
    current = {"username": "sampled-user", **(controls if change_after == 0 else {})}
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current.copy())
    monkeypatch.setattr("services.shadow_eval_runner.accounted_dispatch", lambda payload, dispatch, **_: dispatch(payload))
    calls = []

    def dispatch(payload):
        calls.append(payload["model"])
        if len(calls) == change_after:
            current.update(controls)
        if len(calls) > 1:
            return response(encoded({"winner": "A", "confidence": 0.9, "reasons": ["Synthetic"]}))
        return response("Candidate synthetic")

    with Flask(__name__).test_request_context():
        result = evaluate(sample(), "openrouter:example/model", default_config(), dispatch, deadline=time.monotonic() + 10)
    assert len(calls) == change_after
    assert calls == ["openrouter:example/model", "free:json"][:change_after]
    assert result["outcome"] == "failed"


@pytest.mark.parametrize("source", [None, {"revoked_at": "2026-10-20"}, {"expires_at": "2000-01-01T00:00:00Z"}])
def test_unknown_or_inactive_source_authority_refuses_replay(source, monkeypatch):
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: source)
    assert not source_allows_replay(sample())


def test_unavailable_source_authority_refuses_replay(monkeypatch):
    def unavailable(_):
        raise RuntimeError("Synthetic storage failure")
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", unavailable)
    assert not source_allows_replay(sample())
