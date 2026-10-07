"""Synthetic shadow evaluation contracts, durable bounds and accounting."""

import copy
import json
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask, Response, g

from error_handlers import APIError
from services import key_controls
from services.shadow_eval_contract import (
    TASKS, default_config, eligible, encoded, make_sample, task_type, validate_config,
)
from services.shadow_eval_judge import judge_payload, outcome, parse_judgment, tool_validity
from services.shadow_eval_league import league, proposal
from services.shadow_eval_runner import PRINCIPAL, evaluate, run
from services.shadow_eval_sampling import SampleStream, init_shadow_sampling
from services.shadow_eval_store import ShadowEvalStore as Store
from services.intelligence_store import IntelligenceStore
from tests.test_intelligence_policy import candidate, policy


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("INTELLIGENCE_REQUIRE_DURABLE_STORAGE", "false")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "eval.sqlite3"))
    monkeypatch.delenv("SHADOW_EVAL_JUDGE_MODEL", raising=False)
    return Store


def sample(**changes):
    value = make_sample({"model": "auto:test", "messages": [{"role": "user", "content": "Synthetic greeting"}]},
        {"username": "sampled-user"}, "auto:test", {"content": "Synthetic answer"}, "openai:production", 100,
        {"prompt_tokens": 4, "completion_tokens": 2})
    return {**value, **changes}


def configured(store, **changes):
    old = store.config()
    config = {**old, "enabled": True, **changes}
    config["candidate_models"] = {**old["candidate_models"], "chat": ["openai:candidate"]}
    return store.save_config(config, old)


@pytest.mark.parametrize("rate,draw,accepted", [(None, 0, False), (0, 0, False), (0.2, 0.199, True), (0.2, 0.2, False), (0.21, 0, False), (True, 0, False)])
def test_sampling_probability(rate, draw, accepted):
    payload = {"model": "auto:test", "messages": []}
    assert eligible(payload, {"shadow_eval_rate": rate}, "/v1/chat/completions", random_value=draw) is accepted


@pytest.mark.parametrize("model,path,expected", [("auto:test", "/v1/chat/completions", True), ("cascade:test", "/v1/chat/completions", True),
    ("openai:concrete", "/v1/chat/completions", False), ("free:json", "/v1/chat/completions", False),
    ("auto:image", "/v1/images/generations", False), ("auto:test", "/roleplay/v1/chat/completions", False),
    ("auto:test", "/v1/messages", True), ("cascade:test", "/optimize/v1/chat/completions", True),
    ("openai:concrete", "/v1/messages", False), ("openai:concrete", "/optimize/v1/chat/completions", False),
    ("auto:test", "/v1/knowledge", False), ("openai:concrete", "/intelligence/v1/chat/completions", True)])
def test_eligibility(model, path, expected):
    assert eligible({"model": model, "messages": []}, {"shadow_eval_rate": 0.1}, path, random_value=0) is expected


@pytest.mark.parametrize("payload,task", [({"tools": [{}]}, "coding"), ({"messages": [{"content": "```python\nx=1"}]}, "coding"),
    ({"response_format": {"type": "json_object"}}, "extraction"), ({"response_format": {"type": "json_schema"}}, "extraction"),
    ({"messages": [{"content": "Write a long-form article"}]}, "writing"),
    ({"messages": [{"content": "Solve this step-by-step: 2+3"}]}, "reasoning"), ({"messages": [{"content": "Hello"}]}, "chat")])
def test_task_classification(payload, task):
    assert task_type(payload) == task


def test_secret_skip_size_caps_and_heuristic_preservation():
    payload = {"model": "auto:test", "messages": [{"role": "user", "content": "Hello"}]}
    args = ({"username": "sampled-user"}, "auto:test", {"content": "Synthetic answer"}, "openai:production", 1, {})
    secret = "sk-" + "proj-" + "Abc0123456789" * 6
    assert make_sample({**payload, "messages": [{"content": secret}]}, *args) is None
    assert make_sample({**payload, "metadata": {"private": secret}}, *args) is None
    assert make_sample({**payload, "messages": [{"content": "x" * 65536}]}, *args) is None
    assert make_sample(payload, *args[:2], {"content": "λ" * 32768}, *args[3:]) is None
    heuristic = "token = abc123XYZ789QrStUv"
    value = make_sample({**payload, "messages": [{"content": heuristic}]}, *args)
    assert value["request"]["messages"][0]["content"] == heuristic
    assert "metadata" not in value["request"]


@pytest.mark.parametrize("rate", [-0.1, 0.21, True, float("nan"), float("inf"), "bad"])
def test_key_rate_validation(rate):
    with pytest.raises(APIError):
        key_controls.validate({"shadow_eval_rate": rate})


def test_key_rate_storage_and_default():
    assert key_controls.validate({})["shadow_eval_rate"] is None
    assert key_controls.validate({"shadow_eval_rate": "0.1"})["shadow_eval_rate"] == 0.1
    assert key_controls.public(key_controls.from_storage({"shadow_eval_rate": 0.1}))["shadow_eval_rate"] == 0.1
    assert key_controls.from_storage({"shadow_eval_rate": 1})["shadow_eval_rate"] is None


def test_store_ttl_cap_and_on_demand_text(store):
    with StoreConnection() as connection:
        Store.ensure(connection)
        now = time.time()
        for index in range(2002):
            value = sample(id=f"{index:032x}", created_at=now - (2002 - index))
            connection.execute("INSERT INTO shadow_eval_samples VALUES (?, ?, ?)", (value["id"], value["created_at"], encoded(value)))
        expired = sample(id="f" * 32, created_at=now - 604800)
        connection.execute("INSERT INTO shadow_eval_samples VALUES (?, ?, ?)", (expired["id"], expired["created_at"], encoded(expired)))
        connection.commit()
    store.cleanup()
    with StoreConnection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM shadow_eval_samples").fetchone()[0] == 2000
    assert store.sample(f"{0:032x}") is None
    assert store.sample(expired["id"]) is None
    metadata = store.samples()
    assert len(metadata) == 20 and "request" not in encoded(metadata) and "production_answer" not in encoded(metadata)
    assert "request" in store.sample(metadata[0]["id"])


class StoreConnection:
    def __enter__(self):
        self.connection = IntelligenceStore.connect()
        return self.connection

    def __exit__(self, *args):
        self.connection.close()


def test_daily_claims_are_atomic_and_purge_does_not_refill(store):
    config = configured(store, daily_cap=2)
    run_id = "a" * 32
    assert store.lease(run_id)
    assert not store.lease("b" * 32)
    first = sample(); store.put(first)
    assert store.claim(first, "openai:candidate", config, run_id, "c" * 32)
    assert not store.claim(first, "openai:candidate", config, run_id, "d" * 32)
    assert not store.claim(first, "openai:unconfigured", config, run_id, "d" * 32)
    second = sample(); store.put(second)
    assert store.claim(second, "openai:candidate", config, run_id, "d" * 32)
    store.purge()
    third = sample(); store.put(third)
    assert not store.claim(third, "openai:candidate", config, run_id, "e" * 32)
    store.release(run_id)
    assert store.lease("b" * 32)


def test_daily_reset_and_config_compare_and_swap(store):
    config = configured(store, daily_cap=1)
    run_id = "a" * 32; assert store.lease(run_id)
    first = sample(); store.put(first)
    assert store.claim(first, "openai:candidate", config, run_id, "b" * 32)
    with StoreConnection() as connection:
        connection.execute("UPDATE shadow_eval_config SET day = day - 1")
        connection.commit()
    second = sample(); store.put(second)
    assert store.claim(second, "openai:candidate", config, run_id, "c" * 32)
    with pytest.raises(ValueError, match="changed"):
        store.save_config(default_config(), default_config())
    disabled = store.save_config({**config, "enabled": False}, config)
    third = sample(); store.put(third)
    assert not store.claim(third, "openai:candidate", disabled, run_id, "d" * 32)


@pytest.mark.parametrize("change", [{"enabled": 1}, {"max_replays_per_run": 0}, {"daily_cap": 501},
    {"judge_model": "gemini"}, {"candidate_models": {"chat": ["openai:test"]}}])
def test_config_bounds(change):
    with pytest.raises(ValueError):
        validate_config({**default_config(), **change})


def test_default_judge_and_explicit_gemini(monkeypatch):
    monkeypatch.delenv("SHADOW_EVAL_JUDGE_MODEL", raising=False)
    assert not default_config()["judge_model"].startswith("gemini:")
    assert validate_config({**default_config(), "judge_model": "gemini:operator-choice"})["judge_model"].startswith("gemini:")


@pytest.mark.parametrize("first,second,expected", [("A", "B", "win"), ("B", "A", "loss"), ("A", "A", "tie"), ("tie", "tie", "tie"), ("tie", "B", "tie")])
def test_judge_agreement(first, second, expected):
    assert outcome({"winner": first}, {"winner": second}, True) == expected
    assert outcome({"winner": second}, {"winner": first}, False) == expected


@pytest.mark.parametrize("text", ['{}', '```json\n{}\n```', '{"winner":"C","confidence":1,"reasons":[]}',
    '{"winner":"A","confidence":true,"reasons":[]}', '{"winner":"A","confidence":NaN,"reasons":[]}',
    '{"winner":"A","winner":"B","confidence":1,"reasons":[]}'])
def test_malformed_judge_output(text):
    with pytest.raises((ValueError, TypeError)):
        parse_judgment(text)


def test_judge_is_blind_and_swaps_order():
    value = sample()
    a = judge_payload("free:json", value, {"content": "Candidate synthetic"}, True)
    b = judge_payload("free:json", value, {"content": "Candidate synthetic"}, False)
    assert json.loads(a["messages"][1]["content"])["A"] == json.loads(b["messages"][1]["content"])["B"]
    assert value["production_model"] not in encoded(a["messages"])
    assert "sampled-user" not in encoded(a)


def response(content, model="openai:candidate"):
    return Response(encoded({"choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2}, "multillm": {"selected_model": model}}), mimetype="application/json")


def test_replays_and_two_judges_use_one_ledger_row_each_and_not_sampled_key(store, monkeypatch):
    from services.shadow_eval_runner import accounted_dispatch
    from services.judge_routing import judge_candidate_allowed

    # API fixtures reload service modules; patch the actual dispatch collaborators.
    request_accounting = accounted_dispatch.__globals__["request_accounting"]
    BudgetService = accounted_dispatch.__globals__["BudgetService"]
    RateLimitService = accounted_dispatch.__globals__["RateLimitService"]

    rows, admitted, budget_users, calls = [], [], [], []
    monkeypatch.setenv("SHADOW_EVAL_DAILY_BUDGET_USD", "2")
    monkeypatch.setattr(request_accounting.usage_ledger.LEDGER, "record", lambda row: rows.append(row))
    monkeypatch.setattr(BudgetService, "record_cost", lambda row: None)
    monkeypatch.setattr(BudgetService, "check_and_reserve", lambda user, cost: budget_users.append(user["username"]) or SimpleNamespace(allowed=True, reservation=None))
    monkeypatch.setattr(RateLimitService, "enforce_request", lambda **kwargs: admitted.append(kwargs["user"]["username"]) or SimpleNamespace(allowed=True))
    config = configured(store, max_replays_per_run=1)
    store.put(sample())

    def dispatch(payload):
        calls.append(payload)
        assert g.authenticated_user["username"] == PRINCIPAL
        if payload["model"] == config["judge_model"]:
            assert not judge_candidate_allowed("gemini:hidden")
            first = json.loads(payload["messages"][1]["content"])["A"]["content"] == "Candidate synthetic"
            return response(encoded({"winner": "A" if first else "B", "confidence": 0.9, "reasons": ["Synthetic reason"]}), "openai:judge")
        return response("Candidate synthetic")

    app = Flask(__name__)
    with app.test_request_context(json={}):
        g.authenticated_user = {"username": "admin-trigger"}
        assert run(app, dispatch) == 1
    assert len(calls) == len(rows) == 3
    assert admitted == budget_users == [PRINCIPAL] * 3
    assert all(row["principal"] == PRINCIPAL and row["key_prefix"] is None for row in rows)
    assert [row["requested_model"] for row in rows] == ["openai:candidate", "free:json", "free:json"]
    assert store.results()[0]["outcome"] == "win"


def test_per_run_and_daily_caps_and_failures(store, monkeypatch):
    config = configured(store, max_replays_per_run=2, daily_cap=3)
    for _ in range(5): store.put(sample())
    monkeypatch.setattr("services.shadow_eval_runner.evaluate", lambda value, model, settings, dispatch, **kwargs: result(value["id"]))
    app = Flask(__name__)
    with app.test_request_context(json={}):
        assert run(app, Mock()) == 2
        assert run(app, Mock()) == 1
        assert run(app, Mock()) == 0
    assert len(store.results()) == 3
    store.save_config({**config, "enabled": False}, config)
    with app.test_request_context(json={}): assert run(app, Mock()) == 0


def result(identifier="a" * 32, outcome="win", **changes):
    return {"sample_id": identifier, "task_type": "chat", "candidate_model": "openai:candidate", "candidate_route": "openai:candidate",
        "production_model": "openai:production", "outcome": outcome, "judge_model": "free:json",
        "latencies": {"production": 100, "candidate": 200, "judges": [10, 10]},
        "usage": {"production": {}, "candidate": {}, "judges": [{}, {}]},
        "costs": {"production": 0.01, "candidate": 0.02, "judges": [None, None]}, "tool_validity": None, **changes}


def test_elo_and_medians_with_known_inputs():
    rows = league([result()])
    by_model = {row["model"]: row for row in rows}
    assert by_model["openai:candidate"]["rating"] == 1516
    assert by_model["openai:production"]["rating"] == 1484
    assert by_model["openai:candidate"]["median_latency_ms"] == 200
    assert by_model["openai:candidate"]["median_cost_usd"] == 0.02
    assert by_model["openai:candidate"]["wins"] == by_model["openai:production"]["losses"] == 1
    tied = league([result(outcome="tie")])
    assert all(row["rating"] == 1500 and row["ties"] == 1 for row in tied)
    assert league([result(outcome="failed")]) == []


def test_twenty_comparison_threshold_policy_validation_and_guarded_backup(store):
    original = policy(candidates=[candidate("openai:candidate"), candidate("openai:production")])
    IntelligenceStore.seed(original)
    route = SimpleNamespace(id="auto:test", candidates=["openai:production", "openai:candidate"])
    assert proposal(original, league([result()] * 19), [route])["policy_diff"] == []
    proposed = proposal(original, league([result()] * 20), [route])
    assert len(proposed["policy_diff"]) == 2
    assert proposed["suggested_auto_route_orders"][0]["to"] == ["openai:candidate", "openai:production"]
    assert store.apply(original, proposed["policy"])
    assert not store.apply(original, proposed["policy"])
    with StoreConnection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM shadow_eval_policy_backups").fetchone()[0] == 1
    assert IntelligenceStore.policy() == proposed["policy"]
    with pytest.raises(ValueError): store.apply(proposed["policy"], {**proposed["policy"], "version": 9})
    assert "Synthetic answer" not in encoded(proposed)


def test_stream_capture_complete_truncated_failed_and_tool_calls():
    events = [b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n',
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"completion_tokens":2}}\n\n', b'data: [DONE]\n\n']
    captures = []
    stream = SampleStream(iter(events), lambda *args: captures.append(args), "openai:production")
    assert list(stream) == events
    stream.close(); assert len(captures) == 1 and captures[0][0]["content"] == "Hello"
    for chunks in (events[:1], [b'data: {"error":"failed"}\n\n', *events], [b'x' * 131073, *events]):
        captures.clear(); stream = SampleStream(iter(chunks), lambda *args: captures.append(args), "openai:production")
        assert list(stream) == chunks
        stream.close(); assert captures == []


def test_sampling_hook_never_fails_response_and_has_no_recursive_internal_samples(monkeypatch):
    app = Flask(__name__); init_shadow_sampling(app)
    captures = []
    monkeypatch.setattr("services.shadow_eval_sampling.random.random", lambda: 0)
    monkeypatch.setattr("services.shadow_eval_sampling.submit", lambda value: captures.append(value))
    @app.post("/v1/chat/completions")
    def complete():
        g.authenticated_user = {"username": "sampled-user", "shadow_eval_rate": 0.2}
        return response("Synthetic answer", "openai:production")
    payload = {"model": "auto:test", "messages": [{"content": "Synthetic greeting"}]}
    client = app.test_client()
    assert client.post("/v1/chat/completions", json=payload).status_code == 200
    assert captures[0]["key_id"] == "sampled-user"
    monkeypatch.setattr("services.shadow_eval_sampling.submit", Mock(side_effect=RuntimeError()))
    assert client.post("/v1/chat/completions", json=payload).status_code == 200


def test_malformed_judge_is_failed_and_not_rated(monkeypatch):
    monkeypatch.setattr("services.shadow_eval_runner.call", lambda payload, dispatch, **kwargs: {
        "answer": {"content": "Malformed"}, "model": "openai:candidate", "usage": {}, "cost": None, "latency_ms": 1})
    value = evaluate(sample(), "openai:candidate", default_config(), Mock(), deadline=time.monotonic() + 10)
    assert value["outcome"] == "failed" and league([value]) == []


def test_tool_validity_uses_declared_schema():
    value = sample(task_type="coding", request={"messages": [], "tools": [{"type": "function", "function": {
        "name": "lookup", "parameters": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}}}]})
    valid = {"tool_calls": [{"id": "synthetic-call", "type": "function", "function": {"name": "lookup", "arguments": '{"id":2}'}}]}
    assert tool_validity(valid, value) == {"checked": 1, "valid": 1, "invalid": 0}
    invalid = copy.deepcopy(valid); invalid["tool_calls"][0]["function"]["name"] = "invented"
    assert tool_validity(invalid, value)["invalid"] == 1


@pytest.mark.parametrize("vector", json.loads((__import__("pathlib").Path(__file__).parent / "fixtures/shadow_eval_vectors.json").read_text()))
def test_shared_config_vectors(vector):
    value = {**default_config(), **vector["changes"]}
    if vector["valid"]:
        assert validate_config(value) == value
    else:
        with pytest.raises(ValueError):
            validate_config(value)


def test_native_dispatch_is_sampled_once_after_normalization(monkeypatch):
    from services.shadow_eval_sampling import sample_chat_dispatch
    app = Flask(__name__)
    init_shadow_sampling(app)
    draws = Mock(return_value=0)
    samples = []
    monkeypatch.setattr("services.shadow_eval_sampling.random.random", draws)
    monkeypatch.setattr("services.shadow_eval_sampling.submit", samples.append)

    @sample_chat_dispatch
    def dispatch(app, auth, metrics, proxy, payload):
        return app.json.response({"choices": [{"message": {"content": "Synthetic completion"}}],
                                  "multillm": {"selected_model": "openai:production"}})

    @app.post("/v1/responses")
    def respond():
        g.authenticated_user = {"username": "sampled-user", "shadow_eval_rate": 0.2}
        return dispatch(app, None, None, None, {"model": "auto:test", "messages": [{"role": "user", "content": "Synthetic"}]})

    assert app.test_client().post("/v1/responses", json={"model": "auto:test", "input": "Synthetic"}).status_code == 200
    assert len(samples) == 1
    assert samples[0]["request"]["messages"][0]["content"] == "Synthetic"
    assert draws.call_count == 1
    draws.return_value = 0.5
    assert app.test_client().post("/v1/responses", json={"model": "auto:test", "input": "Synthetic"}).status_code == 200
    assert len(samples) == 1 and draws.call_count == 2


def rated(model, rating, task="chat", count=20):
    return {"model": model, "task_type": task, "sample_count": count, "rating": rating}


def test_proposal_anchors_mean_and_orders_rated_models_without_touching_unevaluated():
    base = policy(candidates=[candidate("openai:better", task_scores={"chat": 80}),
        candidate("openai:worse", task_scores={"chat": 90}), candidate("openai:unrated", task_scores={"chat": 95})])
    document = proposal(base, [rated("openai:better", 1550), rated("openai:worse", 1450), rated("openai:unrated", 1800, count=19)])
    scores = {item["model"]: item["task_scores"]["chat"] for item in document["policy"]["candidates"]}
    assert scores == {"openai:better": 90, "openai:worse": 80, "openai:unrated": 95}
    assert (scores["openai:better"] + scores["openai:worse"]) / 2 == 85
    assert all(change["model"] != "openai:unrated" for change in document["policy_diff"])
    assert base["candidates"][0]["task_scores"]["chat"] == 80


@pytest.mark.parametrize("previous,ratings,expected", [
    (80, [2000, 1000], [95, 65]), (None, [2000, 1000], [100, 20]),
    (None, [3000, 0], [100, 0]), (None, [1500, 1500], [70, 70]),
])
def test_proposal_step_limit_clamp_and_default_anchor(previous, ratings, expected):
    scores = {} if previous is None else {"chat": previous}
    base = policy(candidates=[candidate("openai:a", task_scores=scores), candidate("openai:b", task_scores=scores)])
    document = proposal(base, [rated("openai:a", ratings[0]), rated("openai:b", ratings[1])])
    assert [item["task_scores"]["chat"] for item in document["policy"]["candidates"]] == expected


def test_proposal_anchors_each_task_independently():
    base = policy(candidates=[candidate("openai:a", task_scores={"chat": 90, "coding": 70}),
                             candidate("openai:b", task_scores={"chat": 90, "coding": 70})])
    # Use the same Elo spread against two different absolute score baselines.
    rows = [rated(model, rating, task) for task in ("chat", "coding")
            for model, rating in (("openai:a", 1550), ("openai:b", 1450))]
    document = proposal(base, rows)
    assert [item["task_scores"] for item in document["policy"]["candidates"]] == [
        {"chat": 95, "coding": 75}, {"chat": 85, "coding": 65}]


@pytest.mark.parametrize("wrapped", [False, True])
def test_judge_accepts_fence_extra_keys_numeric_confidence_and_normalizes_reasons(wrapped):
    text = encoded({"winner": "A", "confidence": "0.75", "extra": "ignored",
                    "reasons": [None, "x" * 180, 42, "second", "third", "fourth"]})
    if wrapped:
        text = "```json\n" + text + "\n```"
    assert parse_judgment(text) == {"winner": "A", "confidence": 0.75,
                                    "reasons": ["x" * 160, "second", "third"]}
    assert parse_judgment('{"winner":"tie","confidence":1,"reasons":null}')["reasons"] == []


@pytest.mark.parametrize("text", [
    'x' * 4097, '{"winner":[],"confidence":1}', '{"winner":"A","confidence":"NaN"}',
    '{"winner":"A","confidence":"1.1"}', '{"winner":"A","confidence":"bad"}',
    '```json\n```json\n{"winner":"A","confidence":1}\n```\n```',
])
def test_judge_rejects_oversize_invalid_score_and_nested_fences(text):
    with pytest.raises((ValueError, TypeError)):
        parse_judgment(text)


@pytest.mark.parametrize("usage,limits,expected", [
    ({}, {}, 8192), ({"completion_tokens": 0}, {}, 1024), ({"completion_tokens": 2000}, {}, 4000),
    ({"completion_tokens": 10000}, {}, 8192), ({}, {"max_tokens": 500}, 500),
    ({"completion_tokens": 3000}, {"max_completion_tokens": 3000}, 3000),
    ({}, {"max_tokens": 2000, "max_completion_tokens": 1000}, 1000),
])
def test_replay_cap_preserves_full_request_and_uses_normal_completion_translation(usage, limits, expected):
    from services.shadow_eval_runner import replay_payload
    value = sample(usage=usage)
    value["request"].update(limits, tools=[{"function": {"name": "synthetic", "parameters": {"type": "object"}}}])
    before = copy.deepcopy(value)
    payload = replay_payload(value, "openai:candidate")
    assert payload["max_completion_tokens"] == expected and "max_tokens" not in payload
    assert payload["messages"] == value["request"]["messages"] and payload["tools"] == value["request"]["tools"]
    assert value == before


@pytest.mark.parametrize("production_finish,candidate_finish,selected,expected", [
    ("stop", "length", "openai:candidate", "candidate_truncated"),
    (None, "length", "openai:candidate", "candidate_truncated"),
    ("length", "length", "openai:candidate", "tie"),
    ("stop", "stop", "openai:production", "same_model"),
])
def test_unfair_and_same_model_comparisons_are_excluded_and_counted(monkeypatch, production_finish, candidate_finish, selected, expected):
    from services.shadow_eval_league import result_counts
    calls = []
    def fake_call(payload, dispatch, **kwargs):
        calls.append(payload)
        return {"answer": {"content": encoded({"winner": "tie", "confidence": 1}) if kwargs.get("judge") else "Synthetic"},
                "model": selected, "usage": {}, "cost": None, "latency_ms": 1, "finish_reason": candidate_finish}
    monkeypatch.setattr("services.shadow_eval_runner.call", fake_call)
    value = evaluate(sample(production_finish_reason=production_finish), "openai:candidate", default_config(), Mock(), deadline=time.monotonic()+10)
    assert value["outcome"] == expected
    counts = result_counts([value])
    assert counts["failed"] == 0
    if expected == "tie":
        assert counts["judged"] == 1 and len(calls) == 3 and league([value])
        assert all(payload["max_tokens"] == 1024 for payload in calls[1:])
    else:
        assert counts[expected] == 1 and len(calls) == 1 and league([value]) == []
    if expected == "candidate_truncated":
        assert value["candidate_truncated"] is True
        assert league([result(candidate_truncated=True)]) == []


def test_judge_compacts_system_recent_messages_tools_and_keeps_answer_format():
    from services.shadow_eval_context import compact_request, SYSTEM_BYTES, MESSAGE_BYTES
    tools = [{"type": "function", "function": {"name": name, "description": "Synthetic tool", "parameters": {"type": "object", "padding": "x" * 5000}}}
             for name in ("called-a", "called-b", "unused")]
    request = {"messages": [{"role": "system", "content": "λ" * 10000}, {"role": "system", "content": "second system"}] +
        [{"role": "user", "content": str(index)} for index in range(12)], "tools": tools,
        "response_format": {"type": "json_object"}}
    answers = [{"content": "Synthetic", "tool_calls": [{"function": {"name": name, "arguments": "{}"}}]} for name in ("called-a", "called-b")]
    before = copy.deepcopy(request)
    view = compact_request(request, answers)
    systems = [item for item in view["messages"] if item["role"] == "system"]
    recent = [item for item in view["messages"] if item["role"] != "system"]
    assert len(encoded(systems).encode()) <= SYSTEM_BYTES
    assert len(encoded(recent).encode()) <= MESSAGE_BYTES
    assert [item["content"] for item in recent] == [str(index) for index in range(4, 12)]
    assert view["tools"][:2] == tools[:2] and "parameters" not in view["tools"][2]["function"]
    assert view["response_format"] == request["response_format"] and request == before


def test_judge_message_budget_keeps_newest_and_whole_request_drops_oldest_first():
    from services.shadow_eval_context import compact_request
    messages = [{"role": "user", "content": str(index) + "λ" * 5000} for index in range(10)]
    value = sample(request={"messages": messages})
    view = compact_request(value["request"], [])
    kept = [item["content"] for item in view["messages"]]
    assert len(encoded(view["messages"]).encode()) <= 24576
    assert kept[-1] == messages[-1]["content"] and kept[-2] == messages[-2]["content"]
    assert kept[0].startswith("7") and len(kept[0]) < len(messages[7]["content"])
    value["production_answer"] = {"content": "x" * 22000}
    answer = {"content": "x" * 22000}
    payload = judge_payload("free:json", value, answer, True)
    data = json.loads(payload["messages"][1]["content"])
    assert len(encoded(payload).encode()) <= 65536
    assert data["A"] == answer and data["B"] == value["production_answer"]
    kept = data["request"]["messages"]
    assert kept[-1] == messages[-1] and len(kept) < len(view["messages"])
    with pytest.raises(ValueError, match="64 KiB"):
        judge_payload("free:json", sample(production_answer={"content": "x" * 32750}), {"content": "x" * 32750}, True)


def test_sample_contract_retains_request_limits_and_finish_reason(store):
    from services.shadow_eval_contract import valid_sample
    value = make_sample({"model": "auto:test", "messages": [], "max_tokens": 500, "max_completion_tokens": 600},
        {"username": "sampled-user"}, "auto:test", {"content": "Synthetic"}, "openai:production", 1, {}, finish_reason="length")
    assert value["production_finish_reason"] == "length"
    assert value["request"]["max_tokens"] == 500 and value["request"]["max_completion_tokens"] == 600
    store.put(value)
    assert store.sample(value["id"]) == value
    assert valid_sample(sample(), time.time())  # Existing retained samples remain readable.
    value["request"]["max_tokens"] = True
    assert not valid_sample(value, time.time())


def test_capture_preserves_nonstream_and_stream_finish_reasons(monkeypatch):
    from services.shadow_eval_sampling import sample_success
    samples = []
    monkeypatch.setattr("services.shadow_eval_sampling.submit", samples.append)
    monkeypatch.setattr("services.shadow_eval_sampling.random.random", lambda: 0)
    app = Flask(__name__)
    init_shadow_sampling(app)
    payload = {"model": "auto:test", "messages": []}
    with app.test_request_context("/v1/chat/completions", method="POST", json=payload):
        g.authenticated_user = {"username": "sampled-user", "shadow_eval_rate": 0.2}
        g.shadow_eval_started = time.monotonic()
        response = app.json.response({"choices": [{"message": {"content": "Synthetic"}, "finish_reason": "length"}],
                                     "multillm": {"selected_model": "openai:production"}})
        sample_success(response, payload)
    assert samples[0]["production_finish_reason"] == "length"
    captured = []
    chunks = [b'data: {"choices":[{"delta":{"content":"Synthetic"},"finish_reason":"length"}]}\n\n', b'data: [DONE]\n\n']
    list(SampleStream(iter(chunks), lambda *args: captured.append(args), "openai:production"))
    assert captured[0][3] == "length"


@pytest.fixture
def coverage(monkeypatch):
    import queue
    from services import shadow_eval_sampling as sampling
    monkeypatch.setattr(sampling, "_COUNTS", dict.fromkeys(sampling.sampling_counts(), 0))
    monkeypatch.setattr(sampling, "_QUEUE", queue.Queue(maxsize=1))
    monkeypatch.setattr(sampling, "_WORKER", SimpleNamespace(is_alive=lambda: True))
    return sampling


@pytest.mark.parametrize("path", ["/v1/responses", "/v1/messages", "/optimize/v1/chat/completions"])
def test_accounted_subrequest_cannot_consume_outer_sampling_decision(monkeypatch, coverage, path):
    from services.accounted_dispatch import accounted_dispatch
    from services.shadow_eval_sampling import sample_chat_dispatch
    collaborators = accounted_dispatch.__globals__
    monkeypatch.setattr(collaborators["RateLimitService"], "enforce_request", lambda **kwargs: SimpleNamespace(allowed=True))
    monkeypatch.setattr(collaborators["request_accounting"], "_record", Mock())
    draws = Mock(return_value=0.1)
    monkeypatch.setattr(coverage.random, "random", draws)
    app = Flask(__name__)
    init_shadow_sampling(app)
    payload = {"model": "cascade:test", "messages": [{"role": "user", "content": "Synthetic"}]}

    @sample_chat_dispatch
    def chat_dispatch(app, auth, metrics, proxy, payload):
        return response("Synthetic answer", "openai:production")

    def outer():
        g.authenticated_user = {"username": "sampled-user", "shadow_eval_rate": 0.2}
        # Even a routed subrequest with an otherwise eligible payload must be ignored.
        accounted_dispatch({**payload, "model": "auto:internal"}, lambda data: chat_dispatch(app, None, None, None, data), kind="chat")
        assert not getattr(g, "gateway_subrequest", False)
        assert not getattr(g, "shadow_eval_sampled", False)
        return chat_dispatch(app, None, None, None, payload)
    app.add_url_rule(path, view_func=outer, methods=["POST"])
    assert app.test_client().post(path, json=payload).status_code == 200
    assert draws.call_count == 1
    assert coverage.sampling_counts() == {"eligible": 1, "sampled": 1, "skipped_rate": 0,
        "skipped_secret": 0, "skipped_oversize": 0, "skipped_queue_full": 0, "skipped_error": 0}
    assert coverage._QUEUE.get_nowait()["route"] == "cascade:test"


@pytest.mark.parametrize("initial", [False, True])
def test_accounted_subrequest_flag_restores_after_nested_success_or_exception(monkeypatch, initial):
    from services.accounted_dispatch import accounted_dispatch
    collaborators = accounted_dispatch.__globals__
    monkeypatch.setattr(collaborators["RateLimitService"], "enforce_request", lambda **kwargs: SimpleNamespace(allowed=True))
    monkeypatch.setattr(collaborators["request_accounting"], "_record", Mock())
    app = Flask(__name__)
    with app.test_request_context(json={}):
        g.gateway_subrequest = initial
        def child(data):
            assert g.gateway_subrequest is True
            return response("Synthetic")
        def parent(data):
            assert g.gateway_subrequest is True
            accounted_dispatch(data, child, kind="chat")
            assert g.gateway_subrequest is True
            return response("Synthetic")
        payload = {"model": "openai:synthetic", "messages": []}
        accounted_dispatch(payload, parent, kind="chat")
        assert g.gateway_subrequest is initial
        with pytest.raises(RuntimeError):
            accounted_dispatch(payload, Mock(side_effect=RuntimeError("Synthetic")), kind="chat")
        assert g.gateway_subrequest is initial


def test_sampling_counters_cover_rate_secret_size_queue_error_and_are_bounded(monkeypatch, coverage):
    app = Flask(__name__)
    init_shadow_sampling(app)
    draw = Mock(return_value=0.1)
    monkeypatch.setattr(coverage.random, "random", draw)
    payload = {"model": "auto:test", "messages": [{"role": "user", "content": "Synthetic"}]}
    def visit(body, reply=None):
        with app.test_request_context("/v1/chat/completions", method="POST", json=body):
            g.authenticated_user = {"username": "sampled-user", "shadow_eval_rate": 0.2}
            g.shadow_eval_started = time.monotonic()
            reply = reply if reply is not None else response("Synthetic", "openai:production")
            assert coverage.sample_success(reply, body) is reply
            coverage.sample_success(reply, body)  # No second decision or skip count.
    draw.return_value = 0.3; visit(payload)
    draw.return_value = 0.1
    secret = "sk-" + "proj-" + "Abc0123456789" * 6
    visit({**payload, "messages": [{"role": "user", "content": secret}]})
    visit({**payload, "messages": [{"role": "user", "content": "x" * 65536}]})
    visit(payload); visit(payload)
    visit(payload, Response("Not JSON", mimetype="application/json"))
    assert coverage.sampling_counts() == {"eligible": 6, "sampled": 1, "skipped_rate": 1,
        "skipped_secret": 1, "skipped_oversize": 1, "skipped_queue_full": 1, "skipped_error": 1}
    assert draw.call_count == 6
    snapshot = coverage.sampling_counts(); snapshot["sampled"] = 99
    assert coverage.sampling_counts()["sampled"] == 1
    coverage._COUNTS["eligible"] = coverage._COUNTER_MAX
    coverage.count("eligible")
    assert coverage.sampling_counts()["eligible"] == coverage._COUNTER_MAX


def test_answer_secret_and_size_skips_are_visible(coverage):
    reasons = []
    args = ({"model": "auto:test", "messages": []}, {"username": "synthetic"}, "auto:test")
    secret = "sk-" + "proj-" + "Abc0123456789" * 6
    assert make_sample(*args, {"content": secret}, "openai:production", 1, {}, on_skip=reasons.append) is None
    assert make_sample(*args, {"content": "x" * 32768}, "openai:production", 1, {}, on_skip=reasons.append) is None
    assert reasons == ["skipped_secret", "skipped_oversize"]


def test_stream_skip_counters_do_not_count_failure_twice(coverage):
    for chunks in ([b'x' * 131073], [b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n']):
        stream = SampleStream(iter(chunks), Mock(), "openai:production")
        assert list(stream) == chunks
        stream.close(); stream.close()
    assert coverage.sampling_counts()["skipped_oversize"] == 1
    assert coverage.sampling_counts()["skipped_error"] == 1


def test_persistence_failure_counter_is_content_free(monkeypatch, coverage):
    monkeypatch.setattr(coverage._QUEUE, "get", Mock(side_effect=[sample(), StopIteration]))
    monkeypatch.setattr(coverage._QUEUE, "task_done", Mock())
    monkeypatch.setattr(coverage.ShadowEvalStore, "put", Mock(side_effect=RuntimeError("Synthetic")))
    with pytest.raises(StopIteration):
        coverage._persist()
    assert coverage.sampling_counts()["skipped_error"] == 1
