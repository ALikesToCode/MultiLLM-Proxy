"""Three-arm evaluation, bounded storage and offline cost replay contracts."""

import copy
import importlib
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask

from services.shadow_eval_contract import encoded
from services.shadow_eval_league import league, proposal
from services.shadow_eval_runner import evaluate, run
from services.shadow_eval_store import ShadowEvalStore as Store
from tests.test_intelligence_policy import candidate, policy
from tests.test_shadow_eval import configured, result, sample, store  # noqa: F401
from tests.test_shadow_eval_routes import client  # noqa: F401


def options(**changes):
    return {"three_arm": True, "seed": 17, "bootstrap_draws": 1000, **changes}


def three_result(index=0, ab="tie", ac="win", bc="win", **changes):
    value = result(f"{index:032x}")
    value["outcome"] = ac if ac == bc else "tie"
    for field in ("latencies", "usage", "costs"):
        value[field]["judges"] *= 3
    value["noise_floor"] = {"version": 1, "run_id": "f" * 32, "seed": 17,
        "bootstrap_draws": 1000, "completed_arms": 3, "candidate_first": [True, False, True],
        "pairs": {"ab": ab, "ac": ac, "bc": bc},
        "repeat": {"model": "openai:production", "latency_ms": 90, "usage": {}, "cost": None,
                   "tool_validity": None}}
    return {**value, **changes}


@pytest.fixture(autouse=True)
def disabled_by_default(monkeypatch):
    monkeypatch.delenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", raising=False)
    monkeypatch.setattr("config.load_runtime_env", lambda: None)


def test_default_off_keeps_paired_calls_shapes_storage_and_league(store, monkeypatch):
    from services.shadow_eval_sampling import eligible
    monkeypatch.setattr("services.shadow_eval_runner.random_order", lambda: True)
    calls = []
    def dispatch(payload, unused, **kwargs):
        calls.append(payload)
        answer = "candidate" if not kwargs else encoded({"winner": "A" if len(calls) == 2 else "B", "confidence": 1})
        return {"answer": {"content": answer}, "model": "openai:candidate", "usage": {}, "cost": None, "latency_ms": 1}
    monkeypatch.setattr("services.shadow_eval_runner.call", dispatch)
    value = sample()
    config = configured(store)
    store.put(value)
    assert store.lease("a" * 32)
    assert store.claim(value, "openai:candidate", config, "a" * 32, "b" * 32)
    paired = evaluate(value, "openai:candidate", config, Mock(), deadline=time.monotonic() + 30)
    assert len(calls) == 3 and set(paired) == set(result())
    assert paired["outcome"] == "win"
    store.finish("b" * 32, paired)
    saved = store._call("results", after="")[0]["document"]
    assert saved == encoded(paired)
    expected = encoded(league([paired]))
    before = eligible({"model": "auto:test", "messages": []}, {"shadow_eval_rate": .1}, "/v1/chat/completions", random_value=0)
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    assert encoded(league([paired])) == expected
    assert eligible({"model": "auto:test", "messages": []}, {"shadow_eval_rate": .1}, "/v1/chat/completions", random_value=0) == before


def test_statistical_gate_reproducible_clear_effect_noisy_null_and_small_n(monkeypatch):
    from services.evaluation_noise_floor import summarize
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    clear = [three_result(index) for index in range(30)]
    stats = summarize(clear)
    assert stats == summarize(list(reversed(clear)))
    assert stats[0]["eligible"] is True
    assert stats[0]["adjusted_ci"][0] > stats[0]["noise_floor"] == 0
    assert summarize(clear[:29])[0]["eligible"] is False
    noisy = [three_result(index, ab="win" if index % 2 else "loss", ac="win", bc="loss") for index in range(40)]
    assert summarize(noisy)[0]["eligible"] is False
    assert summarize(clear + clear)[0]["sample_count"] == 30
    exploratory = copy.deepcopy(clear)
    for value in exploratory:
        value["noise_floor"]["bootstrap_draws"] = 1
    assert summarize(exploratory)[0]["eligible"] is False


def test_balanced_order_and_seed_bounds():
    from services.evaluation_noise_floor import judge_orders, run_options
    first = judge_orders("a" * 32, 17)
    assert first == judge_orders("a" * 32, 17)
    assert len(first) == 3 and all(pair == (pair[0], not pair[0]) for pair in first)
    assert run_options({"three_arm": True}) == options(seed=0)
    for change in ({"seed": True}, {"seed": -1}, {"seed": 2**32}, {"bootstrap_draws": 5001},
                   {"bootstrap_draws": 0}, {"three_arm": "true"}, {"unknown": 1}):
        with pytest.raises(ValueError):
            run_options(options(**change))


def test_enabled_runner_records_three_arms_six_blind_judges_and_no_content(store, monkeypatch):
    from services.evaluation_noise_floor import judge_orders
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    config = configured(store, max_replays_per_run=18, daily_cap=18)
    value = sample()
    store.put(value)
    calls, answers = [], []
    def dispatch(payload, unused, **kwargs):
        calls.append((copy.deepcopy(payload), kwargs))
        if not kwargs:
            answer = {"content": "arm-" + str(len(calls))}
            answers.append(answer)
            model = payload["model"]
        else:
            pair = json.loads(payload["messages"][1]["content"])
            assert value["production_model"] not in encoded(pair)
            assert "sampled-user" not in encoded(pair)
            winner = "A" if pair["A"] == answers[2] else "B" if pair["B"] == answers[2] else "tie"
            answer = {"content": encoded({"winner": winner, "confidence": 1})}
            model = "openai:judge"
        return {"answer": answer, "model": model, "usage": {"prompt_tokens": 4, "completion_tokens": 2},
                "cost": .001, "latency_ms": 5, "finish_reason": "stop"}
    monkeypatch.setattr("services.shadow_eval_runner.call", dispatch)
    with Flask(__name__).test_request_context(json={}):
        assert run(None, Mock(), store=store, options=options()) == 1
    assert len(calls) == 9
    assert [payload["model"] for payload, _ in calls[:3]] == [value["production_model"]] * 2 + ["openai:candidate"]
    record = store.results()[0]
    assert record["noise_floor"]["pairs"] == {"ab": "tie", "ac": "win", "bc": "win"}
    assert record["noise_floor"]["candidate_first"] == [pair[0] for pair in judge_orders(value["id"], 17)]
    assert record["noise_floor"]["completed_arms"] == 3
    assert len(record["costs"]["judges"]) == 6
    assert "arm-" not in encoded(record) and "Synthetic" not in encoded(record)
    from services.intelligence_store import IntelligenceStore
    with IntelligenceStore.connect() as connection:
        assert connection.execute("SELECT replay_count FROM shadow_eval_config").fetchone()[0] == 9


def test_every_arm_and_judge_uses_normal_accounting(store, monkeypatch):
    from flask import g
    from services.shadow_eval_runner import PRINCIPAL, accounted_dispatch
    from tests.test_shadow_eval import response
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    monkeypatch.setenv("SHADOW_EVAL_DAILY_BUDGET_USD", "2")
    config = configured(store, max_replays_per_run=9)
    store.put(sample())
    rows, admitted, billed = [], [], []
    accounting = accounted_dispatch.__globals__["request_accounting"]
    monkeypatch.setattr(accounting.usage_ledger.LEDGER, "record", rows.append)
    budgets = accounted_dispatch.__globals__["BudgetService"]
    monkeypatch.setattr(budgets, "record_cost", lambda row: None)
    monkeypatch.setattr(budgets, "check_and_reserve", lambda user, cost: billed.append(user["username"]) or
        SimpleNamespace(allowed=True, reservation=None))
    limits = accounted_dispatch.__globals__["RateLimitService"]
    monkeypatch.setattr(limits, "enforce_request", lambda **kw: admitted.append(kw["user"]["username"]) or SimpleNamespace(allowed=True))
    def dispatch(payload):
        assert g.authenticated_user["username"] == PRINCIPAL
        text = encoded({"winner": "tie", "confidence": 1}) if payload["model"] == config["judge_model"] else "arm"
        return response(text, "openai:judge" if payload["model"] == config["judge_model"] else payload["model"])
    with Flask(__name__).test_request_context(json={}):
        assert run(None, dispatch, store=store, options=options()) == 1
    assert admitted == billed == [PRINCIPAL] * 9
    assert len(rows) == 9 and all(row["principal"] == PRINCIPAL for row in rows)


@pytest.mark.parametrize("run_cap,daily_cap,expected", [(8, 500, 0), (20, 8, 0), (20, 17, 1), (18, 18, 2)])
def test_cap_reserves_all_calls_before_any_dispatch(store, monkeypatch, run_cap, daily_cap, expected):
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    configured(store, max_replays_per_run=run_cap, daily_cap=daily_cap)
    for _ in range(3):
        store.put(sample())
    calls = Mock(side_effect=RuntimeError("synthetic upstream unavailable"))
    monkeypatch.setattr("services.shadow_eval_runner.call", calls)
    with Flask(__name__).test_request_context(json={}):
        assert run(None, Mock(), store=store, options=options()) == expected
    assert calls.call_count == expected
    from services.intelligence_store import IntelligenceStore
    with IntelligenceStore.connect() as connection:
        assert connection.execute("SELECT replay_count FROM shadow_eval_config").fetchone()[0] == expected * 9
        assert connection.execute("SELECT COUNT(*) FROM shadow_eval_results").fetchone()[0] == expected


@pytest.mark.parametrize("failure", ["deadline", "malformed", "truncated", "baseline_changed"])
def test_failed_comparisons_never_promote_or_retry(monkeypatch, failure):
    from services.evaluation_noise_floor import evaluate_three_arm, summarize
    calls = []
    def dispatch(payload, unused, **kwargs):
        calls.append(payload)
        return {"answer": {"content": "bad"}, "model": "openai:wrong" if failure == "baseline_changed" else payload["model"],
                "latency_ms": 1, "usage": {}, "cost": None,
                "finish_reason": "length" if failure == "truncated" else "stop"}
    evaluated = evaluate_three_arm(sample(), "openai:candidate", {"judge_model": "free:json"}, Mock(),
        deadline=0 if failure == "deadline" else time.monotonic() + 30,
        options=options(), run_id="a" * 32, call=dispatch)
    assert evaluated["outcome"] in {"failed", "candidate_truncated"}
    assert len(calls) <= 4
    assert summarize([evaluated] * 30) == []


def test_proposals_require_noise_gate_and_existing_review_rules(monkeypatch):
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    base = policy(candidates=[candidate("openai:candidate"), candidate("openai:production")])
    route = SimpleNamespace(id="auto:test", candidates=["openai:production", "openai:candidate"])
    for records in ([three_result(i) for i in range(29)],
                    [three_result(i, ab="win", ac="tie", bc="tie") for i in range(30)]):
        document = proposal(base, league(records), [route])
        assert document["policy_diff"] == [] and document["suggested_auto_route_orders"] == []
    document = proposal(base, league([three_result(i) for i in range(30)]), [route])
    assert any(item["model"] == "openai:candidate" for item in document["policy_diff"])
    assert base == policy(candidates=[candidate("openai:candidate"), candidate("openai:production")])
    invalid = [three_result(i, tool_validity={"production": {"checked": 1, "valid": 1, "invalid": 0},
        "candidate": {"checked": 1, "valid": 0, "invalid": 1}}) for i in range(30)]
    assert proposal(base, league(invalid), [route])["policy_diff"] == []
    monkeypatch.delenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED")
    assert league([three_result(i) for i in range(30)]) == []


def test_registered_admin_options_default_off_and_stale_statistics(client, monkeypatch):
    _, browser = client
    route = importlib.import_module("routes.shadow_eval")
    start = Mock(return_value=True)
    monkeypatch.setattr(route, "start_run", start)
    configured(Store, max_replays_per_run=18)
    headers = {"Authorization": "Bearer synthetic-shadow-key"}
    assert browser.post("/admin/shadow-eval/run", headers=headers, json=options()).status_code == 400
    assert start.call_count == 0
    assert browser.post("/admin/shadow-eval/run", headers=headers, json={}).json == {"started": True}
    assert "options" not in start.call_args.kwargs
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "true")
    response = browser.post("/admin/shadow-eval/run", headers=headers, json=options())
    assert response.status_code == 202 and start.call_args.kwargs["options"] == options()
    for invalid in (options(seed=True), options(bootstrap_draws=5001), options(extra=True)):
        assert browser.post("/admin/shadow-eval/run", headers=headers, json=invalid).status_code == 400
    assert browser.post("/admin/shadow-eval/run", json=options()).status_code == 401
    old = Store.config()
    Store.save_config({**old, "max_replays_per_run": 8}, old)
    assert browser.post("/admin/shadow-eval/run", headers=headers, json=options()).status_code == 400
    Store.save_config(old, Store.config())
    base = policy(candidates=[candidate("openai:candidate"), candidate("openai:production")])
    from services.intelligence_store import IntelligenceStore
    IntelligenceStore.seed(base)
    records = [three_result(i) for i in range(30)]
    monkeypatch.setattr(Store, "results", lambda: records)
    document = browser.post("/admin/workbench/shadow/propose", json={}).json
    assert document["policy_diff"] and "noise_floor" in document
    records.append(three_result(31, ab="win", ac="loss", bc="loss"))
    assert browser.post("/admin/workbench/shadow/apply", json={"confirm": True, "revision": document["revision"]}).status_code == 409
    assert IntelligenceStore.policy() == base
    assert b"Synthetic" not in browser.get("/admin/workbench/shadow/league").data


def test_offline_replay_null_unknown_prices_tokens_and_deterministic_totals(tmp_path):
    from scripts.replay_routing_cost import replay
    observations = [{"sample_id": "one", "production_model": "openai:old", "latency_ms": 37,
                     "usage": {"prompt_tokens": 100, "completion_tokens": 20}},
                    {"sample_id": "two", "production_model": "openai:old", "latency_ms": 41,
                     "usage": {"prompt_tokens": 200}},
                    {"sample_id": "three", "production_model": "openai:old", "usage": {}}]
    prices = {"openai:new": {"input_per_million": 2, "output_per_million": 4}, "openai:unknown": None}
    report = replay(observations, prices)
    assert report == replay(observations, prices)
    assert report["candidates"]["openai:new"]["cells"] == [.00028, None, None]
    assert report["candidates"]["openai:new"]["total_usd"] is None
    assert report["candidates"]["openai:new"]["known_subtotal_usd"] == .00028
    assert report["candidates"]["openai:new"]["coverage"] == 1 / 3
    assert report["candidates"]["openai:unknown"]["cells"] == [None] * 3
    assert report["observed_latency_ms"] == [37, 41, None]
    assert replay(observations[:1], prices)["candidates"]["openai:new"]["total_usd"] == .00028
    with pytest.raises(ValueError):
        replay([{**observations[0], "request": {"messages": []}}], prices)
    for invalid in (True, -1, float("nan")):
        with pytest.raises(ValueError):
            replay(observations, {"openai:bad": {"input_per_million": invalid, "output_per_million": 1}})
    path = tmp_path / "observations.json"
    path.write_text(encoded(observations))
    price_path = tmp_path / "prices.json"
    price_path.write_text(encoded(prices))
    process = subprocess.run([sys.executable, "-I",
        str(Path(__file__).resolve().parents[1] / "scripts/replay_routing_cost.py"),
        "--observations", str(path), "--prices", str(price_path)], capture_output=True, text=True, check=True)
    assert json.loads(process.stdout) == report
