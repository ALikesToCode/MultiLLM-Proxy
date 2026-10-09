"""Read-only ordering, bounded evidence and administrator feedback contracts."""

import copy
import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask
from flask_wtf.csrf import CSRFError, CSRFProtect

NOW = 2_000_000_000.0
BEFORE = ["openai:production", "openai:candidate"]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setenv("BANDIT_MODE", "")
    monkeypatch.setenv("CONFIG_SNAPSHOTS_ENABLED", "true")
    monkeypatch.setenv("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "")


def engine():
    module = importlib.import_module("services.bandit_recommendations")
    return module.BanditRecommendations(clock=lambda: NOW)


def populate(value, count=50, *, quality=(0.0, 1.0), costs=(0.02, 0.01), age=0):
    for side, model in enumerate(BEFORE):
        for index in range(count):
            assert value.observe(observation_id=f"{side * 10000 + index:032x}", task_type="chat", model=model,
                                 observed_at=NOW - age, quality=quality[side], cost_usd=costs[side], trusted=True)


def propose(value, **changes):
    return value.propose(task_type="chat", eligible_order=BEFORE, base_revision=7, seed=17, **changes)


@pytest.mark.parametrize("count", [0, 1, 49])
def test_sparse_cells_cannot_move(count):
    value = engine()
    populate(value, count)
    document = propose(value)
    assert document["eligible_order_after"] == BEFORE
    assert document["uncertainty"]["reason"] == "insufficient_evidence"


@pytest.mark.parametrize("field,unknown", [("costs", (0.02, None)), ("quality", (0.0, None))])
def test_unknown_is_not_favourable_zero(field, unknown):
    value = engine()
    populate(value, **{field: unknown})
    document = propose(value)
    assert document["eligible_order_after"] == BEFORE
    row = document["evidence"][1]
    assert row["utility_ci"] is None
    assert row["coverage"]["cost" if field == "costs" else "quality"] == 0


def test_seeded_confidence_clear_effect_and_null():
    value = engine()
    populate(value)
    document = propose(value)
    assert document == propose(value)
    assert document["eligible_order_after"] == BEFORE[::-1]
    assert document["base_revision"] == 7
    assert document["uncertainty"]["confidence"] == 0.95
    assert document["evidence"][1]["utility_ci"][0] > document["evidence"][0]["utility_ci"][1]
    null = engine()
    populate(null, quality=(0.5, 0.5), costs=(0.01, 0.01))
    assert propose(null)["eligible_order_after"] == BEFORE


def test_half_life_and_single_adjacent_step():
    value = engine()
    populate(value, count=100, age=7 * 86400)
    assert propose(value)["evidence"][0]["decayed_samples"] == 50
    models = [*BEFORE, "openai:third"]
    for index in range(100):
        value.observe(observation_id=f"{30000 + index:032x}", task_type="chat", model=models[2],
                      observed_at=NOW, quality=1, cost_usd=0, trusted=True)
    document = value.propose(task_type="chat", eligible_order=models, base_revision=7, seed=17)
    moved = [i for i, model in enumerate(models) if document["eligible_order_after"][i] != model]
    assert len(moved) == 2 and moved[1] - moved[0] == 1
    assert set(document["eligible_order_after"]) == set(models)


def test_untrusted_duplicate_invalid_and_bounded_cells():
    value = engine()
    record = dict(observation_id="a" * 32, task_type="chat", model=BEFORE[0], observed_at=NOW, quality=1, cost_usd=0)
    assert not value.observe(**record)
    assert value.observe(**record, trusted=True)
    assert not value.observe(**record, trusted=True)
    for changes in ({"quality": float("nan")}, {"cost_usd": -1}, {"quality": True}, {"observed_at": NOW + 1}):
        assert not value.observe(**{**record, "observation_id": "b" * 32, **changes}, trusted=True)
    for index in range(1000):
        accepted = value.observe(**{**record, "observation_id": f"{index:032x}", "model": f"openai:m{index}"}, trusted=True)
        assert accepted is (index < 999)
    assert len(value.cells()) == 1000


def test_feedback_is_single_use_actor_bound_and_does_not_inflate_samples():
    value = engine()
    populate(value, quality=(None, None))
    identifier = f"{10000:032x}"
    nonce = value.issue_nonce(identifier, "operator")
    with pytest.raises(ValueError):
        value.feedback(nonce, 1, "another-operator")
    value.feedback(nonce, 1, "operator")
    with pytest.raises(ValueError):
        value.feedback(nonce, 1, "operator")
    cell = propose(value)["evidence"][1]
    assert cell["sample_count"] == 50 and cell["feedback_count"] == 1
    assert cell["coverage"]["quality"] == 0.02


def records(count=50, **changes):
    return [{"_id": f"{index + 1:032x}", "_created_at": NOW, "sample_id": f"{index:032x}",
             "task_type": "chat", "candidate_model": BEFORE[1], "production_model": BEFORE[0],
             "outcome": "win", "costs": {"candidate": 0.01, "production": 0.02},
             "latencies": {"candidate": 100, "production": 100},
             "tool_validity": None, **changes} for index in range(count)]


def test_stored_result_adapter_requires_metadata_deduplicates_and_respects_noise_gate(monkeypatch):
    module = importlib.import_module("services.shadow_eval_league")
    route = SimpleNamespace(id="auto:review", candidates=BEFORE)
    value = engine()
    data = records()
    document = module.bandit_proposal(data + data, route, "chat", 7, seed=17, recommender=value)
    assert document["eligible_order_after"] == BEFORE[::-1]
    assert all(row["sample_count"] == 50 for row in document["evidence"])
    assert module.bandit_proposal(records(_created_at=None), route, "chat", 7,
                                  recommender=value)["eligible_order_after"] == BEFORE
    blocked = records(noise_floor={"version": 1})
    monkeypatch.setattr(module.noise_floor, "summarize", lambda data: [{"task_type": "chat",
        "candidate_model": BEFORE[1], "baseline_model": BEFORE[0], "eligible": False}])
    assert module.bandit_proposal(blocked, route, "chat", 7, recommender=value)["eligible_order_after"] == BEFORE


@pytest.fixture
def browser(monkeypatch):
    route = importlib.import_module("routes.shadow_eval")
    module = route.bandit
    monkeypatch.setattr(module, "recommendations", engine())
    monkeypatch.setattr(module.time, "time", lambda: NOW)
    app = Flask(__name__)
    app.config.update(SECRET_KEY="synthetic-bandit-session", TESTING=True, WTF_CSRF_ENABLED=False,
                      API_BASE_URLS={"openai": "https://synthetic.invalid"})
    importlib.import_module("error_handlers").init_error_handlers(app)
    csrf = CSRFProtect(app)
    app.register_error_handler(CSRFError, importlib.import_module("routes.csrf_errors").handle_csrf_error)
    route.register_shadow_eval_routes(app, csrf, Mock(), Mock(), Mock())
    snapshots = importlib.import_module("routes.config_snapshots")
    snapshots.register_config_snapshot_routes(app)
    monkeypatch.setattr(route.login_required.__globals__["AuthService"], "is_authenticated", lambda: True)
    monkeypatch.setattr(route.require_admin_dashboard_user.__globals__["AuthService"], "get_current_user",
                        lambda: {"username": "operator", "is_admin": True})
    monkeypatch.setattr(snapshots.require_admin_dashboard_user.__globals__["AuthService"], "get_current_user",
                        lambda: {"username": "operator", "is_admin": True})
    monkeypatch.setattr(route.ShadowEvalStore, "results", lambda: records())
    monkeypatch.setattr(route.AutoRouteService, "list_routes", lambda: [SimpleNamespace(id="auto:review", candidates=BEFORE)])
    no_write = Mock(side_effect=AssertionError("No route policy writes"))
    no_dispatch = Mock(side_effect=AssertionError("No provider requests"))
    monkeypatch.setattr(route.ShadowEvalStore, "apply", no_write)
    monkeypatch.setattr(route, "start_run", no_dispatch)
    monkeypatch.setattr(route, "dispatch_unified_chat_completion", no_dispatch)
    monkeypatch.setattr(route.bandit.config_snapshots, "call", lambda operation: {"current_revision": 7})
    monkeypatch.setattr(route.bandit.auto_route_d1, "snapshot_request", lambda operation: {"version": 1, "routes": [
        {"route_id": "auto:review", "candidates": BEFORE, "updated_at": "2026-10-09T00:00:00Z"}]})
    return app.test_client(), route, no_write, no_dispatch, snapshots


@pytest.mark.parametrize("mode", ["shadow", "recommendation"])
def test_registered_proposal_no_write_no_extra_calls_and_reviewed_cas(browser, monkeypatch, mode):
    client, route, no_write, no_dispatch, snapshots = browser
    monkeypatch.setenv("BANDIT_MODE", mode)
    response = client.post("/admin/workbench/shadow/propose", json={"route_id": "auto:review", "task_type": "chat", "seed": 17})
    assert response.status_code == 200
    document = response.json
    assert document["mode"] == mode and document["eligible_order_after"] == BEFORE[::-1]
    assert document["base_revision"] == 7
    assert client.post("/admin/workbench/shadow/apply", json={"confirm": True, "revision": "anything"}).status_code == 400
    no_write.assert_not_called()
    no_dispatch.assert_not_called()
    calls = []
    def stale_apply(operation, **values):
        calls.append((operation, values))
        raise importlib.import_module("error_handlers").APIError("Snapshot request was rejected", 409, {"error": "revision_conflict"})
    monkeypatch.setattr(snapshots.config_snapshots, "call", stale_apply)
    assert client.post("/admin/config/snapshots/" + "a" * 32 + "/apply",
                       json={"confirm": True, "current_revision": document["base_revision"]}).status_code == 409
    assert calls[0][0] == "snapshot_apply" and calls[0][1]["current_revision"] == 7


def test_off_default_empty_and_bad_mode_preserve_proposal_bytes(browser, monkeypatch, caplog):
    client, route, _, _, _ = browser
    from tests.test_intelligence_policy import candidate, policy
    base = policy(candidates=[candidate(model) for model in BEFORE])
    monkeypatch.setattr(route.IntelligenceStore, "policy", lambda: copy.deepcopy(base))
    monkeypatch.setattr(route.bandit, "_warned", False)
    monkeypatch.setattr(route.bandit.config_snapshots, "call", Mock(side_effect=AssertionError("No new storage")))
    expected = client.post("/admin/workbench/shadow/propose", json={}).data
    assert b'"policy_diff"' in expected
    for mode in ("off", "", "malformed-private-value", "malformed-private-value"):
        monkeypatch.setenv("BANDIT_MODE", mode)
        assert client.post("/admin/workbench/shadow/propose", json={}).data == expected
    assert sum("BANDIT_MODE" in record.message for record in caplog.records) == 1
    assert "malformed-private-value" not in caplog.text
    route.bandit.config_snapshots.call.assert_not_called()


def test_registered_feedback_and_csrf_admin_replay_guards(browser, monkeypatch):
    client, route, no_write, no_dispatch, _ = browser
    assert client.post("/admin/workbench/shadow/bandit/nonce", json={}).status_code == 404
    monkeypatch.setenv("BANDIT_MODE", "recommendation")
    response = client.post("/admin/workbench/shadow/bandit/nonce", json={"sample_id": "0" * 32, "model": BEFORE[1]})
    assert response.status_code == 200
    body = {"nonce": response.json["nonce"], "quality": 0}
    assert client.post("/admin/workbench/shadow/bandit/feedback", json=body).status_code == 200
    assert client.post("/admin/workbench/shadow/bandit/feedback", json=body).status_code == 409
    client.application.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/admin/workbench/shadow/bandit/feedback", json=body).status_code == 400
    client.application.config["WTF_CSRF_ENABLED"] = False
    monkeypatch.setattr(route.require_admin_dashboard_user.__globals__["AuthService"], "get_current_user",
                        lambda: {"username": "operator", "is_admin": False})
    assert client.post("/admin/workbench/shadow/propose", json={}).status_code == 403
    no_write.assert_not_called()
    no_dispatch.assert_not_called()


def test_revision_race_and_missing_storage_fail_closed(browser, monkeypatch):
    client, route, _, _, _ = browser
    monkeypatch.setenv("BANDIT_MODE", "recommendation")
    monkeypatch.setattr(route.bandit.config_snapshots, "call", Mock(side_effect=[{"current_revision": 7}, {"current_revision": 8}]))
    body = {"route_id": "auto:review", "task_type": "chat"}
    assert client.post("/admin/workbench/shadow/propose", json=body).status_code == 409
    monkeypatch.setattr(route.bandit.auto_route_d1, "snapshot_request", lambda operation: {"version": 1})
    monkeypatch.setattr(route.bandit.config_snapshots, "call", lambda operation: {"current_revision": 7})
    assert client.post("/admin/workbench/shadow/propose", json=body).status_code == 503


def test_nonce_expiry_concurrency_and_purged_evidence():
    from concurrent.futures import ThreadPoolExecutor
    value = engine()
    populate(value)
    nonce = value.issue_nonce(f"{10000:032x}", "operator")
    def submit():
        try:
            value.feedback(nonce, 1, "operator")
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(lambda unused: submit(), range(2))) == 1
    expired = value.issue_nonce(f"{10001:032x}", "operator")
    value.clock = lambda: NOW + 901
    with pytest.raises(ValueError):
        value.feedback(expired, 1, "operator")
    value.clock = lambda: NOW
    removed = value.issue_nonce(f"{10002:032x}", "operator")
    value.replace_results([])
    with pytest.raises(ValueError):
        value.feedback(removed, 1, "operator")
    assert value.cells() == []


@pytest.mark.parametrize("body", [{}, {"route_id": "auto:review", "task_type": "chat", "seed": True},
                                 {"route_id": "auto:review", "task_type": "chat", "trusted": True}])
def test_invalid_or_untrusted_proposal_input_rejected_before_storage(browser, monkeypatch, body):
    client, route, _, _, _ = browser
    monkeypatch.setenv("BANDIT_MODE", "recommendation")
    storage = Mock(side_effect=AssertionError("No storage on invalid input"))
    monkeypatch.setattr(route.bandit.config_snapshots, "call", storage)
    assert client.post("/admin/workbench/shadow/propose", json=body).status_code == 400
    storage.assert_not_called()


@pytest.mark.parametrize("noise,move", [("tie", True), ("win", False)])
def test_real_three_arm_noise_gate_even_when_evaluation_is_off(noise, move):
    from tests.test_evaluation_noise_floor import three_result
    module = importlib.import_module("services.shadow_eval_league")
    data = [three_result(index, ab=noise, _id=f"{index + 1:032x}", _created_at=NOW) for index in range(50)]
    route = SimpleNamespace(id="auto:review", candidates=BEFORE)
    document = module.bandit_proposal(data, route, "chat", 7, recommender=engine())
    assert (document["eligible_order_after"] != BEFORE) is move


def test_content_is_excluded_and_malformed_cost_stays_unknown(caplog):
    module = importlib.import_module("services.shadow_eval_league")
    data = records(prompt="private-content-marker", answer="private-content-marker")
    data[0]["costs"]["candidate"] = float("inf")
    route = SimpleNamespace(id="auto:review", candidates=BEFORE)
    document = module.bandit_proposal(data, route, "chat", 7, recommender=engine())
    assert document["eligible_order_after"] == BEFORE
    assert document["evidence"][1]["coverage"]["cost"] == 0.98
    assert "private-content-marker" not in str(document) + caplog.text
