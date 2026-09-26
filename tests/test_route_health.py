"""Health- and latency-aware candidate ordering stays deterministic, bounded and fair."""

import json

import pytest

from services import route_health
from services.route_health import MAX_SAMPLES, MAX_TARGETS, RouteHealth, valid_state

ROUTE = "auto:glm-5.2"
A, B, C = "nanogpt:glm-5.2", "opencode:glm-5.2", "navyai:glm-5.2"
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def health(monkeypatch):
    for name in ("AUTO_ROUTE_ORDERING", "AUTO_ROUTE_ORDERING_OVERRIDES", "AUTO_ROUTE_EXPLORE_EVERY",
                 "AUTO_ROUTE_COST_WEIGHT", "AUTO_ROUTE_LATENCY_WEIGHT", "MODEL_PRICING_USD_PER_MILLION"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AUTO_ROUTE_HEALTH_HALF_LIFE_SECONDS", "600")
    RouteHealth.reset()
    yield
    RouteHealth.reset()


def order(candidates=(A, B, C), **kwargs):
    return RouteHealth.order(ROUTE, candidates, now=kwargs.pop("now", NOW), **kwargs)


def fail(candidate, times=1, at=NOW - 1):
    for _ in range(times):
        RouteHealth.record(candidate, ok=False, outcome="http_503", status=503, now=at)


def succeed(candidate, latency_ms=800, times=1, at=NOW - 1):
    for _ in range(times):
        RouteHealth.record(candidate, ok=True, outcome="ok", latency_ms=latency_ms, status=200, now=at)


def test_operator_order_is_the_default_whatever_the_health(monkeypatch):
    fail(A, times=5)
    assert order() == route_health.RouteOrder((A, B, C), "priority")


def test_health_ordering_moves_a_failing_candidate_behind_healthy_ones(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    fail(A, times=2)
    succeed(B)
    assert order() == route_health.RouteOrder((B, C, A), "health")
    assert order() == order(), "the same figures always give the same order"


def test_small_differences_keep_the_configured_order(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    succeed(A, latency_ms=1500)
    succeed(B, latency_ms=900)
    assert order().candidates == (A, B, C)


def test_a_much_slower_candidate_yields_to_a_fast_one(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    succeed(A, latency_ms=30_000, times=3)
    succeed(B, latency_ms=700, times=3)
    assert order().candidates == (B, C, A), "an unmeasured candidate also passes the slow one"


def test_a_failed_candidate_returns_to_its_place_as_evidence_ages(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    fail(A, at=NOW)
    succeed(B, at=NOW)
    assert order(now=NOW + 1).candidates[0] == B
    later = NOW + 4 * 600
    succeed(B, at=later)
    assert order(now=later + 1).candidates[0] == A, "a candidate without fresh failures is tried again"


def test_open_circuits_go_last(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    states = {"nanogpt": "open", "opencode": "closed", "navyai": "half_open"}
    assert order(circuit_state=states.__getitem__).candidates == (B, C, A)


def test_per_route_override_wins_over_the_global_setting(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "priority")
    monkeypatch.setenv("AUTO_ROUTE_ORDERING_OVERRIDES", f"{ROUTE}=health, auto:image=priority, bogus")
    fail(A, times=2)
    assert order().mode == "health"
    assert RouteHealth.order("auto:image", (A, B), now=NOW).mode == "priority"
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    assert RouteHealth.order("auto:image", (A, B), now=NOW).candidates == (A, B)


def test_cost_weight_prefers_the_cheaper_candidate_only_when_enabled(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps({
        A: {"input": 10, "output": 30}, B: {"input": 1, "output": 3}}))
    assert order().candidates[0] == A
    monkeypatch.setenv("AUTO_ROUTE_COST_WEIGHT", "0.5")
    assert order().candidates[0] == B


def test_exploration_probes_the_candidate_heard_from_least_recently(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    monkeypatch.setenv("AUTO_ROUTE_EXPLORE_EVERY", "3")
    succeed(A, at=NOW - 10)
    succeed(B, at=NOW - 5)
    modes = [order() for _ in range(3)]
    assert [item.mode for item in modes] == ["health", "health", "health-probe"]
    assert modes[2].candidates[0] == C, "never-seen navyai is the stalest"


def test_memory_is_bounded(monkeypatch):
    for index in range(MAX_TARGETS + 50):
        succeed(f"p{index % 7}:model-{index}")
    for _ in range(MAX_SAMPLES + 10):
        succeed(A)
    assert len(RouteHealth._entries) <= MAX_TARGETS
    assert len(RouteHealth.snapshot(A)["samples"]) == MAX_SAMPLES


def test_summary_reports_rate_median_and_status_without_counts():
    succeed(A, latency_ms=400, times=3)
    succeed(A, latency_ms=900)
    fail(A)
    summary = RouteHealth.summary(A, now=NOW)
    assert summary["success_rate"] == 0.8
    assert summary["p50_latency_ms"] == 400
    assert summary["status"] == "degraded"
    assert "samples" not in summary and "total" not in summary
    fail(A, times=3)
    assert RouteHealth.summary(A, now=NOW)["status"] == "down"
    assert RouteHealth.summary(B, now=NOW)["status"] == "unknown"
    assert RouteHealth.summary("provider:nanogpt", now=NOW)["status"] == "down"


def test_free_checks_nudge_candidates_and_set_provider_check_times(monkeypatch):
    monkeypatch.setenv("AUTO_ROUTE_ORDERING", "health")
    RouteHealth.record_check("nanogpt", ok=False, status=401, candidates=(A, B), now=NOW)
    assert RouteHealth.snapshot(A)["ewma_success"] < 1.0
    assert RouteHealth.snapshot(B) is None, "only the checked provider's candidates change"
    provider = RouteHealth.summary("provider:nanogpt", now=NOW + 60)
    assert provider["last_check"] == "failed" and provider["status"] == "down"
    assert RouteHealth.summary("provider:nanogpt", now=NOW + 3 * 3600)["status"] == "unknown", "stale checks expire"


def test_rows_round_trip_and_merge_keeps_newer_evidence():
    succeed(A, at=NOW - 100)
    rows = RouteHealth.dirty_rows(64)
    assert {row["target"] for row in rows} == {A, "provider:nanogpt"}
    assert all(valid_state(row["state"]) for row in rows)
    RouteHealth.mark_stored(rows)
    assert not RouteHealth.has_changes()

    RouteHealth.reset()
    fail(A, at=NOW)
    assert RouteHealth.merge_rows([*rows, {"target": "x:y", "state": {"kind": "candidate"}}]) == 2
    merged = RouteHealth.snapshot(A)
    assert merged["last_failure_at"] == NOW and merged["last_success_at"] == NOW - 100
    assert len(merged["samples"]) == 2
    assert merged["ewma_at"] == NOW, "the newer in-memory average is kept"


def test_a_row_changed_during_a_write_stays_dirty():
    succeed(A)
    rows = RouteHealth.dirty_rows(64)
    succeed(A)
    RouteHealth.mark_stored(rows)
    assert A in RouteHealth._dirty
