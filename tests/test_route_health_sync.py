"""Route health survives restarts through batched D1 writes that never block a request."""

import pytest

from services import auto_route_d1, intelligence_d1_store, route_health_d1, route_health_sync
from services.intelligence_d1_store import PrivateIntelligenceError
from services.route_health import RouteHealth

NOW = 1_800_000_000.0


class FakeRouteHealthStore:
    """The Worker's fixed route health operations, held in memory."""

    def __init__(self):
        self.rows, self.snapshot, self.calls, self.down = {}, None, [], False

    def __call__(self, payload, *, endpoint):
        if endpoint == "auto_routes":
            return {"version": 1, "routes": []}
        assert endpoint == "route_health"
        self.calls.append(payload["operation"])
        if self.down:
            raise PrivateIntelligenceError(503, "storage_unavailable")
        if payload["operation"] == "list":
            return {"version": 1, "rows": [{"target": target, **row} for target, row in self.rows.items()]}
        if payload["operation"] == "put":
            assert len(payload["rows"]) <= route_health_d1.MAX_ROWS_PER_PUT
            for row in payload["rows"]:
                self.rows[row["target"]] = {"state": row["state"], "updated_at": row["updated_at"]}
            return {"version": 1, "stored": len(payload["rows"])}
        self.snapshot = payload["body"]
        return {"version": 1, "stored": True}


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "registry.sqlite3"))
    monkeypatch.delenv("ROUTE_HEALTH_PERSIST", raising=False)
    fake = FakeRouteHealthStore()
    monkeypatch.setattr(intelligence_d1_store, "request_private_intelligence", fake)
    RouteHealth.reset()
    route_health_sync.reset()
    auto_route_d1.reset_cache()
    yield fake
    RouteHealth.reset()
    route_health_sync.reset()
    auto_route_d1.reset_cache()


def test_changed_entries_and_the_public_snapshot_are_written_in_one_pass(store):
    assert route_health_sync.load()
    RouteHealth.record("nanogpt:zai-org/glm-5.2:thinking", ok=True, outcome="ok", latency_ms=900, now=NOW)
    assert route_health_sync.flush(now=NOW)
    assert set(store.rows) == {"nanogpt:zai-org/glm-5.2:thinking", "provider:nanogpt"}
    assert store.snapshot["version"] == 1
    assert {route["id"] for route in store.snapshot["routes"]} >= {"auto:glm-5.2", "auto:image"}
    assert not RouteHealth.has_changes()
    calls = len(store.calls)
    assert route_health_sync.flush(now=NOW + 1)
    assert len(store.calls) == calls, "nothing changed and the snapshot is recent: no D1 call"


def test_a_restarted_container_starts_from_the_stored_figures(store):
    route_health_sync.load()
    RouteHealth.record("opencode:glm-5.2", ok=False, outcome="http_503", status=503, now=NOW)
    route_health_sync.flush(now=NOW)

    RouteHealth.reset()
    route_health_sync.reset()
    assert RouteHealth.snapshot("opencode:glm-5.2") is None
    assert route_health_sync.load()
    restored = RouteHealth.snapshot("opencode:glm-5.2")
    assert restored["last_failure_at"] == NOW and restored["last_status"] == 503


def test_a_d1_outage_keeps_changes_for_the_next_pass(store):
    route_health_sync.load()
    RouteHealth.record("navyai:glm-5.2", ok=True, outcome="ok", latency_ms=500, now=NOW)
    store.down = True
    assert not route_health_sync.flush(now=NOW)
    assert RouteHealth.has_changes()
    store.down = False
    assert route_health_sync.flush(now=NOW + 60)
    assert "navyai:glm-5.2" in store.rows


def test_nothing_is_written_before_the_stored_rows_are_merged(store):
    store.down = True
    RouteHealth.record("navyai:glm-5.2", ok=True, outcome="ok", now=NOW)
    assert not route_health_sync.load()
    assert not route_health_sync.flush(now=NOW)
    assert store.calls == ["list"], "writing first would replace older stored samples"


def test_persistence_is_off_without_the_d1_store(store, monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    assert not route_health_sync.enabled()
    assert not route_health_sync.start_background()
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("ROUTE_HEALTH_PERSIST", "false")
    assert not route_health_sync.enabled()


def test_an_oversized_snapshot_drops_routes_until_it_fits():
    snapshot = {"version": 1, "routes": [{"id": f"auto:r{index}", "pad": "x" * 10_000} for index in range(40)]}
    bounded = route_health_sync.bounded_snapshot(snapshot)
    assert 0 < len(bounded["routes"]) < 40
    assert bounded["routes"][0]["id"] == "auto:r0"
