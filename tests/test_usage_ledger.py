"""The write-behind usage ledger, its SQL and D1 stores, and metrics restored from it."""

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from services import usage_ledger, usage_store
from services.intelligence_d1_store import PrivateIntelligenceError
from services.metrics_service import MetricsService


def row(principal="alice", *, at=None, model="openai:gpt-4.1", status=200, latency=300, cost=0.002,
        tokens=(100, 20), kind="chat"):
    return {
        "at": at or usage_ledger.utc_timestamp(), "principal": principal, "key_prefix": "mllm_abcdefgh",
        "kind": kind, "endpoint": "/v1/chat/completions", "requested_model": model, "selected_model": model,
        "status": status, "latency_ms": latency, "input_tokens": tokens[0] if tokens else None,
        "output_tokens": tokens[1] if tokens else None, "cost_usd": cost,
        "cost_basis": "usage" if cost is not None else None, "request_id": "req_test",
    }


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "true")
    monkeypatch.setenv("USAGE_LEDGER_BACKEND", "sql")
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.sqlite3"))
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("USAGE_LEDGER_FLUSH_SECONDS", "300")
    usage_ledger.LEDGER.reset()
    yield usage_ledger.LEDGER
    usage_ledger.LEDGER.reset()


class RecordingStore:
    backend = "sql"

    def __init__(self, failures=0):
        self.batches, self.failures = [], failures

    def record(self, batch_id, rows):
        if self.failures:
            self.failures -= 1
            raise usage_store.UsageStoreError("storage_unavailable")
        self.batches.append((batch_id, list(rows)))
        return len(rows)


def test_rows_are_written_behind_in_batches_with_daily_rollups(ledger):
    store = ledger.store()
    today = usage_ledger.utc_timestamp()[:10]
    assert ledger.record(row(latency=100))
    assert ledger.record(row(latency=5000, status=502, cost=None, tokens=None))
    assert ledger.record(row("bob", model="gguu:gpt-image-2", kind="images", cost=0.04, tokens=None))
    assert store.recent(today, None, None, 10) == [], "recording never writes synchronously"
    assert ledger.flush(timeout=5)
    assert ledger.stats()["recorded"] == 3 and ledger.stats()["buffered"] == 0

    totals = store.totals("alice", today, today[:8] + "01")
    assert totals == {"day_usd": pytest.approx(0.002), "month_usd": pytest.approx(0.002),
                      "day_requests": 2, "month_requests": 2}
    by_model = {entry["model"]: entry for entry in store.summary("model", today, today, None, 10)}
    assert by_model["openai:gpt-4.1"]["requests"] == 2 and by_model["openai:gpt-4.1"]["errors"] == 1
    assert by_model["openai:gpt-4.1"]["priced_requests"] == 1
    assert by_model["openai:gpt-4.1"]["latency_buckets"][0] == 1
    assert by_model["openai:gpt-4.1"]["latency_buckets"][usage_store.latency_bucket(5000)] == 1
    summary = usage_store.summarize(by_model["openai:gpt-4.1"])
    assert summary["error_rate"] == 50.0 and summary["latency_p50_ms"] <= 250 and summary["latency_p95_ms"] > 4000
    principals = [entry["principal"] for entry in store.summary("principal", today, today, None, 10)]
    assert principals == ["bob", "alice"], "ordered by cost"
    assert [entry["day"] for entry in store.summary("day", today, today, "bob", 10)] == [today]

    recent = store.recent(today, "alice", None, 1)
    assert len(recent) == 1 and recent[0]["status"] == 502
    older = store.recent(today, "alice", recent[0]["id"], 5)
    assert [entry["status"] for entry in older] == [200]
    assert "key_prefix" in recent[0] and "prompt" not in recent[0]


def test_a_failed_flush_retries_the_same_batch_then_drops_and_counts(ledger, monkeypatch):
    store = RecordingStore(failures=1)
    monkeypatch.setattr(ledger, "store", lambda: store)
    flushed, dropped = [], []
    ledger.add_listener(flushed.extend, dropped.extend)
    try:
        ledger.record(row())
        assert ledger.flush_once() == 0
        failed_batch = ledger._pending["id"]
        assert ledger.stats()["failed_flushes"] == 1 and ledger.stats()["buffered"] == 1
        ledger.record(row("bob"))
        assert ledger.flush(timeout=5)
        assert store.batches[0][0] == failed_batch, "a retry reuses the batch ID so storage applies it once"
        assert [len(rows) for _, rows in store.batches] == [1, 1]
        assert [item["principal"] for item in flushed] == ["alice", "bob"]

        monkeypatch.setenv("USAGE_LEDGER_MAX_ATTEMPTS", "2")
        store.failures = 5
        ledger.record(row("carol"))
        ledger._pending = None
        assert ledger.flush_once() == 0
        ledger._pending["retry_at"] = 0
        assert ledger.flush_once() == 0
        assert ledger.stats()["dropped"] == 1 and [item["principal"] for item in dropped] == ["carol"]
    finally:
        ledger._listeners.pop()


def test_a_full_buffer_drops_new_rows_and_a_disabled_ledger_reports_them(ledger, monkeypatch):
    monkeypatch.setenv("USAGE_LEDGER_MAX_BUFFER", "2")
    monkeypatch.setattr(ledger, "_ensure_thread", lambda: None)
    dropped = []
    ledger.add_listener(lambda rows: None, dropped.extend)
    try:
        assert ledger.record(row("a")) and ledger.record(row("b"))
        assert not ledger.record(row("c"))
        assert ledger.stats()["dropped"] == 1 and ledger.stats()["buffered"] == 2
        monkeypatch.setenv("USAGE_LEDGER_ENABLED", "false")
        assert not ledger.record(row("d"))
        assert [item["principal"] for item in dropped] == ["c", "d"]
    finally:
        ledger._listeners.pop()


def test_the_background_thread_flushes_without_blocking_requests(ledger, monkeypatch):
    # A full batch wakes the flusher at once instead of waiting for the interval.
    monkeypatch.setenv("USAGE_LEDGER_BATCH_SIZE", "1")
    store = RecordingStore()
    monkeypatch.setattr(ledger, "store", lambda: store)
    started = time.monotonic()
    ledger.record(row())
    assert time.monotonic() - started < 0.5
    deadline = time.monotonic() + 5
    while not store.batches and time.monotonic() < deadline:
        time.sleep(0.02)
    assert store.batches and ledger.stats()["last_flush_at"]


def test_batches_stay_under_the_private_request_limit(ledger, monkeypatch):
    monkeypatch.setattr(ledger, "_ensure_thread", lambda: None)
    monkeypatch.setenv("USAGE_LEDGER_BATCH_SIZE", "500")
    big = dict(row(), endpoint="/" + "e" * 255)
    for _ in range(500):
        ledger.record(dict(big))
    batch = ledger._take_batch()
    assert 1 < len(batch["rows"]) < 500
    assert len(usage_ledger.json.dumps(batch["rows"], separators=(",", ":"))) <= usage_ledger.MAX_BATCH_BYTES


def test_prune_removes_old_raw_rows_and_rollups(ledger, monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(days=45)
    ledger.record(row(at=usage_ledger.utc_timestamp(old)))
    ledger.record(row())
    ledger.flush(timeout=5)
    monkeypatch.setenv("USAGE_LEDGER_ROLLUP_RETENTION_DAYS", "40")
    assert ledger.prune() == {"events": 1, "batches": 0, "rollups": 1}
    store = ledger.store()
    assert len(store.recent("2000-01-01T00:00:00.000Z", None, None, 10)) == 1
    assert len(store.summary("day", "2000-01-01", "2999-12-31", None, 10)) == 1


def test_percentiles_interpolate_inside_buckets():
    assert usage_store.percentile([0] * 11, 0.5) is None
    assert usage_store.percentile([10] + [0] * 10, 0.5) == 125
    assert usage_store.percentile([0] * 10 + [4], 0.95) == 120000
    assert usage_store.percentile([50, 50] + [0] * 9, 0.95) == 475


def test_d1_store_speaks_the_private_usage_operations(monkeypatch):
    calls = []

    def fake(payload, *, endpoint):
        assert endpoint == "usage"
        calls.append(payload)
        if payload["operation"] == "record":
            return {"version": 1, "recorded": len(payload["rows"]), "duplicate": False}
        if payload["operation"] == "totals":
            return {"version": 1, "totals": {"day_usd": 1.5, "month_usd": 3.0, "day_requests": 2, "month_requests": 4}}
        if payload["operation"] == "summary":
            return {"version": 1, "rows": [{"model": "openai:gpt-4.1", **dict.fromkeys(usage_store.TOTAL_COLUMNS[:7], 1),
                                            "latency_buckets": [1] + [0] * 10}]}
        raise PrivateIntelligenceError(503, "storage_unavailable")

    monkeypatch.setattr(usage_store.intelligence_d1_store, "request_private_intelligence", fake)
    store = usage_store.D1UsageStore()
    assert store.record("a" * 32, [row()]) == 1
    assert store.totals("alice", "2026-09-26", "2026-09-01")["month_usd"] == 3.0
    assert store.summary("model", "2026-09-01", "2026-09-26", None, 5)[0]["model"] == "openai:gpt-4.1"
    with pytest.raises(usage_store.UsageStoreError):
        store.recent("2026-09-01T00:00:00.000Z", None, None, 5)
    assert calls[0]["batch"] == "a" * 32 and calls[0]["rows"][0]["principal"] == "alice"

    monkeypatch.setattr(usage_store.intelligence_d1_store, "request_private_intelligence",
                        lambda payload, *, endpoint: {"version": 1, "totals": {"day_usd": "1"}})
    with pytest.raises(usage_store.UsageStoreError):
        store.totals("alice", "2026-09-26", "2026-09-01")


def test_the_backend_follows_the_worker_d1_store_unless_set(monkeypatch):
    monkeypatch.delenv("USAGE_LEDGER_BACKEND", raising=False)
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    assert usage_store.selected_backend() == "d1"
    monkeypatch.setenv("USAGE_LEDGER_BACKEND", "sql")
    assert usage_store.selected_backend() == "sql"
    monkeypatch.delenv("USAGE_LEDGER_BACKEND")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    assert usage_store.selected_backend() == "sql"


def test_recent_requests_survive_a_restart_through_the_ledger(ledger):
    earlier = datetime.now(timezone.utc) - timedelta(hours=2)
    ledger.record(row(at=usage_ledger.utc_timestamp(earlier), status=500))
    ledger.record(row(at=usage_ledger.utc_timestamp(earlier + timedelta(minutes=1))))
    ledger.record(row(at=usage_ledger.utc_timestamp(datetime.now(timezone.utc) - timedelta(days=2))))
    ledger.flush(timeout=5)

    metrics = MetricsService()
    metrics.track_request(provider="openai", status_code=200, response_time=10.0)
    assert usage_ledger.hydrate_metrics(metrics) == 2
    assert len(metrics.requests) == 3
    assert metrics.requests[0]["status_code"] == 500 and metrics.requests[-1]["response_time"] == 10.0
    stats = metrics.get_stats()
    assert stats["total_requests"] == 3 and stats["failed_requests"] == 1
    records = metrics.get_request_records(limit=5)
    assert {record["route_decision"] for record in records} >= {"ledger"}


def test_hydration_never_displaces_live_requests(ledger):
    ledger.record(row(at=usage_ledger.utc_timestamp(datetime.now(timezone.utc) - timedelta(hours=1))))
    ledger.flush(timeout=5)
    metrics = MetricsService()
    for _ in range(metrics.requests.maxlen):
        metrics.track_request(provider="openai", status_code=200, response_time=1.0)
    assert usage_ledger.hydrate_metrics(metrics) == 0


def test_startup_hydration_runs_in_the_background(ledger, monkeypatch):
    finished = threading.Event()
    monkeypatch.setattr(usage_ledger, "hydrate_metrics", lambda metrics: finished.set())
    usage_ledger.start(MetricsService())
    assert finished.wait(5)
