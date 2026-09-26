"""Rate limits in D1 mode: in-memory admission, write-behind usage, shared across instances."""

import logging

import pytest

from services import control_state_d1, intelligence_d1_store, rate_limit_d1
from services.rate_limit_service import RateLimitService
from tests.control_state_fake import FakeControlState

ALICE = {"username": "alice", "api_key_prefix": "mllm_live_alice"}
MESSAGE = {"messages": [{"role": "user", "content": "0123456789ab"}], "max_completion_tokens": 5}


@pytest.fixture
def d1(monkeypatch, tmp_path):
    clock = {"now": 1_790_000_040.0 + 1}  # One second into a minute.
    for name, value in {"INTELLIGENCE_STORAGE_BACKEND": "d1", "RATE_LIMIT_ENABLED": "true", "JWT_SECRET": "rate-limit-test",
                        "CONTROL_PLANE_DATABASE_URL": "", "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3")}.items():
        monkeypatch.setenv(name, value)
    for name in ("RATE_LIMIT_RPM", "RATE_LIMIT_TPM", "DAILY_REQUEST_LIMIT", "OPENAI_RATE_LIMIT_RPM", "OPENAI_DAILY_REQUEST_LIMIT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(control_state_d1, "BACKGROUND", False)
    monkeypatch.setattr(rate_limit_d1, "_clock", lambda: clock["now"])
    fake = FakeControlState(lambda: clock["now"])
    monkeypatch.setattr(intelligence_d1_store, "request_private_intelligence", fake)
    rate_limit_d1.reset()
    fake.clock_state = clock
    yield fake
    rate_limit_d1.reset()
    assert not (tmp_path / "limits.sqlite3").exists(), "D1 mode keeps no Container-local usage database"


def enforce(user=ALICE, provider="openai"):
    return RateLimitService.enforce_request(provider, user, b"{}", MESSAGE, "203.0.113.10")


def test_requests_are_admitted_from_memory_and_flushed_in_the_background(d1):
    for _ in range(5):
        assert enforce().allowed
    assert d1.calls == [], "admission never waits on D1"
    rate_limit_d1.sync()
    assert d1.calls == [("rate_limits", "sync")]
    _, payload = d1.payloads[0]
    [increment] = payload["increments"]
    assert (increment["requests"], increment["tokens"]) == (5, 5 * 8)
    assert "alice" not in str(d1.usage) and "203.0.113.10" not in str(d1.usage), "D1 holds keyed hashes only"
    assert sorted(span for (_, _, span, _, _) in d1.usage) == [60, 3600]


def test_a_daily_budget_survives_a_restart_after_one_refresh(d1, monkeypatch):
    monkeypatch.setenv("DAILY_REQUEST_LIMIT", "3")
    assert all(enforce().allowed for _ in range(3))
    assert enforce().error == "daily_budget_exceeded"
    rate_limit_d1.sync()
    rate_limit_d1.reset()  # A new Container: empty memory and a new ledger identity.
    d1.clock_state["now"] += 3600
    # Until the first refresh the new process knows only its own usage: brief over-admission.
    assert enforce().allowed
    rate_limit_d1.sync()
    decision = enforce()
    assert (decision.allowed, decision.error) == (False, "daily_budget_exceeded")


def test_instances_share_the_minute_window(d1, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_RPM", "4")
    assert all(enforce().allowed for _ in range(3))
    rate_limit_d1.sync()
    rate_limit_d1.reset()  # Another instance.
    assert enforce().allowed
    rate_limit_d1.sync()
    assert d1.payloads[-1][1]["read"], "the new identity's shared usage is fetched on the next sync"
    decision = enforce()
    assert (decision.allowed, decision.error) == (False, "rate_limit_exceeded")
    d1.clock_state["now"] += 120
    rate_limit_d1.sync()
    assert enforce().allowed, "shared per-minute usage expires with its minute"


def test_reservations_are_finalized_in_memory_with_exact_tokens(d1):
    reservation = RateLimitService.reserve_request_slot("kimi-code", ALICE, "203.0.113.10")
    finalized = RateLimitService.finalize_request_slot(
        reservation.metadata["reservation_id"], "kimi-code", ALICE, b"{}", MESSAGE, "203.0.113.10")
    assert reservation.allowed and finalized.allowed
    assert (finalized.metadata["input_tokens"], finalized.metadata["output_tokens"]) == (3, 5)
    wrong = RateLimitService.finalize_request_slot(
        reservation.metadata["reservation_id"], "kimi-code", {"username": "mallory"}, b"{}", MESSAGE, "203.0.113.10")
    assert wrong.error == "invalid_rate_reservation"
    assert d1.calls == []
    rate_limit_d1.sync()
    [increment] = d1.payloads[0][1]["increments"]
    assert (increment["requests"], increment["tokens"]) == (1, 8)


def test_an_outage_keeps_local_limits_and_a_resent_flush_counts_once(d1, monkeypatch, caplog):
    monkeypatch.setenv("RATE_LIMIT_RPM", "3")
    d1.down.add("rate_limits")
    with caplog.at_level(logging.WARNING, logger="services.rate_limit_d1"):
        assert all(enforce().allowed for _ in range(3))
        rate_limit_d1.sync()
    assert "could not be synced" in caplog.text
    assert enforce().error == "rate_limit_exceeded", "this Container's own counts still limit"
    rate_limit_d1.sync()
    assert d1.count("rate_limits") == 1, "a failed sync backs off instead of retrying every tick"
    d1.down.clear()
    d1.lose_reply = True
    d1.clock_state["now"] += rate_limit_d1.FAILURE_BACKOFF_SECONDS
    rate_limit_d1.sync()
    first = d1.payloads[-1][1]["flush_id"]
    d1.lose_reply = False
    d1.clock_state["now"] += rate_limit_d1.FAILURE_BACKOFF_SECONDS
    rate_limit_d1.sync()
    assert d1.payloads[-1][1]["flush_id"] == first, "an uncertain flush is resent unchanged"
    assert sum(requests for (_, _, span, _, _), (requests, _) in d1.usage.items() if span == 3600) == 3


def test_a_refused_flush_is_dropped_instead_of_resent(d1):
    assert enforce().allowed
    d1.refuse = True
    rate_limit_d1.sync()
    d1.refuse = False
    d1.clock_state["now"] += rate_limit_d1.FAILURE_BACKOFF_SECONDS
    rate_limit_d1.sync()
    assert d1.payloads[-1][1]["increments"] == []


def test_disabled_rate_limits_and_non_d1_mode_do_not_touch_d1(d1, monkeypatch, tmp_path):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    assert enforce().allowed
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "local" / "limits.sqlite3"))
    assert enforce().allowed
    control_state_d1.run_tasks()
    assert d1.calls == []
    assert (tmp_path / "local" / "limits.sqlite3").exists(), "without D1 the local ledger is used as before"
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "limits.sqlite3"))


def test_the_background_thread_starts_once_per_process(monkeypatch):
    started = []
    monkeypatch.setattr(control_state_d1, "BACKGROUND", True)
    monkeypatch.setattr(control_state_d1, "_worker", {"thread": None, "pid": None})
    monkeypatch.setattr(control_state_d1, "_run", lambda: started.append(True))
    control_state_d1.ensure_running()
    control_state_d1._worker["thread"].join(timeout=5)
    assert started == [True]
    monkeypatch.setattr(control_state_d1, "BACKGROUND", False)
    control_state_d1.ensure_running()
    assert started == [True]
