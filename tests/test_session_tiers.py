"""Session lane policy and content-free storage contracts."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from services.intelligence_contract import GatewayError
from services.session_tiers import LocalSessionTierStore, SQLiteSessionTierStore, SessionTiers, settings

MIGRATION = "0021_session_tiers.sql"
A = {"model": "openai:a", "quality_tier": 1}
B = {"model": "openai:b", "quality_tier": 2}
F = {"model": "other:a", "quality_tier": 1}
USER = [{"role": "user", "content": "private prompt"}]


def make(store=None):
    return SessionTiers(store or LocalSessionTierStore(), clock=lambda: 100, ttl_seconds=1800)


def begin(service, **kw):
    return service.begin(principal="authenticated", session="private session", lane="main",
                         approved_model="openai:a", approved_tier=1, revision="r1",
                         messages=USER, candidates=[A, B, F], **kw)


@pytest.mark.parametrize("env", [{}, {"SESSION_TIER_MODE": ""}, {"SESSION_TIER_MODE": "bad"},
    {"SESSION_TIER_MODE": "sticky", "SESSION_TIER_TTL_SECONDS": "bad"}])
def test_default_empty_and_malformed_are_off(env, caplog):
    assert not settings(env).enabled
    assert "bad" not in caplog.text


def test_defaults_and_bounds():
    assert settings({"SESSION_TIER_MODE": "sticky", "SESSION_TIER_TTL_SECONDS": ""}).ttl_seconds == 1800
    assert not settings({"SESSION_TIER_MODE": "sticky", "SESSION_TIER_TTL_SECONDS": "86401"}).enabled


def test_role_and_principal_isolation():
    s = make()
    first = begin(s)
    other = s.begin(principal="other", session="private session", lane="main", approved_model=B["model"],
                    approved_tier=2, revision="r1", messages=USER, candidates=[A, B])
    delegated = s.begin(principal="authenticated", session="private session", lane="delegation", approved_model=B["model"],
                        approved_tier=2, revision="r1", messages=USER, candidates=[A, B])
    assert first.select([B, A, F]) == [A, F]
    assert other.select([A, B]) == [B] == delegated.select([A, B])


def test_tool_loop_requires_all_matching_results_before_tier_change():
    s = make()
    t = begin(s)
    t.finish(A, success=True, tool_calls=[{"id": "one"}, {"id": "two"}])
    t = s.begin(principal="authenticated", session="private session", lane="main", approved_model=B["model"],
                approved_tier=2, revision="r1", candidates=[B, A],
                messages=[{"role": "tool", "tool_call_id": "one", "content": "private result"}, *USER])
    assert t.select([B, A]) == [A]
    t.finish(A, success=True)
    t = s.begin(principal="authenticated", session="private session", lane="main", approved_model=B["model"],
                approved_tier=2, revision="r1", candidates=[B, A],
                messages=[{"role": "tool", "tool_call_id": "wrong", "content": "x"}, *USER])
    assert t.select([B, A]) == [A]
    t.finish(A, success=True)
    t = s.begin(principal="authenticated", session="private session", lane="main", approved_model=B["model"],
                approved_tier=2, revision="r1", candidates=[B, A],
                messages=[{"role": "tool", "tool_call_id": "two", "content": "x"}, *USER])
    assert t.select([B, A]) == [B]


def test_unsafe_continuation_cannot_change_and_actual_fallback_is_honest():
    s = make()
    t = begin(s)
    t.finish(F, success=True)
    assert next(iter(s.store.rows.values()))["actual_model"] == F["model"]
    t = s.begin(principal="authenticated", session="private session", lane="main", approved_model=B["model"],
                approved_tier=2, revision="r1", candidates=[A, B, F], messages=[{"role": "assistant", "content": "x"}])
    assert t.select([B, A, F]) == [F, A]
    t.finish(F, success=False)
    assert begin(s).select([A, F]) == [F, A]


def test_revision_expiry_and_credential_failure_clear_only_lane():
    s = make()
    t = begin(s)
    t.finish(A, success=True, tool_calls=[{"id": "one"}])
    s.clock = lambda: 1900
    t = begin(s)
    assert not t.row["pending_tools"]
    t.finish(A, success=True)
    t = s.begin(principal="authenticated", session="private session", lane="main", approved_model=B["model"],
                approved_tier=2, revision="r2", messages=USER, candidates=[B])
    t.finish(None, success=False, credential_failed=True)
    assert not s.store.rows


def test_grants_and_cooldown_admission_win():
    s = make()
    t = begin(s)
    t.finish(A, success=True)
    assert begin(s).select([B, F]) == [F]
    with pytest.raises(GatewayError) as error:
        begin(make(), unavailable=lambda c: True)
    assert error.value.status == 503


def test_same_tier_different_native_model_cannot_enter_the_tool_loop():
    other = {"model": "other:different", "quality_tier": 1}
    t = make().begin(principal="authenticated", session="session", lane="main",
                     approved_model=A["model"], approved_tier=1, revision="r1",
                     messages=USER, candidates=[A, F, other])
    assert t.select([other, F, A]) == [A, F]


def test_concurrent_turns_fail_closed_and_late_finish_cannot_replace_new_binding():
    s = make()
    def attempt(_):
        try:
            return begin(s)
        except GatewayError as e:
            assert e.code == "session_tier_busy"
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        turns = [t for t in pool.map(attempt, range(8)) if t]
    assert len(turns) == 1
    s.clock = lambda: 1900
    current = begin(s)
    turns[0].finish(F, success=True)
    assert next(iter(s.store.rows.values()))["lease"] == current.row["lease"]


def test_store_contains_no_content_or_raw_identity():
    s = make()
    t = begin(s)
    t.finish(A, success=True, tool_calls=[{"id": "private call", "function": {"arguments": "private args"}}])
    saved = json.dumps(s.store.rows)
    assert "private" not in saved and "authenticated" not in saved
    assert len(next(iter(s.store.rows))) == 64


def test_sqlite_migration_additive_old_rows_and_missing_table():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE prior (value TEXT)")
    conn.execute("INSERT INTO prior VALUES ('old')")
    conn.commit()
    s = make(SQLiteSessionTierStore(conn))
    with pytest.raises(GatewayError) as error:
        begin(s)
    assert error.value.code == "session_tier_storage_unavailable" and error.value.status == 503
    sql = (Path(__file__).parents[1] / "intelligence-migrations" / MIGRATION).read_text()
    conn.executescript(sql)
    conn.executescript(sql)
    t = begin(s)
    t.finish(A, success=True)
    assert begin(make(SQLiteSessionTierStore(conn))).select([B, A]) == [A]
    assert conn.execute("SELECT value FROM prior").fetchone()[0] == "old"


def test_capacity_fail_closed():
    s = make(LocalSessionTierStore(max_entries=1))
    begin(s)
    with pytest.raises(GatewayError) as error:
        s.begin(principal="other", session="session", lane="aux", approved_model=A["model"],
                approved_tier=1, revision="r1", messages=USER, candidates=[A])
    assert error.value.status == 503


def test_managed_policy_hook_default_and_explicit_unchanged(monkeypatch):
    import services.intelligence_policy as policy
    from types import SimpleNamespace
    from services.session_tiers import prepare_session_tier
    monkeypatch.setattr(policy, "eligible", lambda *args: True)
    monkeypatch.setattr(policy, "expected_reply_ms", lambda *args: None)
    c = {**A, "capabilities": [], "max_output_tokens": 100, "context_window": 1000}
    request = SimpleNamespace(explicit=False, required=set(), input_tokens=1, output_tokens=1,
        task="chat", profile="balanced", allow_paid=False, payload={"model": "auto:intelligence"})
    choices = policy.select_candidates({"candidates": [c]}, request, {})
    t = begin(make())
    assert policy.select_candidates({"candidates": [c]}, request, {}, session_tier=t) == choices
    body = {"model": "auto:intelligence", "session_tier": {"invalid": "private"}}
    assert prepare_session_tier(body, principal="p", revision="r", candidates=[], environ={}) == (body, None)
    body = {"model": "openai:a", "session_tier": {"invalid": "private"}}
    cleaned, ticket = prepare_session_tier(body, principal="p", revision="r", candidates=[],
                                           environ={"SESSION_TIER_MODE": "sticky"})
    assert cleaned == {"model": "openai:a"} and ticket is None
