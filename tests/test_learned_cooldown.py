"""Passive cooldown learning with synthetic traffic and storage."""

import importlib
import json
import math
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

PROVIDER = "ce-gpt-pro"
KEYS = ["synthetic-first", "synthetic-second"]
RULE = {"provider": PROVIDER, "model": "A", "quota_bucket": None}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    global learned, credentials, nano, cooldown, classify, store
    cooldown = importlib.import_module("services.model_cooldown")
    learned = cooldown.learned
    credentials = importlib.import_module("services.credential_pool")
    nano = importlib.import_module("services.nanogpt_key_pool")
    classify = importlib.import_module("services.upstream_outcome").classify_upstream_outcome
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", "apply")
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", json.dumps({"buckets": [RULE]}))
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "local")
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true")
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "3600")
    monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", "false")
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", "false")
    store = learned.LearnedCooldown()
    monkeypatch.setattr(learned, "learned_cooldown", store)
    monkeypatch.setattr(credentials.CredentialPool, "keys", staticmethod(lambda provider: KEYS))
    for pool in (credentials.CredentialPool, nano.NanoGPTKeyPool, nano.NanoGPTUnifiedKeyPool):
        pool.reset()
    cooldown.model_cooldown.reset()
    yield
    for pool in (credentials.CredentialPool, nano.NanoGPTKeyPool, nano.NanoGPTUnifiedKeyPool):
        pool.reset()
    cooldown.model_cooldown.reset()


def observe(status, now, **kwargs):
    return store.observe(PROVIDER, KEYS[0], classify(status), model="A", now=now, **kwargs)


def recoveries(count=3, start=100, delay=60):
    result = None
    for index in range(count):
        observe(429, start + index * (delay + 1))
        result = observe(200, start + index * (delay + 1) + delay)
    return result


def test_three_recoveries_choose_binary_trial_then_failures_raise_lower():
    first = recoveries(2)
    assert not first.confident
    assert first.steps == 0
    assert first.upper_seconds == 60
    result = recoveries(1, start=222)
    assert result.confident and result.steps == 1
    assert result.suggested_seconds == 30
    observe(429, 300)
    for now in (330, 361, 393):
        result = observe(429, now)
    assert result.lower_seconds == 33
    assert result.steps == 2
    assert result.suggested_seconds == 46


def test_success_requires_later_throttle_in_same_bucket():
    assert observe(200, 100) is None
    observe(429, 100)
    other = store.observe(PROVIDER, KEYS[1], classify(200), model="A", now=160)
    assert other is None
    result = observe(200, 160)
    assert result.upper_seconds == 60 and result.samples == 2
    assert observe(200, 200) is None


def test_contradictions_and_out_of_order_noise_widen_and_disable_apply():
    recoveries()
    observe(429, 300)
    result = observe(429, 400)
    assert result.upper_seconds > 60 and not result.confident
    width = result.upper_seconds - result.lower_seconds
    result = observe(200, 399)
    assert result.upper_seconds - result.lower_seconds >= width
    assert not result.confident


def test_minimum_floor_including_outside_learning_bounds(monkeypatch):
    recoveries()
    delay = learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A",
        now=300, current_seconds=60, retry_after_seconds=90)
    assert delay >= 90
    assert observe(200, 320).lower_seconds >= 70
    assert learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A",
        now=401, current_seconds=10, retry_after_seconds=7200) >= 7200


@pytest.mark.parametrize("hint", [math.nan, math.inf, -1, True, "90"])
def test_untrusted_hints_do_not_become_floors(hint):
    recoveries()
    assert learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A",
        now=300, current_seconds=60, retry_after_seconds=hint) == 30


def test_max_steps_and_absolute_ttl():
    result = recoveries(45)
    assert result.steps == 12
    assert 1 <= result.lower_seconds <= result.upper_seconds <= 3600
    entry = next(iter(store.snapshot(now=3000).values()))
    assert learned.valid_state(entry, entry["credential_digest"], 3000)
    assert len(store.snapshot(now=100 + learned.TTL_SECONDS)) == 0
    result = observe(429, 100 + learned.TTL_SECONDS)
    assert result.steps == 0 and result.samples == 1


def test_trusted_floor_persists_for_later_observations():
    recoveries()
    learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A", now=300,
        current_seconds=60, retry_after_seconds=7200)
    assert learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A", now=400,
        current_seconds=60) >= 7100


def test_default_mode_warning_once_and_no_value(monkeypatch, caplog):
    learned._warned.clear()
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", "private-malformed-mode")
    assert learned.settings().mode == "off"
    assert learned.settings().mode == "off"
    assert len(caplog.records) == 1
    assert "private-malformed-mode" not in caplog.text


def test_quota_only_opt_in_uses_exact_match(monkeypatch):
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", json.dumps({"buckets": [{**RULE, "model": None, "quota_bucket": "shared"}]}))
    assert store.observe(PROVIDER, KEYS[0], classify(429), model="A", quota_bucket="shared", now=100) is None
    assert store.observe(PROVIDER, KEYS[0], classify(429), quota_bucket="shared", now=100) is not None


def test_model_cooldown_cap_and_trusted_floor(monkeypatch):
    recoveries()
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "10")
    credentials.CredentialPool.record(PROVIDER, KEYS[0], 429, model="A", now=300)
    assert credentials.CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=310) == KEYS[:1]
    credentials.CredentialPool.record(PROVIDER, KEYS[0], 429, model="A", now=400, retry_after_seconds=90)
    assert credentials.CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=410) == []
    assert credentials.CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=490) == KEYS[:1]


@pytest.mark.parametrize("status", [400, 401, 402, 403, 404, 422, 500, 503])
def test_auth_caller_and_provider_failures_are_not_learned(status):
    assert observe(status, 100) is None
    assert store.snapshot(now=100) == {}
    cancelled = classify(429, cancelled=True)
    assert store.observe(PROVIDER, KEYS[0], cancelled, model="A", now=100) is None


@pytest.mark.parametrize("mode", ["off", "", "malformed"])
def test_off_preserves_state_cooldowns_order_and_no_storage(monkeypatch, mode):
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", mode)
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", "malformed-private-value")
    monkeypatch.setattr(store, "observe", Mock(side_effect=AssertionError("storage touched")))
    credentials.CredentialPool.record(PROVIDER, KEYS[0], 429, model="A", now=100)
    assert credentials.CredentialPool.select(PROVIDER, model="A", now=101) == KEYS[1]
    assert credentials.CredentialPool.available(PROVIDER, KEYS, model="A", now=160) == KEYS
    assert credentials.CredentialPool._resting == {}
    assert store.snapshot(now=100) == {}


@pytest.mark.parametrize("seconds", [0, 60])
def test_off_passes_nanogpt_rejection_cooldown_through(monkeypatch, seconds):
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", "off")
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "false")
    invalidate = Mock()
    monkeypatch.setattr(nano.NanoGPTKeyPool, "invalidate", invalidate)
    nano.NanoGPTKeyPool.record_result(KEYS[0], 429, rejected_cooldown_seconds=seconds, now=100)
    assert invalidate.call_args.kwargs["rejected_cooldown_seconds"] == seconds


def test_shadow_reports_suggestion_without_changing_cooldowns(monkeypatch, caplog):
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", "shadow")
    recoveries()
    with caplog.at_level("INFO", logger=learned.__name__):
        credentials.CredentialPool.record(PROVIDER, KEYS[0], 429, model="A", now=300)
    assert credentials.CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=330) == []
    assert credentials.CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=360) == KEYS[:1]
    assert "suggested_seconds=30" in caplog.text
    assert all(key not in caplog.text for key in KEYS)


@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize("kind", ["credential", "nano", "unified"])
def test_registered_pool_record_paths_apply_only_duration(monkeypatch, scoped, kind):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true" if scoped else "false")
    provider = PROVIDER if kind == "credential" else ("nanogpt" if kind == "nano" else "nanogpt-unified")
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", json.dumps({"buckets": [{**RULE, "provider": provider}]}))
    if kind == "credential":
        record = lambda status, now: credentials.CredentialPool.record(provider, KEYS[0], status, model="A", now=now)
        available = lambda now: credentials.CredentialPool.available(provider, KEYS, model="A", now=now)
    else:
        pool = nano.NanoGPTKeyPool if kind == "nano" else nano.NanoGPTUnifiedKeyPool
        record = lambda status, now: pool.record_result(KEYS[0], status, model="A", now=now)
        available = lambda now: [pool.select_available_key(KEYS, model="A", now=now)]
    for start in (100, 161, 222):
        record(429, start)
        record(200, start + 60)
    record(429, 300)
    assert KEYS[0] not in available(329)
    assert KEYS[0] in available(330)
    assert not classify(429).replay_permission


def test_model_quota_credential_and_provider_isolation(monkeypatch):
    rules = [RULE, {**RULE, "model": "B"}, {**RULE, "quota_bucket": "q"}, {**RULE, "provider": "ce-gpt-plus"}]
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", json.dumps({"buckets": rules}))
    recoveries()
    for changes in ({"model": "B"}, {"quota_bucket": "q"}, {"provider": "ce-gpt-plus"}, {"credential": KEYS[1]}):
        args = {"provider": PROVIDER, "credential": KEYS[0], "model": "A", "outcome": classify(429), "now": 300, **changes}
        result = store.observe(**args)
        assert result.steps == 0 and not result.confident
    encoded = json.dumps(store.snapshot(now=300))
    assert all(text not in encoded for text in [*KEYS, PROVIDER, "ce-gpt-plus"])


@pytest.mark.parametrize("policy", ["[]", '{"extra":1}', '{"buckets":[{}]}',
    '{"buckets":[{"provider":"*","model":"A","quota_bucket":null}]}',
    '{"buckets":[{"provider":"ce-gpt-pro","model":true,"quota_bucket":null}]}',
    '{"buckets":[{"provider":"ce-gpt-pro","model":null,"quota_bucket":null}]}',
    '{"buckets":[],"buckets":[]}', '{"buckets":[NaN]}'])
def test_strict_policy_fails_off_once_without_values(monkeypatch, caplog, policy):
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", policy)
    learned._warned.clear()
    assert learned.settings().mode == "off"
    assert learned.settings().mode == "off"
    assert len(caplog.records) == 1 and policy not in caplog.text


def test_empty_defaults_no_opt_in_and_bounded_concurrency(monkeypatch):
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", "")
    assert observe(429, 100) is None
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", json.dumps({"buckets": [RULE]}))
    small = learned.LearnedCooldown(max_entries=2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda index: small.observe(PROVIDER, f"synthetic-{index}", classify(429), model="A", now=100), range(10)))
    assert sum(result is not None for result in results) == 2
    assert len(small.snapshot(now=100)) == 2


def test_policy_budget_counts_utf8_bytes(monkeypatch):
    rules = [{**RULE, "model": "界" * 250 + str(index)} for index in range(50)]
    policy = json.dumps({"buckets": rules}, ensure_ascii=False)
    assert len(policy) < 32768 < len(policy.encode("utf-8"))
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", policy)
    assert learned.settings().mode == "off"


def test_d1_missing_table_falls_back_once_and_off_never_calls(monkeypatch, caplog):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    call = Mock(side_effect=RuntimeError("sensitive storage detail"))
    monkeypatch.setattr(store, "_call", call)
    learned._warned.clear()
    for now in (100, 200):
        assert learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A", now=now, current_seconds=60) == 60
    assert len(caplog.records) == 1 and "sensitive" not in caplog.text
    monkeypatch.setenv("LEARNED_COOLDOWN_MODE", "off")
    call.reset_mock()
    assert observe(429, 300) is None
    call.assert_not_called()


def test_fixed_d1_transport_uses_named_allowlist_endpoint(monkeypatch):
    control = importlib.import_module("services.control_state_d1")
    call = Mock(return_value={"version": 1, "entry": None})
    monkeypatch.setattr(control, "call", call)
    digest = "a" * 64
    assert store._call("get", bucket_digest=digest, credential_digest=digest, now=100)["entry"] is None
    call.assert_called_once_with("learned-cooldown", "get", bucket_digest=digest, credential_digest=digest, now=100)


def test_d1_contract_cas_conflict_and_invalid_rows_fail_to_existing(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    rows = {}
    conflict = [False]
    def call(operation, **values):
        assert all(key not in json.dumps(values) for key in KEYS)
        if operation == "get":
            return {"version": 1, "entry": rows.get(values["bucket_digest"])}
        if conflict[0]:
            return {"version": 1, "stored": False}
        rows[values["bucket_digest"]] = values["entry"]
        return {"version": 1, "stored": True}
    monkeypatch.setattr(store, "_call", call)
    recoveries()
    assert next(iter(rows.values()))["steps"] == 1
    conflict[0] = True
    assert learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A", now=300, current_seconds=60) == 60
    conflict[0] = False
    next(iter(rows.values()))["lower_seconds"] = -1
    assert learned.adjust_cooldown(PROVIDER, KEYS[0], classify(429), model="A", now=400, current_seconds=60) == 60


def test_catalog_probes_are_not_observations(monkeypatch):
    monkeypatch.setenv("LEARNED_COOLDOWN_POLICY_JSON", json.dumps({"buckets": [{**RULE, "provider": "nanogpt"}]}))
    probe = Mock(return_value=200)
    assert nano.NanoGPTKeyPool.select_key(KEYS, probe, model="A", now=100) == KEYS[0]
    assert probe.call_count == 1 and store.snapshot(now=100) == {}


def test_migration_additive_idempotent_preserves_old_rows():
    import sqlite3
    from pathlib import Path
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE old_state (value TEXT)")
    db.execute("INSERT INTO old_state VALUES ('kept')")
    sql = Path("intelligence-migrations/0031_learned_cooldown.sql").read_text()
    db.executescript(sql)
    db.executescript(sql)
    assert db.execute("SELECT value FROM old_state").fetchone() == ("kept",)
    assert "learned_cooldown" in {row[0] for row in db.execute("SELECT name FROM sqlite_master")}
