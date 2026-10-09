"""Reset scheduling with synthetic identities, clocks, and upstream responses."""

import importlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from flask import Flask, g

PROVIDER = "ce-gpt-pro"
KEYS = ["synthetic-first", "synthetic-second", "synthetic-third"]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    global schedule, credentials, nano, cooldown
    schedule = importlib.import_module("services.pool_reset_schedule")
    credentials = importlib.import_module("services.credential_pool")
    nano = importlib.import_module("services.nanogpt_key_pool")
    cooldown = importlib.import_module("services.model_cooldown")
    monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", "true")
    monkeypatch.setenv("POOL_OBSERVATION_TTL_SECONDS", "60")
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "false")
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "3600")
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", "false")
    credentials.CredentialPool.reset()
    nano.NanoGPTKeyPool.reset()
    nano.NanoGPTUnifiedKeyPool.reset()
    cooldown.model_cooldown.reset()
    clock = [1000.0]
    store = schedule.PoolResetSchedule(clock=lambda: clock[0], monotonic=lambda: clock[0])
    monkeypatch.setattr(schedule, "pool_reset_schedule", store)
    monkeypatch.setattr(credentials.CredentialPool, "keys", staticmethod(lambda provider: KEYS))
    yield clock, store
    credentials.CredentialPool.reset()
    nano.NanoGPTKeyPool.reset()
    nano.NanoGPTUnifiedKeyPool.reset()
    cooldown.model_cooldown.reset()


def observe(store, key, delay, *, provider=PROVIDER, remaining=10, **kwargs):
    store.observe(provider, store.credential_id(provider, key), [
        {"remaining": remaining, "resets_in_ms": delay * 1000}
    ], observed_at=1000, **kwargs)


def test_fresh_reset_order_stable_ties_and_unknown_fallback(isolated):
    clock, store = isolated
    observe(store, KEYS[0], 100)
    observe(store, KEYS[1], 20)
    observe(store, KEYS[2], 20)
    assert credentials.CredentialPool.available(PROVIDER, KEYS, now=1000) == [KEYS[1], KEYS[2], KEYS[0]]
    assert credentials.CredentialPool.select(PROVIDER, now=1000) == KEYS[1]
    assert store.available(PROVIDER, [KEYS[2], KEYS[1]], configured_order=KEYS) == KEYS[1:]
    clock[0] = 1060
    assert credentials.CredentialPool.select(PROVIDER, now=1060) == KEYS[0]
    assert store.entry_count == 0
    observe(store, KEYS[1], 200)
    assert store.available(PROVIDER, KEYS) == KEYS


def test_exhaustion_and_cooling_excluded_despite_near_reset(isolated):
    _, store = isolated
    observe(store, KEYS[0], 1, remaining=0)
    observe(store, KEYS[1], 2)
    observe(store, KEYS[2], 100)
    credentials.CredentialPool.record(PROVIDER, KEYS[1], 429, now=1000)
    assert credentials.CredentialPool.available(PROVIDER, KEYS, now=1000) == KEYS[2:]
    assert credentials.CredentialPool.select(PROVIDER, now=1000) == KEYS[2]


def test_account_model_bucket_and_pool_isolation(isolated):
    _, store = isolated
    observe(store, KEYS[0], 20, remaining=0, model="A")
    assert store.available(PROVIDER, KEYS, model="A") == KEYS[1:]
    assert store.available(PROVIDER, KEYS, model="B") == KEYS
    assert store.available("ce-gpt-plus", KEYS, model="A") == KEYS
    observe(store, KEYS[1], 30, remaining=0, quota_bucket="shared")
    assert store.available(PROVIDER, KEYS, model="B", quota_bucket="shared") == [KEYS[0], KEYS[2]]
    observe(store, KEYS[2], 40, remaining=0)
    assert store.available(PROVIDER, KEYS, model="B") == KEYS[:2]


@pytest.mark.parametrize("window", [
    {"limit": 10, "used": 9, "remaining": 8, "resets_in_ms": 1000},
    {"remaining": -1, "resets_in_ms": 1000},
    {"remaining": True, "resets_in_ms": 1000},
    {"remaining": float("nan"), "resets_in_ms": 1000},
    {"limit": 10, "used": 10, "remaining": 0, "percent_used": 20, "resets_in_ms": 1000},
    {"remaining": 10, "resets_at": "bad-date"},
    {"remaining": 10, "resets_at": "1970-01-01T00:00:01Z"},
    {"remaining": 10, "resets_in_ms": 1000, "resets_at": "1970-01-01T00:30:00Z"},
])
def test_contradictory_or_missing_data_clears_old_evidence(isolated, window):
    _, store = isolated
    observe(store, KEYS[0], 10, remaining=0)
    store.observe(PROVIDER, store.credential_id(PROVIDER, KEYS[0]), [window], observed_at=1000)
    assert store.available(PROVIDER, KEYS) == KEYS


def test_derived_quota_multiple_windows_and_reset_rollover(isolated):
    clock, store = isolated
    store.observe(PROVIDER, store.credential_id(PROVIDER, KEYS[0]), [
        {"limit": 10, "used": 5, "resets_in_ms": 10000},
        {"remaining": 0, "resets_in_ms": 20000},
    ], observed_at=1000)
    assert store.available(PROVIDER, KEYS) == KEYS[1:]
    clock[0] = 1021
    assert store.available(PROVIDER, KEYS) == KEYS


def test_clock_skew_old_observations_and_retry_bounds(isolated):
    clock, store = isolated
    for observed_at in (900, 1010, float("inf")):
        store.observe(PROVIDER, store.credential_id(PROVIDER, KEYS[0]), [
            {"remaining": 0, "resets_in_ms": 10000}
        ], observed_at=observed_at)
        assert store.available(PROVIDER, KEYS) == KEYS
    observe(store, KEYS[0], 999999, remaining=0)
    assert store.retry_after(PROVIDER, KEYS, fallback=5) == 3600
    clock[0] = 999
    assert store.available(PROVIDER, KEYS) == KEYS
    assert store.retry_after(PROVIDER, KEYS, fallback=-1) == 1


@pytest.mark.parametrize("flag", [None, "", "false", "0", "malformed-secret-value"])
@pytest.mark.parametrize("model_cooldown", ["false", "true"])
def test_disabled_sequences_cooldowns_and_errors_unchanged(isolated, monkeypatch, flag, model_cooldown):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", model_cooldown)

    def sequence(value):
        if value is None:
            monkeypatch.delenv("POOL_RESET_SCHEDULING_ENABLED", raising=False)
        else:
            monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", value)
        credentials.CredentialPool.reset()
        nano.NanoGPTKeyPool.reset()
        cooldown.model_cooldown.reset()
        selected = []
        for key in KEYS:
            selected.append(credentials.CredentialPool.select(PROVIDER, now=1000))
            credentials.CredentialPool.record(PROVIDER, key, 429, now=1000)
        selected.append(credentials.CredentialPool.select(PROVIDER, now=1001))
        selected.append(credentials.CredentialPool.select(PROVIDER, now=1060))
        probe = Mock(return_value=200)
        for key in KEYS:
            selected.append(nano.NanoGPTKeyPool.select_key(KEYS, probe, now=1000))
            nano.NanoGPTKeyPool.record_result(key, 429, now=1000)
        with pytest.raises(nano.NanoGPTKeyPoolExhausted) as error:
            nano.NanoGPTKeyPool.select_key(KEYS, probe, now=1001)
        return selected, dict(credentials.CredentialPool._resting), dict(nano.NanoGPTKeyPool._rejected_until), str(error.value), probe.call_args_list

    expected = sequence("false")
    assert sequence(flag) == expected
    assert isolated[1].entry_count == 0


@pytest.mark.parametrize("value", ["bad-sensitive-value", "4", "3601", "1.5", "-1", "NaN"])
def test_invalid_ttl_disables_once_without_value(monkeypatch, caplog, value):
    schedule._warned_settings.clear()
    monkeypatch.setenv("POOL_OBSERVATION_TTL_SECONDS", value)
    assert not schedule.settings().enabled
    assert not schedule.settings().enabled
    records = [r.message for r in caplog.records if "POOL_OBSERVATION_TTL_SECONDS" in r.message]
    assert len(records) == 1
    assert value not in records[0]


def test_empty_defaults_and_malformed_flag(monkeypatch, caplog):
    monkeypatch.setenv("POOL_OBSERVATION_TTL_SECONDS", "")
    assert schedule.settings().ttl_seconds == 60
    for value in ("5", "3600"):
        monkeypatch.setenv("POOL_OBSERVATION_TTL_SECONDS", value)
        assert schedule.settings().enabled
    schedule._warned_settings.clear()
    monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", "flag-sensitive-value")
    assert not schedule.settings().enabled
    assert not schedule.settings().enabled
    assert len(caplog.records) == 1
    assert "flag-sensitive-value" not in caplog.text


@pytest.mark.parametrize("scoped", [False, True])
def test_real_429_keeps_body_refines_advice_and_never_dispatches(isolated, monkeypatch, scoped):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true" if scoped else "false")
    _, store = isolated
    for key, delay in zip(KEYS, [30, 10, 20]):
        observe(store, key, delay, remaining=0, model="A")
        credentials.CredentialPool.record(PROVIDER, key, 429, model="A", now=1000)
    app = Flask(__name__)
    app.register_error_handler(cooldown.ModelCooldownExhausted, cooldown.cooldown_error_response)
    send = Mock()

    @app.before_request
    def request_id():
        g.request_id = "synthetic-request-id"

    @app.post("/v1/test-reset")
    def dispatch():
        credentials.CredentialPool.select(PROVIDER, model="A", now=1000)
        send()
        return {"ok": True}

    response = app.test_client().post("/v1/test-reset", json={"model": "A"})
    with app.test_request_context():
        g.request_id = "synthetic-request-id"
        expected = cooldown.ModelCooldownExhausted(60).to_dict()
    assert response.status_code == 429
    assert response.json == expected
    assert response.headers["Retry-After"] == "10"
    send.assert_not_called()


@pytest.mark.parametrize("pool_name", ["NanoGPTKeyPool", "NanoGPTUnifiedKeyPool"])
@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize("single", [False, True])
def test_nanogpt_without_observations_preserves_validation_sequence(isolated, monkeypatch, pool_name, scoped, single):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true" if scoped else "false")
    pool = getattr(nano, pool_name)
    keys = KEYS[:1] if single else KEYS

    def sequence(flag):
        monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", flag)
        pool.reset()
        cooldown.model_cooldown.reset()
        probe = Mock(side_effect=[503, 200, 200] if single else [401, 200, 503, 200, 401, 200])
        selected = []
        for now in (1000, 1001, 1002, 1003, 1014, 1015):
            key = pool.select_key(keys, probe, now=now, model="A" if scoped else None,
                                  check_ttl_seconds=10, check_every_requests=2)
            selected.append(key)
            pool.record_result(key, 200, now=now, model="A" if scoped else None)
        return selected, probe.call_args_list, pool._active_until, pool._active_requests, dict(pool._rejected_until)

    expected = sequence("false")
    assert expected[0] == ([KEYS[0]] * 6 if single else [KEYS[1], KEYS[1], KEYS[2], KEYS[2], KEYS[0], KEYS[0]])
    assert len(expected[1]) == (2 if single else 6)
    assert sequence("true") == expected


@pytest.mark.parametrize("pool_name", ["NanoGPTKeyPool", "NanoGPTUnifiedKeyPool"])
@pytest.mark.parametrize("scoped", [False, True])
def test_nanogpt_exhausted_active_key_validates_replacement(isolated, monkeypatch, pool_name, scoped):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true" if scoped else "false")
    pool = getattr(nano, pool_name)
    probe = Mock(return_value=200)
    assert pool.select_key(KEYS[:2], probe, now=1000, model="A") == KEYS[0]
    observe(isolated[1], KEYS[0], 10, provider=pool._model_cooldown_provider, remaining=0, model="A")
    assert pool.select_key(KEYS[:2], probe, now=1001, model="A") == KEYS[1]
    assert [call.args[0] for call in probe.call_args_list] == KEYS[:2]


@pytest.mark.parametrize("pool_name", ["NanoGPTKeyPool", "NanoGPTUnifiedKeyPool"])
def test_nanogpt_reset_order_changes_first_probe_but_keeps_validated_active(isolated, pool_name):
    pool = getattr(nano, pool_name)
    provider = pool._model_cooldown_provider
    observe(isolated[1], KEYS[0], 100, provider=provider)
    observe(isolated[1], KEYS[1], 10, provider=provider)
    probe = Mock(return_value=200)
    assert pool.select_key(KEYS, probe, now=1000, check_every_requests=1) == KEYS[1]
    observe(isolated[1], KEYS[0], 5, provider=provider)
    assert pool.select_key(KEYS, probe, now=1001, check_every_requests=1) == KEYS[1]
    probe.assert_called_once_with(KEYS[1])
    pool.record_result(KEYS[1], 200, now=1001)
    assert pool.select_key(KEYS, probe, now=1002, check_every_requests=1) == KEYS[1]
    assert [call.args[0] for call in probe.call_args_list] == [KEYS[1], KEYS[1]]


@pytest.mark.parametrize("pool_name", ["NanoGPTKeyPool", "NanoGPTUnifiedKeyPool"])
@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize("cooling", [False, True])
def test_nanogpt_exhausted_or_cooling_pool_raises_without_probe(isolated, monkeypatch, pool_name, scoped, cooling):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true" if scoped else "false")
    pool = getattr(nano, pool_name)
    for key, delay in zip(KEYS, [30, 10, 20]):
        observe(isolated[1], key, delay, provider=pool._model_cooldown_provider,
                remaining=10 if cooling else 0, model="A")
        if cooling:
            pool.record_result(key, 429, now=1000, model="A")
    probe = Mock(side_effect=AssertionError("Exhausted selection must not probe"))
    with pytest.raises(cooldown.ModelCooldownExhausted) as error:
        pool.select_key(KEYS, probe, now=1000, model="A")
    assert error.value.retry_after == 10
    probe.assert_not_called()


@pytest.mark.parametrize("pool_name", ["NanoGPTKeyPool", "NanoGPTUnifiedKeyPool"])
def test_nanogpt_available_selection_keeps_no_probe_behavior(isolated, pool_name):
    pool = getattr(nano, pool_name)
    provider = pool._model_cooldown_provider
    observe(isolated[1], KEYS[0], 100, provider=provider)
    observe(isolated[1], KEYS[1], 10, provider=provider)
    assert pool.select_available_key(KEYS, now=1000) == KEYS[1]
    for key in KEYS:
        pool.record_result(key, 429, retry_after_seconds=11, now=1000)
    with pytest.raises(cooldown.ModelCooldownExhausted) as error:
        pool.select_available_key(KEYS, now=1000)
    assert error.value.retry_after == 11


def test_record_result_metadata_and_cancelled_outcome(isolated):
    _, store = isolated
    credentials.CredentialPool.record(PROVIDER, KEYS[0], 429, retry_after_seconds=15, model="A", now=1000)
    assert store.retry_after(PROVIDER, KEYS, model="A") == 15
    cancelled = importlib.import_module("services.upstream_outcome").classify_upstream_outcome(429, cancelled=True)
    credentials.CredentialPool.record(PROVIDER, KEYS[1], 429, retry_after_seconds=1, outcome=cancelled, now=1000)
    assert store.entry_count == 1
    nano.NanoGPTKeyPool.record_result(KEYS[1], 200, usage_windows=[
        {"remaining": 10, "resets_in_ms": 5000}
    ], now=1000)
    assert store.entry_count == 2


def test_affinity_is_limited_to_healthy_candidates(isolated, monkeypatch):
    affinity = importlib.import_module("services.prompt_cache_affinity")
    seen = []
    monkeypatch.setattr(affinity, "prefer_credential", lambda provider, model, eligible: seen.append(eligible) or (KEYS[0] if KEYS[0] in eligible else None))
    observe(isolated[1], KEYS[0], 1, remaining=0)
    assert credentials.CredentialPool.select(PROVIDER, model="A", now=1000) == KEYS[1]
    assert seen == [KEYS[1:]]


def test_bounded_opaque_storage_ttl_oldest_and_concurrency(isolated):
    clock, _ = isolated
    store = schedule.PoolResetSchedule(clock=lambda: clock[0], monotonic=lambda: clock[0], max_entries=2)
    for key in KEYS:
        observe(store, key, 100)
    assert store.entry_count == 2
    assert store.available(PROVIDER, KEYS[:1]) == KEYS[:1]
    assert all(key not in repr(store.__dict__) for key in KEYS)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: observe(store, KEYS[1], 100), range(100)))
    assert store.entry_count == 2
    clock[0] = 1061
    assert store.entry_count == 0
    assert schedule.PoolResetSchedule(max_entries=20000)._max_entries == 10000


@pytest.mark.parametrize("enabled", ["false", "true"])
def test_usage_snapshot_cache_never_refreshes_observation_or_adds_calls(isolated, monkeypatch, enabled):
    monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", enabled)
    usage = importlib.import_module("services.provider_usage_service")
    clock, store = isolated
    auth = Mock()
    auth.get_api_key.return_value = KEYS[0]
    auth.get_api_keys.return_value = KEYS
    auth.provider_credential_env_names.return_value = ()
    metrics = Mock()
    metrics.get_cost_summary.return_value = {}
    metrics.get_provider_stats.return_value = {}
    response = Mock(status_code=200, content=json.dumps({"usage": {
        "tokens_remaining_today": 10, "resets_in_ms": 100000
    }}).encode())
    proxy = Mock()
    proxy.make_request.return_value = response
    service = usage.ProviderUsageService(config={"API_BASE_URLS": {"navyai": "https://invalid.example"}, "PROVIDER_USAGE_CACHE_TTL_SECONDS": 300}, auth_service=auth, metrics_service=metrics, proxy_service=proxy, monotonic=lambda: clock[0])
    monkeypatch.setattr(service, "_utcnow", lambda: datetime.fromtimestamp(clock[0], timezone.utc).isoformat())
    first = service.snapshot(["navyai"])
    assert store.entry_count == (1 if enabled == "true" else 0)
    clock[0] = 1061
    second = service.snapshot(["navyai"])
    assert second["providers"][0]["source"]["cached"]
    assert first["providers"][0]["windows"] == second["providers"][0]["windows"]
    assert store.entry_count == 0
    assert proxy.make_request.call_count == 1
    response.close.assert_called_once()


def test_subscription_usage_is_not_a_scheduler_source(isolated, monkeypatch):
    usage = importlib.import_module("services.provider_usage_service")
    response = Mock(status_code=200, content=json.dumps({"daily": {"used": 0, "remaining": 10, "resetAt": 1010000}}).encode())
    proxy = Mock()
    proxy.make_request.return_value = response
    service = usage.ProviderUsageService(config={"NANOGPT_SUBSCRIPTION_BASE_URL": "https://invalid.example"}, auth_service=Mock(), metrics_service=Mock(), proxy_service=proxy)
    service._fetch(usage.PROVIDER_USAGE_PROBES["nanogpt"], KEYS)
    assert isolated[1].entry_count == 0
    proxy.make_request.assert_called_once()


def test_disabled_and_enabled_usage_snapshots_match_bytes(isolated, monkeypatch):
    usage = importlib.import_module("services.provider_usage_service")
    auth = Mock()
    auth.get_api_key.return_value = KEYS[0]
    auth.provider_credential_env_names.return_value = ()
    metrics = Mock()
    metrics.get_cost_summary.return_value = {}
    metrics.get_provider_stats.return_value = {}
    proxy = Mock()
    proxy.make_request.return_value = Mock(status_code=200, content=b'{"usage":{"tokens_remaining_today":10,"resets_in_ms":10000}}')
    snapshots = []
    for flag in ("false", "true"):
        monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", flag)
        service = usage.ProviderUsageService(config={"API_BASE_URLS": {"navyai": "https://invalid.example"}}, auth_service=auth, metrics_service=metrics, proxy_service=proxy)
        monkeypatch.setattr(service, "_utcnow", lambda: "1970-01-01T00:16:40Z")
        snapshots.append(json.dumps(service.snapshot(["navyai"]), sort_keys=True))
    assert snapshots[0] == snapshots[1]
    assert proxy.make_request.call_count == 2


def test_observation_validation_and_delayed_updates(isolated):
    _, store = isolated
    identity = store.credential_id(PROVIDER, KEYS[0])
    observe(store, KEYS[0], 50, remaining=0)
    store.observe(PROVIDER, identity, [{"remaining": 10, "resets_in_ms": 1000}], observed_at=999)
    assert store.available(PROVIDER, KEYS) == KEYS[1:]
    for invalid in (None, 42, "credential-prefix"):
        store.observe(PROVIDER, invalid, [{"remaining": 0, "resets_in_ms": 1000}])
    store.observe(PROVIDER, identity, [{"remaining": 0, "resets_in_ms": 1000}], model="x" * 257)
    assert store.entry_count == 1
    store.observe(PROVIDER, identity, [{"remaining": 10**1000, "resets_in_ms": 1000}])
    assert store.available(PROVIDER, KEYS) == KEYS


def test_monotonic_expiry_and_tolerated_future_skew():
    mono = [0.0]
    store = schedule.PoolResetSchedule(clock=lambda: 1000, monotonic=lambda: mono[0])
    store.observe(PROVIDER, store.credential_id(PROVIDER, KEYS[0]), [
        {"remaining": 0, "resets_in_ms": 100000}
    ], observed_at=1005)
    assert store.available(PROVIDER, KEYS) == KEYS[1:]
    mono[0] = 60
    assert store.available(PROVIDER, KEYS) == KEYS
    assert store.entry_count == 0


@pytest.mark.parametrize("enabled", ["false", "true"])
def test_registered_raw_pool_path_preserves_wire_and_stops_before_post(isolated, monkeypatch, tmp_path, enabled):
    monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", enabled)
    monkeypatch.setenv("ADMIN_API_KEY", "admin-test-key")
    monkeypatch.setenv("FLASK_SECRET_KEY", "flask-test-secret")
    monkeypatch.setenv("JWT_SECRET", "jwt-test-secret")
    for name in ("AUTH_DB_PATH", "RATE_LIMIT_DB_PATH", "MODEL_REGISTRY_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / (name + ".sqlite3")))
    with patch("env_loader.load_runtime_env"), patch("config.load_runtime_env"):
        app_module = importlib.import_module("app")
    with patch.object(app_module, "load_runtime_env"), patch("config.load_runtime_env"):
        app = app_module.create_app()
    app.config.update(WTF_CSRF_ENABLED=False, IMAGE_RELAY_CATALOG_AUTO_REFRESH=False,
                      PROVIDER_CATALOG_AUTO_REFRESH=False, PROMPT_CACHE_ENABLED=False)
    monkeypatch.setattr(app_module.AuthService, "verify_api_key", lambda *args: {"username": "alice", "is_admin": True})
    store = isolated[1]
    observe(store, KEYS[0], 100)
    observe(store, KEYS[1], 10)
    upstream = Mock(status_code=200, raw=None, content=b'{"exact":"provider-response"}', headers={"content-type": "application/json"})
    send = Mock(side_effect=lambda **kwargs: Mock(status_code=200, raw=None, content=upstream.content, headers=upstream.headers))
    monkeypatch.setattr(app_module.ProxyService, "make_request", send)
    client = app.test_client()
    headers = {"Authorization": "Bearer admin-test-key", "Content-Type": "application/json"}
    wire = b'{ "model":"gpt-6.1-sol", "messages":[] }'
    response = client.post("/ce-gpt-pro/v1/chat/completions", data=wire, headers=headers)
    assert response.status_code == 200
    assert response.data == upstream.content
    assert send.call_args.kwargs["data"] == wire
    assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer " + (KEYS[1] if enabled == "true" else KEYS[0])
    assert send.call_count == 1
    for key in KEYS:
        observe(store, key, 10, remaining=0)
    send.reset_mock()
    response = client.post("/ce-gpt-pro/v1/chat/completions", data=wire, headers=headers)
    if enabled == "true":
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "10"
        assert response.json["error"] == "model_cooldown"
        send.assert_not_called()
    else:
        assert response.status_code == 200
        assert response.data == upstream.content
        assert send.call_count == 1
