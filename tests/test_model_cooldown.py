"""Model cooldown evidence, selection, and compatibility contracts."""

import math
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import pytest
from flask import Flask

from error_handlers import init_error_handlers
from services.credential_pool import CredentialPool
from services.nanogpt_key_pool import (
    NanoGPTKeyPool,
    NanoGPTUnifiedKeyPool,
    NanoGPTKeyPoolExhausted,
)
from services.model_cooldown import (
    ModelCooldown,
    ModelCooldownExhausted,
    ModelCooldownCapacity,
    cooldown_error_response,
    model_cooldown,
    settings,
)
from services.upstream_outcome import UpstreamOutcome, classify_upstream_outcome

PROVIDER = "ce-gpt-pro"
KEYS = ["synthetic-first", "synthetic-second"]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true")
    monkeypatch.delenv("MODEL_COOLDOWN_MAX_SECONDS", raising=False)
    CredentialPool.reset()
    NanoGPTKeyPool.reset()
    NanoGPTUnifiedKeyPool.reset()
    model_cooldown.reset()
    yield
    CredentialPool.reset()
    NanoGPTKeyPool.reset()
    NanoGPTUnifiedKeyPool.reset()
    model_cooldown.reset()


def test_throttle_leaves_other_model_and_provider_available():
    CredentialPool.record(PROVIDER, KEYS[0], 429, model="A", now=100)
    assert CredentialPool.available(PROVIDER, KEYS, model="A", now=101) == KEYS[1:]
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=101) == KEYS
    assert CredentialPool.available("ce-gpt-plus", KEYS, model="A", now=101) == KEYS
    assert CredentialPool._resting == {}


def test_explicit_shared_bucket_and_success_clear_only_that_bucket():
    CredentialPool.record(
        PROVIDER, KEYS[0], 429, model="A", quota_bucket="shared", now=100
    )
    CredentialPool.record(PROVIDER, KEYS[0], 429, model="C", now=100)
    assert (
        CredentialPool.available(
            PROVIDER, KEYS, model="B", quota_bucket="shared", now=101
        )
        == KEYS[1:]
    )
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=101) == KEYS
    CredentialPool.record(
        PROVIDER, KEYS[0], 200, model="B", quota_bucket="shared", now=102
    )
    assert (
        CredentialPool.available(
            PROVIDER, KEYS, model="A", quota_bucket="shared", now=103
        )
        == KEYS
    )
    assert CredentialPool.available(PROVIDER, KEYS, model="C", now=103) == KEYS[1:]


def test_auth_is_wide_and_success_cannot_clear_it():
    CredentialPool.record(PROVIDER, KEYS[0], 401, model="A", now=100)
    CredentialPool.record(PROVIDER, KEYS[0], 200, model="B", now=101)
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=102) == KEYS[1:]
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=400) == KEYS


@pytest.mark.parametrize("status", [400, 402, 403, 404, 422, 500])
def test_status_alone_does_not_invent_quota_or_wide_auth(status):
    CredentialPool.record(PROVIDER, KEYS[0], status, model="A", now=100)
    assert CredentialPool.available(PROVIDER, KEYS, model="A", now=101) == KEYS


def test_classified_cancelled_and_scoped_auth_evidence():
    CredentialPool.record(
        PROVIDER,
        KEYS[0],
        429,
        model="A",
        now=100,
        outcome=classify_upstream_outcome(429, cancelled=True),
    )
    CredentialPool.record(
        PROVIDER, KEYS[0], 401, model="A", now=100, credential_wide_auth=False
    )
    assert CredentialPool.available(PROVIDER, KEYS, model="A", now=101) == KEYS
    CredentialPool.record(
        PROVIDER, KEYS[0], 403, model="A", now=100, credential_wide_auth=True
    )
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=101) == KEYS[1:]


def test_exhaustion_requires_classified_evidence():
    exhausted = UpstreamOutcome(False, "neutral", "throttled", "quota_exhausted")
    CredentialPool.record(PROVIDER, KEYS[0], 402, model="A", outcome=exhausted, now=100)
    assert CredentialPool.available(PROVIDER, KEYS, model="A", now=101) == KEYS[1:]
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=101) == KEYS
    assert exhausted.replay_permission is False


def test_all_cooling_select_raises_bounded_real_429_without_dispatch(monkeypatch):
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "10")
    for key in KEYS:
        CredentialPool.record(
            PROVIDER, key, 429, model="A", now=100, retry_after_seconds=999
        )
    with patch.object(CredentialPool, "keys", return_value=KEYS):
        with pytest.raises(ModelCooldownExhausted) as caught:
            CredentialPool.select(PROVIDER, model="A", now=101)
        assert CredentialPool.select(PROVIDER, model="B", now=101) == KEYS[0]
    assert caught.value.status_code == 429
    assert caught.value.retry_after == 9
    assert all(key not in str(caught.value) for key in KEYS)


def test_registered_error_adapter_preserves_json_and_retry_after():
    for key in KEYS:
        CredentialPool.record(PROVIDER, key, 429, model="A", now=100)
    app = Flask(__name__)
    init_error_handlers(app)
    app.register_error_handler(ModelCooldownExhausted, cooldown_error_response)
    send = Mock()

    @app.post("/v1/test-cooldown")
    def dispatch():
        CredentialPool.select(PROVIDER, model="A", now=101)
        send()
        return {"ok": True}

    with patch.object(CredentialPool, "keys", return_value=KEYS):
        response = app.test_client().post("/v1/test-cooldown", json={})
    assert response.status_code == 429
    assert response.json["error"] == "model_cooldown"
    assert response.headers["Retry-After"] == "59"
    send.assert_not_called()


@pytest.mark.parametrize("enabled", [None, "", "false", "0", "garbage"])
def test_disabled_preserves_legacy_pool_behaviour(monkeypatch, enabled):
    if enabled is None:
        monkeypatch.delenv("MODEL_COOLDOWN_ENABLED", raising=False)
    else:
        monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", enabled)
    for key in KEYS:
        CredentialPool.record(PROVIDER, key, 402, model="A", now=100)
    with patch.object(CredentialPool, "keys", return_value=KEYS):
        assert CredentialPool.select(PROVIDER, model="A", now=101) == KEYS[0]
    assert CredentialPool.available(PROVIDER, KEYS, model="B", now=101) == []
    assert model_cooldown.entry_count == 0
    NanoGPTKeyPool.record_result(KEYS[0], 402, model="A", now=100)
    assert KEYS[0] in NanoGPTKeyPool._rejected_until


@pytest.mark.parametrize("value", ["bad", "0", "-1", "NaN", "1.5"])
def test_bad_config_fails_off_and_logs_once_without_value(monkeypatch, caplog, value):
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", value)
    assert not settings().enabled
    assert not settings().enabled
    messages = [
        r.message for r in caplog.records if "MODEL_COOLDOWN_MAX_SECONDS" in r.message
    ]
    assert len(messages) <= 1
    assert all(value not in message for message in messages)


def test_empty_cap_means_default(monkeypatch):
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "")
    assert settings().enabled
    assert settings().max_seconds == 3600


@pytest.mark.parametrize("delay", [math.nan, math.inf, -1, "untrusted", True])
def test_malformed_reset_advice_uses_default(delay):
    CredentialPool.record(
        PROVIDER, KEYS[0], 429, model="A", now=100, retry_after_seconds=delay
    )
    assert CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=159) == []
    assert CredentialPool.available(PROVIDER, KEYS[:1], model="A", now=160) == KEYS[:1]


@pytest.mark.parametrize("status,duration", [(429, 60), (401, 300)])
def test_unwired_credential_calls_match_flag_off(monkeypatch, status, duration):
    snapshots = []
    for enabled in ("false", "true"):
        monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", enabled)
        CredentialPool.reset()
        model_cooldown.reset()
        with patch.object(CredentialPool, "keys", return_value=KEYS):
            CredentialPool.record_headers(
                PROVIDER, {"Authorization": "Bearer " + KEYS[0]}, status, now=100
            )
            assert CredentialPool.select(PROVIDER, now=101) == KEYS[1]
            assert CredentialPool.available(PROVIDER, KEYS, now=101) == KEYS[1:]
            assert CredentialPool.available(PROVIDER, KEYS, now=100 + duration) == KEYS
            CredentialPool.record(PROVIDER, KEYS[1], status, now=100)
            assert CredentialPool.select(PROVIDER, now=101) == KEYS[0]
            assert CredentialPool.available(PROVIDER, KEYS, now=101) == []
            snapshots.append(dict(CredentialPool._resting))
            CredentialPool.record_headers(
                PROVIDER, {"Authorization": "Bearer " + KEYS[0]}, 200, now=102
            )
            assert CredentialPool.available(PROVIDER, KEYS, now=103) == KEYS[:1]
            assert model_cooldown.entry_count == 0
    assert snapshots[0] == snapshots[1]


@pytest.mark.parametrize("pool", [NanoGPTKeyPool, NanoGPTUnifiedKeyPool])
@pytest.mark.parametrize("status,duration", [(429, 17), (401, 91)])
def test_unwired_nanogpt_calls_match_flag_off(monkeypatch, pool, status, duration):
    snapshots = []
    for enabled in ("false", "true"):
        monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", enabled)
        pool.reset()
        model_cooldown.reset()
        probe = Mock(return_value=200)
        assert pool.select_key(KEYS, probe, now=99) == KEYS[0]
        pool.record_result(
            KEYS[0],
            status,
            now=100,
            check_ttl_seconds=91,
            rejected_cooldown_seconds=17,
        )
        assert pool._active_key is None
        assert pool.select_available_key(KEYS, now=101) == KEYS[1]
        assert pool.select_key(KEYS, probe, now=101) == KEYS[1]
        pool.record_result(
            KEYS[1],
            status,
            now=100,
            check_ttl_seconds=91,
            rejected_cooldown_seconds=17,
        )
        assert pool.select_available_key(KEYS, now=101) is None
        probe.reset_mock()
        with pytest.raises(NanoGPTKeyPoolExhausted, match="All configured"):
            pool.select_key(KEYS, probe, now=101)
        probe.assert_not_called()
        snapshots.append(dict(pool._rejected_until))
        assert pool.select_available_key(KEYS, now=100 + duration) == KEYS[0]
        assert model_cooldown.entry_count == 0
    assert snapshots[0] == snapshots[1]


@pytest.mark.parametrize("scope", [{"model": "A"}, {"quota_bucket": "shared"}])
@pytest.mark.parametrize("status", [429, 401])
def test_scoped_credential_selection_respects_legacy_rest(scope, status):
    for key in KEYS:
        CredentialPool.record(PROVIDER, key, status, now=100)
    assert CredentialPool.available(PROVIDER, KEYS, now=101, **scope) == []
    with patch.object(CredentialPool, "keys", return_value=KEYS):
        with pytest.raises(ModelCooldownExhausted) as caught:
            CredentialPool.select(PROVIDER, now=101, **scope)
    assert caught.value.retry_after == (59 if status == 429 else 299)
    assert CredentialPool.available(PROVIDER, KEYS, now=400, **scope) == KEYS


@pytest.mark.parametrize("pool", [NanoGPTKeyPool, NanoGPTUnifiedKeyPool])
@pytest.mark.parametrize("scope", [{"model": "A"}, {"quota_bucket": "shared"}])
def test_scoped_nanogpt_selection_respects_legacy_rest(pool, scope):
    assert pool.select_key(KEYS, Mock(return_value=200), now=99) == KEYS[0]
    pool.record_result(KEYS[0], 429, now=100)
    assert pool.select_available_key(KEYS, now=101, **scope) == KEYS[1]
    probe = Mock(return_value=200)
    assert pool.select_key(KEYS, probe, now=101, **scope) == KEYS[1]
    probe.assert_called_once_with(KEYS[1])
    pool.record_result(KEYS[1], 401, now=100)
    probe.reset_mock()
    with pytest.raises(ModelCooldownExhausted) as caught:
        pool.select_key(KEYS, probe, now=101, **scope)
    assert caught.value.retry_after == 59
    with pytest.raises(ModelCooldownExhausted):
        pool.select_available_key(KEYS, now=101, **scope)
    probe.assert_not_called()


def test_scoped_auth_rests_legacy_credential_until_same_capped_deadline(monkeypatch):
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "10")
    CredentialPool.record(
        PROVIDER,
        KEYS[0],
        403,
        model="A",
        credential_wide_auth=True,
        retry_after_seconds=999,
        now=100,
    )
    assert CredentialPool._resting == {(PROVIDER, KEYS[0]): 110}
    with patch.object(CredentialPool, "keys", return_value=KEYS):
        assert CredentialPool.select(PROVIDER, now=101) == KEYS[1]
    assert CredentialPool.available(PROVIDER, KEYS, now=110) == KEYS


@pytest.mark.parametrize("pool", [NanoGPTKeyPool, NanoGPTUnifiedKeyPool])
def test_scoped_nanogpt_auth_rests_legacy_key_and_invalidates_active(pool):
    assert pool.select_key(KEYS, Mock(return_value=200), model="A", now=99) == KEYS[0]
    pool.record_result(KEYS[0], 401, model="A", now=100, retry_after_seconds=11)
    assert pool._active_key is None
    assert pool._rejected_until == {KEYS[0]: 111}
    assert pool.select_available_key(KEYS, now=101) == KEYS[1]
    assert pool.select_available_key(KEYS, now=111) == KEYS[0]


@pytest.mark.parametrize("status", [429, 401])
def test_scoped_success_preserves_legacy_credential_rest(status):
    CredentialPool.record(PROVIDER, KEYS[0], 429, model="A", now=99)
    CredentialPool.record(PROVIDER, KEYS[0], status, now=100)
    before = dict(CredentialPool._resting)
    CredentialPool.record(PROVIDER, KEYS[0], 200, model="A", now=101)
    assert CredentialPool._resting == before
    assert model_cooldown.entry_count == 0
    assert CredentialPool.available(PROVIDER, KEYS, now=102) == KEYS[1:]
    assert CredentialPool.available(PROVIDER, KEYS, model="A", now=102) == KEYS[1:]


@pytest.mark.parametrize("pool", [NanoGPTKeyPool, NanoGPTUnifiedKeyPool])
def test_scoped_nanogpt_success_preserves_legacy_rest(pool):
    pool.record_result(KEYS[0], 429, model="A", now=99)
    pool.record_result(KEYS[0], 401, now=100)
    before = dict(pool._rejected_until)
    pool.record_result(KEYS[0], 200, model="A", now=101)
    assert pool._rejected_until == before
    assert model_cooldown.entry_count == 0
    assert pool.select_available_key(KEYS, now=102) == KEYS[1]
    assert pool.select_available_key(KEYS, model="A", now=102) == KEYS[1]


def test_record_headers_accepts_explicit_context():
    CredentialPool.record_headers(
        PROVIDER, {"aUtHoRiZaTiOn": "Bearer " + KEYS[0]}, 429, model="A", now=100
    )
    assert CredentialPool.available(PROVIDER, KEYS, model="A", now=101) == KEYS[1:]


@pytest.mark.parametrize("pool", [NanoGPTKeyPool, NanoGPTUnifiedKeyPool])
def test_nanogpt_model_selection_keeps_precedence_and_skips_probes_when_cooling(pool):
    probe = Mock(return_value=200)
    assert pool.select_key(KEYS, probe, model="A", now=100) == KEYS[0]
    pool.record_result(KEYS[0], 429, model="A", now=101)
    assert pool.select_key(KEYS, probe, model="B", now=102) == KEYS[0]
    assert pool.select_key(KEYS, probe, model="A", now=102) == KEYS[1]
    pool.record_result(KEYS[1], 429, model="A", now=103)
    probe.reset_mock()
    with pytest.raises(ModelCooldownExhausted):
        pool.select_key(KEYS, probe, model="A", now=104)
    probe.assert_not_called()
    assert pool._rejected_until == {}


def test_nanogpt_available_and_invalidate_use_same_model_state():
    NanoGPTUnifiedKeyPool.invalidate(KEYS[0], 429, model="A", now=100)
    assert (
        NanoGPTUnifiedKeyPool.select_available_key(KEYS, model="A", now=101) == KEYS[1]
    )
    assert (
        NanoGPTUnifiedKeyPool.select_available_key(KEYS, model="B", now=101) == KEYS[0]
    )
    assert NanoGPTKeyPool.select_available_key(KEYS, model="A", now=101) == KEYS[0]


def test_nanogpt_probe_rejection_is_auth_evidence_not_model_quota():
    probe = Mock(side_effect=[401, 200])
    assert NanoGPTKeyPool.select_key(KEYS, probe, model="A", now=100) == KEYS[1]
    assert NanoGPTKeyPool.select_available_key(KEYS, model="B", now=101) == KEYS[1]


def test_nanogpt_filtering_does_not_turn_a_multi_key_pool_into_a_probe_bypass():
    NanoGPTKeyPool.record_result(KEYS[0], 429, model="A", now=100)
    probe = Mock(return_value=200)
    assert NanoGPTKeyPool.select_key(KEYS, probe, model="A", now=101) == KEYS[1]
    probe.assert_called_once_with(KEYS[1])


def test_nanogpt_probe_permission_error_keeps_previously_validated_key():
    assert NanoGPTKeyPool.select_key(KEYS[:1], Mock(), model="A", now=100) == KEYS[0]
    NanoGPTKeyPool.record_result(KEYS[0], 200, model="A", now=101)
    assert (
        NanoGPTKeyPool.select_key(
            KEYS[:1],
            Mock(return_value=403),
            model="A",
            now=102,
            check_every_requests=1,
        )
        == KEYS[0]
    )


def test_nanogpt_scoped_success_does_not_clear_other_bucket():
    NanoGPTKeyPool.record_result(KEYS[0], 429, model="A", now=100)
    NanoGPTKeyPool.record_result(KEYS[0], 200, model="B", now=101)
    assert NanoGPTKeyPool.select_available_key(KEYS, model="A", now=102) == KEYS[1]


def test_storage_is_hmac_bounded_expires_and_fails_closed_at_capacity():
    store = ModelCooldown(max_entries=2)
    outcome = classify_upstream_outcome(429)
    for key in KEYS:
        store.record(PROVIDER, key, outcome, model="A", now=100, max_seconds=10)
    assert store.entry_count == 2
    assert all(key not in repr(store.__dict__) for key in KEYS)
    digest = store.credential_id(PROVIDER, KEYS[0])
    assert len(digest) == 64
    assert digest == store.credential_id(PROVIDER, KEYS[0])
    store.record(
        PROVIDER, "synthetic-overflow", outcome, model="A", now=100, max_seconds=10
    )
    assert store.entry_count == 2
    with pytest.raises(ModelCooldownCapacity):
        store.available(
            PROVIDER, ["synthetic-overflow"], model="A", now=101, max_seconds=10
        )
    assert store.available(PROVIDER, KEYS, model="A", now=110, max_seconds=10) == KEYS
    assert store.entry_count == 0


def test_concurrent_updates_and_fractional_retry_bound():
    store = ModelCooldown()
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(
            executor.map(
                lambda _: store.record(
                    PROVIDER,
                    KEYS[0],
                    classify_upstream_outcome(429),
                    model="A",
                    now=100,
                    retry_after_seconds=1.1,
                    max_seconds=2,
                ),
                range(100),
            )
        )
    with pytest.raises(ModelCooldownExhausted) as caught:
        store.select(PROVIDER, KEYS[:1], model="A", now=100.2, max_seconds=2)
    assert caught.value.retry_after == 1
    assert store.entry_count == 1
