from dataclasses import FrozenInstanceError
from unittest import TestCase
from unittest.mock import Mock, patch

import pytest
import requests

from services.resilience_service import ResilienceService


NEUTRAL_STATUSES = [
    100,
    199,
    300,
    302,
    399,
    400,
    401,
    402,
    403,
    404,
    409,
    422,
    429,
    499,
    501,
    505,
    599,
]
FAILURE_STATUSES = [408, 500, 502, 503, 504]
SUCCESS_STATUSES = [200, 201, 204, 206, 299]


@pytest.fixture
def check():
    return TestCase()


@pytest.fixture(autouse=True)
def circuit_settings(monkeypatch):
    for name, value in {
        "CIRCUIT_BREAKER_DEGRADED_FAILURES": "2",
        "CIRCUIT_BREAKER_FAILURES": "3",
        "CIRCUIT_BREAKER_COOLDOWN_SECONDS": "10",
        "CIRCUIT_BREAKER_HALF_OPEN_SUCCESSES": "2",
        "CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES": "2",
    }.items():
        monkeypatch.setenv(name, value)
    ResilienceService.reset()
    yield
    ResilienceService.reset()


def open_circuit():
    for now in (100, 101, 102):
        ResilienceService.record_result("openai", 503, now=now)


@pytest.mark.parametrize("status", NEUTRAL_STATUSES)
def test_neutral_status_releases_only_one_half_open_probe(check, status):
    open_circuit()
    check.assertTrue(ResilienceService.before_request("openai", now=113).allowed)
    check.assertTrue(ResilienceService.before_request("openai", now=113).allowed)
    result = ResilienceService.record_result("openai", status, now=114)
    check.assertEqual(result["state"], "half_open")
    check.assertEqual(result["half_open_in_flight"], 1)
    check.assertEqual(result["total_successes"], 0)
    check.assertEqual(result["total_failures"], 3)
    check.assertEqual(result["consecutive_failures"], 3)
    check.assertEqual(result["rate_limit_events"], int(status == 429))
    check.assertTrue(ResilienceService.before_request("openai", now=115).allowed)
    first_success = ResilienceService.record_result("openai", 200, now=116)
    check.assertEqual(first_success["state"], "half_open")
    check.assertEqual(first_success["half_open_in_flight"], 1)
    check.assertEqual(
        ResilienceService.record_result("openai", 204, now=117)["state"], "closed"
    )


@pytest.mark.parametrize("status", NEUTRAL_STATUSES)
@pytest.mark.parametrize("failures,expected_state", [(2, "degraded"), (3, "open")])
def test_neutral_status_does_not_heal_degraded_or_open_circuit(
    check, status, failures, expected_state
):
    for now in range(100, 100 + failures):
        ResilienceService.record_result("openai", 503, now=now)
    result = ResilienceService.record_result("openai", status, now=104)
    check.assertEqual(result["state"], expected_state)
    check.assertEqual(result["consecutive_failures"], failures)
    check.assertEqual(result["total_failures"], failures)
    check.assertEqual(result["total_successes"], 0)


@pytest.mark.parametrize(
    "status", SUCCESS_STATUSES + NEUTRAL_STATUSES + FAILURE_STATUSES
)
def test_status_classification(check, status):
    from services.upstream_outcome import classify_upstream_outcome

    result = classify_upstream_outcome(status)
    expected_health = (
        "success"
        if status in SUCCESS_STATUSES
        else "failure"
        if status in FAILURE_STATUSES
        else "neutral"
    )
    expected_credential = (
        "accepted"
        if status in SUCCESS_STATUSES
        else "rejected"
        if status in (401, 403)
        else "throttled"
        if status == 429
        else "unknown"
    )
    check.assertEqual(result.provider_health, expected_health)
    check.assertEqual(result.credential_health, expected_credential)
    check.assertIs(result.replay_permission, False)
    check.assertTrue(result.reason)
    with pytest.raises(FrozenInstanceError):
        result.provider_health = "success"


@pytest.mark.parametrize("status", SUCCESS_STATUSES)
def test_success_recovers_at_existing_threshold(check, status):
    ResilienceService.record_result("openai", 503, now=100)
    ResilienceService.record_result("openai", 503, now=101)
    check.assertEqual(
        ResilienceService.record_result("openai", status, now=102)["state"], "closed"
    )
    open_circuit()
    check.assertTrue(ResilienceService.before_request("openai", now=113).allowed)
    check.assertEqual(
        ResilienceService.record_result("openai", status, now=114)["state"], "half_open"
    )
    check.assertTrue(ResilienceService.before_request("openai", now=115).allowed)
    result = ResilienceService.record_result("openai", status, now=116)
    check.assertEqual(result["state"], "closed")
    check.assertEqual(result["total_successes"], 3)


@pytest.mark.parametrize("status", FAILURE_STATUSES)
def test_failure_preserves_thresholds_and_probe_reopening(check, status):
    check.assertEqual(
        ResilienceService.record_result("openai", status, now=100)["state"], "closed"
    )
    check.assertEqual(
        ResilienceService.record_result("openai", status, now=101)["state"], "degraded"
    )
    check.assertEqual(
        ResilienceService.record_result("openai", status, now=102)["state"], "open"
    )
    check.assertTrue(ResilienceService.before_request("openai", now=113).allowed)
    result = ResilienceService.record_result("openai", status, now=114)
    check.assertEqual(result["state"], "open")
    check.assertEqual(result["total_failures"], 4)
    check.assertEqual(result["retry_after_seconds"], 20)


@pytest.mark.parametrize("status", [401, 429])
def test_repeated_neutral_probes_never_occupy_capacity_permanently(check, status):
    open_circuit()
    for now in range(113, 123):
        check.assertTrue(ResilienceService.before_request("openai", now=now).allowed)
        result = ResilienceService.record_result("openai", status, now=now)
        check.assertEqual(result["half_open_in_flight"], 0)
        check.assertEqual(result["total_successes"], 0)
    check.assertEqual(
        ResilienceService.record_result("openai", status, now=124)[
            "half_open_in_flight"
        ],
        0,
    )


@pytest.fixture
def proxy():
    from services.proxy_service import ProxyService

    return ProxyService


@pytest.mark.parametrize(
    "method,headers,status,streaming,expected",
    [
        ("POST", {}, 503, False, False),
        ("POST", {"iDeMpOtEnCy-KeY": "synthetic"}, 503, False, True),
        ("POST", {"Idempotency-Key": "synthetic"}, 429, True, False),
        ("GET", {}, 503, False, True),
        ("HEAD", {}, 408, False, True),
        ("OPTIONS", {}, 500, False, True),
        ("DELETE", {}, 503, False, False),
        ("GET", {}, 401, False, False),
        ("GET", {}, 501, False, False),
    ],
)
def test_replay_status_permissions_remain_transport_policy(
    check, proxy, method, headers, status, streaming, expected
):
    from services.upstream_outcome import classify_upstream_outcome

    permission = proxy._should_retry_status(method, headers, status, streaming)
    check.assertIs(permission, expected)
    result = classify_upstream_outcome(status, replay_permission=permission)
    check.assertIs(result.replay_permission, expected)
    check.assertEqual(
        result.provider_health, "failure" if status in FAILURE_STATUSES else "neutral"
    )


@pytest.mark.parametrize(
    "error,kind",
    [
        (requests.ConnectTimeout("synthetic"), "connect"),
        (requests.ReadTimeout("synthetic"), "timeout"),
        (requests.ConnectionError("synthetic"), "interrupted"),
    ],
)
@pytest.mark.parametrize(
    "method,data", [("POST", b"{}"), ("GET", None), ("GET", b"{}")]
)
def test_transport_failure_keeps_replay_distinct_from_health(
    check, proxy, error, kind, method, data
):
    from services.upstream_outcome import classify_upstream_outcome

    permission = proxy._should_retry_exception(method, data, error)
    check.assertEqual(
        permission, kind == "connect" or (method == "GET" and data is None)
    )
    check.assertEqual(proxy._transport_failure_kind(error), kind)
    result = classify_upstream_outcome(
        transport_failure=kind, replay_permission=permission
    )
    check.assertEqual(result.provider_health, "failure")
    check.assertEqual(result.credential_health, "unknown")
    check.assertEqual(result.replay_permission, permission)
    check.assertEqual(result.reason, "transport_" + kind)


def test_cancellation_overrides_status_and_replay_without_recovery(check):
    from services.upstream_outcome import classify_upstream_outcome

    open_circuit()
    ResilienceService.before_request("openai", now=113)
    outcome = classify_upstream_outcome(200, cancelled=True, replay_permission=True)
    check.assertEqual(outcome.provider_health, "neutral")
    check.assertEqual(outcome.credential_health, "unknown")
    check.assertIs(outcome.replay_permission, False)
    check.assertEqual(outcome.reason, "cancelled")
    result = ResilienceService.record_result("openai", 200, outcome=outcome, now=114)
    check.assertEqual(result["state"], "half_open")
    check.assertEqual(result["half_open_in_flight"], 0)
    check.assertEqual(result["total_failures"], 3)
    check.assertEqual(result["total_successes"], 0)
    check.assertEqual(result["rate_limit_events"], 0)


@pytest.mark.parametrize("status", [401, 403, 429])
def test_credential_signals_do_not_mutate_pools(check, proxy, monkeypatch, status):
    from services.credential_pool import CredentialPool
    from services.upstream_outcome import classify_upstream_outcome

    resting = {("ce-cli", "synthetic-key"): 999.0}
    monkeypatch.setattr(CredentialPool, "_resting", resting.copy())
    with patch.object(CredentialPool, "record") as record:
        classify_upstream_outcome(status)
        proxy._record_circuit_result("openai", status)
    record.assert_not_called()
    check.assertEqual(CredentialPool._resting, resting)


@pytest.mark.parametrize("force_raw,provider", [(True, "openai"), (False, "nanogpt")])
@pytest.mark.parametrize("status", [200, 401, 429, 503])
def test_raw_transport_preserves_response_and_single_forward(
    check, proxy, force_raw, provider, status
):
    response = requests.Response()
    response.status_code = status
    response._content = b"  {raw bytes}\n"
    response.headers["Content-Type"] = "application/json"
    response.headers["X-Upstream"] = "unchanged"
    session = Mock()
    session.request.return_value = response
    with (
        patch.object(proxy, "_get_provider_session", return_value=session),
        patch.object(ResilienceService, "before_request") as before,
        patch.object(ResilienceService, "record_result") as record,
    ):
        result = proxy._make_base_request(
            "POST",
            "https://example.invalid/v1/chat/completions",
            {"Idempotency-Key": "synthetic"},
            {},
            b"{}",
            provider,
            force_raw_passthrough=force_raw,
        )
    check.assertIs(result, response)
    check.assertEqual(result.content, b"  {raw bytes}\n")
    check.assertEqual(result.headers["X-Upstream"], "unchanged")
    session.request.assert_called_once()
    before.assert_not_called()
    record.assert_not_called()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 429])
def test_managed_transport_neutral_result_releases_probe(check, proxy, status):
    open_circuit()
    response = requests.Response()
    response.status_code = status
    response._content = b"unchanged bytes"
    response.headers["Content-Type"] = "text/plain"
    session = Mock()
    session.request.return_value = response
    with (
        patch("services.resilience_service.time.time", return_value=113),
        patch.object(proxy, "_get_provider_session", return_value=session),
    ):
        result = proxy._make_base_request(
            "POST",
            "https://example.invalid/v1/chat/completions",
            {},
            {},
            b"{}",
            "openai",
        )
    check.assertIs(result, response)
    check.assertEqual(result.content, b"unchanged bytes")
    session.request.assert_called_once()
    snapshot = ResilienceService.snapshot("openai", now=114)
    check.assertEqual(snapshot["state"], "half_open")
    check.assertEqual(snapshot["half_open_in_flight"], 0)
    check.assertEqual(snapshot["total_successes"], 0)
    check.assertEqual(snapshot["total_failures"], 3)


@pytest.mark.parametrize(
    "error", [requests.ReadTimeout("synthetic"), requests.ConnectionError("synthetic")]
)
def test_ambiguous_post_with_idempotency_key_never_replays(check, proxy, error):
    session = Mock()
    session.request.side_effect = error
    with patch.object(proxy, "_get_provider_session", return_value=session):
        result = proxy._make_base_request(
            "POST",
            "https://example.invalid/v1/chat/completions",
            {"Idempotency-Key": "synthetic"},
            {},
            b"{}",
            "openai",
        )
    session.request.assert_called_once()
    check.assertEqual(result.status_code, 502)
    check.assertEqual(
        result.multillm_transport_failure, proxy._transport_failure_kind(error)
    )
    check.assertEqual(ResilienceService.snapshot("openai")["total_failures"], 1)


@pytest.mark.parametrize("failure", [requests.ConnectTimeout("synthetic"), 503])
def test_retry_limit_and_terminal_penalty_remain_unchanged(check, proxy, failure):
    if isinstance(failure, int):
        response = requests.Response()
        response.status_code = failure
        response._content = b"upstream failure"
        response.headers["Content-Type"] = "text/plain"
        session = Mock()
        session.request.return_value = response
    else:
        session = Mock()
        session.request.side_effect = failure
    with (
        patch.object(proxy, "_get_provider_session", return_value=session),
        patch("services.proxy_service.time.sleep") as sleep,
    ):
        result = proxy._make_base_request(
            "POST",
            "https://example.invalid/v1/chat/completions",
            {"Idempotency-Key": "synthetic"},
            {},
            b"{}",
            "openai",
        )
    check.assertEqual(session.request.call_count, 4)
    check.assertEqual(sleep.call_count, 3)
    check.assertEqual(result.status_code, 503 if isinstance(failure, int) else 502)
    check.assertEqual(ResilienceService.snapshot("openai")["total_failures"], 1)


def test_raw_transport_exception_is_single_forward_without_circuit_update(check, proxy):
    session = Mock()
    session.request.side_effect = requests.ConnectTimeout("synthetic")
    with (
        patch.object(proxy, "_get_provider_session", return_value=session),
        patch.object(ResilienceService, "before_request") as before,
        patch.object(ResilienceService, "record_result") as record,
    ):
        result = proxy._make_base_request(
            "POST",
            "https://example.invalid/v1/chat/completions",
            {},
            {},
            b"{}",
            "openai",
            force_raw_passthrough=True,
        )
    check.assertEqual(result.status_code, 502)
    session.request.assert_called_once()
    before.assert_not_called()
    record.assert_not_called()


def test_missing_evidence_is_neutral_and_non_replayable(check):
    from services.upstream_outcome import classify_upstream_outcome

    outcome = classify_upstream_outcome()
    check.assertEqual(outcome.provider_health, "neutral")
    check.assertEqual(outcome.credential_health, "unknown")
    check.assertFalse(outcome.replay_permission)
    check.assertEqual(outcome.reason, "unknown")
