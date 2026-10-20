"""Retry hints change local scheduling, never transport permissions or bytes."""

from dataclasses import FrozenInstanceError
from email.utils import formatdate
from unittest.mock import Mock, patch

import pytest
import requests


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.delenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", raising=False)
    monkeypatch.delenv("UPSTREAM_RETRY_AFTER_MAX_SECONDS", raising=False)
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "off")
    from services.resilience_service import ResilienceService

    ResilienceService.reset()
    yield
    ResilienceService.reset()


def parse(headers, now=100, status=429, maximum=3600):
    from services.retry_advice import parse_retry_advice

    return parse_retry_advice(headers, now=now, status_code=status, max_seconds=maximum)


def test_delta_date_equivalence_and_immutable_advice():
    delta = parse({"Retry-After": "20"})
    date = parse({"retry-after": formatdate(120, usegmt=True)})
    assert (
        (delta.observed_at, delta.retry_at, delta.delay_seconds, delta.scope)
        == (date.observed_at, date.retry_at, date.delay_seconds, date.scope)
        == (100, 120, 20, "rate_limit")
    )
    assert delta.source == "retry-after"
    with pytest.raises(FrozenInstanceError):
        delta.delay_seconds = 1


@pytest.mark.parametrize(
    "value",
    [
        "",
        "bad",
        "nan",
        "inf",
        "-1",
        "0",
        "1e999",
        "x" * 513,
        formatdate(99, usegmt=True),
    ],
)
def test_malformed_nonfinite_and_stale_advice(value):
    assert parse({"Retry-After": value}) is None


def test_maximum_clamps_only_local_advice():
    headers = {"Retry-After": "999999", "X-Unrelated": "unchanged"}
    before = headers.copy()
    advice = parse(headers, maximum=10)
    assert (advice.delay_seconds, advice.retry_at) == (10, 110)
    assert headers == before


@pytest.mark.parametrize(
    "value,delay",
    [("120", 20), ("99", None), ("nan", None), ("-1", None), ("999999999", 3600)],
)
def test_epoch_reset(value, delay):
    advice = parse({"X-RateLimit-Reset": value})
    assert (advice.delay_seconds if advice else None) == delay


def test_exhausted_dimensions_and_precise_reset_precedence():
    advice = parse(
        {
            "Retry-After": "2",
            "X-RateLimit-Remaining-Requests": "0",
            "X-RateLimit-Reset-Requests": "1h2m3.4s",
            "X-RateLimit-Remaining-Tokens": "0",
            "X-RateLimit-Reset-Tokens": "7.66s",
        }
    )
    assert (advice.source, advice.delay_seconds, advice.scope) == (
        "x-ratelimit-reset-requests",
        3600,
        "quota_exhausted",
    )
    advice = parse(
        {
            "anthropic-ratelimit-tokens-remaining": "0",
            "anthropic-ratelimit-tokens-reset": "1970-01-01T00:02:00Z",
        }
    )
    assert advice.delay_seconds == 20 and advice.scope == "quota_exhausted"
    assert (
        parse(
            {"X-RateLimit-Remaining-Requests": "1", "X-RateLimit-Reset-Requests": "5s"}
        )
        is None
    )


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 200])
def test_authentication_and_caller_errors_are_not_throttling(status):
    assert parse({"Retry-After": "20"}, status=status) is None


@pytest.mark.parametrize(
    "flag,maximum,enabled,limit",
    [
        ("", "", False, 3600),
        ("false", "bad", False, 3600),
        ("true", "", True, 3600),
        ("1", "10", True, 10),
        ("bad", "10", False, 3600),
        ("true", "nan", False, 3600),
        ("true", "-1", False, 3600),
        ("true", "0", False, 3600),
    ],
)
def test_configuration_defaults_and_invalid_values(
    monkeypatch, flag, maximum, enabled, limit
):
    from services.retry_advice import retry_advice_settings

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", flag)
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_MAX_SECONDS", maximum)
    settings = retry_advice_settings()
    assert (settings.enabled, settings.max_seconds) == (enabled, limit)


def test_invalid_settings_log_once_without_value(monkeypatch, caplog):
    from services import retry_advice

    retry_advice._warned_settings.clear()
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "private-invalid-setting")
    for _ in range(2):
        assert not retry_advice.retry_advice_settings().enabled
    assert len(caplog.records) == 1
    assert "private-invalid-setting" not in caplog.text


def response(status=429, hint="20"):
    result = requests.Response()
    result.status_code = status
    result._content = b"  {raw bytes}\n"
    result.headers.update({"Content-Type": "text/plain", "Retry-After": hint})
    return result


def dispatch(
    upstreams,
    *,
    method="GET",
    headers=None,
    raw=False,
    deadline=None,
    streaming=False,
    provider="openai",
):
    from services.proxy_service import ProxyService

    session = Mock()
    session.request.side_effect = upstreams
    with (
        patch.object(ProxyService, "_get_provider_session", return_value=session),
        patch("services.proxy_service.time.sleep") as sleep,
        patch("services.managed_dispatch.time.time", return_value=100),
        patch("services.managed_dispatch.time.monotonic", return_value=100),
    ):
        kwargs = {"deadline": deadline} if deadline is not None else {}
        result = ProxyService._make_base_request(
            method,
            "https://provider.invalid/v1/models",
            headers or {},
            {},
            b"{}" if method == "POST" else None,
            provider,
            force_raw_passthrough=raw,
            is_streaming=streaming,
            timeout_override=(1, 2),
            **kwargs,
        )
    return result, session, sleep


@pytest.mark.parametrize("flag", [None, "", "false", "bad"])
def test_disabled_transport_retains_waits_and_headers(monkeypatch, flag):
    if flag is not None:
        monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", flag)
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_MAX_SECONDS", "2")
    first, last = response(), response(200)
    result, session, sleep = dispatch([first, last])
    assert result is last and session.request.call_count == 2
    sleep.assert_called_once_with(1.0)
    assert result.headers["Retry-After"] == "20"
    assert [c.kwargs["timeout"] for c in session.request.call_args_list] == [
        (1, 2),
        (1, 2),
    ]


def test_allowed_wait_uses_bounded_advice(monkeypatch):
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_MAX_SECONDS", "5")
    result, session, sleep = dispatch([response(), response(200)], deadline=106)
    assert result.status_code == 200 and session.request.call_count == 2
    sleep.assert_called_once_with(5)


def test_deadline_refuses_wait_and_preserves_upstream(monkeypatch):
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    upstream = response()
    original = dict(upstream.headers)
    with patch.object(upstream, "close") as close:
        result, session, sleep = dispatch([upstream], deadline=105)
    assert result is upstream and result.content == b"  {raw bytes}\n"
    assert dict(result.headers) == original
    assert session.request.call_count == 1
    sleep.assert_not_called()
    close.assert_not_called()


@pytest.mark.parametrize(
    "raw,streaming,key",
    [(False, False, False), (True, False, True), (False, True, True)],
)
def test_ambiguous_post_raw_and_stream_do_not_gain_replay(
    monkeypatch, raw, streaming, key
):
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    upstream = response()
    result, session, sleep = dispatch(
        [upstream],
        method="POST",
        raw=raw,
        streaming=streaming,
        headers={"Idempotency-Key": "synthetic"} if key else {},
    )
    assert result is upstream and result.content == b"  {raw bytes}\n"
    assert result.headers["Retry-After"] == "20"
    assert session.request.call_count == 1
    sleep.assert_not_called()


def test_429_advice_does_not_heal_provider(monkeypatch):
    from services.proxy_service import ProxyService
    from services.resilience_service import ResilienceService

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    with patch.object(ResilienceService, "record_result") as record:
        result, _, _ = dispatch([response()], method="POST")
    assert result.status_code == 429
    assert record.call_args.kwargs["outcome"].provider_health == "neutral"
    assert not ProxyService._should_retry_status("POST", {}, 429, False)


def test_free_quota_enabled_clamps_and_disabled_preserves_legacy(monkeypatch):
    from services.free_quota_service import FreeQuotaService, retry_seconds

    headers = {
        "x-ratelimit-remaining-requests": "0",
        "x-ratelimit-reset-requests": "2h",
    }
    assert retry_seconds(headers, 100) == 7200
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_MAX_SECONDS", "5")
    assert retry_seconds(headers, 100) == 5
    with patch.object(FreeQuotaService, "block") as block:
        FreeQuotaService.observe("openai", headers, now=100)
    block.assert_called_once_with("provider:openai", 5, now=100)
    assert headers["x-ratelimit-reset-requests"] == "2h"


def test_free_quota_invalid_hint_bounds_default(monkeypatch):
    from services.free_quota_service import retry_seconds

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_MAX_SECONDS", "5")
    assert retry_seconds({"Retry-After": "nan"}, 100) == 5


@pytest.mark.parametrize(
    "enabled,key,calls", [(False, False, 2), (True, False, 1), (True, True, 2)]
)
def test_timeout_body_does_not_authorize_ambiguous_post(
    monkeypatch, enabled, key, calls
):
    import json

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", str(enabled).lower())
    upstream = response(400)
    upstream._content = json.dumps(
        {"error": {"message": "timeout", "code": 400}}
    ).encode()
    upstream.headers["Content-Type"] = "application/json"
    result, session, _ = dispatch(
        [upstream, response(200)],
        method="POST",
        provider="opencode",
        headers={"Idempotency-Key": "synthetic"} if key else {},
    )
    assert session.request.call_count == calls
    assert result.status_code == (200 if calls == 2 else 400)


@pytest.mark.parametrize(
    "error,method,count",
    [
        (requests.ReadTimeout("synthetic"), "POST", 1),
        (requests.ConnectionError("synthetic"), "POST", 1),
        (requests.ConnectTimeout("synthetic"), "POST", 2),
        (requests.ReadTimeout("synthetic"), "GET", 2),
    ],
)
def test_enabled_exception_policy_is_unchanged(monkeypatch, error, method, count):
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    result, session, sleep = dispatch([error, response(200)], method=method)
    assert session.request.call_count == count
    assert result.status_code == (200 if count == 2 else 502)
    assert sleep.call_count == count - 1


def test_deadline_expired_during_wait_keeps_response_open(monkeypatch):
    from services.managed_dispatch import retry_managed_attempt
    from services.upstream_outcome import classify_upstream_outcome

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    upstream = response(hint="2")
    attempt, sleep = Mock(), Mock()
    with (
        patch("services.managed_dispatch.time.time", return_value=100),
        patch("services.managed_dispatch.time.monotonic", side_effect=[100, 104]),
        patch.object(upstream, "close") as close,
    ):
        result = retry_managed_attempt(
            attempt,
            lambda: classify_upstream_outcome(429, replay_permission=True),
            retry_count=0,
            max_retries=3,
            retry_delay=1,
            response=upstream,
            deadline=103,
            sleep=sleep,
        )
    assert result is None
    attempt.assert_not_called()
    close.assert_not_called()
    sleep.assert_called_once_with(2)


@pytest.mark.parametrize("permission,count", [(False, 0), (True, 3)])
def test_permission_and_attempt_limit_precede_parsing(monkeypatch, permission, count):
    from services.managed_dispatch import retry_managed_attempt
    from services.upstream_outcome import classify_upstream_outcome

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    attempt, sleep = Mock(), Mock()
    upstream = response()
    with patch("services.managed_dispatch.parse_retry_advice") as parse_hint:
        result = retry_managed_attempt(
            attempt,
            lambda: classify_upstream_outcome(429, replay_permission=permission),
            retry_count=count,
            max_retries=3,
            retry_delay=1,
            response=upstream,
            sleep=sleep,
        )
    assert result is None
    attempt.assert_not_called()
    sleep.assert_not_called()
    parse_hint.assert_not_called()


def test_existing_cascade_deadline_is_used(monkeypatch):
    from flask import Flask, g

    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "true")
    with Flask(__name__).test_request_context():
        g.cascade_deadline = 105
        upstream = response()
        result, session, sleep = dispatch([upstream])
    assert result is upstream and session.request.call_count == 1
    sleep.assert_not_called()


@pytest.mark.parametrize("flag", ["false", "true"])
@pytest.mark.parametrize("provider", ["nanogpt", "groq"])
def test_registered_proxy_path_preserves_raw_error(
    monkeypatch, tmp_path, flag, provider
):
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", flag)
    for name, value in {
        "ADMIN_API_KEY": "admin-test-key",
        "FLASK_SECRET_KEY": "test-secret",
        "JWT_SECRET": "jwt-test-secret",
        "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"),
        "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3"),
        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"),
    }.items():
        monkeypatch.setenv(name, value)
    with patch("env_loader.load_runtime_env"), patch("config.load_runtime_env"):
        import app
    with patch("app.load_runtime_env"), patch("config.load_runtime_env"):
        application = app.create_app()
    application.config.update(
        WTF_CSRF_ENABLED=False, IMAGE_RELAY_CATALOG_AUTO_REFRESH=False
    )
    upstream = response()
    session = Mock()
    session.request.side_effect = (
        [upstream, response(200)] if provider == "groq" else [upstream]
    )
    with (
        patch.object(app.AuthService, "get_api_key", return_value="synthetic"),
        # Other suites can leave pooled NanoGPT keys configured; keep this path keyless.
        patch.object(app.AuthService, "get_api_keys", return_value=[]),
        patch.object(app.ProxyService, "_get_provider_session", return_value=session),
        patch("services.proxy_service.time.sleep") as sleep,
    ):
        result = application.test_client().get(
            f"/{provider}/v1/models", headers={"Authorization": "Bearer admin-test-key"}
        )
    if provider == "groq":
        assert result.status_code == 200 and session.request.call_count == 2
        sleep.assert_called_once_with(20 if flag == "true" else 1.0)
    else:
        assert result.status_code == 429 and result.data == upstream.content
        assert result.headers["Retry-After"] == "20"
        assert session.request.call_count == 1
        sleep.assert_not_called()
