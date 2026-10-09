"""Gateway-only admission advice; never infer provider quotas or replay permission."""

import logging
import math
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Mapping

from flask import g, has_request_context, request

logger = logging.getLogger(__name__)
HEADER_PREFIX = "X-MultiLLM-RateLimit-"
MAX_COUNTER = 2**53 - 1
MAX_USAGE_PROVIDERS = 32
_warned_invalid = False


def enabled() -> bool:
    global _warned_invalid
    value = os.environ.get("RATE_LIMIT_HEADERS_ENABLED", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value not in {"", "0", "false", "no", "off"} and not _warned_invalid:
        _warned_invalid = True
        logger.warning("Invalid RATE_LIMIT_HEADERS_ENABLED; advisory headers disabled")
    return False


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_COUNTER


def bounded_snapshot(snapshot) -> dict:
    if not isinstance(snapshot, Mapping) or not _integer(snapshot.get("limit"), 1):
        return {}
    result = {"limit": snapshot["limit"]}
    remaining = snapshot.get("remaining")
    if _integer(remaining) and remaining <= result["limit"]:
        result["remaining"] = remaining
    reset = snapshot.get("reset")
    if _integer(reset, 1) and reset <= 86400:
        result["reset"] = reset
    return result


def snapshot_headers(snapshot) -> dict:
    return {HEADER_PREFIX + name.title(): str(value)
            for name, value in bounded_snapshot(snapshot).items()}


def _reset_seconds(connection, metadata, window, now, *, offset=0, latest=False):
    """Read expiry from the same SQLite transaction as the admission counters."""
    query = (
        "SELECT created_at FROM request_usage "
        "WHERE identity = ? AND provider = ? AND created_at >= ? AND id != ? "
        "ORDER BY created_at DESC LIMIT 1 OFFSET ?"
    ) if latest else (
        "SELECT created_at FROM request_usage "
        "WHERE identity = ? AND provider = ? AND created_at >= ? AND id != ? "
        "ORDER BY created_at ASC LIMIT 1 OFFSET ?"
    )
    row = connection.execute(query, (
        metadata["identity"], metadata["provider"], (now - timedelta(seconds=window)).isoformat(),
        metadata.get("reservation_id", -1), offset,
    )).fetchone()
    if row is None:
        return None
    admitted = datetime.fromisoformat(row["created_at"])
    return min(window, max(1, math.ceil((admitted + timedelta(seconds=window) - now).total_seconds())))


def _counter_snapshot(metadata, minute_count, minute_tokens, daily_count, token_limited, *, consume=False):
    rpm, daily = metadata["rpm_limit"], metadata["daily_request_limit"]
    denied = minute_count >= rpm or token_limited or daily_count >= daily
    limit, count, window, kind = rpm, minute_count, 60, "requests"
    if minute_count < rpm and token_limited:
        limit, count, kind = metadata["tpm_limit"], minute_tokens, "tokens"
    elif minute_count < rpm and not token_limited and daily_count >= daily:
        limit, count, window = daily, daily_count, 86400
    remaining = max(0, limit - count - int(consume and not denied))
    return bounded_snapshot({"limit": limit, "remaining": remaining}), count, window, kind, denied


def capture_admission(metadata, minute_count, minute_tokens, daily_count,
                      token_limited, now, *, connection=None):
    """Small service hook, called under its existing transaction before check-and-admit.

    The first snapshot stays request-local even if transformation or fallback later
    rechecks capacity. D1 counts are known to its ledger; precise expiry is not.
    """
    if not enabled():
        return None
    snapshot, count, window, kind, denied = _counter_snapshot(
        metadata, minute_count, minute_tokens, daily_count, token_limited, consume=True)
    reset = None
    if snapshot and connection is not None:
        offset = max(0, count - snapshot["limit"]) if denied and kind != "tokens" else 0
        reset = _reset_seconds(connection, metadata, window, now, offset=offset,
                               latest=denied and kind == "tokens")
        if reset is None and not denied:
            reset = window  # The about-to-be-admitted request starts this window.
        if reset is not None:
            snapshot["reset"] = reset
    if snapshot:
        metadata["rate_limit_advice"] = dict(snapshot)
        if has_request_context() and not hasattr(g, "rate_limit_advice"):
            g.rate_limit_advice = dict(snapshot)
    retry_after = (reset or window) if denied else None
    if denied and has_request_context():
        g.gateway_rate_limit_retry_after = retry_after
    return retry_after


def apply_rate_limit_headers(response, *, managed=True):
    if not enabled() or not managed or not getattr(g, "authenticated_user", None):
        return response
    snapshot = getattr(g, "rate_limit_advice", None)
    for name, value in snapshot_headers(snapshot).items():
        response.headers[name] = value
    retry_after = getattr(g, "gateway_rate_limit_retry_after", None)
    if response.status_code == 429 and _integer(retry_after, 1) and "Retry-After" not in response.headers:
        response.headers["Retry-After"] = str(retry_after)
    return response


def register_rate_limit_headers(app, *, is_managed=None):
    """W22 registrar hook; the coordinator may inject its managed-route predicate."""
    if is_managed is None:
        is_managed = lambda: request.path.startswith("/v1/")

    @app.after_request
    def decorate(response):
        if not enabled():
            return response
        return apply_rate_limit_headers(response, managed=is_managed())


def _utcnow():
    return datetime.now(timezone.utc)


def usage_snapshot(user, remote_addr=None, *, service=None, now=None) -> dict:
    """Read at most 32 observed provider counters for one authorized principal.

    D1 has no bounded public provider/expiry inventory; omit unavailable fields
    rather than read internal ledger state or start a new synchronization.
    """
    if not enabled() or os.environ.get("RATE_LIMIT_ENABLED", "true").lower() in {"0", "false", "no"}:
        return {}
    if service is None:
        from services.rate_limit_service import RateLimitService
        service = RateLimitService
    from services import rate_limit_d1
    if rate_limit_d1.active():
        return {}
    now = now or _utcnow()
    identity, _ = service._identity_for_user(user, remote_addr)
    path = service._get_storage_path().resolve()
    if not path.exists():
        return {}
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            providers = connection.execute(
                "SELECT DISTINCT provider FROM request_usage WHERE identity = ? AND created_at >= ? "
                "ORDER BY provider LIMIT ?", (identity, (now - timedelta(days=1)).isoformat(), MAX_USAGE_PROVIDERS),
            ).fetchall()
            result = {}
            for row in providers:
                snapshot = _usage_provider_snapshot(connection, service, identity, row["provider"], now)
                if snapshot:
                    result[row["provider"]] = snapshot
            return result
    except (sqlite3.Error, ValueError):
        logger.warning("Gateway rate-limit usage snapshot unavailable")
        return {}


def _usage_provider_snapshot(connection, service, identity, provider, now):
    counts = connection.execute(
        "SELECT SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS requests, "
        "SUM(CASE WHEN created_at >= ? THEN estimated_tokens ELSE 0 END) AS tokens, "
        "COUNT(*) AS daily FROM request_usage WHERE identity = ? AND provider = ? AND created_at >= ?",
        ((now - timedelta(seconds=60)).isoformat(), (now - timedelta(seconds=60)).isoformat(),
         identity, provider, (now - timedelta(days=1)).isoformat()),
    ).fetchone()
    metadata = {
        "identity": identity, "provider": provider,
        "rpm_limit": service._provider_limit(provider, "RATE_LIMIT_RPM", service.RATE_LIMITS.get(
            provider, service.RATE_LIMITS["default"])["requests"]),
        "tpm_limit": service._provider_limit(provider, "RATE_LIMIT_TPM", 200000),
        "daily_request_limit": service._provider_limit(provider, "DAILY_REQUEST_LIMIT", 10000),
    }
    tokens = counts["tokens"] or 0
    snapshot, count, window, kind, denied = _counter_snapshot(
        metadata, counts["requests"] or 0, tokens, counts["daily"], tokens >= metadata["tpm_limit"])
    if snapshot:
        reset = _reset_seconds(connection, metadata, window, now,
                               offset=max(0, count - snapshot["limit"]) if denied and kind != "tokens" else 0,
                               latest=denied and kind == "tokens")
        if reset is not None:
            snapshot["reset"] = reset
    return snapshot
