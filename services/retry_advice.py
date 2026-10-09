"""Content-free, bounded retry hints; these never authorize request replay."""

import logging
import math
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Mapping

from services.upstream_outcome import classify_upstream_outcome

logger = logging.getLogger(__name__)
_DEFAULT_MAX = 3600
_warned_settings: set[str] = set()
_warning_lock = threading.Lock()
_DURATION = re.compile(
    r"(?:(\d+(?:\.\d+)?)d)?(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?"
    r"(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?"
)
_NUMBER = re.compile(r"\d+(?:\.\d+)?")


@dataclass(frozen=True)
class RetryAdviceSettings:
    enabled: bool = False
    max_seconds: int = _DEFAULT_MAX


@dataclass(frozen=True)
class RetryAdvice:
    source: str
    observed_at: float
    retry_at: float
    delay_seconds: float
    scope: str


def _warn_once(name: str) -> None:
    with _warning_lock:
        if name in _warned_settings:
            return
        _warned_settings.add(name)
    logger.warning("Invalid %s; upstream retry advice disabled", name)


def retry_advice_settings() -> RetryAdviceSettings:
    flag_name = "UPSTREAM_RETRY_AFTER_ADVICE_ENABLED"
    flag = os.environ.get(flag_name, "").strip().lower()
    if flag in ("", "false", "0", "no", "off"):
        return RetryAdviceSettings()
    if flag not in ("true", "1", "yes", "on"):
        _warn_once(flag_name)
        return RetryAdviceSettings()
    limit_name = "UPSTREAM_RETRY_AFTER_MAX_SECONDS"
    value = os.environ.get(limit_name, "").strip()
    try:
        limit = int(value) if value else _DEFAULT_MAX
        # Match the existing free-pool maximum and keep sleep values operational.
        if not 1 <= limit <= 7 * 24 * 3600:
            raise ValueError
    except ValueError:
        _warn_once(limit_name)
        return RetryAdviceSettings()
    return RetryAdviceSettings(True, limit)


def _value(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name, "")
    return value.strip() if isinstance(value, str) and len(value) <= 512 else ""


def _number(value: str) -> float | None:
    if not _NUMBER.fullmatch(value):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _duration(value: str) -> float | None:
    match = _DURATION.fullmatch(value)
    if not match or not any(match.groups()):
        return None
    delay = sum(
        float(amount or 0) * unit
        for amount, unit in zip(match.groups(), (86400, 3600, 60, 1, 0.001))
    )
    return delay if math.isfinite(delay) else None


def _date_delay(value: str, now: float, *, iso: bool = False) -> float | None:
    try:
        date = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if iso
            else parsedate_to_datetime(value)
        )
        if date.tzinfo is None:
            return None
        delay = date.timestamp() - now
        return delay if math.isfinite(delay) else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _exhausted(headers: Mapping[str, str], name: str) -> bool:
    try:
        remaining = float(_value(headers, name))
        return math.isfinite(remaining) and remaining <= 0
    except ValueError:
        return False


def _reset_hints(
    headers: Mapping[str, str], now: float
) -> tuple[list[tuple[str, float]], bool]:
    hints: list[tuple[str, float]] = []
    exhausted = False
    for dimension in ("requests", "tokens"):
        for prefix, iso in (("x-ratelimit", False), ("anthropic-ratelimit", True)):
            if not _exhausted(
                headers,
                f"{prefix}-remaining-{dimension}"
                if not iso
                else f"{prefix}-{dimension}-remaining",
            ):
                continue
            exhausted = True
            name = (
                f"{prefix}-reset-{dimension}"
                if not iso
                else f"{prefix}-{dimension}-reset"
            )
            value = _value(headers, name)
            delay = _date_delay(value, now, iso=True) if iso else _duration(value)
            if delay is not None and delay > 0:
                hints.append((name, delay))
    return hints, exhausted


def parse_retry_advice(
    headers: Mapping[str, str],
    *,
    now: float,
    status_code: int = 429,
    max_seconds: int = _DEFAULT_MAX,
) -> RetryAdvice | None:
    """Normalize known header formats without reading bodies or mutating headers.

    Exhausted dimensions and Retry-After combine using the latest valid reset.
    This avoids sending before either active limit permits another attempt.
    """
    if not math.isfinite(now) or not 1 <= max_seconds <= 7 * 24 * 3600:
        return None
    outcome = classify_upstream_outcome(status_code)
    if outcome.reason in ("http_credential_rejected", "http_caller_error"):
        return None
    normalized = {name.lower(): value for name, value in headers.items()}
    hints, exhausted = _reset_hints(normalized, now)
    if outcome.reason == "http_throttled":
        scope = "quota_exhausted" if exhausted else "rate_limit"
    elif outcome.provider_health == "failure":
        scope = "provider"
    elif outcome.provider_health == "success" and exhausted:
        scope = "quota_exhausted"
    else:
        return None
    value = _value(normalized, "retry-after")
    delay = _number(value)
    if delay is None:
        delay = _date_delay(value, now)
    if delay is not None and delay > 0:
        hints.append(("retry-after", delay))
    epoch = _number(_value(normalized, "x-ratelimit-reset"))
    if epoch is not None and epoch > now:
        hints.append(("x-ratelimit-reset", epoch - now))
    if not hints:
        return None
    source, delay = max(hints, key=lambda hint: hint[1])
    delay = min(delay, max_seconds)
    return RetryAdvice(source, now, now + delay, delay, scope)
