from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        try:
            parsed = float(value)
        except ValueError:
            return None
        if not math.isfinite(parsed):
            return None
        return int(parsed) if parsed.is_integer() else parsed
    return None


def _bounded_text(value: Any, maximum: int = 80) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized[:maximum] if normalized else None


def _epoch_ms_iso(value: Any) -> str | None:
    epoch_ms = _number(value)
    if epoch_ms is None:
        return None
    try:
        return datetime.fromtimestamp(
            float(epoch_ms) / 1000,
            tz=timezone.utc,
        ).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _window(
    name: str,
    unit: str,
    *,
    limit: Any = None,
    used: Any = None,
    remaining: Any = None,
    percent_used: Any = None,
    resets_at: Any = None,
    resets_in_ms: Any = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "unit": unit,
        "limit": _number(limit),
        "used": _number(used),
        "remaining": _number(remaining),
        "percent_used": _number(percent_used),
        "resets_at": _bounded_text(resets_at, 64),
        "resets_in_ms": _number(resets_in_ms),
    }


def _reset_epoch(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (OverflowError, OSError, ValueError):
        return None


def _available_quota(window: Mapping[str, Any]) -> float | None:
    values = {name: _number(window.get(name)) for name in ("limit", "used", "remaining", "percent_used")}
    if any(window.get(name) is not None and value is None for name, value in values.items()):
        return None
    try:
        if any(value is not None and (value < 0 or not math.isfinite(value)) for value in values.values()):
            return None
    except OverflowError:
        return None
    limit, used, remaining, percent = (values[name] for name in values)
    if percent is not None and percent > 100:
        return None
    if limit is not None and used is not None:
        calculated = limit - used
        if calculated < 0 or (remaining is not None and not math.isclose(calculated, remaining, abs_tol=1e-6)):
            return None
        remaining = calculated
    if remaining is None or (limit is not None and remaining > limit):
        return None
    if percent is not None and limit is not None and limit > 0:
        expected = 100 * (limit - remaining) / limit
        if not math.isclose(expected, percent, abs_tol=0.01):
            return None
    return float(remaining)


def reset_usage_windows(
    windows: Any, observed_at: float,
) -> tuple[tuple[float, float], ...] | None:
    """Validate quota/reset pairs without changing the public usage snapshot."""
    if not isinstance(windows, (list, tuple)) or not windows or len(windows) > 32:
        return None
    normalized = []
    for window in windows:
        if not isinstance(window, Mapping):
            return None
        remaining = _available_quota(window)
        absolute = _reset_epoch(window.get("resets_at"))
        relative = _number(window.get("resets_in_ms"))
        if window.get("resets_at") is not None and absolute is None:
            return None
        if window.get("resets_in_ms") is not None and (relative is None or relative <= 0):
            return None
        try:
            relative_at = observed_at + float(relative) / 1000 if relative is not None else None
        except OverflowError:
            return None
        if absolute is not None and relative_at is not None and abs(absolute - relative_at) > 5:
            return None
        reset = absolute if absolute is not None else relative_at
        # A bounded horizon includes annual quotas but rejects implausible clocks.
        if remaining is None or reset is None or not 0 < reset - observed_at <= 31_622_400:
            return None
        normalized.append((remaining, reset))
    return tuple(normalized)


def _normalize_navyai(payload: Mapping[str, Any]) -> dict[str, Any]:
    limits = _mapping(payload.get("limits"))
    usage = _mapping(payload.get("usage"))
    per_minute = _mapping(_mapping(payload.get("rate_limits")).get("per_minute"))
    windows = [
        _window(
            "daily",
            "tokens",
            limit=limits.get("tokens_per_day"),
            used=usage.get("tokens_used_today"),
            remaining=usage.get("tokens_remaining_today"),
            percent_used=usage.get("percent_used"),
            resets_at=usage.get("resets_at_utc"),
            resets_in_ms=usage.get("resets_in_ms"),
        )
    ]
    if per_minute:
        windows.append(
            _window(
                "per_minute",
                "requests",
                limit=per_minute.get("limit", limits.get("rpm")),
                used=per_minute.get("used"),
                remaining=per_minute.get("remaining"),
                resets_in_ms=per_minute.get("resets_in_ms"),
            )
        )
    return {
        "account": {"plan": _bounded_text(payload.get("plan")), "state": None},
        "balances": [],
        "windows": windows,
    }


def _normalize_nanogpt(payload: Mapping[str, Any]) -> dict[str, Any]:
    limits = _mapping(payload.get("limits"))
    windows = []
    for name in ("daily", "monthly"):
        period = _mapping(payload.get(name))
        if not period and limits.get(name) is None:
            continue
        percent_fraction = _number(period.get("percentUsed"))
        windows.append(
            _window(
                name,
                "operations",
                limit=limits.get(name),
                used=period.get("used"),
                remaining=period.get("remaining"),
                percent_used=(
                    round(float(percent_fraction) * 100, 6)
                    if percent_fraction is not None
                    else None
                ),
                resets_at=_epoch_ms_iso(period.get("resetAt")),
            )
        )
    active = payload.get("active")
    return {
        "account": {
            "plan": "subscription",
            "state": _bounded_text(payload.get("state")),
            "active": active if isinstance(active, bool) else None,
        },
        "balances": [],
        "windows": windows,
    }


def _normalize_openrouter(payload: Mapping[str, Any]) -> dict[str, Any]:
    data = _mapping(payload.get("data"))
    is_free_tier = data.get("is_free_tier")
    if is_free_tier is True:
        plan = "free"
    elif is_free_tier is False:
        plan = "paid"
    else:
        plan = None
    return {
        "account": {"plan": plan, "state": None},
        "balances": [
            {
                "name": "credits",
                "unit": "USD",
                "limit": _number(data.get("limit")),
                "used": _number(data.get("usage")),
                "remaining": _number(data.get("limit_remaining")),
            }
        ],
        "windows": [],
    }


NORMALIZERS: dict[str, Callable[[Mapping[str, Any]], dict[str, Any]]] = {
    "nanogpt": _normalize_nanogpt,
    "navyai": _normalize_navyai,
    "openrouter": _normalize_openrouter,
}
