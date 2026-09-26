"""Per-key daily and monthly dollar budgets, enforced before dispatch.

A key's spend is the durable ledger total (read from the daily rollups at most once per
`USAGE_BUDGET_REFRESH_SECONDS`), plus what this process recorded since that read,
plus the estimates of its requests still in flight. A request is admitted only if its
estimate fits both limits; after it finishes, its settled cost replaces the estimate.
Periods are UTC days and calendar months. Only priced requests count: configure
`MODEL_PRICING_USD_PER_MILLION` for the models a budgeted key may use.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from services import usage_ledger

logger = logging.getLogger(__name__)

RESERVATION_TTL_SECONDS = 3600
FAILURE_RETRY_SECONDS = 5.0


def _refresh_seconds() -> float:
    try:
        return min(3600.0, max(1.0, float(os.environ.get("USAGE_BUDGET_REFRESH_SECONDS", "60"))))
    except ValueError:
        return 60.0


def periods(now: Optional[datetime] = None) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = day_start.replace(day=1)
    next_month = (month_start + timedelta(days=32)).replace(day=1)
    return {
        "now": now,
        "day": day_start.strftime("%Y-%m-%d"),
        "month": month_start.strftime("%Y-%m"),
        "month_start": month_start.strftime("%Y-%m-%d"),
        "day_resets_at": day_start + timedelta(days=1),
        "month_resets_at": next_month,
    }


def limits(user: Mapping[str, Any]) -> tuple[Optional[float], Optional[float]]:
    """Daily and monthly limits in USD. Administrators have none unless set explicitly."""
    return user.get("daily_budget_usd"), user.get("monthly_budget_usd")


def budgeted(user: Mapping[str, Any]) -> bool:
    return any(limit is not None for limit in limits(user))


@dataclass
class _Principal:
    base: Optional[dict] = None
    fetched: float = 0.0
    failed_until: float = 0.0
    # USD by period key ("2026-09-26" and "2026-09"): recorded but not yet stored,
    # stored since the last durable read, and never stored (dropped or ledger off).
    pending: dict = field(default_factory=dict)
    flushed: dict = field(default_factory=dict)
    lost: dict = field(default_factory=dict)
    inflight: dict = field(default_factory=dict)
    refresh: threading.Lock = field(default_factory=threading.Lock)


def _add(mapping: dict, row: Mapping[str, Any], sign: float = 1.0) -> None:
    cost = float(row.get("cost_usd") or 0.0) * sign
    if not cost:
        return
    day = str(row["at"])[:10]
    for key in (day, day[:7]):
        value = mapping.get(key, 0.0) + cost
        if abs(value) < 1e-12:
            mapping.pop(key, None)
        else:
            mapping[key] = value


@dataclass
class BudgetDecision:
    allowed: bool
    reservation: Optional[str] = None
    error: str = ""
    message: str = ""
    status_code: int = 200
    retry_after: Optional[int] = None
    details: dict = field(default_factory=dict)


class BudgetUnavailable(Exception):
    pass


class BudgetService:
    _lock = threading.Lock()
    _principals: dict[str, _Principal] = {}
    _reservations: dict[str, tuple[str, float, float, str, str]] = {}

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._principals = {}
            cls._reservations = {}

    @classmethod
    def _state(cls, principal: str) -> _Principal:
        with cls._lock:
            return cls._principals.setdefault(principal, _Principal())

    # Ledger listener callbacks: every recorded row is eventually stored or dropped.
    @classmethod
    def on_flushed(cls, rows: list) -> None:
        with cls._lock:
            for row in rows:
                state = cls._principals.get(row["principal"])
                if state is not None:
                    _add(state.pending, row, -1)
                    _add(state.flushed, row)

    @classmethod
    def on_dropped(cls, rows: list) -> None:
        with cls._lock:
            for row in rows:
                state = cls._principals.get(row["principal"])
                if state is not None:
                    _add(state.pending, row, -1)
                    _add(state.lost, row)

    @classmethod
    def _refresh(cls, principal: str, state: _Principal, period: dict) -> None:
        """Read durable totals when due; local accounting covers everything since."""
        with cls._lock:
            due = ((state.base is None or time.monotonic() - state.fetched >= _refresh_seconds()
                    or state.base["day"] != period["day"]) and time.monotonic() >= state.failed_until)
        if not due:
            if state.base is None:
                raise BudgetUnavailable()
            return
        if not state.refresh.acquire(timeout=10):
            if state.base is None:
                raise BudgetUnavailable()
            return
        try:
            with cls._lock:
                if (state.base is not None and time.monotonic() - state.fetched < _refresh_seconds()
                        and state.base["day"] == period["day"]):
                    return
                # Rows stored before the read are in its totals. A flush that lands
                # during the read may be counted twice until the next read; never less.
                stored_before = dict(state.flushed)
            if usage_ledger.enabled():
                try:
                    totals = usage_ledger.LEDGER.store().totals(principal, period["day"], period["month_start"])
                except Exception as error:
                    logger.warning("Usage totals could not be read for a budgeted key (%s)", type(error).__name__)
                    with cls._lock:
                        state.failed_until = time.monotonic() + FAILURE_RETRY_SECONDS
                    if state.base is None:
                        raise BudgetUnavailable() from None
                    return
            else:
                totals = {"day_usd": 0.0, "month_usd": 0.0}
            with cls._lock:
                state.base = {"day": period["day"], "month": period["month"],
                              "day_usd": float(totals["day_usd"]), "month_usd": float(totals["month_usd"])}
                state.fetched = time.monotonic()
                for key, value in stored_before.items():
                    remaining = state.flushed.get(key, 0.0) - value
                    if abs(remaining) < 1e-12:
                        state.flushed.pop(key, None)
                    else:
                        state.flushed[key] = remaining
        finally:
            state.refresh.release()

    @classmethod
    def _spent(cls, state: _Principal, period: dict) -> tuple[float, float, float]:
        """(day, month, in flight) in USD; the caller holds the lock."""
        base = state.base or {}
        day = (base.get("day_usd", 0.0) if base.get("day") == period["day"] else 0.0)
        month = (base.get("month_usd", 0.0) if base.get("month") == period["month"] else 0.0)
        for mapping in (state.pending, state.flushed, state.lost):
            day += mapping.get(period["day"], 0.0)
            month += mapping.get(period["month"], 0.0)
        cutoff = time.monotonic() - RESERVATION_TTL_SECONDS
        for reservation, (_, started, _) in list(state.inflight.items()):
            if started < cutoff:
                state.inflight.pop(reservation, None)
                cls._reservations.pop(reservation, None)
        return day, month, sum(amount for _, _, amount in state.inflight.values())

    @classmethod
    def check_and_reserve(cls, user: Mapping[str, Any], estimate_usd: float,
                          now: Optional[datetime] = None) -> BudgetDecision:
        daily, monthly = limits(user)
        if daily is None and monthly is None:
            return BudgetDecision(True)
        principal = str(user.get("username") or user.get("id") or "")
        period = periods(now)
        state = cls._state(principal)
        try:
            cls._refresh(principal, state, period)
        except BudgetUnavailable:
            return BudgetDecision(False, error="budget_unavailable", status_code=503, retry_after=5,
                                  message="Usage totals are unavailable, so this key's budget cannot be checked. Retry shortly.")
        estimate = max(0.0, float(estimate_usd or 0.0))
        with cls._lock:
            day, month, inflight = cls._spent(state, period)
            exceeded = []
            if daily is not None and (day + inflight >= daily or day + inflight + estimate > daily):
                exceeded.append(("daily", daily, day, period["day_resets_at"]))
            if monthly is not None and (month + inflight >= monthly or month + inflight + estimate > monthly):
                exceeded.append(("monthly", monthly, month, period["month_resets_at"]))
            if not exceeded:
                reservation = uuid.uuid4().hex
                state.inflight[reservation] = (principal, time.monotonic(), estimate)
                cls._reservations[reservation] = (principal, estimate, time.monotonic(), period["day"], period["month"])
                return BudgetDecision(True, reservation=reservation)
        # The latest boundary: the request cannot fit before every exceeded period resets.
        name, limit, spent, resets_at = max(exceeded, key=lambda item: item[3])
        retry_after = max(1, int((resets_at - period["now"]).total_seconds()) + 1)
        return BudgetDecision(
            False, error="budget_exceeded", status_code=429, retry_after=retry_after,
            message=(f"This key's {name} budget of ${limit:.2f} is spent (${spent + inflight:.4f} used or in flight"
                     f"{f', this request is estimated at ${estimate:.4f}' if estimate else ''}). "
                     f"It resets at {resets_at.isoformat()}."),
            details={"period": name, "limit_usd": limit, "spent_usd": round(spent, 10),
                     "in_flight_usd": round(inflight, 10), "estimate_usd": round(estimate, 10),
                     "resets_at": resets_at.isoformat()},
        )

    @classmethod
    def settle(cls, reservation: Optional[str]) -> None:
        """Release an in-flight estimate; the settled cost arrives through `record_cost`."""
        if not reservation:
            return
        with cls._lock:
            entry = cls._reservations.pop(reservation, None)
            if entry is None:
                return
            state = cls._principals.get(entry[0])
            if state is not None:
                state.inflight.pop(reservation, None)

    @classmethod
    def record_cost(cls, row: Mapping[str, Any]) -> None:
        """Count a finished request's cost until the durable totals include it.

        Call before handing the row to the ledger, which then reports it as stored or
        dropped exactly once.
        """
        with cls._lock:
            state = cls._principals.setdefault(str(row["principal"]), _Principal())
            _add(state.pending, row)
            current_month = str(row["at"])[:7]
            for mapping in (state.pending, state.flushed, state.lost):
                for key in [key for key in mapping if key[:7] < current_month]:
                    mapping.pop(key, None)

    @classmethod
    def status(cls, user: Mapping[str, Any], now: Optional[datetime] = None) -> dict[str, Any]:
        """Spend and remaining budget for /v1/usage; reads durable totals when due."""
        daily, monthly = limits(user)
        principal = str(user.get("username") or user.get("id") or "")
        period = periods(now)
        state = cls._state(principal)
        available = True
        try:
            cls._refresh(principal, state, period)
        except BudgetUnavailable:
            available = False
        with cls._lock:
            day, month, inflight = cls._spent(state, period)

        def remaining(limit, spent):
            return None if limit is None else round(max(0.0, limit - spent - inflight), 10)

        return {
            "totals_available": available,
            "day": period["day"],
            "month": period["month"],
            "spent_today_usd": round(day, 10),
            "spent_this_month_usd": round(month, 10),
            "in_flight_usd": round(inflight, 10),
            "daily_budget_usd": daily,
            "monthly_budget_usd": monthly,
            "daily_remaining_usd": remaining(daily, day),
            "monthly_remaining_usd": remaining(monthly, month),
            "daily_resets_at": period["day_resets_at"].isoformat(),
            "monthly_resets_at": period["month_resets_at"].isoformat(),
        }


usage_ledger.LEDGER.add_listener(BudgetService.on_flushed, BudgetService.on_dropped)
