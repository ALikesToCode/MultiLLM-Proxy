"""Recent health of automatic-route candidates and providers.

Every routed attempt records its outcome and time to response here, in memory. Automatic
routes may use the figures to put healthier candidates first; the public status page
reports them. Success is an exponentially weighted moving average that decays back to a
healthy prior while a candidate receives no traffic, so a provider that failed once is
tried again in its configured place after a few half-lives and is never starved. Nothing
here blocks on storage: services.route_health_sync writes changed entries to D1 in batches.
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar

from services.cost_service import CostService

ORDERING_MODES = frozenset({"priority", "health"})
PROVIDER_PREFIX = "provider:"
MAX_TARGETS = 512
MAX_SAMPLES = 32
MAX_ROUTE_COUNTERS = 256
WINDOW_SECONDS = 3600
PRIOR_SUCCESS = 1.0
SUCCESS_ALPHA = 0.2
CHECK_ALPHA = 0.1
LATENCY_ALPHA = 0.3
LATENCY_REFERENCE_MS = 10_000.0
# Public status thresholds over the recent window.
UP_SUCCESS_RATE = 0.95
DEGRADED_SUCCESS_RATE = 0.5
DOWN_CONSECUTIVE_FAILURES = 3

_STATE_FIELDS = (
    "kind", "ewma_success", "ewma_at", "ewma_latency_ms", "latency_at", "last_status",
    "last_outcome", "consecutive_failures", "last_success_at", "last_failure_at",
    "last_check_at", "last_check_ok", "last_check_status", "samples", "updated_at",
)
_OUTCOME_LENGTH = 32


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value):
        return default
    return min(maximum, max(minimum, value))


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def _parse_overrides(raw: str) -> dict[str, str]:
    overrides = {}
    for item in raw.split(","):
        route_id, separator, mode = item.partition("=")
        route_id, mode = route_id.strip(), mode.strip().lower()
        if separator and route_id.startswith("auto:") and mode in ORDERING_MODES:
            overrides[route_id] = mode
    return overrides


@dataclass(frozen=True)
class OrderingSettings:
    default_mode: str
    overrides: dict[str, str]
    half_life_seconds: float
    latency_weight: float
    cost_weight: float
    score_margin: float
    explore_every: int
    check_interval_seconds: float

    def mode_for(self, route_id: str) -> str:
        return self.overrides.get(route_id, self.default_mode)


def ordering_settings() -> OrderingSettings:
    """Read the routing settings from the environment on every call, like the circuits."""
    mode = os.environ.get("AUTO_ROUTE_ORDERING", "priority").strip().lower()
    return OrderingSettings(
        default_mode=mode if mode in ORDERING_MODES else "priority",
        overrides=_parse_overrides(os.environ.get("AUTO_ROUTE_ORDERING_OVERRIDES", "")),
        half_life_seconds=_env_float("AUTO_ROUTE_HEALTH_HALF_LIFE_SECONDS", 600, 30, 86_400),
        latency_weight=_env_float("AUTO_ROUTE_LATENCY_WEIGHT", 0.2, 0, 1),
        cost_weight=_env_float("AUTO_ROUTE_COST_WEIGHT", 0, 0, 1),
        score_margin=_env_float("AUTO_ROUTE_SCORE_MARGIN", 0.05, 0, 1),
        explore_every=_env_int("AUTO_ROUTE_EXPLORE_EVERY", 0, 0, 10_000),
        check_interval_seconds=60 * _env_int("HEALTH_CHECK_INTERVAL_MINUTES", 30, 5, 1440),
    )


def iso_time(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def provider_of(candidate: str) -> str:
    return candidate.split(":", 1)[0].strip().lower()


def _decayed(value: float, since: float | None, now: float, half_life: float) -> float:
    """Pull a stored average back toward the healthy prior as its evidence ages."""
    if since is None:
        return PRIOR_SUCCESS
    weight = 0.5 ** (max(0.0, now - since) / half_life)
    return PRIOR_SUCCESS + (value - PRIOR_SUCCESS) * weight


def _new_entry(kind: str) -> dict[str, Any]:
    return {
        "kind": kind, "ewma_success": PRIOR_SUCCESS, "ewma_at": None, "ewma_latency_ms": None,
        "latency_at": None, "last_status": None, "last_outcome": None, "consecutive_failures": 0,
        "last_success_at": None, "last_failure_at": None, "last_check_at": None,
        "last_check_ok": None, "last_check_status": None, "samples": [], "updated_at": 0.0,
        "version": 0,
    }


@dataclass(frozen=True)
class RouteOrder:
    candidates: tuple[str, ...]
    mode: str  # priority, health or health-probe


def _number(value: Any, *, minimum: float = 0.0, maximum: float = 1e13) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def _optional_number(value: Any, **bounds: float) -> bool:
    return value is None or _number(value, **bounds)


def _optional_status(value: Any) -> bool:
    return value is None or (type(value) is int and 100 <= value <= 599)


def valid_state(state: Any) -> bool:
    """A stored row's state, checked before it may replace anything in memory."""
    if not isinstance(state, dict) or set(state) != set(_STATE_FIELDS):
        return False
    samples = state["samples"]
    return (
        state["kind"] in {"candidate", "provider"}
        and _number(state["ewma_success"], maximum=1.0)
        and all(_optional_number(state[name]) for name in (
            "ewma_at", "ewma_latency_ms", "latency_at", "last_success_at",
            "last_failure_at", "last_check_at"))
        and _number(state["updated_at"])
        and _optional_status(state["last_status"])
        and _optional_status(state["last_check_status"])
        and (state["last_outcome"] is None or (
            isinstance(state["last_outcome"], str) and len(state["last_outcome"]) <= _OUTCOME_LENGTH))
        and type(state["consecutive_failures"]) is int and 0 <= state["consecutive_failures"] <= 1_000_000
        and state["last_check_ok"] in (None, True, False)
        and isinstance(samples, list) and len(samples) <= MAX_SAMPLES
        and all(
            isinstance(sample, list) and len(sample) == 3 and _number(sample[0])
            and sample[1] in (0, 1) and type(sample[1]) is int and _optional_number(sample[2])
            for sample in samples
        )
    )


class RouteHealth:
    """Process-local, bounded health figures keyed by candidate model ID and by provider."""

    _lock = threading.RLock()
    _entries: ClassVar[OrderedDict[str, dict[str, Any]]] = OrderedDict()
    _dirty: ClassVar[set[str]] = set()
    _route_counters: ClassVar[OrderedDict[str, int]] = OrderedDict()

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._entries = OrderedDict()
            cls._dirty = set()
            cls._route_counters = OrderedDict()

    @classmethod
    def _entry(cls, target: str, kind: str) -> dict[str, Any]:
        entry = cls._entries.get(target)
        if entry is None:
            entry = _new_entry(kind)
            cls._entries[target] = entry
            while len(cls._entries) > MAX_TARGETS:
                evicted, _ = cls._entries.popitem(last=False)
                cls._dirty.discard(evicted)
        else:
            cls._entries.move_to_end(target)
        return entry

    @classmethod
    def _touch(cls, target: str, entry: dict[str, Any], now: float) -> None:
        entry["updated_at"] = now
        entry["version"] += 1
        cls._dirty.add(target)

    @staticmethod
    def _observe(entry: dict[str, Any], success: bool, alpha: float, now: float, half_life: float) -> None:
        current = _decayed(entry["ewma_success"], entry["ewma_at"], now, half_life)
        entry["ewma_success"] = min(1.0, max(0.0, current + alpha * ((1.0 if success else 0.0) - current)))
        entry["ewma_at"] = now

    @classmethod
    def _record_sample(cls, target: str, kind: str, *, ok: bool, latency_ms: float | None,
                       status: int | None, outcome: str, now: float, half_life: float) -> None:
        entry = cls._entry(target, kind)
        cls._observe(entry, ok, SUCCESS_ALPHA, now, half_life)
        if ok:
            entry["last_success_at"] = now
            entry["consecutive_failures"] = 0
            if latency_ms is not None:
                previous = entry["ewma_latency_ms"]
                entry["ewma_latency_ms"] = (
                    latency_ms if previous is None else previous + LATENCY_ALPHA * (latency_ms - previous)
                )
                entry["latency_at"] = now
        else:
            entry["last_failure_at"] = now
            entry["consecutive_failures"] += 1
        entry["last_status"] = status if status is None or 100 <= status <= 599 else None
        entry["last_outcome"] = outcome[:_OUTCOME_LENGTH]
        entry["samples"].append([now, 1 if ok else 0, None if latency_ms is None else round(latency_ms, 1)])
        del entry["samples"][:-MAX_SAMPLES]
        cls._touch(target, entry, now)

    @classmethod
    def record(cls, candidate: str, *, ok: bool, outcome: str, latency_ms: float | None = None,
               status: int | None = None, now: float | None = None) -> None:
        """One routed attempt: a success with its time to response, or a failure."""
        current_time = time.time() if now is None else now
        half_life = ordering_settings().half_life_seconds
        with cls._lock:
            for target, kind in ((candidate, "candidate"), (PROVIDER_PREFIX + provider_of(candidate), "provider")):
                cls._record_sample(target, kind, ok=ok, latency_ms=latency_ms, status=status,
                                   outcome=outcome, now=current_time, half_life=half_life)

    @classmethod
    def record_check(cls, provider: str, *, ok: bool, status: int | None = None,
                     candidates: Iterable[str] = (), now: float | None = None) -> None:
        """A free reachability check. It nudges the provider's candidates without adding traffic samples."""
        current_time = time.time() if now is None else now
        half_life = ordering_settings().half_life_seconds
        with cls._lock:
            target = PROVIDER_PREFIX + provider
            entry = cls._entry(target, "provider")
            entry["last_check_at"] = current_time
            entry["last_check_ok"] = ok
            entry["last_check_status"] = status if status is not None and 100 <= status <= 599 else None
            cls._touch(target, entry, current_time)
            for candidate in candidates:
                if provider_of(candidate) != provider:
                    continue
                candidate_entry = cls._entry(candidate, "candidate")
                cls._observe(candidate_entry, ok, CHECK_ALPHA, current_time, half_life)
                cls._touch(candidate, candidate_entry, current_time)

    @classmethod
    def snapshot(cls, target: str) -> dict[str, Any] | None:
        with cls._lock:
            entry = cls._entries.get(target)
            return None if entry is None else {**entry, "samples": [list(sample) for sample in entry["samples"]]}

    # Ordering -----------------------------------------------------------------

    @classmethod
    def _score(cls, candidate: str, now: float, settings: OrderingSettings, cost_penalty: float) -> float:
        entry = cls._entries.get(candidate)
        if entry is None:
            return PRIOR_SUCCESS - settings.cost_weight * cost_penalty
        success = _decayed(entry["ewma_success"], entry["ewma_at"], now, settings.half_life_seconds)
        latency_penalty = 0.0
        if entry["ewma_latency_ms"] is not None and entry["latency_at"] is not None:
            latency = entry["ewma_latency_ms"]
            weight = 0.5 ** (max(0.0, now - entry["latency_at"]) / settings.half_life_seconds)
            latency_penalty = latency / (latency + LATENCY_REFERENCE_MS) * weight
        return success - settings.latency_weight * latency_penalty - settings.cost_weight * cost_penalty

    @staticmethod
    def _cost_penalties(candidates: tuple[str, ...]) -> dict[str, float]:
        prices = {}
        for candidate in candidates:
            pricing = CostService.pricing_for(candidate)
            if pricing is not None:
                prices[candidate] = float(pricing["input"] + pricing["output"])
        highest = max(prices.values(), default=0.0)
        return {candidate: (prices[candidate] / highest if highest else 0.0) for candidate in prices}

    @classmethod
    def order(cls, route_id: str, candidates: Iterable[str], *,
              circuit_state: Callable[[str], str] | None = None, now: float | None = None) -> RouteOrder:
        """Candidates in the order to try them. Operator order is the default and the tiebreaker."""
        configured = tuple(candidates)
        settings = ordering_settings()
        if settings.mode_for(route_id) != "health" or len(configured) < 2:
            return RouteOrder(configured, "priority")
        current_time = time.time() if now is None else now
        costs = cls._cost_penalties(configured) if settings.cost_weight else {}
        with cls._lock:
            scores = {candidate: cls._score(candidate, current_time, settings, costs.get(candidate, 0.0))
                      for candidate in configured}
            last_seen = {}
            for candidate in configured:
                samples = (cls._entries.get(candidate) or {}).get("samples") or []
                last_seen[candidate] = samples[-1][0] if samples else -1.0
            count = cls._route_counters.pop(route_id, 0) + 1
            cls._route_counters[route_id] = count
            while len(cls._route_counters) > MAX_ROUTE_COUNTERS:
                cls._route_counters.popitem(last=False)
        open_circuit = {
            candidate: circuit_state is not None and circuit_state(provider_of(candidate)) == "open"
            for candidate in configured
        }
        # A candidate passes the one before it only when it is better by more than the margin,
        # so small differences keep the configured order. The relation is transitive, so the
        # pass terminates and the result depends only on the scores and the configured order.
        ordered = list(configured)
        swapped = True
        while swapped:
            swapped = False
            for index in range(1, len(ordered)):
                previous, current = ordered[index - 1], ordered[index]
                if scores[current] > scores[previous] + settings.score_margin:
                    ordered[index - 1], ordered[index] = current, previous
                    swapped = True
        ordered = [c for c in ordered if not open_circuit[c]] + [c for c in ordered if open_circuit[c]]
        mode = "health"
        if settings.explore_every and count % settings.explore_every == 0:
            eligible = [c for c in ordered[1:] if not open_circuit[c]]
            if eligible:
                # The candidate heard from least recently; configured order breaks ties.
                probe = min(eligible, key=lambda c: (last_seen[c], configured.index(c)))
                ordered.remove(probe)
                ordered.insert(0, probe)
                mode = "health-probe"
        return RouteOrder(tuple(ordered), mode)

    # Public summaries ---------------------------------------------------------

    @classmethod
    def summary(cls, target: str, *, now: float | None = None) -> dict[str, Any]:
        """Status, recent success rate and median time to response; no counts or usage."""
        current_time = time.time() if now is None else now
        settings = ordering_settings()
        with cls._lock:
            entry = cls._entries.get(target)
            entry = None if entry is None else {**entry, "samples": list(entry["samples"])}
        if entry is None:
            return {"status": "unknown", "success_rate": None, "p50_latency_ms": None,
                    "last_success_at": None, "last_failure_at": None, "last_check_at": None,
                    "last_check": None, "check_status": None}
        recent = [sample for sample in entry["samples"] if current_time - sample[0] <= WINDOW_SECONDS]
        latencies = sorted(sample[2] for sample in recent if sample[1] and sample[2] is not None)
        success_rate = round(sum(sample[1] for sample in recent) / len(recent), 3) if recent else None
        p50 = round(latencies[(len(latencies) - 1) // 2]) if latencies else None
        check_fresh = (
            entry["last_check_at"] is not None
            and current_time - entry["last_check_at"] <= 2 * settings.check_interval_seconds
        )
        if recent:
            if entry["consecutive_failures"] >= DOWN_CONSECUTIVE_FAILURES:
                status = "down"
            elif success_rate >= UP_SUCCESS_RATE:
                status = "up"
            elif success_rate >= DEGRADED_SUCCESS_RATE:
                status = "degraded"
            else:
                status = "down"
        elif check_fresh:
            status = "up" if entry["last_check_ok"] else "down"
        else:
            status = "unknown"
        return {
            "status": status,
            "success_rate": success_rate,
            "p50_latency_ms": p50,
            "last_success_at": iso_time(entry["last_success_at"]),
            "last_failure_at": iso_time(entry["last_failure_at"]),
            "last_check_at": iso_time(entry["last_check_at"]),
            "last_check": None if entry["last_check_ok"] is None else ("ok" if entry["last_check_ok"] else "failed"),
            # The latest free check while it is recent; not published on its own.
            "check_status": ("up" if entry["last_check_ok"] else "down") if check_fresh else None,
        }

    # Persistence --------------------------------------------------------------

    @classmethod
    def dirty_rows(cls, limit: int) -> list[dict[str, Any]]:
        """Changed entries as storable rows, with the version each was read at."""
        with cls._lock:
            rows = []
            for target in sorted(cls._dirty)[:limit]:
                entry = cls._entries.get(target)
                if entry is None:
                    cls._dirty.discard(target)
                    continue
                state = {name: entry[name] for name in _STATE_FIELDS}
                state["samples"] = [list(sample) for sample in entry["samples"]]
                rows.append({"target": target, "state": state, "updated_at": iso_time_ms(entry["updated_at"]),
                             "version": entry["version"]})
            return rows

    @classmethod
    def mark_stored(cls, rows: Iterable[dict[str, Any]]) -> None:
        """Clear rows that did not change while they were being written."""
        with cls._lock:
            for row in rows:
                entry = cls._entries.get(row["target"])
                if entry is None or entry["version"] == row["version"]:
                    cls._dirty.discard(row["target"])

    @classmethod
    def has_changes(cls) -> bool:
        with cls._lock:
            return bool(cls._dirty)

    @classmethod
    def merge_rows(cls, rows: Iterable[dict[str, Any]]) -> int:
        """Adopt stored figures after a restart, keeping whichever evidence is newer."""
        merged = 0
        with cls._lock:
            for row in rows:
                target, state = row.get("target"), row.get("state")
                if not isinstance(target, str) or not isinstance(state, dict) or not valid_state(state):
                    continue
                if target not in cls._entries and len(cls._entries) >= MAX_TARGETS:
                    continue
                entry = cls._entry(target, state["kind"])
                cls._merge_state(entry, state)
                merged += 1
        return merged

    @staticmethod
    def _merge_state(entry: dict[str, Any], state: dict[str, Any]) -> None:
        def newer(field: str) -> bool:
            return state[field] is not None and (entry[field] is None or state[field] > entry[field])

        if newer("ewma_at"):
            entry["ewma_success"], entry["ewma_at"] = state["ewma_success"], state["ewma_at"]
        if newer("latency_at"):
            entry["ewma_latency_ms"], entry["latency_at"] = state["ewma_latency_ms"], state["latency_at"]
        if newer("last_check_at"):
            entry["last_check_at"] = state["last_check_at"]
            entry["last_check_ok"], entry["last_check_status"] = state["last_check_ok"], state["last_check_status"]
        if state["updated_at"] > entry["updated_at"]:
            for field in ("last_status", "last_outcome", "consecutive_failures"):
                entry[field] = state[field]
            entry["updated_at"] = state["updated_at"]
        for field in ("last_success_at", "last_failure_at"):
            if newer(field):
                entry[field] = state[field]
        samples = {tuple(sample) for sample in entry["samples"]} | {tuple(sample) for sample in state["samples"]}
        entry["samples"] = [list(sample) for sample in sorted(samples, key=lambda item: item[0])][-MAX_SAMPLES:]


def iso_time_ms(value: float) -> str:
    """Storage timestamps sort as text, so they keep one fixed format."""
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds")
