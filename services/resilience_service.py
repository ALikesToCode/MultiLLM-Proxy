import math
import os
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, ClassVar

PROVIDER_FAILURE_STATUS_CODES = frozenset({408, 500, 502, 503, 504})
NEUTRAL_STATUS_CODES = frozenset({429})


@dataclass(frozen=True)
class CircuitDecision:
    """Describe whether a provider request may enter the transport."""

    allowed: bool
    state: str
    retry_after: int | None = None
    reason: str | None = None


@dataclass(frozen=True)
class CircuitSettings:
    degraded_failures: int
    open_failures: int
    cooldown_seconds: int
    max_cooldown_seconds: int
    half_open_successes: int
    half_open_max_probes: int


class ResilienceService:
    """Thread-safe provider circuit state with observable recovery phases."""

    _lock = threading.RLock()
    _states: ClassVar[dict[str, dict[str, Any]]] = {}

    @staticmethod
    def _env_int(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, default))
        except (TypeError, ValueError):
            return default

    @classmethod
    def settings(cls) -> CircuitSettings:
        open_failures = max(
            1,
            cls._env_int("CIRCUIT_BREAKER_FAILURES", 5),
        )
        degraded_failures = max(
            1,
            min(
                cls._env_int("CIRCUIT_BREAKER_DEGRADED_FAILURES", 3),
                open_failures,
            ),
        )
        cooldown_seconds = max(
            1,
            cls._env_int("CIRCUIT_BREAKER_COOLDOWN_SECONDS", 30),
        )
        return CircuitSettings(
            degraded_failures=degraded_failures,
            open_failures=open_failures,
            cooldown_seconds=cooldown_seconds,
            max_cooldown_seconds=max(
                cooldown_seconds,
                cls._env_int("CIRCUIT_BREAKER_MAX_COOLDOWN_SECONDS", 300),
            ),
            half_open_successes=max(
                1,
                cls._env_int("CIRCUIT_BREAKER_HALF_OPEN_SUCCESSES", 2),
            ),
            half_open_max_probes=max(
                1,
                cls._env_int("CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES", 2),
            ),
        )

    @classmethod
    def _new_state(cls) -> dict[str, Any]:
        return {
            "state": "closed",
            "consecutive_failures": 0,
            "total_failures": 0,
            "total_successes": 0,
            "rate_limit_events": 0,
            "last_status": None,
            "last_failure_at": None,
            "opened_until": 0.0,
            "reopen_count": 0,
            "half_open_in_flight": 0,
            "half_open_successes": 0,
        }

    @classmethod
    def _provider_state(cls, provider: str) -> dict[str, Any]:
        return cls._states.setdefault(provider, cls._new_state())

    @staticmethod
    def _normalize_provider(provider: str) -> str:
        normalized = str(provider or "unknown").strip().lower()
        return normalized or "unknown"

    @classmethod
    def _advance_expired_open_state(
        cls,
        state: dict[str, Any],
        now: float,
    ) -> None:
        if state["state"] == "open" and now >= state["opened_until"]:
            state["state"] = "half_open"
            state["half_open_in_flight"] = 0
            state["half_open_successes"] = 0

    @classmethod
    def before_request(
        cls,
        provider: str,
        *,
        now: float | None = None,
    ) -> CircuitDecision:
        """Reserve a transport attempt when the provider circuit allows one."""
        provider = cls._normalize_provider(provider)
        current_time = time.time() if now is None else now
        settings = cls.settings()

        with cls._lock:
            state = cls._provider_state(provider)
            cls._advance_expired_open_state(state, current_time)

            if state["state"] == "open":
                retry_after = max(
                    1,
                    math.ceil(state["opened_until"] - current_time),
                )
                return CircuitDecision(
                    allowed=False,
                    state="open",
                    retry_after=retry_after,
                    reason="circuit_open",
                )

            if state["state"] == "half_open":
                if (
                    state["half_open_in_flight"]
                    >= settings.half_open_max_probes
                ):
                    return CircuitDecision(
                        allowed=False,
                        state="half_open",
                        retry_after=1,
                        reason="circuit_probe_busy",
                    )
                state["half_open_in_flight"] += 1

            return CircuitDecision(allowed=True, state=state["state"])

    @classmethod
    def _open_circuit(
        cls,
        state: dict[str, Any],
        settings: CircuitSettings,
        now: float,
        *,
        recovery_failure: bool,
    ) -> None:
        if recovery_failure:
            state["reopen_count"] += 1
        multiplier = 2 ** min(state["reopen_count"], 4)
        cooldown = min(
            settings.cooldown_seconds * multiplier,
            settings.max_cooldown_seconds,
        )
        state["state"] = "open"
        state["opened_until"] = now + cooldown
        state["half_open_in_flight"] = 0
        state["half_open_successes"] = 0

    @classmethod
    def record_result(
        cls,
        provider: str,
        status_code: int,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Record a final transport result and return the resulting snapshot."""
        provider = cls._normalize_provider(provider)
        current_time = time.time() if now is None else now
        settings = cls.settings()

        with cls._lock:
            state = cls._provider_state(provider)
            cls._advance_expired_open_state(state, current_time)
            previous_state = state["state"]
            state["last_status"] = status_code

            if status_code in PROVIDER_FAILURE_STATUS_CODES:
                if previous_state == "half_open":
                    state["half_open_in_flight"] = max(
                        0,
                        state["half_open_in_flight"] - 1,
                    )
                state["consecutive_failures"] += 1
                state["total_failures"] += 1
                state["last_failure_at"] = current_time

                if (
                    previous_state == "half_open"
                    or state["consecutive_failures"] >= settings.open_failures
                ):
                    cls._open_circuit(
                        state,
                        settings,
                        current_time,
                        recovery_failure=previous_state == "half_open",
                    )
                elif (
                    state["consecutive_failures"]
                    >= settings.degraded_failures
                ):
                    state["state"] = "degraded"
            elif status_code in NEUTRAL_STATUS_CODES:
                state["rate_limit_events"] += 1
                if previous_state == "half_open":
                    state["half_open_in_flight"] = max(
                        0,
                        state["half_open_in_flight"] - 1,
                    )
            else:
                state["total_successes"] += 1
                if previous_state == "half_open":
                    state["half_open_in_flight"] = max(
                        0,
                        state["half_open_in_flight"] - 1,
                    )
                    state["half_open_successes"] += 1
                    if (
                        state["half_open_successes"]
                        >= settings.half_open_successes
                    ):
                        total_failures = state["total_failures"]
                        total_successes = state["total_successes"]
                        rate_limit_events = state["rate_limit_events"]
                        last_status = state["last_status"]
                        state.update(cls._new_state())
                        state["total_failures"] = total_failures
                        state["total_successes"] = total_successes
                        state["rate_limit_events"] = rate_limit_events
                        state["last_status"] = last_status
                elif previous_state == "open":
                    # A concurrent probe may have reopened the circuit before an
                    # earlier in-flight probe succeeded. That stale success must
                    # not erase the newer recovery decision.
                    state["last_status"] = status_code
                else:
                    total_failures = state["total_failures"]
                    total_successes = state["total_successes"]
                    rate_limit_events = state["rate_limit_events"]
                    state.update(cls._new_state())
                    state["total_failures"] = total_failures
                    state["total_successes"] = total_successes
                    state["rate_limit_events"] = rate_limit_events
                    state["last_status"] = status_code

            return cls._snapshot_locked(provider, state, current_time, settings)

    @classmethod
    def _snapshot_locked(
        cls,
        provider: str,
        state: dict[str, Any],
        now: float,
        settings: CircuitSettings,
    ) -> dict[str, Any]:
        retry_after = 0
        if state["state"] == "open":
            retry_after = max(0, math.ceil(state["opened_until"] - now))
        return {
            "provider": provider,
            "state": state["state"],
            "consecutive_failures": state["consecutive_failures"],
            "total_failures": state["total_failures"],
            "total_successes": state["total_successes"],
            "rate_limit_events": state["rate_limit_events"],
            "last_status": state["last_status"],
            "last_failure_at": state["last_failure_at"],
            "retry_after_seconds": retry_after,
            "half_open_in_flight": state["half_open_in_flight"],
            "half_open_max_probes": settings.half_open_max_probes,
            "degraded_threshold": settings.degraded_failures,
            "open_threshold": settings.open_failures,
        }

    @classmethod
    def snapshot(
        cls,
        provider: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        provider = cls._normalize_provider(provider)
        current_time = time.time() if now is None else now
        settings = cls.settings()
        with cls._lock:
            state = cls._provider_state(provider)
            cls._advance_expired_open_state(state, current_time)
            return cls._snapshot_locked(
                provider,
                state,
                current_time,
                settings,
            )

    @classmethod
    def snapshot_many(
        cls,
        providers: Iterable[str],
        *,
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        return [
            cls.snapshot(provider, now=now)
            for provider in sorted(set(providers))
        ]

    @classmethod
    def reset(cls) -> None:
        """Clear process-local state for tests and controlled restarts."""
        with cls._lock:
            cls._states = {}
