"""Cooldown for NanoGPT provider-selection suffixes the account cannot pay for.

Provider selection is pay-as-you-go. An account with no balance answers 402 to
every suffixed request, and repeated 402s get the key rate limited, which also
blocks the subscription traffic that would otherwise succeed. After a refusal
this breaker stops adding the suffix until the cooldown expires.
"""

from __future__ import annotations

import threading
import time


class NanoGPTSpeedBreaker:
    _lock = threading.Lock()
    _blocked_until = 0.0

    @classmethod
    def allows_suffix(cls, now: float | None = None) -> bool:
        with cls._lock:
            return (now if now is not None else time.monotonic()) >= cls._blocked_until

    @classmethod
    def record_paygo_rejection(
        cls,
        cooldown_seconds: float,
        now: float | None = None,
    ) -> float:
        moment = now if now is not None else time.monotonic()
        with cls._lock:
            cls._blocked_until = max(cls._blocked_until, moment + max(0.0, cooldown_seconds))
            return cls._blocked_until

    @classmethod
    def blocked_until(cls) -> float:
        with cls._lock:
            return cls._blocked_until

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._blocked_until = 0.0
