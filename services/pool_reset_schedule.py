"""Local reset observations refine scheduling only within an eligible account pool."""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from services.model_cooldown import ModelCooldownExhausted
from services.provider_usage_normalizers import reset_usage_windows
from services.upstream_outcome import UpstreamOutcome, classify_upstream_outcome

logger = logging.getLogger(__name__)
MAX_OBSERVATIONS = 10_000
MAX_RETRY_SECONDS = 3600
_warning_lock = threading.Lock()
_warned_settings: set[str] = set()


@dataclass(frozen=True)
class ResetSettings:
    enabled: bool = False
    ttl_seconds: int = 60


def _invalid_setting(name: str) -> None:
    with _warning_lock:
        if name not in _warned_settings:
            _warned_settings.add(name)
            logger.warning("Invalid %s; pool reset scheduling disabled", name)


def settings(environ: Mapping[str, str] | None = None) -> ResetSettings:
    source = os.environ if environ is None else environ
    flag = (source.get("POOL_RESET_SCHEDULING_ENABLED") or "false").strip().lower() or "false"
    if flag not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        _invalid_setting("POOL_RESET_SCHEDULING_ENABLED")
        return ResetSettings()
    ttl = (source.get("POOL_OBSERVATION_TTL_SECONDS") or "60").strip() or "60"
    try:
        if not re.fullmatch(r"[0-9]+", ttl):
            raise ValueError
        seconds = int(ttl)
        if not 5 <= seconds <= 3600:
            raise ValueError
    except ValueError:
        _invalid_setting("POOL_OBSERVATION_TTL_SECONDS")
        return ResetSettings()
    return ResetSettings(flag in {"true", "1", "yes", "on"}, seconds)


@dataclass(frozen=True)
class ResetObservation:
    observed_at: float
    received_at: float
    windows: tuple[tuple[float, float], ...]


class PoolResetSchedule:
    """Retain opaque identities and validated windows, never credential material."""

    def __init__(
        self, *, clock: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
        max_entries: int = MAX_OBSERVATIONS,
    ) -> None:
        self._clock = clock or time.time
        self._monotonic = monotonic or time.monotonic
        self._max_entries = min(MAX_OBSERVATIONS, max(1, max_entries))
        self._salt = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._entries: OrderedDict[tuple[str, str], ResetObservation] = OrderedDict()

    def credential_id(self, provider: str, credential: str) -> str:
        digest = hmac.new(self._salt, digestmod=hashlib.sha256)
        for part in (provider, credential):
            encoded = part.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()

    def _scope(self, model: str | None, quota_bucket: str | None) -> str:
        if quota_bucket:
            return "bucket:" + quota_bucket
        return "model:" + model if model else "account"

    def _prune(self, config: ResetSettings) -> None:
        wall, mono = self._clock(), self._monotonic()
        self._entries = OrderedDict(
            (identity, observation) for identity, observation in self._entries.items()
            if 0 <= wall - observation.observed_at < config.ttl_seconds
            and 0 <= mono - observation.received_at < config.ttl_seconds
        )

    @property
    def entry_count(self) -> int:
        with self._lock:
            self._prune(settings())
            return len(self._entries)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()

    def observe(
        self, provider: str, credential_id: str, windows: Any, *,
        observed_at: float | None = None, model: str | None = None,
        quota_bucket: str | None = None,
    ) -> None:
        """Consume already authorized data; this method performs no I/O."""
        config = settings()
        if not config.enabled or not isinstance(credential_id, str) or not re.fullmatch(r"[a-f0-9]{64}", credential_id):
            return
        if any(value is not None and (not isinstance(value, str) or len(value) > 256) for value in (model, quota_bucket)):
            return
        wall, mono = self._clock(), self._monotonic()
        observed = wall if observed_at is None else observed_at
        identity = (credential_id, self._scope(model, quota_bucket))
        with self._lock:
            self._prune(config)
            previous = self._entries.get(identity)
            if previous is not None and not isinstance(observed, bool) and isinstance(observed, (int, float)) and observed < previous.observed_at:
                return
            self._entries.pop(identity, None)
            try:
                if isinstance(observed, bool) or not isinstance(observed, (int, float)) or not math.isfinite(observed):
                    return
            except OverflowError:
                return
            # Small positive timestamp skew is tolerated without extending freshness.
            if not -5 <= wall - observed < config.ttl_seconds:
                return
            observed = min(wall, observed)
            normalized = reset_usage_windows(windows, observed)
            if normalized is None:
                return
            self._entries[identity] = ResetObservation(observed, mono, normalized)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def _windows(
        self, provider: str, key: str, model: str | None, quota_bucket: str | None,
    ) -> list[tuple[float, float]]:
        identity = self.credential_id(provider, key)
        scope = self._scope(model, quota_bucket)
        windows = []
        for name in dict.fromkeys(("account", scope)):
            observation = self._entries.get((identity, name))
            if observation is not None:
                windows.extend(window for window in observation.windows if window[1] > self._clock())
        return windows

    def available(
        self, provider: str, eligible: Sequence[str], *, model: str | None = None,
        quota_bucket: str | None = None, configured_order: Sequence[str] | None = None,
    ) -> list[str]:
        config = settings()
        if not config.enabled:
            return list(eligible)
        with self._lock:
            self._prune(config)
            windows = {key: self._windows(provider, key, model, quota_bucket) for key in eligible}
            available = [key for key in eligible if not any(remaining == 0 for remaining, _ in windows[key])]
            order = {key: index for index, key in enumerate(configured_order or eligible)}
            ranked = sorted(
                (key for key in available if windows[key]),
                key=lambda key: (min(reset for _, reset in windows[key]), order[key]),
            )
            # Unknown accounts retain their existing position; only fresh slots reorder.
            iterator = iter(ranked)
            return [next(iterator) if windows[key] else key for key in available]

    def retry_after(
        self, provider: str, keys: Sequence[str], *, model: str | None = None,
        quota_bucket: str | None = None, fallback: float = 60,
        max_seconds: int = MAX_RETRY_SECONDS,
    ) -> int:
        cap = min(MAX_RETRY_SECONDS, max(1, max_seconds))
        resets = []
        if settings().enabled:
            with self._lock:
                self._prune(settings())
                resets = [reset for key in keys for _, reset in self._windows(provider, key, model, quota_bucket)]
        delay = min(resets) - self._clock() if resets else fallback
        if not isinstance(delay, (int, float)) or isinstance(delay, bool) or not math.isfinite(delay):
            delay = 60
        return min(cap, max(1, math.ceil(delay)))

    def admit(
        self, provider: str, keys: Sequence[str], eligible: Sequence[str], *,
        model: str | None = None, quota_bucket: str | None = None,
        require_eligible: bool = False, fallback: float = 60, max_seconds: int = MAX_RETRY_SECONDS,
    ) -> list[str]:
        available = self.available(provider, eligible, model=model, quota_bucket=quota_bucket, configured_order=keys)
        if keys and not available and require_eligible:
            raise ModelCooldownExhausted(self.retry_after(
                provider, keys, model=model, quota_bucket=quota_bucket,
                fallback=fallback, max_seconds=max_seconds,
            ))
        return available


pool_reset_schedule = PoolResetSchedule()


def record_pool_usage(
    provider: str, credential: str, windows: Any, *, observed_at: float | None = None,
    model: str | None = None, quota_bucket: str | None = None,
) -> None:
    if settings().enabled:
        pool_reset_schedule.observe(
            provider, pool_reset_schedule.credential_id(provider, credential), windows,
            observed_at=observed_at, model=model, quota_bucket=quota_bucket,
        )


def record_result_observation(
    provider: str, key: str, status: int, *, outcome: UpstreamOutcome | None = None,
    retry_after_seconds: float | None = None, usage_windows: Any = None,
    model: str | None = None, quota_bucket: str | None = None,
) -> None:
    if not settings().enabled:
        return
    classified = outcome or classify_upstream_outcome(status)
    if usage_windows is not None and classified.credential_health == "accepted":
        record_pool_usage(provider, key, usage_windows, model=model, quota_bucket=quota_bucket)
    elif classified.credential_health == "throttled":
        if isinstance(retry_after_seconds, (int, float)) and not isinstance(retry_after_seconds, bool):
            if 0 < retry_after_seconds <= 31_622_400:
                record_pool_usage(provider, key, [{"remaining": 0, "resets_in_ms": retry_after_seconds * 1000}], model=model, quota_bucket=quota_bucket)
