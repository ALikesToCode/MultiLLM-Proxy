"""Bounded, process-local credential/model admission from classified evidence."""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import os
import secrets
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from flask import jsonify

from error_handlers import APIError
from services.upstream_outcome import UpstreamOutcome

logger = logging.getLogger(__name__)
MAX_ENTRIES = 10_000
_warning_lock = threading.Lock()
_warned_settings: set[str] = set()


@dataclass(frozen=True)
class CooldownSettings:
    enabled: bool = False
    max_seconds: int = 3600


def _invalid_setting(name: str) -> None:
    with _warning_lock:
        if name not in _warned_settings:
            _warned_settings.add(name)
            logger.warning("Invalid %s; model cooldown disabled", name)


def settings(environ: Mapping[str, str] | None = None) -> CooldownSettings:
    source = os.environ if environ is None else environ
    enabled = (source.get("MODEL_COOLDOWN_ENABLED") or "false").strip().lower()
    if not enabled:
        enabled = "false"
    if enabled not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        _invalid_setting("MODEL_COOLDOWN_ENABLED")
        return CooldownSettings()
    cap = (source.get("MODEL_COOLDOWN_MAX_SECONDS") or "3600").strip() or "3600"
    try:
        seconds = int(cap)
        if not 1 <= seconds <= 2_147_483_647:
            raise ValueError
    except (TypeError, ValueError):
        _invalid_setting("MODEL_COOLDOWN_MAX_SECONDS")
        return CooldownSettings()
    return CooldownSettings(enabled in {"true", "1", "yes", "on"}, seconds)


class ModelCooldownExhausted(APIError):
    """No eligible credential can be dispatched before its cooldown expires."""

    def __init__(self, retry_after: int):
        super().__init__(
            "All eligible credentials are cooling down.",
            429,
            {"error": "model_cooldown"},
        )
        self.retry_after = retry_after


class ModelCooldownCapacity(APIError):
    """Admission fails closed rather than discarding a live cooldown."""

    def __init__(self, retry_after: int):
        super().__init__("Model cooldown capacity is temporarily unavailable.", 503)
        self.retry_after = retry_after


def cooldown_error_response(error: ModelCooldownExhausted | ModelCooldownCapacity):
    """Emit the cooldown status and bounded Retry-After advice."""
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    response.headers["Retry-After"] = str(error.retry_after)
    return response


def _delay(value: float | None, fallback: int, cap: int) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            if math.isfinite(value) and value >= 0:
                return min(cap, max(1, value))
        except OverflowError:
            pass
    return min(cap, max(1, fallback))


class ModelCooldown:
    """Keep HMAC identities and monotonic deadlines; never retain credentials."""

    def __init__(self, *, max_entries: int = MAX_ENTRIES):
        self._max_entries = min(MAX_ENTRIES, max(1, max_entries))
        self._salt = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, str | None], float] = {}
        self._overflow_until = 0.0

    def _digest(self, *parts: str) -> str:
        digest = hmac.new(self._salt, digestmod=hashlib.sha256)
        for part in parts:
            encoded = part.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()

    def credential_id(self, provider: str, credential: str) -> str:
        return self._digest("credential", provider, credential)

    def _scope(self, model: str | None, quota_bucket: str | None) -> str | None:
        if quota_bucket:
            return self._digest("quota_bucket", quota_bucket)
        return self._digest("model", model) if model else None

    def _prune(self, now: float) -> None:
        self._entries = {
            key: until for key, until in self._entries.items() if until > now
        }
        if self._overflow_until <= now:
            self._overflow_until = 0.0

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._entries)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()
            self._overflow_until = 0.0

    def record(
        self,
        provider: str,
        credential: str,
        outcome: UpstreamOutcome,
        *,
        model: str | None = None,
        quota_bucket: str | None = None,
        credential_wide_auth: bool = False,
        retry_after_seconds: float | None = None,
        fallback_seconds: int = 60,
        max_seconds: int = 3600,
        now: float | None = None,
    ) -> float | None:
        """Return the recorded deadline so adapters can mirror global auth rests."""
        current = time.monotonic() if now is None else now
        scope = self._scope(model, quota_bucket)
        identity = self.credential_id(provider, credential)
        wide_auth = outcome.credential_health == "rejected" and credential_wide_auth
        with self._lock:
            self._prune(current)
            if outcome.credential_health == "accepted":
                if scope is not None:
                    self._entries.pop((identity, scope), None)
                return None
            if not wide_auth and (
                outcome.credential_health != "throttled" or scope is None
            ):
                return None
            entry = (identity, None if wide_auth else scope)
            until = current + _delay(retry_after_seconds, fallback_seconds, max_seconds)
            if entry not in self._entries and len(self._entries) >= self._max_entries:
                # Do not evict live state and silently dispatch a cooling key.
                self._overflow_until = max(self._overflow_until, until)
                return until
            self._entries[entry] = max(self._entries.get(entry, 0), until)
            return self._entries[entry]

    def _remaining(
        self,
        provider: str,
        key: str,
        scope: str | None,
        now: float,
        legacy_rest_until: Mapping[str, float] | None = None,
    ) -> float:
        identity = self.credential_id(provider, key)
        until = max(
            self._entries.get((identity, None), 0.0),
            (legacy_rest_until or {}).get(key, 0.0),
        )
        if scope is not None:
            until = max(until, self._entries.get((identity, scope), 0.0))
        return max(0.0, until - now)

    def available(
        self,
        provider: str,
        keys: Sequence[str],
        *,
        model: str | None = None,
        quota_bucket: str | None = None,
        max_seconds: int = 3600,
        now: float | None = None,
        legacy_rest_until: Mapping[str, float] | None = None,
    ) -> list[str]:
        current = time.monotonic() if now is None else now
        scope = self._scope(model, quota_bucket)
        with self._lock:
            self._prune(current)
            available = [
                key
                for key in keys
                if not self._remaining(provider, key, scope, current, legacy_rest_until)
            ]
            if available and self._overflow_until > current:
                raise ModelCooldownCapacity(
                    min(max_seconds, max(1, math.ceil(self._overflow_until - current)))
                )
            return available

    def select(
        self,
        provider: str,
        keys: Sequence[str],
        *,
        model: str | None = None,
        quota_bucket: str | None = None,
        max_seconds: int = 3600,
        now: float | None = None,
        legacy_rest_until: Mapping[str, float] | None = None,
    ) -> str | None:
        current = time.monotonic() if now is None else now
        with self._lock:
            available = self.available(
                provider,
                keys,
                model=model,
                quota_bucket=quota_bucket,
                max_seconds=max_seconds,
                now=current,
                legacy_rest_until=legacy_rest_until,
            )
            if available:
                return available[0]
            if not keys:
                return None
            scope = self._scope(model, quota_bucket)
            remaining = min(
                self._remaining(provider, key, scope, current, legacy_rest_until)
                for key in keys
            )
            raise ModelCooldownExhausted(min(max_seconds, max(1, math.ceil(remaining))))


model_cooldown = ModelCooldown()
