"""Bounded passive cooldown trials from natural, scoped traffic outcomes."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace

from services.upstream_outcome import UpstreamOutcome

logger = logging.getLogger(__name__)
TTL_SECONDS = 7 * 24 * 3600
MAX_ENTRIES = 1024
MAX_STEPS = 12
_warned: set[str] = set()
_warning_lock = threading.Lock()
_HASH = re.compile(r"[0-9a-f]{64}")


def _warn_once(name: str) -> None:
    with _warning_lock:
        if name in _warned:
            return
        _warned.add(name)
    logger.warning("%s; learned cooldown uses existing behaviour", name)


@dataclass(frozen=True)
class LearnedSettings:
    mode: str = "off"
    buckets: tuple[tuple[str, str | None, str | None], ...] = ()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_field")
        result[key] = value
    return result


def _scope_text(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and value == value.strip() and not any(
        ord(character) < 32 or ord(character) == 127 or character == "*" for character in value
    )


def settings(environ: Mapping[str, str] | None = None) -> LearnedSettings:
    source = os.environ if environ is None else environ
    mode = (source.get("LEARNED_COOLDOWN_MODE") or "off").strip().lower() or "off"
    if mode == "off":
        return LearnedSettings()
    if mode not in {"shadow", "apply"}:
        _warn_once("Invalid LEARNED_COOLDOWN_MODE")
        return LearnedSettings()
    raw = (source.get("LEARNED_COOLDOWN_POLICY_JSON") or "{}").strip() or "{}"
    try:
        if len(raw.encode("utf-8")) > 32768:
            raise ValueError("oversized_policy")
        policy = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(policy, dict) or set(policy) not in (set(), {"buckets"}):
            raise ValueError("invalid_policy")
        rules = policy.get("buckets", [])
        if not isinstance(rules, list) or len(rules) > 128:
            raise ValueError("invalid_buckets")
        buckets = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {"provider", "model", "quota_bucket"}:
                raise ValueError("invalid_scope")
            provider, model, quota = rule["provider"], rule["model"], rule["quota_bucket"]
            if not _scope_text(provider) or any(value is not None and not _scope_text(value) for value in (model, quota)):
                raise ValueError("invalid_identity")
            if model is None and quota is None:
                raise ValueError("unscoped_policy")
            bucket = (provider, model, quota)
            if bucket in buckets:
                raise ValueError("duplicate_scope")
            buckets.append(bucket)
        return LearnedSettings(mode, tuple(buckets))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _warn_once("Invalid LEARNED_COOLDOWN_POLICY_JSON")
        return LearnedSettings()


def _finite(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _floor(value: float | None) -> float:
    return float(value) if _finite(value) and value is not None and value > 0 else 0.0


@dataclass(frozen=True)
class LearnedState:
    credential_digest: str
    lower_seconds: int = 1
    upper_seconds: int = 3600
    trial_seconds: int = 60
    samples: int = 0
    consistent: int = 0
    steps: int = 0
    confident: bool = False
    last_kind: str = "none"
    last_throttle: float | None = None
    last_observed: float = 0
    floor_until: float = 0
    created_at: float = 0
    expires_at: float = 0
    revision: int = 0


def valid_state(value: object, credential_digest: str, now: float) -> bool:
    if not isinstance(value, dict) or set(value) != set(LearnedState.__dataclass_fields__):
        return False
    if value["credential_digest"] != credential_digest or not _HASH.fullmatch(credential_digest):
        return False
    ranges = {"lower_seconds": (1, 3600), "upper_seconds": (1, 3600), "trial_seconds": (1, 3600),
        "samples": (0, 2_147_483_647), "consistent": (0, 3), "steps": (0, MAX_STEPS), "revision": (1, 2_147_483_647)}
    if any(type(value[key]) is not int or not low <= value[key] <= high for key, (low, high) in ranges.items()):
        return False
    if value["lower_seconds"] > value["upper_seconds"] or type(value["confident"]) is not bool or value["last_kind"] not in {"none", "failure", "success"}:
        return False
    times = [value[key] for key in ("last_observed", "floor_until", "created_at", "expires_at")]
    if any(not _finite(item) or item < 0 for item in times):
        return False
    throttle = value["last_throttle"]
    return (throttle is None or _finite(throttle) and value["created_at"] <= throttle <= value["last_observed"]) and (
        value["created_at"] <= value["last_observed"] <= now < value["expires_at"]
        and value["expires_at"] == value["created_at"] + TTL_SECONDS
    )


@dataclass(frozen=True)
class Suggestion:
    bucket_digest: str
    suggested_seconds: float
    lower_seconds: int
    upper_seconds: int
    samples: int
    steps: int
    confident: bool
    minimum_seconds: float


def _widen(state: LearnedState, observed: float) -> LearnedState:
    return replace(state, lower_seconds=max(1, min(state.lower_seconds // 2, math.floor(observed))),
        upper_seconds=min(3600, max(state.upper_seconds * 2, math.ceil(observed) + 1)),
        consistent=0, confident=False, last_kind="none")


def advance(state: LearnedState, kind: str, now: float, floor: float) -> LearnedState:
    """Infer delay bounds only when a real request followed a previous throttle."""
    result = state
    direction = "none"
    if state.samples and now <= state.last_observed:
        result = _widen(state, max(1, state.lower_seconds))
    elif state.last_throttle is not None:
        elapsed = now - state.last_throttle
        if kind == "failure":
            if elapsed >= state.upper_seconds:
                result = _widen(state, elapsed)
            else:
                result = replace(state, lower_seconds=max(state.lower_seconds, min(3600, math.floor(elapsed) + 1)))
                direction = kind
        elif elapsed < state.lower_seconds or now < state.floor_until:
            result = _widen(state, elapsed)
        else:
            result = replace(state, upper_seconds=min(state.upper_seconds, max(1, min(3600, math.ceil(elapsed)))))
            direction = kind
    if direction != "none":
        count = min(3, result.consistent + 1) if result.last_kind == direction else 1
        result = replace(result, consistent=count, last_kind=direction)
        if count >= 3 and result.steps < MAX_STEPS:
            result = replace(result, trial_seconds=(result.lower_seconds + result.upper_seconds) // 2,
                steps=result.steps + 1, consistent=0, confident=True)
    floor_until = max(state.floor_until, now + floor)
    minimum = min(3600, max(1, math.ceil(max(0, floor_until - now))))
    lower = max(minimum, result.lower_seconds)
    upper = max(lower, result.upper_seconds)
    return replace(result, lower_seconds=lower, upper_seconds=upper,
        samples=min(2_147_483_647, state.samples + 1), revision=state.revision + 1,
        last_observed=max(state.last_observed, now), floor_until=floor_until,
        last_throttle=max(state.last_observed, now) if kind == "failure" else None)


class LearnedCooldown:
    """Bounded local authority or fixed D1 compare-and-swap operations."""

    def __init__(self, *, max_entries: int = MAX_ENTRIES):
        self._max_entries = min(MAX_ENTRIES, max(1, max_entries))
        self._lock = threading.RLock()
        self._entries: dict[str, LearnedState] = {}

    @staticmethod
    def _identities(provider: str, credential: str, model: str | None, quota_bucket: str | None) -> tuple[str, str]:
        # Keyed hashes are stable across Containers without storing a key or prefix.
        key = credential.encode("utf-8")
        credential_digest = hmac.new(key, json.dumps(["learned-credential-v1", provider]).encode(), hashlib.sha256).hexdigest()
        bucket = json.dumps(["learned-bucket-v1", provider, model, quota_bucket], separators=(",", ":")).encode()
        return hmac.new(key, bucket, hashlib.sha256).hexdigest(), credential_digest

    @staticmethod
    def _call(operation: str, **values):
        from services import control_state_d1
        return control_state_d1.call("learned-cooldown", operation, **values)

    def snapshot(self, *, now: float | None = None) -> dict[str, dict]:
        current = time.time() if now is None else now
        with self._lock:
            self._prune(current)
            return {key: asdict(value) for key, value in self._entries.items()}

    def _prune(self, now: float) -> None:
        self._entries = {key: value for key, value in self._entries.items() if value.expires_at > now}

    def _read(self, bucket: str, credential: str, now: float, distributed: bool) -> LearnedState | None:
        if not distributed:
            self._prune(now)
            return self._entries.get(bucket)
        response = self._call("get", bucket_digest=bucket, credential_digest=credential, now=now)
        if not isinstance(response, dict) or response.get("version") != 1 or "entry" not in response or response.get("error"):
            raise ValueError("invalid_storage_response")
        entry = response["entry"]
        if entry is None:
            return None
        if not valid_state(entry, credential, now):
            raise ValueError("invalid_storage_entry")
        return LearnedState(**entry)

    def _write(self, bucket: str, state: LearnedState, expected: int, now: float, distributed: bool) -> bool:
        if not distributed:
            if bucket not in self._entries and len(self._entries) >= self._max_entries:
                return False
            self._entries[bucket] = state
            return True
        response = self._call("put", bucket_digest=bucket, credential_digest=state.credential_digest,
            now=now, expected_revision=expected, entry=asdict(state))
        if not isinstance(response, dict) or response.get("version") != 1 or type(response.get("stored")) is not bool or response.get("error"):
            raise ValueError("invalid_storage_response")
        return response["stored"]

    def observe(self, provider: str, credential: str, outcome: UpstreamOutcome, *,
        model: str | None = None, quota_bucket: str | None = None, now: float | None = None,
        retry_after_seconds: float | None = None, default_seconds: float = 60,
        config: LearnedSettings | None = None,
    ) -> Suggestion | None:
        config = settings() if config is None else config
        if config.mode == "off" or (provider, model, quota_bucket) not in config.buckets:
            return None
        kind = "failure" if outcome.credential_health == "throttled" and outcome.reason in {"http_throttled", "quota_exhausted"} else (
            "success" if outcome.provider_health == "success" and outcome.credential_health == "accepted" and outcome.reason == "http_success" else None
        )
        if kind is None:
            return None
        current = time.time() if now is None else now
        if not _finite(current) or current < 0:
            return None
        bucket, digest = self._identities(provider, credential, model, quota_bucket)
        distributed = os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() == "d1"
        with self._lock:
            try:
                state = self._read(bucket, digest, current, distributed)
                if kind == "success" and (state is None or state.last_throttle is None):
                    return None
                if state is None:
                    trial = min(3600, max(1, math.ceil(default_seconds)))
                    state = LearnedState(digest, trial_seconds=trial, created_at=current, expires_at=current + TTL_SECONDS)
                if state.revision >= 2_147_483_647:
                    return None
                updated = advance(state, kind, current, _floor(retry_after_seconds))
                if not self._write(bucket, updated, state.revision, current, distributed):
                    _warn_once("Learned cooldown capacity or revision conflict")
                    return None
            except Exception:  # noqa: BLE001 - optional storage cannot interrupt traffic.
                _warn_once("Learned cooldown storage unavailable")
                return None
        minimum = max(_floor(retry_after_seconds), updated.floor_until - current, 0)
        suggested = max(minimum, min(updated.upper_seconds, max(updated.trial_seconds, updated.lower_seconds)))
        return Suggestion(bucket, suggested, updated.lower_seconds, updated.upper_seconds,
            updated.samples, updated.steps, updated.confident, minimum)


learned_cooldown = LearnedCooldown()


def adjust_cooldown(provider: str, credential: str, outcome: UpstreamOutcome, *,
    current_seconds: float, model: str | None = None, quota_bucket: str | None = None,
    retry_after_seconds: float | None = None, now: float | None = None,
    max_seconds: int = 3600,
) -> float:
    """Change only the recorded duration; selection and replay policy stay outside."""
    config = settings()
    if config.mode == "off" or (provider, model, quota_bucket) not in config.buckets:
        return current_seconds
    suggestion = learned_cooldown.observe(provider, credential, outcome, model=model, quota_bucket=quota_bucket,
        retry_after_seconds=retry_after_seconds, now=now, default_seconds=current_seconds, config=config)
    if suggestion is None:
        return current_seconds
    if config.mode == "shadow":
        logger.info("Learned cooldown bucket=%s suggested_seconds=%s confidence=%s steps=%s",
            suggestion.bucket_digest, suggestion.suggested_seconds, suggestion.confident, suggestion.steps)
        return current_seconds
    if outcome.credential_health != "throttled":
        return current_seconds
    proposed = min(max_seconds, 3600, suggestion.suggested_seconds) if suggestion.confident else current_seconds
    return max(suggestion.minimum_seconds, proposed)
