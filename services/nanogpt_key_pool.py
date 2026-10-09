from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import ClassVar

from services.auth_primitives import is_placeholder_credential
from services.model_cooldown import ModelCooldownExhausted, model_cooldown, settings
from services import pool_reset_schedule as reset_schedule
from services.upstream_outcome import UpstreamOutcome, classify_upstream_outcome

_DIRECT_KEY_NAMES = ("NANOGPT_API_KEY", "NANO_GPT_KEY")
_LIST_KEY_NAMES = ("NANOGPT_API_KEYS", "NANO_GPT_KEYS")
_NUMBERED_KEY_PATTERN = re.compile(
    r"^(NANOGPT_API_KEY|NANO_GPT_KEY)_(\d+)$",
)
_AUTH_REJECTION_STATUSES = frozenset({401, 402, 403})
_TEMPORARY_REJECTION_STATUSES = frozenset({429})
logger = logging.getLogger(__name__)


class NanoGPTKeyPoolExhausted(RuntimeError):
    """Raised when none of the configured NanoGPT keys pass validation."""


def is_nanogpt_credential_rejection(status: int) -> bool:
    """Return whether a response definitively rejected the selected key."""
    return status in (_AUTH_REJECTION_STATUSES | _TEMPORARY_REJECTION_STATUSES)


def _listed_keys(value: str | None) -> list[str]:
    if not value or not value.strip():
        return []

    stripped = value.strip()
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [
                item.strip()
                for item in parsed
                if isinstance(item, str) and item.strip()
            ]

    return [item.strip() for item in re.split(r"[,\n]", stripped) if item.strip()]


def configured_nanogpt_keys(
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Return de-duplicated NanoGPT keys in deterministic preference order."""
    source = os.environ if environ is None else environ
    candidates: list[tuple[int | None, str]] = []

    for name in _DIRECT_KEY_NAMES:
        value = source.get(name)
        if value and value.strip():
            candidates.append((0, value.strip()))

    for name in _LIST_KEY_NAMES:
        candidates.extend((None, value) for value in _listed_keys(source.get(name)))

    numbered: list[tuple[int, int, str]] = []
    for name, value in source.items():
        match = _NUMBERED_KEY_PATTERN.match(name)
        if not match or not value or not value.strip():
            continue
        prefix_rank = _DIRECT_KEY_NAMES.index(match.group(1))
        numbered.append((int(match.group(2)), prefix_rank, value.strip()))
    candidates.extend((index, value) for index, _, value in sorted(numbered))

    preferred_value = (source.get("NANOGPT_PREFERRED_KEY_INDEX") or "").strip()
    preferred_index = (
        int(preferred_value) if re.fullmatch(r"\d+", preferred_value) else None
    )
    if preferred_index is not None:
        candidates = [
            *(candidate for candidate in candidates if candidate[0] == preferred_index),
            *(candidate for candidate in candidates if candidate[0] != preferred_index),
        ]

    keys: list[str] = []
    seen: set[str] = set()
    for _, candidate in candidates:
        if candidate in seen or is_placeholder_credential(candidate):
            continue
        seen.add(candidate)
        keys.append(candidate)
    return keys


class NanoGPTKeyPool:
    """Select and retain one validated configured key per application process."""

    _model_cooldown_provider: ClassVar[str] = "nanogpt"
    _lock: ClassVar[threading.RLock] = threading.RLock()
    _active_key: ClassVar[str | None] = None
    _active_until: ClassVar[float] = 0.0
    _active_requests: ClassVar[int] = 0
    _rejected_until: ClassVar[dict[str, float]] = {}

    @classmethod
    def select_available_key(
        cls,
        keys: Sequence[str],
        *,
        model: str | None = None,
        quota_bucket: str | None = None,
        now: float | None = None,
    ) -> str | None:
        """Select an uncooled credential without claiming a successful probe."""
        configured = list(dict.fromkeys(key.strip() for key in keys if key.strip()))
        now = time.monotonic() if now is None else now
        if reset_schedule.settings().enabled:
            return cls._scheduled_key(configured, model=model, quota_bucket=quota_bucket, now=now)
        config = settings()
        scoped = config.enabled and bool(model or quota_bucket)
        with cls._lock:
            cls._prune(configured, now)
            ordered = [cls._active_key] if cls._active_key in configured else []
            ordered.extend(key for key in configured if key not in ordered)
            if scoped:
                return model_cooldown.select(
                    cls._model_cooldown_provider,
                    ordered,
                    model=model,
                    quota_bucket=quota_bucket,
                    max_seconds=config.max_seconds,
                    now=now,
                    legacy_rest_until=cls._rejected_until,
                )
            return next(
                (key for key in ordered if cls._rejected_until.get(key, 0) <= now), None
            )

    @classmethod
    def _scheduled_key(
        cls, configured: list[str], *, model: str | None = None,
        quota_bucket: str | None = None, now: float,
    ) -> str | None:
        with cls._lock:
            cls._prune(configured, now)
            ordered = [cls._active_key] if cls._active_key in configured else []
            ordered.extend(key for key in configured if key not in ordered)
            return next(iter(cls._scheduled_candidates(
                configured, ordered, model=model, quota_bucket=quota_bucket, now=now,
            )), None)

    @classmethod
    def _scheduled_candidates(
        cls, configured: list[str], ordered: list[str], *,
        model: str | None = None, quota_bucket: str | None = None, now: float,
    ) -> list[str]:
        config = settings()
        eligible = [key for key in ordered if cls._rejected_until.get(key, 0) <= now]
        fallback = min((max(1, cls._rejected_until.get(key, now + 60) - now) for key in configured), default=60)
        if config.enabled and (model or quota_bucket):
            eligible = model_cooldown.available(
                cls._model_cooldown_provider, ordered, model=model,
                quota_bucket=quota_bucket, max_seconds=config.max_seconds,
                now=now, legacy_rest_until=cls._rejected_until,
            )
            if not eligible:
                try:
                    model_cooldown.select(
                        cls._model_cooldown_provider, ordered, model=model,
                        quota_bucket=quota_bucket, max_seconds=config.max_seconds,
                        now=now, legacy_rest_until=cls._rejected_until,
                    )
                except ModelCooldownExhausted as error:
                    fallback = error.retry_after
        return reset_schedule.pool_reset_schedule.admit(
            cls._model_cooldown_provider, configured, eligible, model=model,
            quota_bucket=quota_bucket, require_eligible=True, fallback=fallback,
            max_seconds=config.max_seconds if config.enabled else 3600,
        )

    @classmethod
    def select_key(
        cls,
        keys: Sequence[str],
        probe: Callable[[str], int],
        *,
        check_ttl_seconds: int = 300,
        check_every_requests: int = 50,
        rejected_cooldown_seconds: int = 60,
        now: float | None = None,
        model: str | None = None,
        quota_bucket: str | None = None,
    ) -> str | None:
        configured = list(dict.fromkeys(key.strip() for key in keys if key.strip()))
        if not configured:
            return None

        checked_at = time.monotonic() if now is None else now
        config = settings()
        scoped = config.enabled and bool(model or quota_bucket)
        single_configured_key = len(configured) == 1
        with cls._lock:
            cls._prune(configured, checked_at)
            if reset_schedule.settings().enabled:
                configured = cls._scheduled_candidates(
                    configured, configured, model=model,
                    quota_bucket=quota_bucket, now=checked_at,
                )
            if scoped:
                eligible = model_cooldown.available(
                    cls._model_cooldown_provider,
                    configured,
                    model=model,
                    quota_bucket=quota_bucket,
                    max_seconds=config.max_seconds,
                    now=checked_at,
                    legacy_rest_until=cls._rejected_until,
                )
                if not eligible:
                    return model_cooldown.select(
                        cls._model_cooldown_provider,
                        configured,
                        model=model,
                        quota_bucket=quota_bucket,
                        max_seconds=config.max_seconds,
                        now=checked_at,
                        legacy_rest_until=cls._rejected_until,
                    )
                configured = eligible
            if (
                single_configured_key
                and cls._active_key is None
                and (scoped or cls._rejected_until.get(configured[0], 0) <= checked_at)
            ):
                cls._active_key = configured[0]
                cls._active_until = checked_at + max(1, check_ttl_seconds)
                cls._active_requests = 0
                return configured[0]
            if (
                cls._active_key in configured
                and cls._active_until > checked_at
                and cls._active_requests < max(1, check_every_requests)
                and (
                    scoped or cls._rejected_until.get(cls._active_key, 0) <= checked_at
                )
            ):
                return cls._active_key

            previous_active = cls._active_key
            ambiguous_active = False
            ordered = list(configured)
            if cls._active_key in ordered:
                ordered.remove(cls._active_key)
                ordered.insert(0, cls._active_key)

            attempted = 0
            for key in ordered:
                if cls._rejected_until.get(key, 0) > checked_at:
                    continue
                attempted += 1
                try:
                    status = int(probe(key))
                except (OSError, RuntimeError, TypeError, ValueError) as error:
                    logger.warning(
                        "NanoGPT key validation probe failed (%s)",
                        type(error).__name__,
                    )
                    ambiguous_active = ambiguous_active or key == previous_active
                    continue

                if 200 <= status < 300:
                    cls._active_key = key
                    cls._active_until = checked_at + max(1, check_ttl_seconds)
                    cls._active_requests = 0
                    if not scoped:
                        cls._rejected_until.pop(key, None)
                    return key

                probe_rejected = (
                    classify_upstream_outcome(status).credential_health == "rejected"
                    and status == 401
                    if scoped
                    else is_nanogpt_credential_rejection(status)
                )
                if not probe_rejected:
                    ambiguous_active = ambiguous_active or key == previous_active
                if scoped:
                    # Catalog validation has no model-specific quota evidence.
                    cls._record_model_result(
                        key,
                        status,
                        now=checked_at,
                        check_ttl_seconds=check_ttl_seconds,
                        rejected_cooldown_seconds=rejected_cooldown_seconds,
                    )
                else:
                    cls._mark_rejected(
                        key,
                        status,
                        checked_at,
                        check_ttl_seconds,
                        rejected_cooldown_seconds,
                    )

            if (
                ambiguous_active
                and previous_active in configured
                and (
                    scoped or cls._rejected_until.get(previous_active, 0) <= checked_at
                )
            ):
                cls._active_key = previous_active
                cls._active_until = checked_at + min(
                    max(1, check_ttl_seconds),
                    30,
                )
                cls._active_requests = 0
                return previous_active

            cls._active_key = None
            cls._active_until = 0.0
            cls._active_requests = 0
            if scoped:
                # Genuine probe auth failures can make the entire pool cooling.
                model_cooldown.select(
                    cls._model_cooldown_provider,
                    configured,
                    model=model,
                    quota_bucket=quota_bucket,
                    max_seconds=config.max_seconds,
                    now=checked_at,
                    legacy_rest_until=cls._rejected_until,
                )
            if attempted == 0:
                raise NanoGPTKeyPoolExhausted(
                    "All configured NanoGPT keys are cooling down",
                )
            raise NanoGPTKeyPoolExhausted(
                "No configured NanoGPT API key passed validation",
            )

    @classmethod
    def record_result(
        cls,
        key: str | None,
        status: int,
        *,
        check_ttl_seconds: int = 300,
        rejected_cooldown_seconds: int = 60,
        now: float | None = None,
        model: str | None = None,
        quota_bucket: str | None = None,
        outcome: UpstreamOutcome | None = None,
        credential_wide_auth: bool | None = None,
        retry_after_seconds: float | None = None,
        usage_windows: list[Mapping] | None = None,
    ) -> None:
        """Record one upstream request and invalidate definite key failures."""
        if not key:
            return
        reset_schedule.record_result_observation(
            cls._model_cooldown_provider, key, status, model=model,
            quota_bucket=quota_bucket, outcome=outcome,
            retry_after_seconds=retry_after_seconds, usage_windows=usage_windows,
        )
        if settings().enabled and (model or quota_bucket):
            cls._record_model_result(
                key,
                status,
                model=model,
                quota_bucket=quota_bucket,
                outcome=outcome,
                credential_wide_auth=credential_wide_auth,
                retry_after_seconds=retry_after_seconds,
                now=now,
                check_ttl_seconds=check_ttl_seconds,
                rejected_cooldown_seconds=rejected_cooldown_seconds,
            )
            with cls._lock:
                if cls._active_key == key:
                    cls._active_requests += 1
            return
        if is_nanogpt_credential_rejection(status):
            cls.invalidate(
                key,
                status,
                check_ttl_seconds=check_ttl_seconds,
                rejected_cooldown_seconds=rejected_cooldown_seconds,
                now=now,
            )
            return

        with cls._lock:
            if cls._active_key == key:
                cls._active_requests += 1

    @classmethod
    def invalidate(
        cls,
        key: str | None,
        status: int,
        *,
        check_ttl_seconds: int = 300,
        rejected_cooldown_seconds: int = 60,
        now: float | None = None,
        model: str | None = None,
        quota_bucket: str | None = None,
        outcome: UpstreamOutcome | None = None,
        credential_wide_auth: bool | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        if not key:
            return
        if settings().enabled and (model or quota_bucket):
            cls._record_model_result(
                key,
                status,
                model=model,
                quota_bucket=quota_bucket,
                outcome=outcome,
                credential_wide_auth=credential_wide_auth,
                retry_after_seconds=retry_after_seconds,
                now=now,
                check_ttl_seconds=check_ttl_seconds,
                rejected_cooldown_seconds=rejected_cooldown_seconds,
            )
            return
        rejected_at = time.monotonic() if now is None else now
        with cls._lock:
            if cls._active_key == key:
                cls._active_key = None
                cls._active_until = 0.0
                cls._active_requests = 0
            cls._mark_rejected(
                key,
                status,
                rejected_at,
                check_ttl_seconds,
                rejected_cooldown_seconds,
            )

    @classmethod
    def _record_model_result(
        cls,
        key: str,
        status: int,
        *,
        model: str | None = None,
        quota_bucket: str | None = None,
        outcome: UpstreamOutcome | None = None,
        credential_wide_auth: bool | None = None,
        retry_after_seconds: float | None = None,
        now: float | None = None,
        check_ttl_seconds: int = 300,
        rejected_cooldown_seconds: int = 60,
    ) -> None:
        classified = outcome or classify_upstream_outcome(status)
        wide_auth = (
            status == 401 if credential_wide_auth is None else credential_wide_auth
        )
        until = model_cooldown.record(
            cls._model_cooldown_provider,
            key,
            classified,
            model=model,
            quota_bucket=quota_bucket,
            credential_wide_auth=wide_auth,
            retry_after_seconds=retry_after_seconds,
            now=now,
            max_seconds=settings().max_seconds,
            fallback_seconds=(
                check_ttl_seconds
                if classified.credential_health == "rejected"
                else rejected_cooldown_seconds
            ),
        )

        if (
            classified.credential_health == "rejected"
            and wide_auth
            and until is not None
        ):
            with cls._lock:
                cls._rejected_until[key] = max(cls._rejected_until.get(key, 0), until)
                if cls._active_key == key:
                    cls._active_key = None
                    cls._active_until = 0.0
                    cls._active_requests = 0

    @classmethod
    def reset(cls) -> None:
        """Clear process-local selection state for tests and app reinitialization."""
        with cls._lock:
            cls._active_key = None
            cls._active_until = 0.0
            cls._active_requests = 0
            cls._rejected_until = {}

    @classmethod
    def _prune(cls, configured: Sequence[str], now: float) -> None:
        configured_set = set(configured)
        cls._rejected_until = {
            key: deadline
            for key, deadline in cls._rejected_until.items()
            if key in configured_set and deadline > now
        }
        if cls._active_key not in configured_set:
            cls._active_key = None
            cls._active_until = 0.0
            cls._active_requests = 0

    @classmethod
    def _mark_rejected(
        cls,
        key: str,
        status: int,
        now: float,
        check_ttl_seconds: int,
        rejected_cooldown_seconds: int,
    ) -> None:
        if status in _AUTH_REJECTION_STATUSES:
            cls._rejected_until[key] = now + max(1, check_ttl_seconds)
        elif status in _TEMPORARY_REJECTION_STATUSES:
            cls._rejected_until[key] = now + max(
                1,
                rejected_cooldown_seconds,
            )


class NanoGPTUnifiedKeyPool(NanoGPTKeyPool):
    """Keep unified/subscription credential health separate from raw traffic."""

    _model_cooldown_provider: ClassVar[str] = "nanogpt-unified"

    _lock: ClassVar[threading.RLock] = threading.RLock()
    _active_key: ClassVar[str | None] = None
    _active_until: ClassVar[float] = 0.0
    _active_requests: ClassVar[int] = 0
    _rejected_until: ClassVar[dict[str, float]] = {}
