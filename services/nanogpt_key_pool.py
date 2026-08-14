from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import ClassVar

_DIRECT_KEY_NAMES = ("NANOGPT_API_KEY", "NANO_GPT_KEY")
_LIST_KEY_NAMES = ("NANOGPT_API_KEYS", "NANO_GPT_KEYS")
_NUMBERED_KEY_PATTERN = re.compile(
    r"^(NANOGPT_API_KEY|NANO_GPT_KEY)_(\d+)$",
)
_AUTH_REJECTION_STATUSES = frozenset({401, 403})
_TEMPORARY_REJECTION_STATUSES = frozenset({429})
logger = logging.getLogger(__name__)


class NanoGPTKeyPoolExhausted(RuntimeError):
    """Raised when none of the configured NanoGPT keys pass validation."""


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
    candidates: list[str] = []

    for name in _DIRECT_KEY_NAMES:
        value = source.get(name)
        if value and value.strip():
            candidates.append(value.strip())

    for name in _LIST_KEY_NAMES:
        candidates.extend(_listed_keys(source.get(name)))

    numbered: list[tuple[int, int, str]] = []
    for name, value in source.items():
        match = _NUMBERED_KEY_PATTERN.match(name)
        if not match or not value or not value.strip():
            continue
        prefix_rank = _DIRECT_KEY_NAMES.index(match.group(1))
        numbered.append((int(match.group(2)), prefix_rank, value.strip()))
    candidates.extend(value for _, _, value in sorted(numbered))

    keys: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        keys.append(candidate)
    return keys


class NanoGPTKeyPool:
    """Select and retain one validated configured key per application process."""

    _lock: ClassVar[threading.RLock] = threading.RLock()
    _active_key: ClassVar[str | None] = None
    _active_until: ClassVar[float] = 0.0
    _active_requests: ClassVar[int] = 0
    _rejected_until: ClassVar[dict[str, float]] = {}

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
    ) -> str | None:
        configured = list(dict.fromkeys(key.strip() for key in keys if key.strip()))
        if not configured:
            return None

        checked_at = time.monotonic() if now is None else now
        with cls._lock:
            cls._prune(configured, checked_at)
            if len(configured) == 1 and cls._active_key is None:
                cls._active_key = configured[0]
                cls._active_until = checked_at + max(1, check_ttl_seconds)
                cls._active_requests = 0
                return configured[0]
            if (
                cls._active_key in configured
                and cls._active_until > checked_at
                and cls._active_requests < max(1, check_every_requests)
                and cls._rejected_until.get(cls._active_key, 0) <= checked_at
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
                    cls._rejected_until.pop(key, None)
                    return key

                if status not in (
                    _AUTH_REJECTION_STATUSES | _TEMPORARY_REJECTION_STATUSES
                ):
                    ambiguous_active = ambiguous_active or key == previous_active
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
                and cls._rejected_until.get(previous_active, 0) <= checked_at
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
    ) -> None:
        """Record one upstream request and invalidate definite key failures."""
        if not key:
            return
        if status in (_AUTH_REJECTION_STATUSES | _TEMPORARY_REJECTION_STATUSES):
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
    ) -> None:
        if not key:
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
