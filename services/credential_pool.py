"""Several keys for one provider: use the first that is not resting, and rest refused ones.

Codex Everywhere pools accept a base key and numbered spares (`<BASE>`, `<BASE>_1`,
`<BASE>_2`, ...). Each request uses the first key in that order that is not resting. A key
the provider refuses (401, 402 or 403, which includes an empty balance) rests for five
minutes and a rate-limited key (429) for one minute, so traffic moves to the next key and
returns once the rest ends. State is process-local.
"""

from __future__ import annotations

import os
import re
import threading
import time
from collections.abc import Mapping
from typing import ClassVar

from providers.codex_everywhere import CODEX_EVERYWHERE_POOLS
from services.auth_primitives import usable_credential
from services.model_cooldown import ModelCooldownExhausted, model_cooldown, settings
from services import pool_reset_schedule as reset_schedule
from services import learned_cooldown as learned
from services.upstream_outcome import UpstreamOutcome, classify_upstream_outcome

REFUSED_REST_SECONDS = 300
RATE_LIMITED_REST_SECONDS = 60
REFUSED_STATUSES = frozenset({401, 402, 403})
RATE_LIMITED_STATUSES = frozenset({429})
POOLED_KEY_ENVS = {
    **{pool.provider: pool.credential_env for pool in CODEX_EVERYWHERE_POOLS},
    "ce-image": "CODEX_EVERYWHERE_API_KEY_GPT_IMAGE",
}


def is_key_rejection(status: int | None) -> bool:
    """Whether a status says this key, not the request, was refused."""
    return status in REFUSED_STATUSES or status in RATE_LIMITED_STATUSES


class CredentialPool:
    _lock: ClassVar[threading.Lock] = threading.Lock()
    _resting: ClassVar[dict[tuple[str, str], float]] = {}

    @staticmethod
    def pooled(provider: str | None) -> bool:
        return provider in POOLED_KEY_ENVS

    @staticmethod
    def keys(provider: str, environ: Mapping[str, str] | None = None) -> list[str]:
        """The provider's configured keys: the base name first, then _1, _2, ... ascending."""
        base = POOLED_KEY_ENVS.get(provider)
        if base is None:
            return []
        source = os.environ if environ is None else environ
        numbered = re.compile(rf"^{re.escape(base)}_(\d+)$")
        spares = sorted(
            (int(match.group(1)), name)
            for name in source
            if (match := numbered.fullmatch(name))
        )
        keys: list[str] = []
        for name in (base, *(name for _, name in spares)):
            key = usable_credential(source.get(name), name)
            if key and key.strip() not in keys:
                keys.append(key.strip())
        return keys

    @classmethod
    def available(
        cls,
        provider: str,
        keys: list[str] | None = None,
        *,
        now: float | None = None,
        model: str | None = None,
        quota_bucket: str | None = None,
        require_eligible: bool = False,
    ) -> list[str]:
        """Configured keys that are not resting, in preference order."""
        keys = cls.keys(provider) if keys is None else keys
        if reset_schedule.settings().enabled:
            return cls._scheduled_available(
                provider, keys, now=now, model=model, quota_bucket=quota_bucket,
                require_eligible=require_eligible,
            )
        config = settings()
        if config.enabled and (model or quota_bucket):
            with cls._lock:
                legacy = {key: cls._resting.get((provider, key), 0) for key in keys}
            eligible = model_cooldown.available(
                provider,
                keys,
                model=model,
                quota_bucket=quota_bucket,
                max_seconds=config.max_seconds,
                now=now,
                legacy_rest_until=legacy,
            )
            if require_eligible and keys and not eligible:
                model_cooldown.select(
                    provider, keys, model=model, quota_bucket=quota_bucket,
                    max_seconds=config.max_seconds, now=now, legacy_rest_until=legacy,
                )
            return eligible
        current = time.monotonic() if now is None else now
        with cls._lock:
            return [
                key for key in keys if cls._resting.get((provider, key), 0) <= current
            ]

    @classmethod
    def _scheduled_available(
        cls, provider: str, keys: list[str], *, now: float | None = None,
        model: str | None = None, quota_bucket: str | None = None,
        require_eligible: bool = False,
    ) -> list[str]:
        current = time.monotonic() if now is None else now
        config = settings()
        with cls._lock:
            legacy = {key: cls._resting.get((provider, key), 0) for key in keys}
        eligible = [key for key in keys if legacy[key] <= current]
        fallback = min((max(1, until - current) for until in legacy.values()), default=60)
        if config.enabled and (model or quota_bucket):
            eligible = model_cooldown.available(
                provider, keys, model=model, quota_bucket=quota_bucket,
                max_seconds=config.max_seconds, now=current, legacy_rest_until=legacy,
            )
            if not eligible and require_eligible:
                try:
                    model_cooldown.select(
                        provider, keys, model=model, quota_bucket=quota_bucket,
                        max_seconds=config.max_seconds, now=current, legacy_rest_until=legacy,
                    )
                except ModelCooldownExhausted as error:
                    fallback = error.retry_after
        return reset_schedule.pool_reset_schedule.admit(
            provider, keys, eligible, model=model, quota_bucket=quota_bucket,
            require_eligible=require_eligible, fallback=fallback,
            max_seconds=config.max_seconds if config.enabled else 3600,
        )

    @classmethod
    def select(
        cls,
        provider: str,
        *,
        now: float | None = None,
        model: str | None = None,
        quota_bucket: str | None = None,
    ) -> str | None:
        """The key to use now; the first configured one when every key is resting."""
        keys = cls.keys(provider)
        if reset_schedule.settings().enabled:
            available = cls._scheduled_available(
                provider, keys, now=now, model=model, quota_bucket=quota_bucket,
                require_eligible=True,
            )
            from services.prompt_cache_affinity import prefer_credential
            return prefer_credential(provider, model, available) or next(iter(available), None)
        config = settings()
        if config.enabled and (model or quota_bucket):
            with cls._lock:
                legacy = {key: cls._resting.get((provider, key), 0) for key in keys}
            selected = model_cooldown.select(
                provider,
                keys,
                model=model,
                quota_bucket=quota_bucket,
                max_seconds=config.max_seconds,
                now=now,
                legacy_rest_until=legacy,
            )
            from services.prompt_cache_affinity import prefer_credential
            preferred = prefer_credential(provider, model, cls.available(
                provider, keys, model=model, quota_bucket=quota_bucket, now=now,
            ))
            return preferred or selected
        available = cls.available(provider, keys, now=now)
        from services.prompt_cache_affinity import prefer_credential
        return prefer_credential(provider, model, available) or next(iter(available or keys), None)

    @classmethod
    def record(
        cls,
        provider: str,
        key: str | None,
        status: int,
        *,
        now: float | None = None,
        model: str | None = None,
        quota_bucket: str | None = None,
        outcome: UpstreamOutcome | None = None,
        credential_wide_auth: bool | None = None,
        retry_after_seconds: float | None = None,
        usage_windows: list[Mapping] | None = None,
    ) -> None:
        if not key or provider not in POOLED_KEY_ENVS:
            return
        reset_schedule.record_result_observation(
            provider, key, status, model=model, quota_bucket=quota_bucket,
            outcome=outcome, retry_after_seconds=retry_after_seconds,
            usage_windows=usage_windows,
        )
        config = settings()
        if config.enabled and (model or quota_bucket):
            classified = outcome or classify_upstream_outcome(status)
            wide_auth = (
                status == 401 if credential_wide_auth is None else credential_wide_auth
            )
            until = model_cooldown.record(
                provider,
                key,
                classified,
                model=model,
                quota_bucket=quota_bucket,
                now=now,
                credential_wide_auth=wide_auth,
                retry_after_seconds=retry_after_seconds,
                max_seconds=config.max_seconds,
                fallback_seconds=(
                    REFUSED_REST_SECONDS
                    if classified.credential_health == "rejected"
                    else RATE_LIMITED_REST_SECONDS
                ),
            )
            if (
                classified.credential_health == "rejected"
                and wide_auth
                and until is not None
            ):
                with cls._lock:
                    cls._resting[(provider, key)] = max(
                        cls._resting.get((provider, key), 0), until
                    )
            return
        current = time.monotonic() if now is None else now
        delay = learned.adjust_cooldown(
            provider, key, outcome or classify_upstream_outcome(status),
            model=model, quota_bucket=quota_bucket, now=now,
            current_seconds=RATE_LIMITED_REST_SECONDS,
            retry_after_seconds=retry_after_seconds,
        )
        with cls._lock:
            if status in REFUSED_STATUSES:
                cls._resting[(provider, key)] = current + REFUSED_REST_SECONDS
            elif status in RATE_LIMITED_STATUSES:
                cls._resting[(provider, key)] = current + delay
            elif 200 <= status < 300:
                cls._resting.pop((provider, key), None)

    @classmethod
    def record_headers(
        cls,
        provider: str,
        headers: Mapping[str, str],
        status: int,
        *,
        model: str | None = None,
        quota_bucket: str | None = None,
        outcome: UpstreamOutcome | None = None,
        credential_wide_auth: bool | None = None,
        retry_after_seconds: float | None = None,
        usage_windows: list[Mapping] | None = None,
        now: float | None = None,
    ) -> None:
        """Record the result for the bearer key a request carried."""
        if provider not in POOLED_KEY_ENVS:
            return
        authorization = next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "authorization"
            ),
            "",
        )
        if isinstance(authorization, str) and authorization.startswith("Bearer "):
            cls.record(
                provider,
                authorization[len("Bearer ") :].strip(),
                status,
                model=model,
                quota_bucket=quota_bucket,
                outcome=outcome,
                credential_wide_auth=credential_wide_auth,
                retry_after_seconds=retry_after_seconds,
                usage_windows=usage_windows,
                now=now,
            )

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._resting = {}
