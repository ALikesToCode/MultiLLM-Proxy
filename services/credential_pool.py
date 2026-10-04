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
        cls, provider: str, keys: list[str] | None = None, *, now: float | None = None
    ) -> list[str]:
        """Configured keys that are not resting, in preference order."""
        keys = cls.keys(provider) if keys is None else keys
        current = time.monotonic() if now is None else now
        with cls._lock:
            return [key for key in keys if cls._resting.get((provider, key), 0) <= current]

    @classmethod
    def select(cls, provider: str, *, now: float | None = None) -> str | None:
        """The key to use now; the first configured one when every key is resting."""
        keys = cls.keys(provider)
        return next(iter(cls.available(provider, keys, now=now) or keys), None)

    @classmethod
    def record(
        cls, provider: str, key: str | None, status: int, *, now: float | None = None
    ) -> None:
        if not key or provider not in POOLED_KEY_ENVS:
            return
        current = time.monotonic() if now is None else now
        with cls._lock:
            if status in REFUSED_STATUSES:
                cls._resting[(provider, key)] = current + REFUSED_REST_SECONDS
            elif status in RATE_LIMITED_STATUSES:
                cls._resting[(provider, key)] = current + RATE_LIMITED_REST_SECONDS
            elif 200 <= status < 300:
                cls._resting.pop((provider, key), None)

    @classmethod
    def record_headers(cls, provider: str, headers: Mapping[str, str], status: int) -> None:
        """Record the result for the bearer key a request carried."""
        if provider not in POOLED_KEY_ENVS:
            return
        authorization = next(
            (value for name, value in headers.items() if name.lower() == "authorization"), ""
        )
        if isinstance(authorization, str) and authorization.startswith("Bearer "):
            cls.record(provider, authorization[len("Bearer "):].strip(), status)

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._resting = {}
