from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import ClassVar

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_SECONDS = 300
DEFAULT_CACHE_MAX_ENTRIES = 2048
_CACHE_KEY_VERSION = b"image-prompt-analysis-v1\0"

ImagePromptSpan = tuple[int, int] | None


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name)
    try:
        value = int(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        logger.warning("Invalid integer for %s; using default %s", name, default)
        return default
    return min(max(value, minimum), maximum)


def _cache_enabled() -> bool:
    value = os.environ.get("CONTEXT_ANALYSIS_CACHE_ENABLED", "true")
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _content_key(role: str, content: str) -> str:
    digest = hashlib.sha256()
    digest.update(_CACHE_KEY_VERSION)
    digest.update(role.encode("utf-8"))
    digest.update(b"\0")
    digest.update(content.encode("utf-8"))
    return digest.hexdigest()


class ContextAnalysisCache:
    """Bounded process-local cache that never retains source conversation text."""

    _entries: ClassVar[
        OrderedDict[str, tuple[float, ImagePromptSpan]]
    ] = OrderedDict()
    _lock: ClassVar[threading.RLock] = threading.RLock()

    @classmethod
    def image_prompt_span(
        cls,
        role: str,
        content: str,
        analyze: Callable[[], ImagePromptSpan],
    ) -> tuple[ImagePromptSpan, str]:
        if not _cache_enabled():
            return analyze(), "bypass"

        ttl_seconds = _bounded_env_int(
            "CONTEXT_ANALYSIS_CACHE_TTL_SECONDS",
            DEFAULT_CACHE_TTL_SECONDS,
            0,
            3600,
        )
        max_entries = _bounded_env_int(
            "CONTEXT_ANALYSIS_CACHE_MAX_ENTRIES",
            DEFAULT_CACHE_MAX_ENTRIES,
            0,
            16_384,
        )
        if ttl_seconds == 0 or max_entries == 0:
            return analyze(), "bypass"

        key = _content_key(role, content)
        now = time.monotonic()
        with cls._lock:
            cached = cls._entries.get(key)
            if cached is not None:
                expires_at, span = cached
                if now < expires_at:
                    cls._entries.move_to_end(key)
                    return span, "hit"
                del cls._entries[key]

        span = analyze()
        with cls._lock:
            cls._entries[key] = (now + ttl_seconds, span)
            cls._entries.move_to_end(key)
            while len(cls._entries) > max_entries:
                cls._entries.popitem(last=False)
        return span, "miss"

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._entries.clear()
