"""Shared free-pool cooldowns, without retaining credentials or request content."""

import math
import re
import time
from contextlib import closing
from email.utils import parsedate_to_datetime

from services.sqlite_store import connect, storage_path

MAX_COOLDOWN = 7 * 24 * 3600
_DURATION = re.compile(
    r"(?:(\d+(?:\.\d+)?)d)?(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?"
)


def reset_seconds(value: str) -> float | None:
    match = _DURATION.fullmatch(str(value).strip())
    if not match or not any(match.groups()):
        return None
    return sum(
        float(amount or 0) * unit
        for amount, unit in zip(match.groups(), (86400, 3600, 60, 1, 0.001))
    )


def retry_seconds(headers, now: float, default: int = 60) -> int:
    normalized = {k.lower(): v for k, v in headers.items()}
    value = normalized.get("retry-after", "")
    delay = None
    try:
        delay = float(value)
    except (ValueError, TypeError):
        try:
            delay = parsedate_to_datetime(value).timestamp() - now
        except (ValueError, TypeError, OverflowError):
            pass
    exhausted = []
    for dimension in ("requests", "tokens"):
        try:
            remaining = float(
                normalized.get(f"x-ratelimit-remaining-{dimension}", "nan")
            )
        except (ValueError, TypeError):
            continue
        if remaining <= 0:
            reset = reset_seconds(normalized.get(f"x-ratelimit-reset-{dimension}", ""))
            exhausted.append(reset if reset is not None else default)
    delays = [
        d for d in [delay, *exhausted] if d is not None and math.isfinite(d) and d > 0
    ]
    return min(MAX_COOLDOWN, max(1, math.ceil(max(delays, default=default))))


class FreeQuotaService:
    @staticmethod
    def _connect():
        connection = connect(
            storage_path("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3")
        )
        connection.execute("""CREATE TABLE IF NOT EXISTS free_route_cooldowns (
            scope TEXT PRIMARY KEY, blocked_until REAL NOT NULL
        )""")
        return connection

    @classmethod
    def remaining(cls, scope: str, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with closing(cls._connect()) as connection:
            row = connection.execute(
                "SELECT blocked_until FROM free_route_cooldowns WHERE scope = ?",
                (scope,),
            ).fetchone()
        return max(0, math.ceil(row["blocked_until"] - now)) if row else 0

    @classmethod
    def block(cls, scope: str, seconds: int, *, now: float | None = None) -> None:
        until = (time.time() if now is None else now) + min(
            MAX_COOLDOWN, max(1, seconds)
        )
        with closing(cls._connect()) as connection, connection:
            connection.execute(
                """INSERT INTO free_route_cooldowns (scope, blocked_until)
                VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET blocked_until =
                CASE WHEN excluded.blocked_until > free_route_cooldowns.blocked_until
                THEN excluded.blocked_until ELSE free_route_cooldowns.blocked_until END""",
                (scope, until),
            )

    @classmethod
    def observe(cls, provider: str, headers, *, now: float | None = None) -> None:
        """A successful request can consume the last remaining quota too."""
        normalized = {k.lower(): str(v) for k, v in headers.items()}
        for dimension in ("requests", "tokens"):
            try:
                exhausted = (
                    float(normalized.get(f"x-ratelimit-remaining-{dimension}", "nan"))
                    <= 0
                )
            except ValueError:
                exhausted = False
            if exhausted:
                timestamp = time.time() if now is None else now
                cls.block(
                    f"provider:{provider}",
                    retry_seconds(headers, timestamp),
                    now=timestamp,
                )
                return
