import hashlib
import hmac
import math
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from typing import Optional

from services.sqlite_store import connect, storage_path


DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_WINDOW_SECONDS = 5 * 60
DEFAULT_LOCKOUT_SECONDS = 15 * 60
DEFAULT_MAX_IDENTITIES = 10_000


@dataclass(frozen=True)
class LoginAttemptDecision:
    allowed: bool
    retry_after: Optional[int] = None


class LoginAttemptService:
    """Persist bounded login-failure state without retaining user identifiers."""

    @classmethod
    def _connect(cls) -> sqlite3.Connection:
        return connect(storage_path("RATE_LIMIT_DB_PATH", "rate_limits.sqlite3"))

    @staticmethod
    def _env_int(name: str, default: int, *, maximum: int) -> int:
        configured = (os.environ.get(name) or "").strip()
        if not configured:
            return default
        try:
            value = int(configured)
        except ValueError:
            return default
        return min(max(value, 1), maximum)

    @classmethod
    def _settings(cls) -> tuple[int, int, int, int]:
        return (
            cls._env_int("LOGIN_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS, maximum=100),
            cls._env_int(
                "LOGIN_ATTEMPT_WINDOW_SECONDS",
                DEFAULT_WINDOW_SECONDS,
                maximum=24 * 60 * 60,
            ),
            cls._env_int(
                "LOGIN_LOCKOUT_SECONDS",
                DEFAULT_LOCKOUT_SECONDS,
                maximum=7 * 24 * 60 * 60,
            ),
            cls._env_int(
                "LOGIN_MAX_TRACKED_IDENTITIES",
                DEFAULT_MAX_IDENTITIES,
                maximum=1_000_000,
            ),
        )

    @staticmethod
    def _identity_hash(remote_addr: Optional[str], username: Optional[str]) -> str:
        secret = (os.environ.get("JWT_SECRET") or "").encode("utf-8")
        normalized = (
            f"{remote_addr or 'unknown'}\0{(username or '').strip().casefold()}"
        ).encode("utf-8")
        return hmac.new(secret, normalized, hashlib.sha256).hexdigest()

    @staticmethod
    def _ensure_storage(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                identity_hash TEXT PRIMARY KEY,
                failures INTEGER NOT NULL,
                window_started REAL NOT NULL,
                locked_until REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_login_attempts_updated_at
            ON login_attempts(updated_at)
            """
        )

    @staticmethod
    def _decision_for_lock(locked_until: float, now: float) -> LoginAttemptDecision:
        if locked_until <= now:
            return LoginAttemptDecision(True)
        return LoginAttemptDecision(
            False,
            retry_after=max(1, math.ceil(locked_until - now)),
        )

    @classmethod
    def check(
        cls,
        remote_addr: Optional[str],
        username: Optional[str],
        *,
        now: Optional[float] = None,
    ) -> LoginAttemptDecision:
        current_time = time.time() if now is None else now
        identity_hash = cls._identity_hash(remote_addr, username)
        _, window_seconds, _, _ = cls._settings()

        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT failures, window_started, locked_until
                FROM login_attempts
                WHERE identity_hash = ?
                """,
                (identity_hash,),
            ).fetchone()
            if not row:
                connection.commit()
                return LoginAttemptDecision(True)

            lock_decision = cls._decision_for_lock(float(row["locked_until"]), current_time)
            if not lock_decision.allowed:
                connection.commit()
                return lock_decision

            if current_time - float(row["window_started"]) >= window_seconds:
                connection.execute(
                    "DELETE FROM login_attempts WHERE identity_hash = ?",
                    (identity_hash,),
                )
            connection.commit()
            return LoginAttemptDecision(True)

    @classmethod
    def record_failure(
        cls,
        remote_addr: Optional[str],
        username: Optional[str],
        *,
        now: Optional[float] = None,
    ) -> LoginAttemptDecision:
        current_time = time.time() if now is None else now
        identity_hash = cls._identity_hash(remote_addr, username)
        max_attempts, window_seconds, lockout_seconds, max_identities = cls._settings()

        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT failures, window_started, locked_until
                FROM login_attempts
                WHERE identity_hash = ?
                """,
                (identity_hash,),
            ).fetchone()

            if row and float(row["locked_until"]) > current_time:
                decision = cls._decision_for_lock(float(row["locked_until"]), current_time)
                connection.commit()
                return decision

            if row and current_time - float(row["window_started"]) < window_seconds:
                failures = int(row["failures"]) + 1
                window_started = float(row["window_started"])
            else:
                failures = 1
                window_started = current_time

            locked_until = (
                current_time + lockout_seconds
                if failures >= max_attempts
                else 0.0
            )
            connection.execute(
                """
                INSERT INTO login_attempts (
                    identity_hash, failures, window_started, locked_until, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(identity_hash) DO UPDATE SET
                    failures = excluded.failures,
                    window_started = excluded.window_started,
                    locked_until = excluded.locked_until,
                    updated_at = excluded.updated_at
                """,
                (
                    identity_hash,
                    failures,
                    window_started,
                    locked_until,
                    current_time,
                ),
            )
            cls._prune(connection, current_time, max_identities)
            connection.commit()
            return cls._decision_for_lock(locked_until, current_time)

    @classmethod
    def record_success(
        cls,
        remote_addr: Optional[str],
        username: Optional[str],
    ) -> None:
        identity_hash = cls._identity_hash(remote_addr, username)
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.execute(
                "DELETE FROM login_attempts WHERE identity_hash = ?",
                (identity_hash,),
            )
            connection.commit()

    @classmethod
    def _prune(
        cls,
        connection: sqlite3.Connection,
        current_time: float,
        max_identities: int,
    ) -> None:
        _, window_seconds, lockout_seconds, _ = cls._settings()
        retention_seconds = max(window_seconds, lockout_seconds) * 2
        connection.execute(
            """
            DELETE FROM login_attempts
            WHERE locked_until <= ? AND updated_at < ?
            """,
            (current_time, current_time - retention_seconds),
        )
        row_count = int(
            connection.execute("SELECT COUNT(*) AS count FROM login_attempts").fetchone()["count"]
        )
        excess = row_count - max_identities
        if excess > 0:
            connection.execute(
                """
                DELETE FROM login_attempts
                WHERE identity_hash IN (
                    SELECT identity_hash
                    FROM login_attempts
                    ORDER BY updated_at ASC
                    LIMIT ?
                )
                """,
                (excess,),
            )
