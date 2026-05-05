import logging
import os
import random
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from flask import request
from config import Config
from services.sqlite_store import connect, storage_path

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class LimitDecision:
    allowed: bool
    status_code: int = 200
    error: str = ""
    message: str = ""
    retry_after: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class RateLimitService:
    """
    Manages rate limits for multiple providers and Groq API key token usage.
    Uses in-memory data structures protected by a lock for concurrency safety.
    Ensures no infinite loops by carefully limiting iterations and checks.
    """

    # Tracks requests per (provider, client IP) for request-based rate limiting
    # Format: { "provider:client_ip": [datetime_of_request, ...] }
    _requests: Dict[str, List[datetime]] = {}

    # Lock to protect shared data structures (thread-safe operations)
    _lock = threading.RLock()  # Using RLock instead of Lock to prevent deadlocks

    # Track token usage per Groq API key, storing tuples of (timestamp, tokens_used)
    # Format: { "api_key": [(datetime, tokens_used), ...] }
    _groq_token_usage: Dict[str, List[Tuple[datetime, int]]] = {}

    # Index to track which Groq API key is currently in use
    _current_groq_key_index: int = -1

    # Request limits per provider (requests per time window)
    RATE_LIMITS = {
        'default': {'requests': 1000, 'window': timedelta(minutes=1)},
        'openai': {'requests': 500, 'window': timedelta(minutes=1)},
        'cerebras': {'requests': 500, 'window': timedelta(minutes=1)},
        'xai': {'requests': 500, 'window': timedelta(minutes=1)},
        'googleai': {'requests': 500, 'window': timedelta(minutes=1)},
        'groq': {'requests': 500, 'window': timedelta(minutes=1)},  # Increased since we handle token limits separately
        'together': {'requests': 500, 'window': timedelta(minutes=1)}  # Together AI has a generous rate limit
    }

    _storage_lock = threading.RLock()
    _storage_path: Optional[Path] = None

    @classmethod
    def _default_storage_path(cls) -> Path:
        return storage_path("RATE_LIMIT_DB_PATH", "rate_limits.sqlite3")

    @classmethod
    def _get_storage_path(cls) -> Path:
        configured_path = os.environ.get("RATE_LIMIT_DB_PATH")
        if configured_path:
            return Path(configured_path)
        if cls._storage_path is None:
            cls._storage_path = cls._default_storage_path()
        return cls._storage_path

    @classmethod
    def _connect(cls) -> sqlite3.Connection:
        return connect(cls._get_storage_path())

    @classmethod
    def _ensure_storage(cls, connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS request_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                identity TEXT NOT NULL,
                key_prefix TEXT,
                provider TEXT NOT NULL,
                remote_addr TEXT,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                estimated_tokens INTEGER NOT NULL DEFAULT 0,
                stream INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_request_usage_window
            ON request_usage(identity, provider, created_at)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_request_usage_created_at
            ON request_usage(created_at)
            """
        )

    @staticmethod
    def _env_int(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, default))
        except (TypeError, ValueError):
            logger.warning("Invalid integer for %s; using default %s", name, default)
            return default

    @classmethod
    def _provider_limit(cls, provider: str, name: str, default: int) -> int:
        provider_env = f"{provider.upper()}_{name}"
        shared_env = name
        return cls._env_int(provider_env, cls._env_int(shared_env, default))

    @staticmethod
    def _iter_content_text(value: Any):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            if isinstance(value.get("text"), str):
                yield value["text"]
            if isinstance(value.get("content"), (str, list, dict)):
                yield from RateLimitService._iter_content_text(value["content"])
            if isinstance(value.get("parts"), list):
                yield from RateLimitService._iter_content_text(value["parts"])
        elif isinstance(value, list):
            for item in value:
                yield from RateLimitService._iter_content_text(item)

    @classmethod
    def _message_text_values(cls, messages: Any):
        if not isinstance(messages, list):
            return
        for message in messages:
            if isinstance(message, str):
                yield message
                continue
            if not isinstance(message, dict):
                continue
            if "content" in message:
                yield from cls._iter_content_text(message["content"])
            elif "text" in message:
                yield from cls._iter_content_text(message["text"])
            if "parts" in message:
                yield from cls._iter_content_text(message["parts"])
            if "contents" in message:
                yield from cls._message_text_values(message["contents"])

    @classmethod
    def _payload_text_values(cls, payload: Dict[str, Any]):
        if isinstance(payload.get("messages"), list):
            yield from cls._message_text_values(payload["messages"])
            return
        if isinstance(payload.get("contents"), list):
            yield from cls._message_text_values(payload["contents"])
            return
        if "input" in payload:
            yield from cls._iter_content_text(payload["input"])
            return
        if "prompt" in payload:
            yield from cls._iter_content_text(payload["prompt"])
            return

    @classmethod
    def estimate_input_tokens(cls, payload: Optional[Dict[str, Any]]) -> int:
        if not isinstance(payload, dict):
            return 0

        text = " ".join(cls._payload_text_values(payload))
        if not text:
            return 0
        return max(1, len(text) // 4)

    @staticmethod
    def requested_output_tokens(payload: Optional[Dict[str, Any]]) -> int:
        if not isinstance(payload, dict):
            return 0

        for key in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
            value = payload.get(key)
            if isinstance(value, int):
                return value

        generation_config = payload.get("generationConfig")
        if isinstance(generation_config, dict) and isinstance(generation_config.get("maxOutputTokens"), int):
            return generation_config["maxOutputTokens"]

        return 0

    @staticmethod
    def _identity_for_user(user: Optional[Dict[str, Any]], remote_addr: Optional[str]) -> tuple[str, Optional[str]]:
        if user:
            username = user.get("username") or user.get("id")
            key_prefix = user.get("api_key_prefix")
            identity = username or key_prefix or remote_addr or "unknown"
            return str(identity), key_prefix
        return remote_addr or "unknown", None

    @staticmethod
    def _iso_cutoff(seconds: int) -> str:
        return (_utcnow() - timedelta(seconds=seconds)).isoformat()

    @classmethod
    def _prune_old_usage(cls, connection: sqlite3.Connection) -> None:
        retention_seconds = cls._env_int("RATE_LIMIT_USAGE_RETENTION_SECONDS", 48 * 60 * 60)
        connection.execute(
            "DELETE FROM request_usage WHERE created_at < ?",
            (cls._iso_cutoff(retention_seconds),),
        )

    @classmethod
    def enforce_request(
        cls,
        provider: str,
        user: Optional[Dict[str, Any]],
        payload_bytes: bytes,
        payload_json: Optional[Dict[str, Any]],
        remote_addr: Optional[str],
    ) -> LimitDecision:
        """
        Reserve a request budget slot before dispatch.

        The proxy enforces limits before upstream calls so bursts and failed-cost
        probes cannot bypass RPM/TPM gates. Failed upstream requests currently
        remain counted until request usage reconciliation is added.
        """
        if os.environ.get("RATE_LIMIT_ENABLED", "true").lower() in {"0", "false", "no"}:
            return LimitDecision(True)

        max_request_bytes = cls._provider_limit(provider, "MAX_REQUEST_BYTES", 1024 * 1024)
        if len(payload_bytes or b"") > max_request_bytes:
            return LimitDecision(
                False,
                status_code=413,
                error="request_too_large",
                message="Request body exceeds the configured maximum size.",
                metadata={"max_request_bytes": max_request_bytes},
            )

        input_tokens = cls.estimate_input_tokens(payload_json)
        output_tokens = cls.requested_output_tokens(payload_json)
        max_prompt_tokens = cls._provider_limit(provider, "MAX_PROMPT_TOKENS", 128000)
        max_output_tokens = cls._provider_limit(provider, "MAX_OUTPUT_TOKENS", 8192)
        if input_tokens > max_prompt_tokens:
            return LimitDecision(
                False,
                status_code=400,
                error="prompt_too_large",
                message="Prompt token estimate exceeds the configured maximum.",
                metadata={"input_tokens": input_tokens, "max_prompt_tokens": max_prompt_tokens},
            )
        if output_tokens and output_tokens > max_output_tokens:
            return LimitDecision(
                False,
                status_code=400,
                error="max_output_too_large",
                message="Requested output token count exceeds the configured maximum.",
                metadata={"output_tokens": output_tokens, "max_output_tokens": max_output_tokens},
            )

        identity, key_prefix = cls._identity_for_user(user, remote_addr)
        estimated_tokens = input_tokens + output_tokens
        rpm_limit = cls._provider_limit(provider, "RATE_LIMIT_RPM", cls.RATE_LIMITS.get(provider, cls.RATE_LIMITS["default"])["requests"])
        tpm_limit = cls._provider_limit(provider, "RATE_LIMIT_TPM", 200000)
        daily_limit = cls._provider_limit(provider, "DAILY_REQUEST_LIMIT", 10000)

        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            minute_cutoff = cls._iso_cutoff(60)
            day_cutoff = cls._iso_cutoff(24 * 60 * 60)
            minute_stats = connection.execute(
                """
                SELECT COUNT(*) AS request_count,
                       COALESCE(SUM(estimated_tokens), 0) AS token_count
                FROM request_usage
                WHERE identity = ? AND provider = ? AND created_at >= ?
                """,
                (identity, provider, minute_cutoff),
            ).fetchone()
            daily_stats = connection.execute(
                """
                SELECT COUNT(*) AS request_count
                FROM request_usage
                WHERE identity = ? AND provider = ? AND created_at >= ?
                """,
                (identity, provider, day_cutoff),
            ).fetchone()

            minute_count = int(minute_stats["request_count"])
            minute_tokens = int(minute_stats["token_count"])
            daily_count = int(daily_stats["request_count"])

            metadata = {
                "identity": identity,
                "provider": provider,
                "key_prefix": key_prefix,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "estimated_tokens": estimated_tokens,
                "rpm_limit": rpm_limit,
                "tpm_limit": tpm_limit,
                "daily_request_limit": daily_limit,
            }

            if minute_count >= rpm_limit:
                connection.rollback()
                return LimitDecision(
                    False,
                    status_code=429,
                    error="rate_limit_exceeded",
                    message="Request-per-minute limit exceeded.",
                    retry_after=60,
                    metadata=metadata,
                )
            if estimated_tokens and minute_tokens + estimated_tokens > tpm_limit:
                connection.rollback()
                return LimitDecision(
                    False,
                    status_code=429,
                    error="token_rate_limit_exceeded",
                    message="Token-per-minute limit exceeded.",
                    retry_after=60,
                    metadata=metadata,
                )
            if daily_count >= daily_limit:
                connection.rollback()
                return LimitDecision(
                    False,
                    status_code=429,
                    error="daily_budget_exceeded",
                    message="Daily request budget exceeded.",
                    retry_after=60 * 60,
                    metadata=metadata,
                )

            connection.execute(
                """
                INSERT INTO request_usage (
                    created_at, identity, key_prefix, provider, remote_addr,
                    input_tokens, output_tokens, estimated_tokens, stream
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _utcnow().isoformat(),
                    identity,
                    key_prefix,
                    provider,
                    remote_addr,
                    input_tokens,
                    output_tokens,
                    estimated_tokens,
                    int(bool(payload_json.get("stream"))) if isinstance(payload_json, dict) else 0,
                ),
            )
            # Non-security sampling for opportunistic cleanup.
            if random.random() < 0.01:  # nosec B311
                cls._prune_old_usage(connection)
            connection.commit()
            return LimitDecision(True, metadata=metadata)

    @classmethod
    def get_next_groq_key(cls) -> Optional[str]:
        """
        Rotate through the configured Groq API keys and return the next key 
        that still has available tokens within the last minute.
        
        The loop is explicitly capped by the number of keys to avoid any infinite 
        looping scenario. If no suitable key is found after trying each one once, 
        we return None immediately.
        
        Returns:
            Optional[str]: The next available Groq API key, or None if all are exhausted or none are configured.
        """
        with cls._lock:
            # If no keys configured, return None immediately
            if not Config.GROQ_API_KEYS:
                logger.warning("No Groq API keys configured.")
                return None

            keys_count = len(Config.GROQ_API_KEYS)
            
            # Ensure keys_count is positive (it should be if GROQ_API_KEYS is not empty)
            if keys_count == 0:
                logger.warning("No Groq API keys available (empty configuration).")
                return None

            # Try each key at most once
            for _ in range(keys_count):
                cls._current_groq_key_index = (cls._current_groq_key_index + 1) % keys_count
                current_key = Config.GROQ_API_KEYS[cls._current_groq_key_index]

                if cls.check_groq_token_limit(current_key):
                    logger.info(
                        f"Using Groq API key {cls._current_groq_key_index + 1}/{keys_count}"
                    )
                    return current_key
                else:
                    logger.info(
                        f"Groq API key {cls._current_groq_key_index + 1} is token-limited, trying next key."
                    )
            
            logger.warning("All Groq API keys are token-limited.")
            return None

    @classmethod
    def update_groq_token_usage(cls, api_key: str, token_count: int) -> None:
        """
        Update the token usage record for a given Groq API key.

        Args:
            api_key (str): The Groq API key used.
            token_count (int): Number of tokens consumed by this request.
        """
        if not api_key:
            return
            
        with cls._lock:
            now = datetime.now()
            # Clean up usage older than 1 minute
            cls._groq_token_usage.setdefault(api_key, [])
            cls._groq_token_usage[api_key] = [
                (timestamp, tokens)
                for timestamp, tokens in cls._groq_token_usage[api_key]
                if now - timestamp < timedelta(minutes=1)
            ]
            
            # Append the new usage
            cls._groq_token_usage[api_key].append((now, token_count))
            
            total_tokens = sum(t for _, t in cls._groq_token_usage[api_key])
            logger.info(
                f"Groq API key usage updated: {total_tokens}/{Config.GROQ_TOKEN_LIMIT} tokens in the last minute."
            )

    @classmethod
    def check_groq_token_limit(cls, api_key: str) -> bool:
        """
        Check if the specified Groq API key still has available tokens within the last minute.

        Args:
            api_key (str): The Groq API key to check.

        Returns:
            bool: True if the key can still be used, False if it has reached its token limit.
        """
        if not api_key:
            return False

        with cls._lock:
            now = datetime.now()
            minute_ago = now - timedelta(minutes=1)

            usage = cls._groq_token_usage.get(api_key, [])
            total_tokens = sum(tokens for timestamp, tokens in usage if timestamp > minute_ago)
            
            available = total_tokens < Config.GROQ_TOKEN_LIMIT
            if not available:
                logger.warning(
                    f"Groq API key token limit reached: {total_tokens}/{Config.GROQ_TOKEN_LIMIT} tokens in last minute. "
                    "Will attempt to use next available key."
                )
            return available

    @classmethod
    def is_rate_limited(cls, provider: str) -> bool:
        """
        Determine if the request is rate-limited for the given provider.
        Rate limits are enforced per IP address.

        Args:
            provider (str): The provider name.

        Returns:
            bool: True if rate limit has been exceeded, False otherwise.
        """
        with cls._lock:
            now = datetime.now()
            client_ip = request.remote_addr or "unknown_ip"
            key = f"{provider}:{client_ip}"

            limit_settings = cls.RATE_LIMITS.get(provider, cls.RATE_LIMITS['default'])

            # Remove requests older than the current time window
            cls._requests.setdefault(key, [])
            windowed_requests = [
                t for t in cls._requests[key]
                if now - t < limit_settings['window']
            ]
            cls._requests[key] = windowed_requests

            # Check if limit is exceeded
            if len(cls._requests[key]) >= limit_settings['requests']:
                logger.warning(
                    f"Request rate limit exceeded for {provider} from {client_ip}: "
                    f"{len(cls._requests[key])} requests in the last minute. "
                    f"Limit is {limit_settings['requests']} requests per minute."
                )
                return True

            # Record this request time
            cls._requests[key].append(now)
            return False
