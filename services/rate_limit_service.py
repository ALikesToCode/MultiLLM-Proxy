import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from flask import request
from config import Config

logger = logging.getLogger(__name__)

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
        'default': {'requests': 100, 'window': timedelta(minutes=1)},
        'openai': {'requests': 60, 'window': timedelta(minutes=1)},
        'cerebras': {'requests': 40, 'window': timedelta(minutes=1)},
        'xai': {'requests': 50, 'window': timedelta(minutes=1)},
        'googleai': {'requests': 30, 'window': timedelta(minutes=1)},
        'groq': {'requests': 30, 'window': timedelta(minutes=1)}
    }

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
                logger.info(
                    f"Groq API key token limit reached: {total_tokens}/{Config.GROQ_TOKEN_LIMIT} tokens in last minute."
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
                logger.info(
                    f"Rate limit exceeded for {provider} from {client_ip}: "
                    f"{len(cls._requests[key])} requests in the last minute."
                )
                return True

            # Record this request time
            cls._requests[key].append(now)
            return False
