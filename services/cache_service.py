from collections import OrderedDict
from functools import lru_cache
from datetime import datetime, timedelta
import json
import logging
import threading
import time

logger = logging.getLogger(__name__)

class CacheService:
    _cache = {}
    _cache_times = {}
    DEFAULT_TTL = timedelta(minutes=5)

    @classmethod
    def get(cls, key):
        """Get a value from the cache if it exists and hasn't expired."""
        try:
            if key in cls._cache:
                if datetime.now() < cls._cache_times[key]:
                    return cls._cache[key]
                else:
                    # Clean up expired cache
                    del cls._cache[key]
                    del cls._cache_times[key]
            return None
        except Exception as error:
            logger.error("Cache read failed type=%s", type(error).__name__)
            return None

    @classmethod
    def set(cls, key, value, ttl=DEFAULT_TTL):
        """Set a value in the cache with a TTL."""
        try:
            cls._cache[key] = value
            cls._cache_times[key] = datetime.now() + ttl
        except Exception as error:
            logger.error("Cache write failed type=%s", type(error).__name__)

    @classmethod
    def clear(cls):
        """Clear all cached values."""
        try:
            cls._cache.clear()
            cls._cache_times.clear()
        except Exception as error:
            logger.error("Cache clear failed type=%s", type(error).__name__)

    @staticmethod
    @lru_cache(maxsize=1000)
    def generate_cache_key(method, url, body=None):
        """Generate a unique cache key for a request."""
        try:
            # Handle binary data safely
            if body is not None:
                if isinstance(body, bytes):
                    try:
                        body = body.decode('utf-8')
                    except UnicodeDecodeError:
                        # If we can't decode it, use a hash of the bytes
                        body = str(hash(body))
                
                # Handle JSON serialization safely
                if isinstance(body, (dict, list)):
                    try:
                        body = json.dumps(body, sort_keys=True)
                    except (TypeError, ValueError) as error:
                        logger.error(
                            "Cache body serialization failed type=%s",
                            type(error).__name__,
                        )
                        body = str(body)
                elif not isinstance(body, str):
                    body = str(body)
            
            return f"{method}:{url}:{body if body else ''}"
        except Exception as error:
            logger.error("Cache key generation failed type=%s", type(error).__name__)
            # Return a safe fallback key
            return f"{method}:{url}:error-{hash(str(body) if body else '')}"


class ResponseCache:
    """A bounded, thread-safe store of complete response bodies, least recently used evicted first.

    Entries expire after their TTL and the store never exceeds its entry or byte budget.
    Keys are opaque digests chosen by the caller; bodies are never logged.
    """

    def __init__(self, max_entries=512, max_bytes=16 * 1024 * 1024):
        self._lock = threading.Lock()
        self._entries = OrderedDict()
        self._bytes = 0
        self.max_entries = max_entries
        self.max_bytes = max_bytes

    def configure(self, *, max_entries, max_bytes):
        with self._lock:
            self.max_entries, self.max_bytes = max_entries, max_bytes
            self._evict_locked()

    def _evict_locked(self):
        while self._entries and (len(self._entries) > self.max_entries or self._bytes > self.max_bytes):
            _, (_, body, _) = self._entries.popitem(last=False)
            self._bytes -= len(body)

    def get(self, key, *, now=None, max_age=None):
        """(body, metadata, age_seconds) for a live entry, or None."""
        current_time = time.time() if now is None else now
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, body, metadata = entry
            if current_time >= metadata["expires_at"]:
                del self._entries[key]
                self._bytes -= len(body)
                return None
            age = max(0.0, current_time - stored_at)
            if max_age is not None and age > max_age:
                return None
            self._entries.move_to_end(key)
            return body, metadata, age

    def put(self, key, body, metadata, *, ttl_seconds, now=None):
        """Store a body when it fits the byte budget; returns whether it was kept."""
        current_time = time.time() if now is None else now
        if len(body) > self.max_bytes:
            return False
        with self._lock:
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._bytes -= len(previous[1])
            self._entries[key] = (current_time, body, {**metadata, "expires_at": current_time + ttl_seconds})
            self._bytes += len(body)
            self._evict_locked()
            return key in self._entries

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._bytes = 0

    def stats(self):
        with self._lock:
            return {"entries": len(self._entries), "bytes": self._bytes}
