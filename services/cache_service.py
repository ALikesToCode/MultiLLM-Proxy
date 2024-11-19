from functools import lru_cache
from datetime import datetime, timedelta
import json

class CacheService:
    _cache = {}
    _cache_times = {}
    DEFAULT_TTL = timedelta(minutes=5)

    @classmethod
    def get(cls, key):
        if key in cls._cache:
            if datetime.now() < cls._cache_times[key]:
                return cls._cache[key]
            else:
                # Clean up expired cache
                del cls._cache[key]
                del cls._cache_times[key]
        return None

    @classmethod
    def set(cls, key, value, ttl=DEFAULT_TTL):
        cls._cache[key] = value
        cls._cache_times[key] = datetime.now() + ttl

    @classmethod
    def clear(cls):
        cls._cache.clear()
        cls._cache_times.clear()

    @staticmethod
    @lru_cache(maxsize=1000)
    def generate_cache_key(method, url, body=None):
        """Generate a unique cache key for a request"""
        if body and isinstance(body, bytes):
            body = body.decode('utf-8')
        return f"{method}:{url}:{json.dumps(body) if body else ''}" 