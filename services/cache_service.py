from functools import lru_cache
from datetime import datetime, timedelta
import json
import logging

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
        except Exception as e:
            logger.error(f"Error getting cache value: {str(e)}")
            return None

    @classmethod
    def set(cls, key, value, ttl=DEFAULT_TTL):
        """Set a value in the cache with a TTL."""
        try:
            cls._cache[key] = value
            cls._cache_times[key] = datetime.now() + ttl
        except Exception as e:
            logger.error(f"Error setting cache value: {str(e)}")

    @classmethod
    def clear(cls):
        """Clear all cached values."""
        try:
            cls._cache.clear()
            cls._cache_times.clear()
        except Exception as e:
            logger.error(f"Error clearing cache: {str(e)}")

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
                    except (TypeError, ValueError) as e:
                        logger.error(f"Error serializing body to JSON: {str(e)}")
                        body = str(body)
                elif not isinstance(body, str):
                    body = str(body)
            
            return f"{method}:{url}:{body if body else ''}"
        except Exception as e:
            logger.error(f"Error generating cache key: {str(e)}")
            # Return a safe fallback key
            return f"{method}:{url}:error-{hash(str(body) if body else '')}" 