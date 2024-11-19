from datetime import datetime, timedelta
from flask import request
import threading

class RateLimitService:
    _requests = {}
    _lock = threading.Lock()
    
    # Configure limits per provider
    RATE_LIMITS = {
        'default': {'requests': 100, 'window': timedelta(minutes=1)},
        'openai': {'requests': 60, 'window': timedelta(minutes=1)},
        'cerebras': {'requests': 40, 'window': timedelta(minutes=1)},
        'xai': {'requests': 50, 'window': timedelta(minutes=1)},
        'googleai': {'requests': 30, 'window': timedelta(minutes=1)}
    }

    @classmethod
    def is_rate_limited(cls, provider):
        with cls._lock:
            now = datetime.now()
            client_ip = request.remote_addr
            key = f"{provider}:{client_ip}"
            
            # Get rate limit settings
            limit_settings = cls.RATE_LIMITS.get(provider, cls.RATE_LIMITS['default'])
            
            # Clean up old requests
            if key in cls._requests:
                cls._requests[key] = [t for t in cls._requests[key] 
                                    if now - t < limit_settings['window']]
            else:
                cls._requests[key] = []

            # Check if rate limit is exceeded
            if len(cls._requests[key]) >= limit_settings['requests']:
                return True

            # Add new request
            cls._requests[key].append(now)
            return False 