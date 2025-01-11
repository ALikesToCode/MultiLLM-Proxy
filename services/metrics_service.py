import time
from collections import deque
from threading import Lock
from datetime import datetime, timedelta

class MetricsService:
    _instance = None
    _lock = Lock()
    
    def __init__(self):
        # Request tracking for the last 24 hours
        self.requests = deque(maxlen=10000)  # Store last 10000 requests
        self.start_time = time.time()
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def track_request(self, provider, status_code, response_time):
        """Track a new request"""
        now = time.time()
        self.requests.append({
            'timestamp': now,
            'provider': provider,
            'status_code': status_code,
            'response_time': response_time
        })
    
    def get_stats(self, hours=24):
        """Get request statistics for the last N hours"""
        now = time.time()
        cutoff = now - (hours * 3600)
        
        # Filter requests within the time window
        recent_requests = [r for r in self.requests if r['timestamp'] > cutoff]
        
        if not recent_requests:
            return {
                'total_requests': 0,
                'success_rate': 0,
                'avg_response_time': 0
            }
        
        # Calculate statistics
        total = len(recent_requests)
        successful = sum(1 for r in recent_requests if 200 <= r['status_code'] < 300)
        avg_time = sum(r['response_time'] for r in recent_requests) / total if total > 0 else 0
        
        return {
            'total_requests': total,
            'success_rate': round((successful / total * 100) if total > 0 else 0, 1),
            'avg_response_time': round(avg_time, 2)
        }
    
    def get_provider_stats(self, provider, hours=24):
        """Get statistics for a specific provider"""
        now = time.time()
        cutoff = now - (hours * 3600)
        
        # Filter requests for the provider within the time window
        provider_requests = [r for r in self.requests 
                           if r['timestamp'] > cutoff and r['provider'] == provider]
        
        if not provider_requests:
            return {
                'requests_24h': 0,
                'success_rate': 0,
                'avg_latency': 0
            }
        
        total = len(provider_requests)
        successful = sum(1 for r in provider_requests if 200 <= r['status_code'] < 300)
        avg_time = sum(r['response_time'] for r in provider_requests) / total if total > 0 else 0
        
        return {
            'requests_24h': total,
            'success_rate': round((successful / total * 100) if total > 0 else 0, 1),
            'avg_latency': round(avg_time, 2)
        }
    
    def get_recent_activity(self, limit=10):
        """Get recent activity for the status page"""
        recent = sorted(self.requests, key=lambda x: x['timestamp'], reverse=True)[:limit]
        
        return [{
            'time': datetime.fromtimestamp(r['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'provider': r['provider'],
            'status': 'success' if 200 <= r['status_code'] < 300 else 'error',
            'description': f"{r['provider'].upper()} API request {'succeeded' if 200 <= r['status_code'] < 300 else 'failed'}"
        } for r in recent] 