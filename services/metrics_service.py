import time
from collections import deque
from threading import Lock
from datetime import datetime, timedelta
from typing import Optional

from flask import g, has_request_context, request

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
    
    @staticmethod
    def _percentile(values, percentile):
        """Return a nearest-rank percentile from a numeric series."""
        if not values:
            return 0

        ordered = sorted(values)
        rank = max(0, min(len(ordered) - 1, int(((percentile / 100) * len(ordered)) - 1e-9)))
        return ordered[rank]

    def _get_recent_requests(self, hours=24, now=None):
        """Return requests within the requested time window."""
        current_time = now if now is not None else time.time()
        cutoff = current_time - (hours * 3600)
        return [request for request in self.requests if request["timestamp"] > cutoff]

    def _status_code_bucket(self, status_code):
        """Group HTTP status codes for dashboard reporting."""
        if 200 <= status_code < 300:
            return "2xx"
        if 300 <= status_code < 400:
            return "3xx"
        if 400 <= status_code < 500:
            return "4xx"
        if 500 <= status_code < 600:
            return "5xx"
        return "other"

    def _build_traffic_series(self, recent_requests, hours=24, now=None):
        """Build hourly request and error buckets for the last N hours."""
        current_time = now if now is not None else time.time()
        window_start = current_time - (hours * 3600)
        buckets = [
            {
                "label": f"-{hours - index - 1}h",
                "requests": 0,
                "errors": 0,
                "avg_latency": 0,
                "_latencies": [],
            }
            for index in range(hours)
        ]

        for request in recent_requests:
            bucket_index = int((request["timestamp"] - window_start) // 3600)
            if 0 <= bucket_index < hours:
                bucket = buckets[bucket_index]
                bucket["requests"] += 1
                if request["status_code"] >= 400:
                    bucket["errors"] += 1
                bucket["_latencies"].append(request["response_time"])

        for bucket in buckets:
            latencies = bucket.pop("_latencies")
            if latencies:
                bucket["avg_latency"] = round(sum(latencies) / len(latencies), 2)

        return buckets

    def _request_context_metadata(self, provider):
        if not has_request_context():
            return {}

        user = getattr(g, "authenticated_user", None) or {}
        rate_limit = getattr(g, "rate_limit", None) or {}
        payload = request.get_json(silent=True) if request.is_json else None
        model = payload.get("model") if isinstance(payload, dict) else None
        if model and ":" not in str(model) and provider:
            model = f"{provider}:{model}"

        return {
            "request_id": getattr(g, "request_id", None),
            "user_id": user.get("username") or user.get("id"),
            "api_key_prefix": user.get("api_key_prefix"),
            "model": model,
            "input_tokens": rate_limit.get("input_tokens"),
            "output_tokens": rate_limit.get("output_tokens"),
            "estimated_tokens": rate_limit.get("estimated_tokens"),
        }

    def track_request(
        self,
        provider,
        status_code,
        response_time,
        timestamp=None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        api_key_prefix: Optional[str] = None,
        model: Optional[str] = None,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        estimated_tokens: Optional[int] = None,
        estimated_cost: Optional[float] = None,
        actual_cost: Optional[float] = None,
        ttft_ms: Optional[float] = None,
    ):
        """Track a new request"""
        now = timestamp if timestamp is not None else time.time()
        context_metadata = self._request_context_metadata(provider)
        self.requests.append({
            'timestamp': now,
            'provider': provider,
            'status_code': status_code,
            'response_time': response_time,
            'request_id': request_id or context_metadata.get("request_id"),
            'user_id': user_id or context_metadata.get("user_id"),
            'api_key_prefix': api_key_prefix or context_metadata.get("api_key_prefix"),
            'model': model or context_metadata.get("model"),
            'input_tokens': input_tokens if input_tokens is not None else context_metadata.get("input_tokens"),
            'output_tokens': output_tokens if output_tokens is not None else context_metadata.get("output_tokens"),
            'estimated_tokens': estimated_tokens if estimated_tokens is not None else context_metadata.get("estimated_tokens"),
            'estimated_cost': estimated_cost,
            'actual_cost': actual_cost,
            'ttft_ms': ttft_ms,
        })
    
    def get_stats(self, hours=24, now=None):
        """Get request statistics for the last N hours"""
        current_time = now if now is not None else time.time()
        recent_requests = self._get_recent_requests(hours=hours, now=current_time)
        
        if not recent_requests:
            return {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'success_rate': 0,
                'error_rate': 0,
                'avg_response_time': 0,
                'p50_response_time': 0,
                'p95_response_time': 0,
                'requests_per_minute': 0,
                'top_provider': None,
                'status_code_breakdown': {
                    '2xx': 0,
                    '3xx': 0,
                    '4xx': 0,
                    '5xx': 0,
                    'other': 0,
                },
                'traffic_series': self._build_traffic_series([], hours=hours, now=current_time),
                'last_request_at': None,
            }
        
        # Calculate statistics
        total = len(recent_requests)
        successful = sum(1 for r in recent_requests if 200 <= r['status_code'] < 300)
        failed = total - successful
        avg_time = sum(r['response_time'] for r in recent_requests) / total if total > 0 else 0
        latencies = [r['response_time'] for r in recent_requests]
        provider_totals = {}
        status_code_breakdown = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, 'other': 0}

        for request in recent_requests:
            provider_totals[request['provider']] = provider_totals.get(request['provider'], 0) + 1
            status_code_breakdown[self._status_code_bucket(request['status_code'])] += 1

        top_provider = None
        if provider_totals:
            top_provider = sorted(
                provider_totals.items(),
                key=lambda item: (-item[1], item[0]),
            )[0][0]
        
        return {
            'total_requests': total,
            'successful_requests': successful,
            'failed_requests': failed,
            'success_rate': round((successful / total * 100) if total > 0 else 0, 1),
            'error_rate': round((failed / total * 100) if total > 0 else 0, 1),
            'avg_response_time': round(avg_time, 2),
            'p50_response_time': round(self._percentile(latencies, 50), 2),
            'p95_response_time': round(self._percentile(latencies, 95), 2),
            'requests_per_minute': round(total / max(hours * 60, 1), 2),
            'top_provider': top_provider,
            'status_code_breakdown': status_code_breakdown,
            'traffic_series': self._build_traffic_series(recent_requests, hours=hours, now=current_time),
            'last_request_at': datetime.fromtimestamp(
                max(r['timestamp'] for r in recent_requests)
            ).strftime('%Y-%m-%d %H:%M:%S'),
        }
    
    def get_provider_stats(self, provider, hours=24, now=None):
        """Get statistics for a specific provider"""
        current_time = now if now is not None else time.time()
        provider_requests = [
            request for request in self._get_recent_requests(hours=hours, now=current_time)
            if request['provider'] == provider
        ]
        
        if not provider_requests:
            return {
                'requests_24h': 0,
                'success_rate': 0,
                'error_rate': 0,
                'errors': 0,
                'avg_latency': 0,
                'p95_latency': 0,
                'last_request_at': None,
            }
        
        total = len(provider_requests)
        successful = sum(1 for r in provider_requests if 200 <= r['status_code'] < 300)
        failed = total - successful
        avg_time = sum(r['response_time'] for r in provider_requests) / total if total > 0 else 0
        latencies = [r['response_time'] for r in provider_requests]
        
        return {
            'requests_24h': total,
            'success_rate': round((successful / total * 100) if total > 0 else 0, 1),
            'error_rate': round((failed / total * 100) if total > 0 else 0, 1),
            'errors': failed,
            'avg_latency': round(avg_time, 2),
            'p95_latency': round(self._percentile(latencies, 95), 2),
            'last_request_at': datetime.fromtimestamp(
                max(r['timestamp'] for r in provider_requests)
            ).strftime('%Y-%m-%d %H:%M:%S'),
        }

    def get_provider_breakdown(self, hours=24, now=None):
        """Return provider leaderboard data for the dashboard."""
        current_time = now if now is not None else time.time()
        recent_requests = self._get_recent_requests(hours=hours, now=current_time)
        total_requests = len(recent_requests)
        providers = {}

        for request in recent_requests:
            bucket = providers.setdefault(
                request["provider"],
                {
                    "provider": request["provider"],
                    "requests": 0,
                    "errors": 0,
                    "_latencies": [],
                    "_latest": 0,
                },
            )
            bucket["requests"] += 1
            if request["status_code"] >= 400:
                bucket["errors"] += 1
            bucket["_latencies"].append(request["response_time"])
            bucket["_latest"] = max(bucket["_latest"], request["timestamp"])

        breakdown = []
        for provider, bucket in providers.items():
            requests = bucket["requests"]
            latencies = bucket.pop("_latencies")
            errors = bucket["errors"]
            breakdown.append({
                "provider": provider,
                "requests": requests,
                "share": round((requests / total_requests * 100) if total_requests else 0, 1),
                "errors": errors,
                "success_rate": round(((requests - errors) / requests * 100) if requests else 0, 1),
                "error_rate": round((errors / requests * 100) if requests else 0, 1),
                "avg_latency": round(sum(latencies) / len(latencies), 2) if latencies else 0,
                "p95_latency": round(self._percentile(latencies, 95), 2) if latencies else 0,
                "last_request_at": datetime.fromtimestamp(bucket["_latest"]).strftime('%Y-%m-%d %H:%M:%S')
                if bucket["_latest"] else None,
            })

        return sorted(breakdown, key=lambda item: (-item["requests"], item["provider"]))

    def get_recent_failures(self, limit=5, now=None, hours=24):
        """Return the latest failed requests for operator triage."""
        current_time = now if now is not None else time.time()
        failures = [
            request for request in self._get_recent_requests(hours=hours, now=current_time)
            if request["status_code"] >= 400
        ]
        failures = sorted(failures, key=lambda item: item["timestamp"], reverse=True)[:limit]

        return [
            {
                "time": datetime.fromtimestamp(request["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'),
                "request_id": request.get("request_id"),
                "provider": request["provider"],
                "model": request.get("model"),
                "status_code": request["status_code"],
                "response_time": round(request["response_time"], 2),
                "status_bucket": self._status_code_bucket(request["status_code"]),
            }
            for request in failures
        ]

    def get_request_records(self, limit=100, now=None, hours=24):
        """Return recent request-level records without prompt or response bodies."""
        current_time = now if now is not None else time.time()
        records = sorted(
            self._get_recent_requests(hours=hours, now=current_time),
            key=lambda item: item["timestamp"],
            reverse=True,
        )[:limit]

        return [
            {
                "time": datetime.fromtimestamp(record["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'),
                "request_id": record.get("request_id"),
                "user_id": record.get("user_id"),
                "api_key_prefix": record.get("api_key_prefix"),
                "provider": record["provider"],
                "model": record.get("model"),
                "status_code": record["status_code"],
                "input_tokens": record.get("input_tokens"),
                "output_tokens": record.get("output_tokens"),
                "estimated_tokens": record.get("estimated_tokens"),
                "estimated_cost": record.get("estimated_cost"),
                "actual_cost": record.get("actual_cost"),
                "response_time": round(record["response_time"], 2),
                "ttft_ms": record.get("ttft_ms"),
            }
            for record in records
        ]
    
    def get_recent_activity(self, limit=10):
        """Get recent activity for the status page"""
        recent = sorted(self.requests, key=lambda x: x['timestamp'], reverse=True)[:limit]
        
        return [{
            'time': datetime.fromtimestamp(r['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'provider': r['provider'],
            'status': 'success' if 200 <= r['status_code'] < 300 else 'error',
            'status_code': r['status_code'],
            'response_time': round(r['response_time'], 2),
            'description': f"{r['provider'].upper()} API request {'succeeded' if 200 <= r['status_code'] < 300 else 'failed'}"
        } for r in recent]
