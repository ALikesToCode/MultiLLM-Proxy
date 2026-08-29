from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from services.provider_usage_normalizers import NORMALIZERS

logger = logging.getLogger(__name__)

MAX_USAGE_RESPONSE_BYTES = 65_536
AUTH_REJECTION_STATUSES = frozenset({401, 402, 403})


@dataclass(frozen=True)
class ProviderUsageProbe:
    provider: str
    method: str
    base_url_config: str
    path: str
    key_pool: bool = False

    @property
    def endpoint(self) -> str:
        return f"{self.method} /{self.path.lstrip('/')}"


@dataclass(frozen=True)
class CachedUsage:
    expires_at: float
    payload: dict[str, Any]


PROVIDER_USAGE_PROBES = {
    "nanogpt": ProviderUsageProbe(
        provider="nanogpt",
        method="GET",
        base_url_config="NANOGPT_SUBSCRIPTION_BASE_URL",
        path="v1/usage",
        key_pool=True,
    ),
    "navyai": ProviderUsageProbe(
        provider="navyai",
        method="GET",
        base_url_config="API_BASE_URLS.navyai",
        path="v1/usage",
    ),
    "openrouter": ProviderUsageProbe(
        provider="openrouter",
        method="GET",
        base_url_config="API_BASE_URLS.openrouter",
        path="key",
    ),
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class ProviderUsageService:
    """Merge provider-account usage with local proxy telemetry."""

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        auth_service: Any,
        metrics_service: Any,
        proxy_service: Any,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        self.auth_service = auth_service
        self.metrics_service = metrics_service
        self.proxy_service = proxy_service
        self.monotonic = monotonic or time.monotonic
        self.cache_ttl_seconds = int(config.get("PROVIDER_USAGE_CACHE_TTL_SECONDS", 60))
        self.timeout_seconds = int(config.get("PROVIDER_USAGE_TIMEOUT_SECONDS", 8))
        self._cache: dict[str, CachedUsage] = {}
        self._cache_lock = threading.Lock()
        self._provider_locks = {
            provider: threading.Lock()
            for provider in PROVIDER_USAGE_PROBES
        }

    def snapshot(self, provider_ids: Iterable[str]) -> dict[str, Any]:
        providers = sorted({str(provider).strip().lower() for provider in provider_ids if provider})
        cost_summary = self.metrics_service.get_cost_summary()
        provider_costs = {
            item.get("provider"): item
            for item in cost_summary.get("provider_costs", [])
            if isinstance(item, Mapping) and item.get("provider")
        }

        entries = {
            provider: self._base_entry(provider, provider_costs.get(provider))
            for provider in providers
        }
        fetchable = [
            provider
            for provider, entry in entries.items()
            if entry["configured"] and entry["supports_authoritative_usage"]
        ]

        if fetchable:
            with ThreadPoolExecutor(max_workers=min(3, len(fetchable))) as executor:
                futures = {
                    provider: executor.submit(self._authoritative_usage, provider)
                    for provider in fetchable
                }
                for provider in fetchable:
                    entries[provider].update(futures[provider].result())

        result = [entries[provider] for provider in providers]
        return {
            "object": "provider_usage.list",
            "generated_at": self._utcnow(),
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "currency": cost_summary.get("currency", "USD"),
            "providers": result,
            "summary": {
                "providers": len(result),
                "configured": sum(1 for item in result if item["configured"]),
                "authoritative_available": sum(
                    1 for item in result if item["status"] == "available"
                ),
                "unsupported": sum(1 for item in result if item["status"] == "unsupported"),
                "unconfigured": sum(1 for item in result if item["status"] == "unconfigured"),
                "errors": sum(1 for item in result if item["status"] == "error"),
            },
        }

    def _base_entry(
        self,
        provider: str,
        provider_cost: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        supported = provider in PROVIDER_USAGE_PROBES
        credentials = self._credentials(provider)
        configured = bool(credentials) or self._configured_environment(provider)
        if not configured:
            status = "unconfigured"
        elif not supported:
            status = "unsupported"
        else:
            status = "pending"
        stats = self.metrics_service.get_provider_stats(provider)
        cost = _mapping(provider_cost)
        return {
            "provider": provider,
            "configured": configured,
            "supports_authoritative_usage": supported,
            "status": status,
            "source": None,
            "account": {},
            "balances": [],
            "windows": [],
            "local": {
                "requests_24h": stats.get("requests_24h", 0),
                "success_rate": stats.get("success_rate", 0),
                "error_rate": stats.get("error_rate", 0),
                "errors": stats.get("errors", 0),
                "avg_latency_ms": stats.get("avg_latency", 0),
                "p95_latency_ms": stats.get("p95_latency", 0),
                "last_request_at": stats.get("last_request_at"),
                "cost_usd": {
                    "estimated": self._metric_number(cost.get("estimated_cost")),
                    "actual": self._metric_number(cost.get("actual_cost")),
                    "effective": self._metric_number(cost.get("effective_cost")),
                },
            },
            "error": None,
        }

    def _authoritative_usage(self, provider: str) -> dict[str, Any]:
        cached = self._cached(provider)
        if cached is not None:
            return cached

        # Only one request per provider refreshes an expired entry. Other
        # providers remain independent and are still fetched in parallel.
        with self._provider_locks[provider]:
            cached = self._cached(provider)
            if cached is not None:
                return cached
            probe = PROVIDER_USAGE_PROBES[provider]
            fetched = self._fetch(probe, self._credentials(provider))
            if fetched.get("status") == "available":
                with self._cache_lock:
                    self._cache[provider] = CachedUsage(
                        expires_at=self.monotonic() + max(0, self.cache_ttl_seconds),
                        payload=copy.deepcopy(fetched),
                    )
            return fetched

    def _cached(self, provider: str) -> dict[str, Any] | None:
        now = self.monotonic()
        with self._cache_lock:
            cached = self._cache.get(provider)
            if cached is None or cached.expires_at <= now:
                if cached is not None:
                    self._cache.pop(provider, None)
                return None
            payload = copy.deepcopy(cached.payload)
        payload["source"]["cached"] = True
        return payload

    def _fetch(
        self,
        probe: ProviderUsageProbe,
        credentials: Sequence[str],
    ) -> dict[str, Any]:
        last_status = None
        for credential in credentials:
            response = None
            try:
                response = self.proxy_service.make_request(
                    method=probe.method,
                    url=self._probe_url(probe),
                    headers={
                        "Authorization": f"Bearer {credential}",
                        "Accept": "application/json",
                    },
                    params={},
                    data=None,
                    api_provider=probe.provider,
                    use_cache=False,
                    timeout_override=(min(5, self.timeout_seconds), self.timeout_seconds),
                    force_raw_passthrough=True,
                )
                last_status = int(response.status_code)
                if 200 <= last_status < 300:
                    payload = self._response_json(response)
                    normalized = NORMALIZERS[probe.provider](payload)
                    return {
                        "status": "available",
                        **normalized,
                        "source": {
                            "endpoint": probe.endpoint,
                            "fetched_at": self._utcnow(),
                            "cached": False,
                        },
                        "error": None,
                    }
                if last_status not in AUTH_REJECTION_STATUSES or not probe.key_pool:
                    break
            except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as error:
                logger.warning(
                    "Provider usage lookup failed provider=%s type=%s",
                    probe.provider,
                    type(error).__name__,
                )
                return self._error_result(probe, "invalid_response", last_status)
            except Exception as error:  # noqa: BLE001 - isolate provider failures
                logger.warning(
                    "Provider usage transport failed provider=%s type=%s",
                    probe.provider,
                    type(error).__name__,
                )
                return self._error_result(probe, "transport_error", last_status)
            finally:
                if response is not None and hasattr(response, "close"):
                    response.close()

        error_code = (
            "credential_rejected"
            if last_status in AUTH_REJECTION_STATUSES
            else "rate_limited"
            if last_status == 429
            else "upstream_error"
        )
        return self._error_result(probe, error_code, last_status)

    def _response_json(self, response: Any) -> Mapping[str, Any]:
        content = bytes(response.content or b"")
        if not content or len(content) > MAX_USAGE_RESPONSE_BYTES:
            raise ValueError("Provider usage response size is invalid")
        payload = json.loads(content)
        if not isinstance(payload, Mapping):
            raise TypeError("Provider usage response must be a JSON object")
        return payload

    def _error_result(
        self,
        probe: ProviderUsageProbe,
        code: str,
        status_code: int | None,
    ) -> dict[str, Any]:
        return {
            "status": "error",
            "source": {
                "endpoint": probe.endpoint,
                "fetched_at": self._utcnow(),
                "cached": False,
            },
            "account": {},
            "balances": [],
            "windows": [],
            "error": {
                "code": code,
                "status_code": status_code,
            },
        }

    def _credentials(self, provider: str) -> list[str]:
        if provider == "nanogpt":
            values = self.auth_service.get_api_keys(provider)
        else:
            value = self.auth_service.get_api_key(provider)
            values = [value] if value else []
        return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))

    def _configured_environment(self, provider: str) -> bool:
        names = self.auth_service.provider_credential_env_names(provider)
        return any(bool((os.environ.get(name) or "").strip()) for name in names)

    def _probe_url(self, probe: ProviderUsageProbe) -> str:
        if probe.base_url_config.startswith("API_BASE_URLS."):
            provider = probe.base_url_config.partition(".")[2]
            base_url = _mapping(self.config.get("API_BASE_URLS")).get(provider)
        else:
            base_url = self.config.get(probe.base_url_config)
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError(f"Usage base URL is not configured for {probe.provider}")
        return f"{base_url.rstrip('/')}/{probe.path.lstrip('/')}"

    @staticmethod
    def _metric_number(value: Any) -> int | float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0
        return value

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
