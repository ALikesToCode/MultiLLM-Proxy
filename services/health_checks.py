"""Free provider checks: a model-list request per provider used by an automatic route.

A model list proves the credential is accepted and the provider is reachable without
generating anything, so a check never costs money. Providers without a free model-list
endpoint, or without a configured credential, are reported as skipped and left unchanged.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from typing import Any

from services.auto_route_service import AutoRouteService
from services.provider_catalog_service import (
    PROVIDER_CATALOG_SPECS,
    PUBLIC_CATALOG_PROVIDERS,
)
from services.route_health import RouteHealth, iso_time, provider_of

logger = logging.getLogger(__name__)

CHECK_TIMEOUT = (3, 10)
CHECK_PARALLELISM = 4


def _credential(auth_service_cls, provider: str) -> tuple[bool, str | None]:
    if provider in PUBLIC_CATALOG_PROVIDERS:
        return True, None
    if provider == "nanogpt":
        keys = auth_service_cls.get_api_keys(provider)
        return bool(keys), keys[0] if keys else None
    key = auth_service_cls.get_api_key(provider)
    return bool(key), key


def _check(provider: str, base_url: str, credential: str | None, proxy_service_cls) -> dict[str, Any]:
    spec = PROVIDER_CATALOG_SPECS[provider]
    started = time.monotonic()
    response = None
    try:
        headers = proxy_service_cls.prepare_headers(
            {"Accept": "application/json"}, provider, credential, upstream_path=spec.upstream_path)
        response = proxy_service_cls.make_request(
            method="GET",
            url=f"{base_url.rstrip('/')}/{spec.upstream_path}",
            headers=headers,
            params=[],
            data=None,
            api_provider=provider,
            use_cache=False,
            timeout_override=CHECK_TIMEOUT,
            force_raw_passthrough=True,
        )
        status = int(response.status_code)
        transport = getattr(response, "multillm_transport_failure", None)
    except Exception as error:  # noqa: BLE001 - provider transports vary.
        logger.warning("Health check failed provider=%s error_type=%s", provider, type(error).__name__)
        return {"provider": provider, "result": "failed", "reason": "error",
                "latency_ms": round((time.monotonic() - started) * 1000)}
    finally:
        if response is not None and hasattr(response, "close"):
            with suppress(Exception):
                response.close()
    latency_ms = round((time.monotonic() - started) * 1000)
    if transport:
        return {"provider": provider, "result": "failed", "reason": transport, "latency_ms": latency_ms}
    ok = 200 <= status < 300
    return {"provider": provider, "result": "ok" if ok else "failed", "http_status": status,
            "latency_ms": latency_ms, **({} if ok else {"reason": f"http_{status}"})}


def run_free_checks(base_urls: Mapping[str, str], auth_service_cls, proxy_service_cls,
                    *, now: float | None = None) -> dict[str, Any]:
    """Check every provider named by an automatic route and record the results."""
    candidates_by_provider: dict[str, list[str]] = {}
    for route in AutoRouteService.list_routes():
        for candidate in route.candidates:
            candidates_by_provider.setdefault(provider_of(candidate), []).append(candidate)

    results, targets = [], []
    for provider in sorted(candidates_by_provider):
        base_url = base_urls.get(provider)
        if provider not in PROVIDER_CATALOG_SPECS or not base_url:
            results.append({"provider": provider, "result": "skipped", "reason": "no_free_check"})
            continue
        configured, credential = _credential(auth_service_cls, provider)
        if not configured:
            results.append({"provider": provider, "result": "skipped", "reason": "not_configured"})
            continue
        targets.append((provider, str(base_url), credential))

    if targets:
        with ThreadPoolExecutor(max_workers=min(CHECK_PARALLELISM, len(targets))) as pool:
            checked = list(pool.map(lambda target: _check(target[0], target[1], target[2], proxy_service_cls), targets))
        checked_at = time.time() if now is None else now
        for result in checked:
            provider = result["provider"]
            RouteHealth.record_check(provider, ok=result["result"] == "ok", status=result.get("http_status"),
                                     candidates=candidates_by_provider[provider], now=checked_at)
        results.extend(checked)
    else:
        checked_at = time.time() if now is None else now
    return {"checked_at": iso_time(checked_at), "results": sorted(results, key=lambda item: item["provider"])}
