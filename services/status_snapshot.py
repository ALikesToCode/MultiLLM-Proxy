"""The public status document: per automatic route and provider health, without secrets.

It carries statuses, recent success rates, median time to response and check times only:
no keys, request counts, usage, costs, URLs or hostnames. The Container serves it live, and
services.route_health_sync stores a copy in D1 that the Worker serves while it sleeps.
"""

from __future__ import annotations

import time
from typing import Any

from services.auto_route_service import AutoRoute, AutoRouteService
from services.resilience_service import ResilienceService
from services.route_health import (
    PROVIDER_PREFIX,
    WINDOW_SECONDS,
    RouteHealth,
    iso_time,
    ordering_settings,
    provider_of,
)

STATUS_VERSION = 1


def route_kind(route: AutoRoute) -> str:
    if "video" in route.id:
        return "video"
    if "image" in route.id:
        return "image"
    return "chat"


def _circuit_open(provider: str) -> bool:
    return ResilienceService.snapshot(provider)["state"] == "open"


def _route_status(statuses: list[str]) -> str:
    """Up when the first candidate with data is up; degraded while another still serves."""
    known = [status for status in statuses if status != "unknown"]
    if not known:
        return "unknown"
    if known[0] == "up":
        return "up"
    if any(status in {"up", "degraded"} for status in known):
        return "degraded"
    return "down"


def _overall(statuses: list[str]) -> str:
    known = [status for status in statuses if status != "unknown"]
    if not known:
        return "unknown"
    if all(status == "up" for status in known):
        return "up"
    if all(status == "down" for status in known):
        return "down"
    return "degraded"


def _public_fields(summary: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: summary[key] for key in keys}


def build_public_status(*, now: float | None = None) -> dict[str, Any]:
    current_time = time.time() if now is None else now
    settings = ordering_settings()
    providers: dict[str, dict[str, Any]] = {}
    routes = []
    for route in AutoRouteService.list_routes():
        candidates = []
        for priority, candidate in enumerate(route.candidates, start=1):
            provider = provider_of(candidate)
            if provider not in providers:
                summary = RouteHealth.summary(PROVIDER_PREFIX + provider, now=current_time)
                if _circuit_open(provider):
                    summary["status"] = "down"
                providers[provider] = summary
            summary = RouteHealth.summary(candidate, now=current_time)
            status = summary["status"]
            if providers[provider].get("check_status") and status == "unknown":
                # No recent traffic: the provider's free check is the only evidence.
                status = providers[provider]["check_status"]
            if _circuit_open(provider):
                status = "down"
            candidates.append({
                "model": candidate,
                "provider": provider,
                "priority": priority,
                "status": status,
                **_public_fields(summary, ("success_rate", "p50_latency_ms", "last_success_at", "last_failure_at")),
                "last_check_at": providers[provider]["last_check_at"],
            })
        routes.append({
            "id": route.id,
            "kind": route_kind(route),
            "ordering": settings.mode_for(route.id),
            "status": _route_status([candidate["status"] for candidate in candidates]),
            "candidates": candidates,
        })
    provider_rows = [
        {"id": provider, **_public_fields(summary, (
            "status", "success_rate", "p50_latency_ms", "last_check_at", "last_check"))}
        for provider, summary in sorted(providers.items())
    ]
    return {
        "version": STATUS_VERSION,
        "generated_at": iso_time(current_time),
        "window_seconds": WINDOW_SECONDS,
        "overall": _overall([route["status"] for route in routes]),
        "routes": routes,
        "providers": provider_rows,
    }
