"""Versioned cache identity from resolved, server-owned Chat policy."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

from flask import current_app, g, request

LEGACY_REVISION = "legacy"
ISOLATED_REVISION = "v1"
WORKFLOW_VERSION = "chat-v1"
_WORKFLOW_CONFIG = (
    "PROMPT_CACHE_ENABLED", "PROMPT_CACHE_MIN_TOKENS", "NANOGPT_BILLING_MODE",
    "NANOGPT_SPEED_ROUTING",
)
_WORKFLOW_ENV = (
    "GLM_AUTO_OPTIMIZE", "GLM_AUTO_OPTIMIZE_TRIGGER_TOKENS", "GLM_AUTO_OPTIMIZE_KEEP_RECENT_TURNS",
)


@dataclass(frozen=True)
class CachePolicy:
    resolved_route: dict[str, Any]
    model_permissions: list[str] | None
    secret_policy: str
    retention_policy: dict[str, Any]
    workflow_version: str


def policy_revision() -> str:
    # An empty value is how a deployed variable is cleared, so it means the default.
    return os.environ.get("RESPONSE_CACHE_POLICY_REVISION", "").strip() or LEGACY_REVISION


def policy_digest(policy: CachePolicy) -> str:
    """Canonical JSON has no process hashes, raw API keys or request/response content."""
    canonical = json.dumps(asdict(policy), sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _endpoint_identity(url: str) -> str | None:
    parsed = urlsplit(url)
    # Credential-bearing endpoints cannot supply a safe complete identity.
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return url


def _direct_route(model: str) -> dict[str, Any] | None:
    from providers.registry import get_adapter
    from services.model_registry import ModelRegistry

    provider, provider_model = ModelRegistry.parse_model_id(model)
    adapter = get_adapter(provider, current_app.config["API_BASE_URLS"])
    status = ModelRegistry.get_model_status(model)
    if adapter is None or status == "disabled":
        return None
    endpoint = _endpoint_identity(adapter.chat_completions_url())
    if endpoint is None:
        return None
    route = {"model": model, "provider": provider, "provider_model": provider_model,
             "endpoint": endpoint, "status": status}
    if provider == "opencode":
        zen_endpoint = _endpoint_identity(current_app.config["OPENCODE_ZEN_BASE_URL"])
        if zen_endpoint is None:
            return None
        route["zen_endpoint"] = zen_endpoint
    if provider == "aihubmix":
        backup = current_app.config.get("AIHUBMIX_BACKUP_BASE_URL")
        if backup:
            backup_endpoint = _endpoint_identity(backup)
            if backup_endpoint is None:
                return None
            route["backup_endpoint"] = backup_endpoint
    return route


def _resolved_route(model: str) -> dict[str, Any] | None:
    from services.auto_route_service import AutoRouteService
    from services.route_health import ordering_settings

    # These workflows have dynamic pools or additional guardrails. Until their
    # effective plans are available, never replay under an incomplete identity.
    if model.startswith(("free:", "cascade:")):
        return None
    if not AutoRouteService.is_auto_route(model):
        return _direct_route(model)
    route = AutoRouteService.get_route(model)
    if route is None or ordering_settings().mode_for(route.id) != "priority":
        return None
    candidates = []
    for model_id in route.candidates:
        resolved = _direct_route(model_id)
        if resolved is None:
            return None
        candidates.append(resolved)
    return {"id": route.id, "revision": route.updated_at, "candidates": candidates, "ordering": "priority"}


def _policy_snapshot(payload: dict) -> CachePolicy | None:
    from services.key_controls import model_patterns
    from services.secret_firewall import scan_mode

    # Query parameters and provider-selection headers can change upstream work.
    # Their arbitrary values may contain credentials, so do not hash them.
    if request.query_string or any(request.headers.get(name) for name in (
        "X-Provider", "X-Model", "X-MultiLLM-Provider",
    )):
        return None
    route = _resolved_route(payload["model"])
    if route is None:
        return None
    user = getattr(g, "authenticated_user", None) or {}
    patterns = model_patterns(user)
    permissions = sorted({pattern.lower() for pattern in patterns}) if patterns else None
    retention = getattr(g, "multillm_retention_policy", {"mode": "legacy", "revision": "legacy"})
    workflow = getattr(g, "multillm_workflow_version", WORKFLOW_VERSION)
    if (not isinstance(retention, dict) or set(retention) != {"mode", "revision"}
            or retention.get("mode") != "legacy"
            or not isinstance(retention.get("revision"), str) or not retention["revision"]
            or not isinstance(workflow, str) or not workflow):
        return None
    route["workflow_settings"] = {
        "config": {name: current_app.config.get(name) for name in _WORKFLOW_CONFIG},
        "environment": {name: os.environ.get(name) for name in _WORKFLOW_ENV},
    }
    return CachePolicy(route, permissions, scan_mode(user), retention, workflow)


def resolve_policy(payload: dict) -> CachePolicy | None:
    """Unavailable policy bypasses the optimization; the normal view owns errors.

    Read only current main's policy services. No provider calls, credentials,
    content logging, new retries or imports from later feature waves.
    """
    try:
        policy = _policy_snapshot(payload)
        if policy is not None:
            policy_digest(policy)  # Validate before any cache read or write.
        return policy
    except Exception:
        # Policy storage/serialization failure must not grant a shared fallback
        # identity or replace the response/error produced by the normal route.
        return None


def policy_is_current(payload: dict, digest: str) -> bool:
    """Do not store an in-flight answer after its policy or revision changed."""
    if policy_revision() != ISOLATED_REVISION:
        return False
    policy = resolve_policy(payload)
    return policy is not None and policy_digest(policy) == digest
