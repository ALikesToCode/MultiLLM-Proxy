from __future__ import annotations

import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from providers.registry import get_registry
from proxy import PROVIDER_DETAILS
from services.auto_route_service import AutoRouteService
from services.model_catalog_service import build_model_catalog
from services.provider_catalog_service import PROVIDER_CATALOG_SPECS

PROVIDER_DISPLAY_NAMES = {
    "azure": "Azure AI",
    "cerebras": "Cerebras",
    "chutes": "Chutes",
    "codex-easy": "Codex Everywhere",
    "gemini": "Gemini",
    "gemma": "Gemma",
    "googleai": "Google Vertex AI",
    "groq": "Groq",
    "hyperbolic": "Hyperbolic",
    "kimi-code": "Kimi Code",
    "linkapi": "LinkAPI",
    "mimo": "Xiaomi MiMo",
    "nanogpt": "NanoGPT",
    "navyai": "NavyAI",
    "nineteen": "Nineteen AI",
    "openai": "OpenAI",
    "opencode": "OpenCode Go",
    "openrouter": "OpenRouter",
    "palm": "PaLM",
    "sambanova": "SambaNova",
    "scaleway": "Scaleway",
    "together": "Together AI",
    "xai": "xAI",
}


def _provider_is_configured(auth_service_cls, provider: str) -> bool:
    if provider == "googleai":
        return any(
            os.environ.get(name)
            for name in auth_service_cls.provider_credential_env_names(provider)
        )
    if provider == "nanogpt":
        return bool(auth_service_cls.get_api_keys(provider))
    return bool(auth_service_cls.get_api_key(provider))


def _endpoint_kind(path: str) -> str:
    lowered = path.lower()
    if "/models" in lowered:
        return "Models"
    if "/images" in lowered:
        return "Images"
    if "/responses" in lowered:
        return "Responses"
    if "/messages" in lowered:
        return "Messages"
    if "/chat/completions" in lowered:
        return "Chat"
    if "/audio" in lowered:
        return "Audio"
    if "video" in lowered:
        return "Video"
    return "Provider API"


def _native_endpoints(provider: str) -> list[dict[str, str]]:
    endpoints = []
    seen: set[tuple[str, str]] = set()
    for endpoint in PROVIDER_DETAILS.get(provider, {}).get("endpoints", []):
        suffix = str(endpoint.get("url") or "").strip()
        if not suffix:
            continue
        suffix = suffix if suffix.startswith("/") else f"/{suffix}"
        path = f"/{provider}{suffix}"
        method_match = re.search(
            r"\bcurl\s+-X\s+([A-Z]+)",
            str(endpoint.get("curl") or ""),
        )
        method = method_match.group(1) if method_match else "GET"
        identity = (method, path)
        if identity in seen:
            continue
        seen.add(identity)
        endpoints.append(
            {
                "method": method,
                "path": path,
                "kind": _endpoint_kind(path),
            }
        )
    return endpoints


def _examples(base_url: str, auto_model: str) -> dict[str, str]:
    return {
        "models": (
            f'curl "{base_url}/v1/models" \\\n'
            '  -H "Authorization: Bearer $MULTILLM_API_KEY"'
        ),
        "chat": (
            f'curl "{base_url}/v1/chat/completions" \\\n'
            '  -H "Authorization: Bearer $MULTILLM_API_KEY" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            "  -d '{\n"
            '    "model": "opencode:ox-alpha-free",\n'
            '    "messages": [{"role": "user", "content": "Hello"}],\n'
            '    "stream": true\n'
            "  }'"
        ),
        "auto_chat": (
            f'curl "{base_url}/v1/chat/completions" \\\n'
            '  -H "Authorization: Bearer $MULTILLM_API_KEY" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            "  -d '{\n"
            f'    "model": "{auto_model}",\n'
            '    "messages": [{"role": "user", "content": "Use the first available provider"}]\n'
            "  }'"
        ),
        "image": (
            f'curl "{base_url}/v1/images/generations" \\\n'
            '  -H "Authorization: Bearer $MULTILLM_API_KEY" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            "  -d '{\n"
            '    "model": "linkapi:gpt-image-2-c",\n'
            '    "prompt": "A cinematic lighthouse during a storm",\n'
            '    "size": "1024x1024",\n'
            '    "n": 1\n'
            "  }'"
        ),
        "native": (
            f'curl "{base_url}/nanogpt/v1/chat/completions" \\\n'
            '  -H "Authorization: Bearer $MULTILLM_API_KEY" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            "  -d '{\n"
            '    "model": "$NANOGPT_MODEL",\n'
            '    "messages": [{"role": "user", "content": "Preserve the provider contract"}]\n'
            "  }'"
        ),
    }


def build_proxy_documentation(
    base_urls: Mapping[str, str],
    auth_service_cls,
    base_url: str,
    *,
    runtime_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the credential-safe, runtime-backed setup guide payload."""
    runtime = runtime_config or {}
    routes = AutoRouteService.list_routes()
    models = build_model_catalog(base_urls, routes)
    adapters = get_registry(base_urls)
    configured = {
        provider: _provider_is_configured(auth_service_cls, provider)
        for provider in PROVIDER_DETAILS
    }
    models_by_provider: dict[str, list[dict[str, Any]]] = {}
    for model in models:
        model["configured"] = configured.get(model["provider"], False)
        models_by_provider.setdefault(model["provider"], []).append(model)

    providers = []
    for provider in sorted(PROVIDER_DETAILS):
        adapter = adapters.get(provider)
        capabilities = adapter.capabilities() if adapter else None
        endpoints = _native_endpoints(provider)
        credential_env = list(auth_service_cls.provider_credential_env_names(provider))
        provider_models = models_by_provider.get(provider, [])
        providers.append(
            {
                "id": provider,
                "name": PROVIDER_DISPLAY_NAMES.get(provider, provider.title()),
                "description": PROVIDER_DETAILS[provider].get("description", ""),
                "configured": configured[provider],
                "credential_env": credential_env,
                "catalog_path": (
                    PROVIDER_CATALOG_SPECS[provider].proxy_path
                    if provider in PROVIDER_CATALOG_SPECS
                    else None
                ),
                "model_count": len(provider_models),
                "live_model_count": sum(
                    "live" in model["sources"] for model in provider_models
                ),
                "unified_chat": adapter is not None,
                "unified_responses": adapter is not None and provider != "kimi-code",
                "unified_images": bool(capabilities and capabilities.supports_images),
                "native_images": any(
                    endpoint["kind"] == "Images" for endpoint in endpoints
                ),
                "native_endpoints": endpoints,
            }
        )

    provider_by_id = {provider["id"]: provider for provider in providers}
    auto_routes = []
    for route in routes:
        candidates = []
        for priority, model_id in enumerate(route.candidates, start=1):
            provider, provider_model = model_id.split(":", 1)
            candidates.append(
                {
                    "id": model_id,
                    "provider": provider,
                    "model": provider_model,
                    "priority": priority,
                    "configured": provider_by_id[provider]["configured"],
                }
            )
        auto_routes.append(
            {
                "id": route.id,
                "updated_at": route.updated_at,
                "candidates": candidates,
            }
        )
        models.append(
            {
                "id": route.id,
                "provider": "auto",
                "model": route.id.split(":", 1)[1],
                "configured": any(candidate["configured"] for candidate in candidates),
                "status": "available",
                "sources": ["auto-route"],
                "context_window": None,
                "max_output_tokens": None,
                "capabilities": {
                    "supports_chat": True,
                    "supports_streaming": True,
                    "supports_images": False,
                },
            }
        )

    models.sort(key=lambda model: model["id"])
    auto_model = auto_routes[0]["id"] if auto_routes else "auto:glm-5.2"
    nanogpt_billing_mode = str(
        runtime.get("NANOGPT_BILLING_MODE") or "subscription"
    ).lower()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "proxy_credential_env": "ADMIN_API_KEY",
        "summary": {
            "provider_count": len(providers),
            "configured_provider_count": sum(
                provider["configured"] for provider in providers
            ),
            "model_count": len(models),
            "live_model_count": sum("live" in model["sources"] for model in models),
            "auto_route_count": len(auto_routes),
            "unified_image_provider_count": sum(
                provider["unified_images"] for provider in providers
            ),
        },
        "providers": providers,
        "models": models,
        "auto_routes": auto_routes,
        "examples": _examples(base_url, auto_model),
        "nanogpt": {
            "billing_mode": nanogpt_billing_mode,
            "subscription_only": nanogpt_billing_mode == "subscription",
            "text_base_url": base_urls.get("nanogpt"),
            "model_catalog_path": "/v1/models",
        },
        "client_integrations": {
            "janitor_ai": {
                "proxy_url": f"{base_url}/roleplay/v1/chat/completions",
                "api_key_env": "ROLEPLAY_API_KEY",
                "model": "roleplay:auto",
                "append_chat_completions": False,
                "opencode_proxy_url": f"{base_url}/opencode/v1/chat/completions",
                "opencode_api_key_env": "ADMIN_API_KEY",
                "opencode_model": "ox-alpha-free",
                "direct_navy_url": "https://api.navy/v1/chat/completions",
            }
        },
    }
