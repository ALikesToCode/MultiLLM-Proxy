from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict
from typing import Any

from providers.aihubmix import is_aihubmix_image_model
from providers.image_relays import is_image_relay_model
from providers.opencode_go import opencode_go_model_endpoint
from providers.registry import get_registry
from services.auto_route_service import AutoRoute
from services.model_registry import ModelRegistry
from services.provider_catalog_service import ProviderCatalogService


KNOWN_IMAGE_MODEL_IDS = {
    "linkapi": frozenset({"gpt-image-2-c"}),
    "together": frozenset({"openai/gpt-image-2"}),
}


def _model_supports_image_output(
    provider: str,
    model_id: str,
    metadata: Mapping[str, Any] | None,
) -> bool:
    if provider == "aihubmix":
        return is_aihubmix_image_model(model_id)
    if is_image_relay_model(provider, model_id):
        return True
    if model_id in KNOWN_IMAGE_MODEL_IDS.get(provider, frozenset()):
        return True

    provider_metadata = metadata or {}
    explicit_support = provider_metadata.get("supports_image_output")
    if isinstance(explicit_support, bool):
        return explicit_support
    output_modalities = provider_metadata.get("output_modalities")
    if isinstance(output_modalities, list):
        return any(
            str(modality).strip().lower() in {"image", "images"}
            for modality in output_modalities
        )
    return False


def _add_source(
    entries: dict[str, dict[str, Any]],
    provider: str,
    provider_model: str,
    source: str,
    *,
    context_window: int | None = None,
    max_output_tokens: int | None = None,
    provider_metadata: Mapping[str, Any] | None = None,
) -> None:
    model_id = f"{provider}:{provider_model}"
    entry = entries.setdefault(
        model_id,
        {
            "id": model_id,
            "provider": provider,
            "model": provider_model,
            "sources": set(),
            "context_window": None,
            "max_output_tokens": None,
            "provider_metadata": None,
        },
    )
    entry["sources"].add(source)
    for field, value in (
        ("context_window", context_window),
        ("max_output_tokens", max_output_tokens),
    ):
        if value is None:
            continue
        current = entry[field]
        entry[field] = min(current, value) if current is not None else value
    if provider_metadata:
        entry["provider_metadata"] = {
            **(entry["provider_metadata"] or {}),
            **provider_metadata,
        }


def build_model_catalog(
    base_urls: Mapping[str, str],
    routes: Iterable[AutoRoute] = (),
) -> list[dict[str, Any]]:
    """Combine built-in, discovered, and route-referenced model IDs."""
    entries: dict[str, dict[str, Any]] = {}
    for model in ModelRegistry.list_models(dict(base_urls)):
        endpoint = (
            opencode_go_model_endpoint(model.display_name)
            if model.provider == "opencode"
            else None
        )
        _add_source(
            entries,
            model.provider,
            model.display_name,
            "built-in",
            provider_metadata=(
                {
                    "api_endpoint": f"/{endpoint}",
                    "api_protocol": {
                        "v1/chat/completions": "openai_chat_completions",
                        "v1/messages": "anthropic_messages",
                        "v1/responses": "openai_responses",
                    }[endpoint],
                }
                if endpoint
                else None
            ),
        )

    for model in ProviderCatalogService.list_models():
        _add_source(
            entries,
            model.provider,
            model.model_id,
            "live",
            context_window=model.context_window,
            max_output_tokens=model.max_output_tokens,
            provider_metadata=model.metadata,
        )

    for route in routes:
        for model_id in route.candidates:
            provider, provider_model = ModelRegistry.parse_model_id(model_id)
            _add_source(entries, provider, provider_model, "route")

    statuses = ModelRegistry.get_model_statuses(entries)
    adapters = get_registry(base_urls)
    catalog = []
    for model_id in sorted(entries):
        entry = entries[model_id]
        adapter = adapters.get(entry["provider"])
        capabilities = asdict(adapter.capabilities()) if adapter else {}
        if "supports_images" in capabilities:
            capabilities["supports_images"] = _model_supports_image_output(
                entry["provider"],
                entry["model"],
                entry["provider_metadata"],
            )
        catalog.append(
            {
                **entry,
                "sources": sorted(entry["sources"]),
                "status": statuses[model_id],
                "capabilities": capabilities,
            }
        )
    return catalog


def unified_model_payload(model: Mapping[str, Any]) -> dict[str, Any]:
    """Serialize a catalog model without discarding safe upstream metadata."""
    provider_metadata = dict(model.get("provider_metadata") or {})
    upstream_created = provider_metadata.get("created")
    payload = {
        "id": model["id"],
        "object": "model",
        "created": (
            upstream_created
            if isinstance(upstream_created, int)
            and not isinstance(upstream_created, bool)
            else 0
        ),
        "owned_by": model["provider"],
        "provider": model["provider"],
        "provider_model": model["model"],
        "sources": list(model["sources"]),
        "status": model["status"],
        "context_window": model["context_window"],
        "max_output_tokens": model["max_output_tokens"],
        "capabilities": dict(model.get("capabilities") or {}),
    }
    if not provider_metadata:
        return payload

    payload["provider_metadata"] = provider_metadata
    upstream_owner = provider_metadata.get("owned_by")
    if isinstance(upstream_owner, str) and upstream_owner:
        payload["upstream_owned_by"] = upstream_owner
    reserved_fields = {
        "id",
        "object",
        "created",
        "owned_by",
        "status",
        "context_window",
        "max_output_tokens",
    }
    for field, value in provider_metadata.items():
        if field not in reserved_fields:
            payload[field] = value
    return payload
