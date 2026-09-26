from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict
from typing import Any

from providers.aihubmix import is_aihubmix_image_model
from providers.image_relays import is_image_relay_model
from providers.opencode_go import opencode_model_endpoint
from providers.registry import get_registry
from services.auto_route_service import AutoRoute
from services.media_catalog import image_profile, is_video_model
from services.model_registry import ModelRegistry
from services.provider_catalog_metadata import (
    model_supports_tools,
    model_supports_vision,
)
from services.provider_catalog_service import ProviderCatalogService

KNOWN_IMAGE_MODEL_IDS = {
    "linkapi": frozenset({"gpt-image-2-c"}),
    "together": frozenset({"openai/gpt-image-2"}),
}
OPENCODE_API_PROTOCOLS = {
    "v1/chat/completions": "openai_chat_completions",
    "v1/messages": "anthropic_messages",
    "v1/responses": "openai_responses",
}


def _model_provider_metadata(
    provider: str,
    model_id: str,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    normalized = dict(metadata or {})
    endpoint = opencode_model_endpoint(model_id) if provider == "opencode" else None
    if endpoint:
        normalized.update(
            {
                "api_endpoint": f"/{endpoint}",
                "api_protocol": OPENCODE_API_PROTOCOLS[endpoint],
            }
        )
    return normalized or None


def _declared_output(
    metadata: Mapping[str, Any] | None,
    modalities: frozenset[str],
) -> bool | None:
    output_modalities = (metadata or {}).get("output_modalities")
    if not isinstance(output_modalities, list):
        return None
    return any(
        str(modality).strip().lower() in modalities for modality in output_modalities
    )


def _declared_image_output(metadata: Mapping[str, Any] | None) -> bool | None:
    explicit_support = (metadata or {}).get("supports_image_output")
    if isinstance(explicit_support, bool):
        return explicit_support
    return _declared_output(metadata, frozenset({"image", "images"}))


def _model_supports_image_output(
    provider: str,
    model_id: str,
    metadata: Mapping[str, Any] | None,
) -> bool:
    if provider == "aihubmix":
        return is_aihubmix_image_model(model_id)
    declared = _declared_image_output(metadata)
    if declared is not None:
        return declared
    return is_image_relay_model(provider, model_id) or (
        model_id in KNOWN_IMAGE_MODEL_IDS.get(provider, frozenset())
    )


def _model_capabilities(
    adapter: Any,
    provider: str,
    model_id: str,
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Describe what this model serves, not only what its provider can do."""
    capabilities = asdict(adapter.capabilities()) if adapter else {}
    capabilities["supports_vision"] = model_supports_vision(metadata)
    # A model the catalog marks as unable to call tools overrides the provider default.
    if "supports_tools" in capabilities and model_supports_tools(metadata) is False:
        capabilities["supports_tools"] = False
    # Explicit catalog metadata wins over model-family inference.
    image_model = (
        image_profile(provider, model_id) is not None
        and _declared_image_output(metadata) is not False
    )
    if "supports_images" in capabilities:
        capabilities["supports_images"] = _model_supports_image_output(
            provider, model_id, metadata
        ) or (image_model and capabilities["supports_images"])
    capabilities["supports_video"] = is_video_model(model_id)
    text_output = (
        _declared_output(metadata, frozenset({"text"}))
        if (metadata or {}).get("output_modalities")
        else None
    )
    media_only = text_output is False or (
        text_output is None and (image_model or capabilities["supports_video"])
    )
    if media_only:
        capabilities.update(
            supports_chat=False,
            supports_streaming=False,
            supports_tools=False,
            supports_json_schema=False,
        )
    # Responses- and Messages-only models stay chat-capable: unified chat
    # translates for them (docs/protocol-translation.md); api_endpoint names
    # the native protocol.
    return capabilities


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
        _add_source(
            entries,
            model.provider,
            model.display_name,
            "built-in",
            provider_metadata=_model_provider_metadata(
                model.provider,
                model.display_name,
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
            provider_metadata=_model_provider_metadata(
                model.provider,
                model.model_id,
                model.metadata,
            ),
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
        capabilities = _model_capabilities(
            adapters.get(entry["provider"]),
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
        "capabilities": dict(model.get("capabilities") or {}),
        "supports_vision": model_supports_vision(provider_metadata),
    }
    # Unknown limits are omitted: strict OpenAI-style clients reject null numbers.
    for field in ("context_window", "max_output_tokens"):
        if model.get(field) is not None:
            payload[field] = model[field]
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
        "supports_vision",
    }
    for field, value in provider_metadata.items():
        if field not in reserved_fields and value is not None:
            payload[field] = value
    return payload
