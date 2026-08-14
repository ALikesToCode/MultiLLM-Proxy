from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict
from typing import Any

from providers.registry import get_registry
from services.auto_route_service import AutoRoute
from services.model_registry import ModelRegistry
from services.provider_catalog_service import ProviderCatalogService


def _add_source(
    entries: dict[str, dict[str, Any]],
    provider: str,
    provider_model: str,
    source: str,
) -> None:
    model_id = f"{provider}:{provider_model}"
    entry = entries.setdefault(
        model_id,
        {
            "id": model_id,
            "provider": provider,
            "model": provider_model,
            "sources": set(),
        },
    )
    entry["sources"].add(source)


def build_model_catalog(
    base_urls: Mapping[str, str],
    routes: Iterable[AutoRoute] = (),
) -> list[dict[str, Any]]:
    """Combine built-in, discovered, and route-referenced model IDs."""
    entries: dict[str, dict[str, Any]] = {}
    for model in ModelRegistry.list_models(dict(base_urls)):
        _add_source(entries, model.provider, model.display_name, "built-in")

    for model in ProviderCatalogService.list_models():
        _add_source(entries, model.provider, model.model_id, "live")

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
        catalog.append(
            {
                **entry,
                "sources": sorted(entry["sources"]),
                "status": statuses[model_id],
                "capabilities": capabilities,
            }
        )
    return catalog
