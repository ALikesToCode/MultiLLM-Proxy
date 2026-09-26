"""Public model metadata, joined only to model IDs a provider already advertises.

models.dev publishes, per provider, each model's input and output modalities, tool
calling, context and output limits and per-token list prices. AIHubMix also publishes
its own catalog. A refresh fills only what the provider's catalog left unknown, from
the source that describes that same endpoint, and records where each value came from.
"""

from __future__ import annotations

import json
import logging
import math
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import requests

from providers.aihubmix import AIHUBMIX_ALLOWED_HOSTS
from providers.opencode_go import is_opencode_zen_free_model
from services.provider_catalog_metadata import (
    model_supports_tools,
    model_supports_vision,
    sanitize_provider_metadata,
)

if TYPE_CHECKING:
    from services.provider_catalog_service import ProviderCatalogModel

logger = logging.getLogger(__name__)
MODELS_DEV_URL = "https://models.dev/api.json"
AIHUBMIX_CATALOG_URL = "https://aihubmix.com/api/v1/models"


@dataclass(frozen=True)
class ModelsDevSection:
    """The models.dev provider entry that describes one gateway endpoint."""

    name: str
    hosts: frozenset[str]
    # List prices are copied only where the endpoint bills per token at that price.
    pricing: bool


# Reviewed endpoint-to-section pairs. A provider without one is never enriched from
# another gateway's entry, even when the model names look alike.
MODELS_DEV_SECTIONS = {
    "aihubmix": ModelsDevSection("aihubmix", AIHUBMIX_ALLOWED_HOSTS, True),
    "cerebras": ModelsDevSection("cerebras", frozenset({"api.cerebras.ai"}), True),
    "groq": ModelsDevSection("groq", frozenset({"api.groq.com"}), True),
    # NanoGPT's default text endpoint is a subscription, not its list price.
    "nanogpt": ModelsDevSection("nano-gpt", frozenset({"nano-gpt.com"}), False),
    "openai": ModelsDevSection("openai", frozenset({"api.openai.com"}), True),
    "opencode": ModelsDevSection("opencode", frozenset({"opencode.ai"}), True),
    "openrouter": ModelsDevSection("openrouter", frozenset({"openrouter.ai"}), True),
    "together": ModelsDevSection("togetherai", frozenset({"api.together.xyz"}), True),
    "xai": ModelsDevSection("xai", frozenset({"api.x.ai"}), True),
}
# OpenCode Go is a subscription; its free models come from the Zen catalog.
OPENCODE_GO_SECTION = ModelsDevSection("opencode-go", frozenset({"opencode.ai"}), False)
_OPENCODE_PATHS = {"/zen/v1": MODELS_DEV_SECTIONS["opencode"], "/zen/go/v1": OPENCODE_GO_SECTION}
PUBLIC_CAPABILITY_SOURCES = {
    provider: AIHUBMIX_CATALOG_URL if provider == "aihubmix" else MODELS_DEV_URL
    for provider in MODELS_DEV_SECTIONS
}
_SOURCE_URLS = {**PUBLIC_CAPABILITY_SOURCES, "models.dev": MODELS_DEV_URL}
_MAX_CATALOG_BYTES = 16 * 1024 * 1024
_MAX_MODELS = 5000
_MAX_LIMIT = 100_000_000
_MAX_PRICE = 1_000_000
# A catalog is read at most once an hour; after a failed read the last good copy is
# used for a day. Only the compact per-model index is kept, never the raw document.
CACHE_TTL_SECONDS = 3600
STALE_FALLBACK_SECONDS = 24 * 3600
_cache: dict[str, tuple[float, dict[str, dict[str, dict[str, Any]]]]] = {}
_cache_locks: dict[str, threading.Lock] = {}
_cache_guard = threading.Lock()


def _endpoint_section(provider: str, base_url: str) -> ModelsDevSection | None:
    """The section for an official origin, or None for a custom relay."""
    try:
        url = urlsplit(base_url)
        section = MODELS_DEV_SECTIONS.get(provider)
        if (
            section is None
            or url.scheme != "https"
            or url.hostname not in section.hosts
            or url.port not in (None, 443)
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
        ):
            return None
    except ValueError:
        return None
    if provider == "opencode":
        return _OPENCODE_PATHS.get(url.path.rstrip("/"))
    return section


def _model_section(provider: str, endpoint: ModelsDevSection, model_id: str) -> ModelsDevSection:
    # A Go catalog is merged with free Zen models, which Zen serves and describes.
    if provider == "opencode" and is_opencode_zen_free_model(model_id):
        return MODELS_DEV_SECTIONS["opencode"]
    return endpoint


def fetch_public_capabilities(source: str) -> Any:
    """Read a fixed public source without account headers, cookies, netrc or redirects."""
    url = _SOURCE_URLS[source]
    started = time.monotonic()
    with requests.Session() as session:
        session.trust_env = False
        with session.get(
            url,
            headers={"Accept": "application/json"},
            timeout=(3, 10),
            allow_redirects=False,
            stream=True,
        ) as response:
            if response.status_code != 200:
                raise ValueError("Public capability catalog unavailable")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if len(body) + len(chunk) > _MAX_CATALOG_BYTES:
                    raise ValueError("Public capability catalog exceeds size limit")
                if time.monotonic() - started > 30:
                    raise ValueError("Public capability catalog exceeds time limit")
                body.extend(chunk)
            return json.loads(body)


def _positive_limit(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_LIMIT:
        return value
    return None


def _price(value: Any) -> int | float | None:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= _MAX_PRICE
    ):
        return value
    return None


def _models_dev_entry(item: Mapping[str, Any], section: ModelsDevSection) -> dict[str, Any]:
    """Translate one models.dev model into gateway catalog fields."""
    fields: dict[str, Any] = {"modalities": item.get("modalities")}
    if isinstance(item.get("tool_call"), bool):
        fields["supports_tools"] = item["tool_call"]
    if isinstance(item.get("reasoning"), bool):
        fields["supports_reasoning"] = item["reasoning"]
    metadata = sanitize_provider_metadata(fields) or {}
    limit = item.get("limit")
    limit = limit if isinstance(limit, Mapping) else {}
    for field, key in (("context_window", "context"), ("max_output_tokens", "output")):
        if (value := _positive_limit(limit.get(key))) is not None:
            metadata[field] = value
    cost = item.get("cost")
    cost = cost if isinstance(cost, Mapping) else {}
    prices = {field: _price(cost.get(key)) for field, key in
              (("input_cost_per_million", "input"), ("output_cost_per_million", "output"))}
    # Only a complete base-tier input and output price is copied.
    if section.pricing and None not in prices.values():
        metadata.update(prices)
    return metadata


def _models_dev_index(payload: Any) -> dict[str, dict[str, dict[str, Any]]]:
    """Every reviewed section, keyed by the exact model ID it publishes."""
    if not isinstance(payload, Mapping):
        return {}
    index = {}
    sections = {
        section.name: section for section in (*MODELS_DEV_SECTIONS.values(), OPENCODE_GO_SECTION)
    }
    for name, section in sections.items():
        provider = payload.get(name)
        models = provider.get("models") if isinstance(provider, Mapping) else None
        if not isinstance(models, Mapping):
            continue
        entries: dict[str, dict[str, Any]] = {}
        for model_id, item in list(models.items())[:_MAX_MODELS]:
            # An entry whose own id disagrees with its key is ambiguous, not a match.
            if not isinstance(model_id, str) or not isinstance(item, Mapping):
                continue
            if item.get("id", model_id) != model_id:
                continue
            metadata = _models_dev_entry(item, section)
            if metadata:
                entries[model_id] = metadata
        index[name] = entries
    return index


def _aihubmix_index(payload: Any) -> dict[str, dict[str, Any]]:
    """AIHubMix's public catalog contributes image-input metadata only."""
    items = payload.get("data") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        return {}
    result = {}
    for item in items[:_MAX_MODELS]:
        if not isinstance(item, Mapping):
            continue
        model_id = item.get("model_id")
        if not isinstance(model_id, str) or item.get("id", model_id) != model_id:
            continue
        metadata = sanitize_provider_metadata(item) or {}
        if model_supports_vision(metadata) is None:
            continue
        result[model_id] = {
            field: metadata[field]
            for field in ("input_modalities", "supports_vision")
            if field in metadata
        }
    return result


def _index(url: str, payload: Any) -> dict[str, dict[str, dict[str, Any]]]:
    if url == AIHUBMIX_CATALOG_URL:
        return {"aihubmix-catalog": _aihubmix_index(payload)}
    return _models_dev_index(payload)


def extract_public_capabilities(provider: str, payload: Any) -> dict[str, dict[str, Any]]:
    """The primary public source's entries for a provider, keyed by exact model ID."""
    url = PUBLIC_CAPABILITY_SOURCES.get(provider)
    if url is None:
        return {}
    name = "aihubmix-catalog" if url == AIHUBMIX_CATALOG_URL else MODELS_DEV_SECTIONS[provider].name
    return _index(url, payload).get(name, {})


def reset_public_capability_cache() -> None:
    with _cache_guard:
        _cache.clear()


def _cached_index(source: str) -> dict[str, dict[str, dict[str, Any]]] | None:
    """One read per source and hour across concurrent refreshes; stale copy on failure."""
    url = _SOURCE_URLS[source]
    with _cache_guard:
        lock = _cache_locks.setdefault(url, threading.Lock())
    with lock:
        cached = _cache.get(url)
        now = time.monotonic()
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            return cached[1]
        try:
            index = _index(url, fetch_public_capabilities(source))
        except (requests.RequestException, ValueError, TypeError, OverflowError, RecursionError) as error:
            logger.warning(
                "Public capability refresh failed source=%s error_type=%s",
                source,
                type(error).__name__,
            )
            if cached and now - cached[0] < STALE_FALLBACK_SECONDS:
                return cached[1]
            return None
        _cache[url] = (now, index)
        return index


def _complete(model: ProviderCatalogModel, section: ModelsDevSection) -> bool:
    metadata = model.metadata or {}
    return (
        model_supports_vision(metadata) is not None
        and model_supports_tools(metadata) is not None
        and model.context_window is not None
        and model.max_output_tokens is not None
        and (not section.pricing or _has_upstream_price(metadata))
    )


def _has_upstream_price(metadata: Mapping[str, Any]) -> bool:
    return metadata.get("pricing") is not None or metadata.get("input_cost_per_million") is not None


def _merge(
    model: ProviderCatalogModel,
    candidates: list[tuple[str, dict[str, Any]]],
) -> ProviderCatalogModel:
    """Fill unknown fields in source order; explicit provider values always win."""
    metadata = dict(model.metadata or {})
    limits = {"context_window": model.context_window, "max_output_tokens": model.max_output_tokens}
    provenance = dict(metadata.get("metadata_provenance") or {})
    for source, entry in candidates:
        # A null placeholder is not an explicit provider capability decision.
        if model_supports_vision(metadata) is None and model_supports_vision(entry) is not None:
            for field in ("input_modalities", "supports_vision"):
                if field in entry:
                    metadata[field] = entry[field]
                    provenance[field] = source
            metadata["vision_metadata_source"] = source.split("#", 1)[0]
        if model_supports_tools(metadata) is None and "supports_tools" in entry:
            metadata["supports_tools"] = entry["supports_tools"]
            provenance["supports_tools"] = source
        for field in ("output_modalities", "supports_reasoning"):
            if metadata.get(field) is None and field in entry:
                metadata[field] = entry[field]
                provenance[field] = source
        for field in limits:
            if limits[field] is None and field in entry:
                limits[field] = entry[field]
                provenance[field] = source
        if not _has_upstream_price(metadata) and "input_cost_per_million" in entry:
            for field in ("input_cost_per_million", "output_cost_per_million"):
                metadata[field] = entry[field]
                provenance[field] = source
    if provenance == (model.metadata or {}).get("metadata_provenance", {}):
        return model
    metadata["metadata_provenance"] = provenance
    return replace(model, metadata=metadata, **limits)


def enrich_model_capabilities(
    provider: str,
    base_url: str,
    models: tuple[ProviderCatalogModel, ...],
) -> tuple[ProviderCatalogModel, ...]:
    endpoint = _endpoint_section(provider, base_url)
    if endpoint is None:
        return models
    sections = {model.model_id: _model_section(provider, endpoint, model.model_id) for model in models}
    if all(_complete(model, sections[model.model_id]) for model in models):
        return models
    # AIHubMix's own catalog is read first, so its image-input flags win over models.dev.
    sources = ("aihubmix", "models.dev") if provider == "aihubmix" else (provider,)
    indexes = {source: _cached_index(source) for source in sources}
    if all(index is None for index in indexes.values()):
        return models

    enriched = []
    for model in models:
        section = sections[model.model_id]
        candidates = []
        for source, index in indexes.items():
            if index is None:
                continue
            if source == "aihubmix":
                entry = index.get("aihubmix-catalog", {}).get(model.model_id)
                label = AIHUBMIX_CATALOG_URL
            else:
                entry = index.get(section.name, {}).get(model.model_id)
                label = f"{MODELS_DEV_URL}#{section.name}"
            if entry:
                candidates.append((label, entry))
        enriched.append(_merge(model, candidates) if candidates else model)
    return tuple(enriched)
