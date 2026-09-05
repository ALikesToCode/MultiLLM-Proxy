"""Optional public vision metadata, joined only to advertised provider model IDs."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import requests

from providers.aihubmix import AIHUBMIX_ALLOWED_HOSTS
from services.provider_catalog_metadata import (
    model_supports_vision,
    sanitize_provider_metadata,
)

if TYPE_CHECKING:
    from services.provider_catalog_service import ProviderCatalogModel

logger = logging.getLogger(__name__)
PUBLIC_CAPABILITY_SOURCES = {
    "aihubmix": "https://aihubmix.com/api/v1/models",
    "opencode": "https://models.dev/api.json",
}
_MAX_CATALOG_BYTES = 16 * 1024 * 1024
_MAX_MODELS = 5000


def _trusted_provider(provider: str, base_url: str) -> bool:
    try:
        url = urlsplit(base_url)
        hosts = AIHUBMIX_ALLOWED_HOSTS if provider == "aihubmix" else {"opencode.ai"}
        return (
            provider in PUBLIC_CAPABILITY_SOURCES
            and url.scheme == "https"
            and url.hostname in hosts
            and url.port in (None, 443)
            and url.username is None
            and url.password is None
            and not url.query
            and not url.fragment
        )
    except ValueError:
        return False


def fetch_public_capabilities(provider: str) -> Any:
    """Read a fixed public source without account headers, cookies, netrc or redirects."""
    url = PUBLIC_CAPABILITY_SOURCES[provider]
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


def extract_public_capabilities(
    provider: str, payload: Any
) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, Mapping):
        return {}
    if provider == "aihubmix":
        items = payload.get("data")
        if not isinstance(items, list):
            return {}
        records = [
            (item.get("model_id"), item)
            for item in items[:_MAX_MODELS]
            if isinstance(item, Mapping)
        ]
    elif provider == "opencode":
        catalog = payload.get("opencode")
        models = catalog.get("models") if isinstance(catalog, Mapping) else None
        if not isinstance(models, Mapping):
            return {}
        records = list(models.items())[:_MAX_MODELS]
    else:
        return {}

    result = {}
    for model_id, item in records:
        if not isinstance(model_id, str) or not isinstance(item, Mapping):
            continue
        if item.get("id", model_id) != model_id:
            continue
        metadata = sanitize_provider_metadata(item) or {}
        support = model_supports_vision(metadata)
        if support is None:
            continue
        result[model_id] = {
            field: metadata[field]
            for field in ("input_modalities", "supports_vision")
            if field in metadata
        }
        result[model_id]["vision_metadata_source"] = PUBLIC_CAPABILITY_SOURCES[provider]
    return result


def enrich_model_capabilities(
    provider: str,
    base_url: str,
    models: tuple[ProviderCatalogModel, ...],
) -> tuple[ProviderCatalogModel, ...]:
    if not _trusted_provider(provider, base_url):
        return models
    if all(model_supports_vision(model.metadata) is not None for model in models):
        return models
    try:
        metadata_by_id = extract_public_capabilities(
            provider, fetch_public_capabilities(provider)
        )
    except (requests.RequestException, ValueError, TypeError, OverflowError) as error:
        logger.warning(
            "Public capability refresh failed provider=%s error_type=%s",
            provider,
            type(error).__name__,
        )
        return models

    enriched = []
    for model in models:
        metadata = metadata_by_id.get(model.model_id)
        if metadata and model_supports_vision(model.metadata) is None:
            # A null placeholder is not an explicit provider capability decision.
            merged = {**(model.metadata or {}), **metadata}
            enriched.append(replace(model, metadata=merged))
        else:
            enriched.append(model)
    return tuple(enriched)
