from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache

from providers.base import ProviderCapabilities
from providers.openai_compatible import OpenAICompatibleAdapter


PROVIDER_SPECS = (
    (
        "openai",
        "v1/chat/completions",
        ProviderCapabilities(
            supports_tools=True,
            supports_vision=True,
            supports_embeddings=True,
            supports_audio=True,
            supports_images=True,
            supports_json_schema=True,
        ),
    ),
    (
        "openrouter",
        "chat/completions",
        ProviderCapabilities(
            supports_tools=True,
            supports_vision=True,
            supports_json_schema=True,
        ),
    ),
    (
        "gemini",
        "chat/completions",
        ProviderCapabilities(
            supports_tools=True,
            supports_vision=True,
            supports_json_schema=True,
            supports_token_count=True,
        ),
    ),
    (
        "gemma",
        "chat/completions",
        ProviderCapabilities(supports_token_count=True),
    ),
    ("groq", "openai/v1/chat/completions", ProviderCapabilities()),
    ("opencode", "chat/completions", ProviderCapabilities()),
    (
        "mimo",
        "chat/completions",
        ProviderCapabilities(
            supports_tools=True,
            supports_vision=True,
            supports_json_schema=True,
        ),
    ),
    ("together", "v1/chat/completions", ProviderCapabilities()),
    ("chutes", "v1/chat/completions", ProviderCapabilities()),
    ("xai", "v1/chat/completions", ProviderCapabilities()),
    ("cerebras", "v1/chat/completions", ProviderCapabilities()),
    ("azure", "v1/chat/completions", ProviderCapabilities()),
    ("scaleway", "chat/completions", ProviderCapabilities()),
    ("hyperbolic", "chat/completions", ProviderCapabilities()),
    ("sambanova", "chat/completions", ProviderCapabilities()),
)


def build_default_registry(base_urls: Mapping[str, str]) -> dict[str, OpenAICompatibleAdapter]:
    registry: dict[str, OpenAICompatibleAdapter] = {}
    for provider, chat_path, capabilities in PROVIDER_SPECS:
        base_url = base_urls.get(provider)
        if not base_url:
            continue
        registry[provider] = OpenAICompatibleAdapter(
            name=provider,
            base_url=base_url,
            chat_path=chat_path,
            provider_capabilities=capabilities,
        )
    return registry


def get_adapter(provider: str, base_urls: Mapping[str, str]) -> OpenAICompatibleAdapter | None:
    return get_registry(base_urls).get(provider)


def _registry_cache_key(base_urls: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((provider, str(base_url)) for provider, base_url in base_urls.items()))


@lru_cache(maxsize=8)
def _cached_registry(base_url_items: tuple[tuple[str, str], ...]) -> dict[str, OpenAICompatibleAdapter]:
    return build_default_registry(dict(base_url_items))


def get_registry(base_urls: Mapping[str, str]) -> dict[str, OpenAICompatibleAdapter]:
    return _cached_registry(_registry_cache_key(base_urls))
