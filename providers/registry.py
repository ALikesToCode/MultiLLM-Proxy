from __future__ import annotations

from collections.abc import Mapping

from providers.base import ProviderCapabilities
from providers.openai_compatible import OpenAICompatibleAdapter


def build_default_registry(base_urls: Mapping[str, str]) -> dict[str, OpenAICompatibleAdapter]:
    return {
        "openai": OpenAICompatibleAdapter(
            name="openai",
            base_url=base_urls["openai"],
            chat_path="v1/chat/completions",
            provider_capabilities=ProviderCapabilities(
                supports_tools=True,
                supports_vision=True,
                supports_embeddings=True,
                supports_audio=True,
                supports_images=True,
                supports_json_schema=True,
            ),
        ),
        "openrouter": OpenAICompatibleAdapter(
            name="openrouter",
            base_url=base_urls["openrouter"],
            chat_path="chat/completions",
            provider_capabilities=ProviderCapabilities(
                supports_tools=True,
                supports_vision=True,
                supports_json_schema=True,
            ),
        ),
        "gemini": OpenAICompatibleAdapter(
            name="gemini",
            base_url=base_urls["gemini"],
            chat_path="chat/completions",
            provider_capabilities=ProviderCapabilities(
                supports_tools=True,
                supports_vision=True,
                supports_json_schema=True,
                supports_token_count=True,
            ),
        ),
        "gemma": OpenAICompatibleAdapter(
            name="gemma",
            base_url=base_urls["gemma"],
            chat_path="chat/completions",
            provider_capabilities=ProviderCapabilities(supports_token_count=True),
        ),
        "groq": OpenAICompatibleAdapter(
            name="groq",
            base_url=base_urls["groq"],
            chat_path="openai/v1/chat/completions",
        ),
        "opencode": OpenAICompatibleAdapter(
            name="opencode",
            base_url=base_urls["opencode"],
            chat_path="chat/completions",
        ),
        "together": OpenAICompatibleAdapter(
            name="together",
            base_url=base_urls["together"],
            chat_path="v1/chat/completions",
        ),
        "chutes": OpenAICompatibleAdapter(
            name="chutes",
            base_url=base_urls["chutes"],
            chat_path="v1/chat/completions",
        ),
        "xai": OpenAICompatibleAdapter(
            name="xai",
            base_url=base_urls["xai"],
            chat_path="v1/chat/completions",
        ),
        "cerebras": OpenAICompatibleAdapter(
            name="cerebras",
            base_url=base_urls["cerebras"],
            chat_path="v1/chat/completions",
        ),
        "azure": OpenAICompatibleAdapter(
            name="azure",
            base_url=base_urls["azure"],
            chat_path="v1/chat/completions",
        ),
        "scaleway": OpenAICompatibleAdapter(
            name="scaleway",
            base_url=base_urls["scaleway"],
            chat_path="chat/completions",
        ),
        "hyperbolic": OpenAICompatibleAdapter(
            name="hyperbolic",
            base_url=base_urls["hyperbolic"],
            chat_path="chat/completions",
        ),
        "sambanova": OpenAICompatibleAdapter(
            name="sambanova",
            base_url=base_urls["sambanova"],
            chat_path="chat/completions",
        ),
    }


def get_adapter(provider: str, base_urls: Mapping[str, str]) -> OpenAICompatibleAdapter | None:
    return build_default_registry(base_urls).get(provider)
