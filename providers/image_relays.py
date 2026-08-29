from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from providers.base import ProviderCapabilities


MAX_CUSTOM_IMAGE_RELAYS = 32
MAX_MODELS_PER_IMAGE_RELAY = 200
MAX_IMAGE_RELAY_CONFIG_BYTES = 65_536

_PROVIDER_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ENV_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_RESERVED_PROVIDER_IDS = frozenset(
    {
        "azure",
        "cerebras",
        "chutes",
        "codex-easy",
        "gemini",
        "gemma",
        "googleai",
        "groq",
        "hyperbolic",
        "kimi-code",
        "linkapi",
        "mimo",
        "nanogpt",
        "navyai",
        "nineteen",
        "openai",
        "opencode",
        "openrouter",
        "palm",
        "sambanova",
        "scaleway",
        "together",
        "xai",
    }
)


@dataclass(frozen=True)
class ImageRelaySpec:
    provider: str
    display_name: str
    base_url: str
    credential_env: str
    models: tuple[str, ...]
    credential_env_aliases: tuple[str, ...] = ()
    backup_base_url: str | None = None
    supports_chat: bool = True
    supports_edits: bool = True

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_chat=self.supports_chat,
            supports_streaming=self.supports_chat,
            supports_images=True,
        )


BUILTIN_IMAGE_RELAY_SPECS = (
    ImageRelaySpec(
        provider="a6api",
        display_name="A6api",
        base_url="https://api.a6api.com",
        backup_base_url=None,
        credential_env="A6API_API_KEY",
        models=("gpt-image-2",),
    ),
    ImageRelaySpec(
        provider="aimlapi",
        display_name="AI/ML API",
        base_url="https://api.aimlapi.com",
        backup_base_url=None,
        credential_env="AIMLAPI_API_KEY",
        models=("openai/gpt-image-2",),
    ),
    ImageRelaySpec(
        provider="ephone",
        display_name="ePhone AI",
        base_url="https://api.ephone.ai",
        backup_base_url=None,
        credential_env="EPHONE_API_KEY",
        models=("gpt-image-2",),
    ),
    ImageRelaySpec(
        provider="gguu",
        display_name="GGUU AI",
        base_url="https://gguuai.com",
        backup_base_url="https://api.aiaimax.com",
        credential_env="GGUU_API_KEY",
        credential_env_aliases=("GGUUAI_API_KEY",),
        models=("gpt-image-2",),
        supports_chat=False,
    ),
    ImageRelaySpec(
        provider="latix",
        display_name="Latix",
        base_url="https://api.latix.ai",
        backup_base_url=None,
        credential_env="LATIX_API_KEY",
        models=("gpt-image-2",),
    ),
)


def _validated_provider_id(value: Any) -> str:
    provider = str(value or "").strip().lower()
    if not _PROVIDER_ID_PATTERN.fullmatch(provider):
        raise ValueError(
            "Image relay IDs must start with a letter and contain only "
            "lowercase letters, digits, underscores, or hyphens"
        )
    return provider


def _validated_base_url(value: Any) -> str:
    candidate = str(value or "").strip()
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "Image relay base URLs must be credential-free HTTPS origins"
        )

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Image relay base URLs cannot target localhost")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError("Image relay base URLs cannot target private IP space")

    try:
        parsed_port = parsed.port
    except ValueError as error:
        raise ValueError("Image relay base URLs must use a valid port") from error
    port = f":{parsed_port}" if parsed_port is not None else ""
    return urlunsplit(("https", f"{hostname}{port}", "", "", ""))


def _validated_credential_env(value: Any, provider: str) -> str:
    default_name = re.sub(r"[^A-Z0-9]", "_", provider.upper()) + "_API_KEY"
    candidate = str(value or default_name).strip().upper()
    if not _ENV_NAME_PATTERN.fullmatch(candidate):
        raise ValueError(f"Invalid credential_env for image relay: {provider}")
    return candidate


def _validated_optional_base_url(value: Any, primary: str) -> str | None:
    if value is None or not str(value).strip():
        return None
    backup = _validated_base_url(value)
    return None if backup == primary else backup


def _validated_models(value: Any, provider: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"Image relay {provider} must declare at least one model")
    if len(value) > MAX_MODELS_PER_IMAGE_RELAY:
        raise ValueError(f"Image relay {provider} declares too many models")

    models: list[str] = []
    seen: set[str] = set()
    for raw_model in value:
        model = str(raw_model or "").strip()
        if not _MODEL_ID_PATTERN.fullmatch(model):
            raise ValueError(f"Invalid model ID for image relay {provider}")
        if model not in seen:
            seen.add(model)
            models.append(model)
    return tuple(models)


def _validated_bool(value: Any, field: str, provider: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"Image relay {provider} {field} must be a boolean")
    return value


def _custom_spec(provider: str, raw: Any) -> ImageRelaySpec:
    if not isinstance(raw, dict):
        raise ValueError(f"Image relay {provider} must be a JSON object")
    display_name = str(raw.get("display_name") or provider).strip()[:80]
    base_url = _validated_base_url(raw.get("base_url"))
    return ImageRelaySpec(
        provider=provider,
        display_name=display_name or provider,
        base_url=base_url,
        backup_base_url=_validated_optional_base_url(
            raw.get("backup_base_url"),
            base_url,
        ),
        credential_env=_validated_credential_env(
            raw.get("credential_env"),
            provider,
        ),
        models=_validated_models(raw.get("models"), provider),
        supports_chat=_validated_bool(
            raw.get("supports_chat"),
            "supports_chat",
            provider,
            True,
        ),
        supports_edits=_validated_bool(
            raw.get("supports_edits"),
            "supports_edits",
            provider,
            True,
        ),
    )


@lru_cache(maxsize=8)
def _parse_image_relay_specs(serialized: str) -> tuple[ImageRelaySpec, ...]:
    if len(serialized.encode("utf-8")) > MAX_IMAGE_RELAY_CONFIG_BYTES:
        raise ValueError("IMAGE_RELAY_PROVIDERS_JSON is too large")
    if not serialized.strip():
        return BUILTIN_IMAGE_RELAY_SPECS

    try:
        payload = json.loads(serialized)
    except json.JSONDecodeError as error:
        raise ValueError("IMAGE_RELAY_PROVIDERS_JSON must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("IMAGE_RELAY_PROVIDERS_JSON must be a JSON object")
    if len(payload) > MAX_CUSTOM_IMAGE_RELAYS:
        raise ValueError("IMAGE_RELAY_PROVIDERS_JSON declares too many providers")

    specs = {spec.provider: spec for spec in BUILTIN_IMAGE_RELAY_SPECS}
    for raw_provider, raw_spec in payload.items():
        provider = _validated_provider_id(raw_provider)
        if provider in specs or provider in _RESERVED_PROVIDER_IDS:
            raise ValueError(f"Existing provider cannot be overridden: {provider}")
        specs[provider] = _custom_spec(provider, raw_spec)
    return tuple(specs[provider] for provider in sorted(specs))


def image_relay_specs() -> tuple[ImageRelaySpec, ...]:
    return _parse_image_relay_specs(
        os.environ.get("IMAGE_RELAY_PROVIDERS_JSON", "")
    )


def image_relay_spec(provider: str) -> ImageRelaySpec | None:
    normalized = str(provider or "").strip().lower()
    return next(
        (spec for spec in image_relay_specs() if spec.provider == normalized),
        None,
    )


def image_relay_base_urls() -> dict[str, str]:
    return {spec.provider: spec.base_url for spec in image_relay_specs()}


def image_relay_backup_base_url(provider: str) -> str | None:
    spec = image_relay_spec(provider)
    return spec.backup_base_url if spec else None


def image_relay_model_ids(provider: str) -> tuple[str, ...]:
    spec = image_relay_spec(provider)
    return spec.models if spec else ()


def is_image_relay_model(provider: str, model_id: str) -> bool:
    return model_id in image_relay_model_ids(provider)


def image_relay_credential_env_names(provider: str) -> tuple[str, ...]:
    spec = image_relay_spec(provider)
    return (spec.credential_env, *spec.credential_env_aliases) if spec else ()


@lru_cache(maxsize=8)
def _parse_image_relay_api_keys(serialized: str) -> dict[str, str]:
    if not serialized.strip():
        return {}
    if len(serialized.encode("utf-8")) > MAX_IMAGE_RELAY_CONFIG_BYTES:
        raise ValueError("IMAGE_RELAY_API_KEYS_JSON is too large")
    try:
        payload = json.loads(serialized)
    except json.JSONDecodeError as error:
        raise ValueError("IMAGE_RELAY_API_KEYS_JSON must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("IMAGE_RELAY_API_KEYS_JSON must be a JSON object")

    known_providers = {spec.provider for spec in image_relay_specs()}
    keys: dict[str, str] = {}
    for raw_provider, raw_key in payload.items():
        provider = _validated_provider_id(raw_provider)
        if provider not in known_providers:
            raise ValueError(f"Unknown provider in IMAGE_RELAY_API_KEYS_JSON: {provider}")
        key = str(raw_key or "").strip()
        if key:
            keys[provider] = key
    return keys


def image_relay_api_key(provider: str) -> str | None:
    return _parse_image_relay_api_keys(
        os.environ.get("IMAGE_RELAY_API_KEYS_JSON", "")
    ).get(str(provider or "").strip().lower())


def is_valid_image_relay_request(provider: str, path: str, method: str) -> bool:
    spec = image_relay_spec(provider)
    if spec is None or not path or any(character in path for character in "%?#\\"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False

    normalized_path = path.strip("/")
    allowed = {
        "v1/models": {"GET"},
        "v1/images/generations": {"POST"},
    }
    if spec.supports_chat:
        allowed.update(
            {
                "v1/chat/completions": {"POST"},
                "v1/responses": {"POST"},
            }
        )
    if spec.supports_edits:
        allowed["v1/images/edits"] = {"POST"}
    allowed_methods = allowed.get(normalized_path, set())
    return bool(allowed_methods) and (
        method.upper() == "OPTIONS" or method.upper() in allowed_methods
    )


def clear_image_relay_caches() -> None:
    _parse_image_relay_specs.cache_clear()
    _parse_image_relay_api_keys.cache_clear()
