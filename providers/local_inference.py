"""Explicit OpenAI-compatible local endpoints; no host or model discovery."""

from collections.abc import Mapping
import ipaddress
import logging
import os
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from providers.base import ProviderCapabilities
from providers.openai_compatible import OpenAICompatibleAdapter

LOCAL_INFERENCE_ENV = {
    "ollama": ("OLLAMA_BASE_URL", "OLLAMA_API_KEY"),
    "vllm": ("VLLM_BASE_URL", "VLLM_API_KEY"),
    "lmstudio": ("LM_STUDIO_BASE_URL", "LM_STUDIO_API_KEY"),
    "llamacpp": ("LLAMA_CPP_BASE_URL", "LLAMA_CPP_API_KEY"),
    "sglang": ("SGLANG_BASE_URL", "SGLANG_API_KEY"),
}
LOCAL_INFERENCE_PROVIDERS = frozenset(LOCAL_INFERENCE_ENV)
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))
_HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", re.IGNORECASE)
_PATH_PATTERN = re.compile(r"(?:/[A-Za-z0-9_-]+)*/v1")
_invalid_settings_logged: set[str] = set()
logger = logging.getLogger(__name__)


def normalize_local_base_url(value: str) -> str:
    """Validate an operator endpoint without resolving names or probing ports."""
    if len(value) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid local inference base URL")
    candidate = value.strip()
    if any(char in candidate for char in "\\%?#"):
        raise ValueError("Invalid local inference base URL")
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    if (parsed.scheme not in {"http", "https"} or not host
            or parsed.username is not None or parsed.password is not None
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("Invalid local inference origin")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    private = bool(address and (address.is_loopback or any(
        address.version == network.version and address in network
        for network in _PRIVATE_NETWORKS
    )))
    localhost = host == "localhost" or host.endswith(".localhost")
    if address is not None and not (private or address.is_global):
        raise ValueError("Invalid local inference address")
    if address is None and not _HOST_PATTERN.fullmatch(host):
        raise ValueError("Invalid local inference hostname")
    if parsed.scheme == "http" and not (private or localhost):
        raise ValueError("Local HTTP requires a loopback or private address")
    path = parsed.path.rstrip("/") or "/v1"
    if not _PATH_PATTERN.fullmatch(path):
        raise ValueError("Local inference requires an OpenAI-compatible /v1 service")
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parsed.scheme, authority, path, "", ""))


def local_inference_base_urls() -> dict[str, str]:
    urls = {}
    for provider, (env_name, _) in LOCAL_INFERENCE_ENV.items():
        value = os.environ.get(env_name, "")
        if not value.strip():
            continue
        try:
            urls[provider] = normalize_local_base_url(value)
        except ValueError:
            if env_name not in _invalid_settings_logged:
                _invalid_settings_logged.add(env_name)
                logger.warning("Ignoring invalid %s; local inference provider is off", env_name)
    return urls


def local_inference_adapters(base_urls: Mapping[str, str]) -> dict[str, OpenAICompatibleAdapter]:
    adapters = {}
    for provider in LOCAL_INFERENCE_ENV:
        value = base_urls.get(provider)
        if not value:
            continue
        try:
            base_url = normalize_local_base_url(value)
        except ValueError:
            continue
        adapters[provider] = OpenAICompatibleAdapter(
            name=provider, base_url=base_url, chat_path="chat/completions",
            provider_capabilities=ProviderCapabilities(),
        )
    return adapters


def local_credential_env_names(provider: str) -> tuple[str, ...]:
    settings = LOCAL_INFERENCE_ENV.get(provider)
    return (settings[1],) if settings else ()


def local_provider_allows_keyless(provider: str, base_urls: Mapping[str, str]) -> bool:
    return provider in local_inference_adapters(base_urls)


def local_catalog_metadata(provider: str, metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Tag declarations, leaving model-name guesses and monetary cost unknown."""
    result = dict(metadata or {})
    source = f"provider_catalog:{provider}"
    fields = {key for key in result if key.startswith("supports_") or key in {
        "input_modalities", "output_modalities", "context_window", "max_output_tokens",
    }}
    result["metadata_source"] = source
    result["metadata_provenance"] = {
        **(result.get("metadata_provenance") or {}),
        **{key: source for key in fields},
    }
    # Precision declarations follow the existing operator precision policy.
    from services.model_precision import configured_preference

    if configured_preference():
        result.setdefault("precision", "unknown")
        result.setdefault("precision_source", source)
        result["metadata_provenance"]["precision"] = result["precision_source"]
    return result
