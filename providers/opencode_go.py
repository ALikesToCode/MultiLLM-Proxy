from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

# OpenCode Go intentionally serves different models through different wire
# protocols. Keep this mapping close to the native route allowlist so model
# discovery and request routing cannot drift independently.
OPENCODE_GO_RESPONSES_MODEL_IDS = (
    "grok-4.6",
    "gpt-5.6-luna",
    "muse-spark-1.2-contributor",
)
OPENCODE_GO_CHAT_MODEL_IDS = (
    "glm-5.3-flash",
    "glm-5.3",
    "glm-5.2",
    "glm-5.1",
    "kimi-k3",
    "kimi-k2.7-code",
    "kimi-k2.6",
    "longcat-2.0",
    "deepseek-v4-pro",
    "deepseek-v4-flash",
    "deepseek-v4-flash-vision-exp",
    "mimo-v2.5",
    "mimo-v2.5-pro",
    "hy4-preview",
    "hy3",
)
OPENCODE_GO_MESSAGES_MODEL_IDS = (
    "minimax-m3",
    "minimax-m2.7",
    "minimax-m2.5",
    "qwen3.8-max",
    "qwen3.8-flash",
    "qwen3.7-max",
    "qwen3.7-plus",
    "qwen3.6-plus",
)

# These IDs remain in the live Go catalog even though the current endpoint
# table no longer gives them individual rows. Their established protocol is
# retained for compatible clients while runtime discovery remains authoritative.
OPENCODE_GO_CATALOG_COMPATIBILITY_MODELS = {
    "grok-4.5": "v1/chat/completions",
    "glm-5": "v1/chat/completions",
    "kimi-k2.5": "v1/chat/completions",
    "mimo-v2-pro": "v1/chat/completions",
    "mimo-v2-omni": "v1/chat/completions",
    "qwen3.5-plus": "v1/messages",
    "hy3-preview": "v1/chat/completions",
}
OPENCODE_GO_LEGACY_MODEL_IDS = ("ox-alpha-free",)

# OpenCode publishes free Zen models through the standard /zen/v1 origin,
# separately from the Go subscription catalog. Keep the known IDs built in so
# clients have a useful catalog before the first live refresh. Runtime catalog
# discovery also accepts future "-free" IDs without exposing paid Zen models.
OPENCODE_ZEN_FREE_RESPONSES_MODEL_IDS = (
    "muse-spark-1.2-contributor-free",
)
OPENCODE_ZEN_FREE_CHAT_MODEL_IDS = (
    "big-pickle",
    "deepseek-v4-flash-free",
    "hy3-free",
    "laguna-s-2.1-free",
    "ling-3.0-flash-fin-free",
    "mimo-v2.5-free",
    "nemotron-3-ultra-free",
    "nemotron-3.5-lightning-free",
)

OPENCODE_GO_MODEL_ENDPOINTS = {
    **{model: "v1/responses" for model in OPENCODE_GO_RESPONSES_MODEL_IDS},
    **{model: "v1/chat/completions" for model in OPENCODE_GO_CHAT_MODEL_IDS},
    **{model: "v1/messages" for model in OPENCODE_GO_MESSAGES_MODEL_IDS},
    **OPENCODE_GO_CATALOG_COMPATIBILITY_MODELS,
}
OPENCODE_GO_MODEL_IDS = tuple(OPENCODE_GO_MODEL_ENDPOINTS)
OPENCODE_ZEN_FREE_MODEL_ENDPOINTS = {
    **{
        model: "v1/responses"
        for model in OPENCODE_ZEN_FREE_RESPONSES_MODEL_IDS
    },
    **{
        model: "v1/chat/completions"
        for model in OPENCODE_ZEN_FREE_CHAT_MODEL_IDS
    },
}
OPENCODE_ZEN_FREE_MODEL_IDS = tuple(OPENCODE_ZEN_FREE_MODEL_ENDPOINTS)
OPENCODE_MODEL_ENDPOINTS = {
    **OPENCODE_GO_MODEL_ENDPOINTS,
    **OPENCODE_ZEN_FREE_MODEL_ENDPOINTS,
    **{
        model: "v1/chat/completions"
        for model in OPENCODE_GO_LEGACY_MODEL_IDS
    },
}


OPENCODE_GO_REQUEST_HEADER_WHITELIST = {
    "anthropic-beta": "Anthropic-Beta",
    "anthropic-dangerous-direct-browser-access": "Anthropic-Dangerous-Direct-Browser-Access",
    "anthropic-version": "Anthropic-Version",
    "idempotency-key": "Idempotency-Key",
    "openai-beta": "OpenAI-Beta",
    "openai-organization": "OpenAI-Organization",
    "openai-project": "OpenAI-Project",
    "x-client-request-id": "X-Client-Request-ID",
}

OPENCODE_GO_ENDPOINTS = frozenset(
    {
        ("POST", "v1/chat/completions"),
        ("POST", "v1/messages"),
        ("POST", "v1/responses"),
        ("GET", "v1/models"),
    }
)


def _header_value(headers: Mapping[str, Any], name: str) -> Optional[str]:
    direct_value = headers.get(name)
    if direct_value is not None:
        return str(direct_value)

    normalized_name = name.lower()
    for header, value in headers.items():
        if str(header).lower() == normalized_name:
            return str(value)
    return None


def normalized_opencode_go_path(path: str) -> str:
    return path.strip("/")


def canonical_opencode_go_path(path: str) -> str:
    normalized_path = normalized_opencode_go_path(path)
    if not normalized_path:
        return "v1"
    if normalized_path.lower() == "v1":
        return "v1"
    if normalized_path.lower().startswith("v1/"):
        return f"v1/{normalized_path[3:]}"
    return f"v1/{normalized_path}"


def build_opencode_go_url(base_url: str, path: str) -> str:
    canonical_path = canonical_opencode_go_path(path)
    normalized_base_url = base_url.rstrip("/")

    if normalized_base_url.lower().endswith("/v1"):
        suffix = canonical_path[3:] if canonical_path.lower().startswith("v1/") else ""
    else:
        suffix = canonical_path

    return (
        f"{normalized_base_url}/{suffix}"
        if suffix
        else normalized_base_url
    )


def is_opencode_go_documented_request(path: str, method: str) -> bool:
    return (
        method.upper(),
        canonical_opencode_go_path(path).lower(),
    ) in OPENCODE_GO_ENDPOINTS


def is_opencode_go_anthropic_request(path: str) -> bool:
    return canonical_opencode_go_path(path).lower() == "v1/messages"


def opencode_go_model_endpoint(model_id: str) -> Optional[str]:
    return OPENCODE_GO_MODEL_ENDPOINTS.get(model_id.strip().lower())


def is_opencode_zen_free_model(model_id: str) -> bool:
    normalized_model = model_id.strip().lower()
    return normalized_model == "big-pickle" or normalized_model.endswith("-free")


def opencode_model_endpoint(model_id: str) -> Optional[str]:
    normalized_model = model_id.strip().lower()
    endpoint = OPENCODE_MODEL_ENDPOINTS.get(normalized_model)
    if endpoint:
        return endpoint
    if is_opencode_zen_free_model(normalized_model):
        return "v1/chat/completions"
    return None


def build_opencode_model_url(
    go_base_url: str,
    zen_base_url: str,
    model_id: str,
    path: str,
) -> str:
    base_url = (
        zen_base_url
        if is_opencode_zen_free_model(model_id)
        else go_base_url
    )
    return build_opencode_go_url(base_url, path)


def is_opencode_go_native_path(path: str) -> bool:
    canonical_path = canonical_opencode_go_path(path).lower()
    if canonical_path not in {endpoint_path for _, endpoint_path in OPENCODE_GO_ENDPOINTS}:
        return False
    return normalized_opencode_go_path(path).lower() != "chat/completions"


def is_opencode_go_native_request(path: str, method: str) -> bool:
    """Use raw transport for documented routes without changing the legacy chat path."""
    return (
        is_opencode_go_documented_request(path, method)
        and is_opencode_go_native_path(path)
    )


def opencode_go_caller_authorization(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    authorization = _header_value(headers, "Authorization")
    if not proxy_api_key or not authorization:
        return None
    scheme, separator, credentials = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credentials.strip():
        return None
    return f"{scheme} {credentials.strip()}"


def opencode_go_caller_api_key(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    upstream_api_key = _header_value(headers, "X-Api-Key")
    if not proxy_api_key or not upstream_api_key or not upstream_api_key.strip():
        return None
    return upstream_api_key.strip()


def opencode_go_has_caller_auth(headers: Mapping[str, Any]) -> bool:
    return bool(
        opencode_go_caller_authorization(headers)
        or opencode_go_caller_api_key(headers)
    )
