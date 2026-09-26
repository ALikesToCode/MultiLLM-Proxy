"""Which wire protocols each provider model accepts natively.

Unified routes pass a request through unchanged when the selected model speaks
the caller's protocol and translate it otherwise. To declare a provider, add
its whole-catalog endpoints to PROVIDER_NATIVE_ENDPOINTS, or register a
per-model resolver in MODEL_ENDPOINT_RESOLVERS when models differ.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from providers.opencode_go import opencode_model_endpoint

CHAT_COMPLETIONS = "v1/chat/completions"
RESPONSES = "v1/responses"
MESSAGES = "v1/messages"

# Providers whose every model accepts these endpoints besides Chat Completions.
PROVIDER_NATIVE_ENDPOINTS: Mapping[str, frozenset[str]] = {
    "codex-easy": frozenset({RESPONSES}),
    "linkapi": frozenset({RESPONSES}),
    "nanogpt": frozenset({RESPONSES, MESSAGES}),
    "navyai": frozenset({RESPONSES, MESSAGES}),
}

# Providers that serve each model over exactly one endpoint. A resolver returns
# None for a model it does not know, which then uses Chat Completions.
MODEL_ENDPOINT_RESOLVERS: Mapping[str, Callable[[str], str | None]] = {
    "opencode": opencode_model_endpoint,
}


def native_endpoints(provider: str, model: str) -> frozenset[str]:
    """Endpoints the provider model accepts without translation."""
    resolver = MODEL_ENDPOINT_RESOLVERS.get(provider)
    endpoint = resolver(model) if resolver is not None else None
    if endpoint:
        return frozenset({endpoint})
    return frozenset({CHAT_COMPLETIONS}) | PROVIDER_NATIVE_ENDPOINTS.get(provider, frozenset())


def speaks(provider: str, model: str, endpoint: str) -> bool:
    return endpoint in native_endpoints(provider, model)


def chat_bridge_endpoint(provider: str, model: str) -> str | None:
    """The endpoint a Chat Completions request must be translated to, if any."""
    endpoints = native_endpoints(provider, model)
    if CHAT_COMPLETIONS in endpoints:
        return None
    for endpoint in (RESPONSES, MESSAGES):
        if endpoint in endpoints:
            return endpoint
    return None
