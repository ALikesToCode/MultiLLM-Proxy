"""Provider-specific filtering of caller headers before upstream authentication."""

from collections.abc import Mapping

from providers.anthropic import ANTHROPIC_REQUEST_HEADER_WHITELIST
from providers.codex_everywhere import CODEX_EVERYWHERE_PROVIDERS
from providers.image_relays import image_relay_spec
from providers.nanogpt import NANOGPT_REQUEST_HEADER_WHITELIST
from providers.navyai import NAVYAI_REQUEST_HEADER_WHITELIST
from providers.opencode_go import OPENCODE_GO_REQUEST_HEADER_WHITELIST
from services.client_headers import OPENCODE_CLIENT_HEADER_NAMES

_OPENAI_HEADERS = {
    "idempotency-key": "Idempotency-Key",
    "openai-beta": "OpenAI-Beta",
    "openai-project": "OpenAI-Project",
    "x-client-request-id": "X-Client-Request-ID",
}
_GOOGLE_HEADERS = {"x-goog-user-project": "X-Goog-User-Project"}
_PROVIDER_HEADERS = {
    "anthropic": ANTHROPIC_REQUEST_HEADER_WHITELIST,
    "googleai": _GOOGLE_HEADERS,
    "gemini": _GOOGLE_HEADERS,
    "gemma": _GOOGLE_HEADERS,
    "nanogpt": NANOGPT_REQUEST_HEADER_WHITELIST,
    "navyai": NAVYAI_REQUEST_HEADER_WHITELIST,
    "opencode": {
        **OPENCODE_GO_REQUEST_HEADER_WHITELIST,
        **OPENCODE_CLIENT_HEADER_NAMES,
    },
}
_STAINLESS_PROVIDERS = (
    frozenset({"anthropic", "codex-easy", "kimi-code", "nanogpt", "navyai", "opencode"})
    | CODEX_EVERYWHERE_PROVIDERS
)


def _provider_headers(provider: str, upstream_path: str) -> Mapping[str, str]:
    if provider in _PROVIDER_HEADERS:
        return _PROVIDER_HEADERS[provider]
    if provider == "linkapi":
        headers = {
            **_OPENAI_HEADERS,
            **_GOOGLE_HEADERS,
            "anthropic-beta": "Anthropic-Beta",
            "x-goog-api-client": "X-Goog-Api-Client",
        }
        if upstream_path.strip("/").lower() == "v1/chat/completions":
            headers["x-grok-conv-id"] = "X-Grok-Conv-Id"
        return headers
    if provider in {"aihubmix", "together", "kimi-code"} or image_relay_spec(provider):
        return _OPENAI_HEADERS
    if provider == "codex-easy" or provider in CODEX_EVERYWHERE_PROVIDERS:
        return {
            **_OPENAI_HEADERS,
            "anthropic-beta": "Anthropic-Beta",
            "x-grok-conv-id": "X-Grok-Conv-Id",
        }
    return {}


def filter_upstream_headers(
    request_headers: Mapping[str, str],
    provider: str,
    upstream_path: str,
    common_headers: Mapping[str, str],
) -> dict[str, str]:
    whitelist = {**common_headers, **_provider_headers(provider, upstream_path)}
    headers = {}
    for name, value in request_headers.items():
        canonical = whitelist.get(name.lower())
        if canonical:
            headers[canonical] = value
        elif provider in _STAINLESS_PROVIDERS and name.lower().startswith(
            "x-stainless-"
        ):
            headers[name] = value
    return headers
