from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from services.context_optimizer import estimate_payload_tokens

_CACHE_KEY_CHAT_PROVIDERS = frozenset({"kimi-code", "openai"})
_CACHE_KEY_RESPONSES_PROVIDERS = frozenset({"codex-easy", "linkapi", "openai"})
_CONVERSATION_HEADER_PROVIDERS = frozenset({"codex-easy", "linkapi"})


@dataclass(frozen=True)
class PromptCacheDecision:
    payload: dict[str, Any]
    request_headers: dict[str, str]
    status: str
    mode: str
    estimated_input_tokens: int


def _header_value(headers: Mapping[str, Any] | None, name: str) -> str:
    if not headers:
        return ""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered and isinstance(value, str):
            return value.strip()
    return ""


def _contains_cache_control(value: Any) -> bool:
    if isinstance(value, dict):
        if "cache_control" in value:
            return True
        return any(_contains_cache_control(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_cache_control(item) for item in value)
    return False


def _stable_prefix(payload: Mapping[str, Any]) -> Any:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return payload.get("input", "")

    prefix = []
    dialogue_count = 0
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").lower()
        if role in {"system", "developer"}:
            prefix.append(message)
            continue
        if dialogue_count < 1:
            prefix.append(message)
            dialogue_count += 1
        if dialogue_count >= 1:
            break
    return prefix


def _cache_key(provider: str, model: str, payload: Mapping[str, Any]) -> str:
    stable_material = json.dumps(
        {
            "provider": provider,
            "model": model,
            "prefix": _stable_prefix(payload),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(stable_material).hexdigest()
    return f"mllm-{digest[:48]}"


def _caller_controls_cache(
    payload: Mapping[str, Any],
    request_headers: Mapping[str, Any] | None,
) -> bool:
    return (
        any(key in payload for key in ("caching", "prompt_caching", "prompt_cache_key"))
        or _contains_cache_control(payload)
        or bool(_header_value(request_headers, "X-Grok-Conv-Id"))
    )


def apply_prompt_cache_policy(
    payload: Mapping[str, Any],
    *,
    provider: str,
    model: str,
    endpoint: str = "chat",
    request_headers: Mapping[str, Any] | None = None,
    enabled: bool = True,
    minimum_tokens: int = 1_024,
    nanogpt_subscription_only: bool = False,
) -> PromptCacheDecision:
    """Add only provider-supported cache affinity hints; never cache responses."""
    copied = dict(payload)
    if provider == "nanogpt" and nanogpt_subscription_only:
        copied.pop("caching", None)
    cacheable_input = (
        {"messages": payload["messages"]}
        if isinstance(payload.get("messages"), list)
        else {"input": payload.get("input", "")}
    )
    estimated_tokens = estimate_payload_tokens(cacheable_input)
    if _caller_controls_cache(copied, request_headers):
        return PromptCacheDecision(
            payload=copied,
            request_headers={},
            status="caller",
            mode="caller-controlled",
            estimated_input_tokens=estimated_tokens,
        )
    if not enabled:
        return PromptCacheDecision(
            payload=copied,
            request_headers={},
            status="skipped",
            mode="disabled",
            estimated_input_tokens=estimated_tokens,
        )
    if estimated_tokens < max(1, minimum_tokens):
        return PromptCacheDecision(
            payload=copied,
            request_headers={},
            status="skipped",
            mode="below-threshold",
            estimated_input_tokens=estimated_tokens,
        )

    normalized_endpoint = endpoint.strip().lower()
    normalized_model = model.strip().lower()
    if provider == "nanogpt" and nanogpt_subscription_only:
        return PromptCacheDecision(
            payload=copied,
            request_headers={},
            status="skipped",
            mode="nanogpt-subscription-only",
            estimated_input_tokens=estimated_tokens,
        )
    if provider == "nanogpt" and normalized_endpoint == "chat":
        copied["caching"] = True
        return PromptCacheDecision(
            payload=copied,
            request_headers={},
            status="applied",
            mode="nanogpt-routing",
            estimated_input_tokens=estimated_tokens,
        )
    if (
        normalized_endpoint == "responses"
        and provider in _CACHE_KEY_RESPONSES_PROVIDERS
    ) or (normalized_endpoint == "chat" and provider in _CACHE_KEY_CHAT_PROVIDERS):
        cache_key = _cache_key(provider, model, payload)
        copied["prompt_cache_key"] = cache_key
        return PromptCacheDecision(
            payload=copied,
            request_headers={},
            status="applied",
            mode="cache-key",
            estimated_input_tokens=estimated_tokens,
        )
    if (
        normalized_endpoint == "chat"
        and provider in _CONVERSATION_HEADER_PROVIDERS
        and "grok" in normalized_model
    ):
        cache_key = _cache_key(provider, model, payload)
        return PromptCacheDecision(
            payload=copied,
            request_headers={"X-Grok-Conv-Id": cache_key},
            status="applied",
            mode="conversation-affinity",
            estimated_input_tokens=estimated_tokens,
        )
    return PromptCacheDecision(
        payload=copied,
        request_headers={},
        status="implicit",
        mode="implicit-prefix",
        estimated_input_tokens=estimated_tokens,
    )
