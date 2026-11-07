"""Claude's advisor tool: the models a request names inside its tools.

A Messages request may declare `{"type": "advisor_20260301", "model": ...}`. The
request's own model writes the answer, and the tool's model is called server-side
for advice, billed at its own prices. Key controls apply to that model as they do
to the request's model, so it is resolved to its catalog id here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

BETA = "advisor-tool-2026-03-01"
TOOL_PREFIX = "advisor_"
TOOL_TYPE = "advisor_20260301"
# Chat Completions and Responses requests ask for an advisor with this body field;
# it becomes the Messages tool when the request is translated for Claude.
EXTENSION = "advisor"
EXTENSION_KEYS = ("model", "max_uses", "max_tokens", "caching")
EXECUTOR_PREFIX = "anthropic:"
# Executors whose provider is chosen later. A bare advisor id names a Claude model.
ROUTED_PROVIDERS = frozenset({"auto", "free", "cascade", "intelligence"})
DEFAULT_PROVIDER = "anthropic"


class AdvisorError(ValueError):
    """An advisor tool that names no usable model."""


# A cache write costs this much more than reading the same prompt: 1.25 times the
# input price for five minutes, twice for an hour.
CACHE_WRITE_EXTRA = {"5m": 0.25, "1h": 1.0}


@dataclass(frozen=True)
class Advisor:
    model: str
    max_uses: Optional[int]
    max_tokens: Optional[int]
    # The share of the advisor's prompt price each call adds by writing the cache.
    cache_write: float = 0.0


def executor_provider(model: Any, provider: Optional[str] = None) -> str:
    """The provider namespace of a bare advisor id: the executor's own provider."""
    if provider:
        return provider.strip().lower()
    if isinstance(model, str) and ":" in model:
        namespace = model.split(":", 1)[0].strip().lower()
        if namespace and namespace not in ROUTED_PROVIDERS:
            return namespace
    return DEFAULT_PROVIDER


def is_advisor_tool(tool: Any) -> bool:
    # Any spelling of the type is checked; whether Claude accepts it is Claude's call.
    return (isinstance(tool, dict) and isinstance(tool.get("type"), str)
            and tool["type"].strip().lower().startswith(TOOL_PREFIX))


def advisor_tools(payload: Any) -> list[dict]:
    tools = payload.get("tools") if isinstance(payload, dict) else None
    if not isinstance(tools, list):
        return []
    return [tool for tool in tools if is_advisor_tool(tool)]


def extension_tool(payload: Any) -> Optional[dict]:
    """The Messages advisor tool a Chat Completions or Responses request asks for in
    its `advisor` field, or None. The executor must be a Claude model."""
    value = payload.get(EXTENSION) if isinstance(payload, dict) else None
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AdvisorError("'advisor' must be an object such as "
                           '{"model": "anthropic:claude-sonnet-5-5", "max_uses": 1, "max_tokens": 2048}')
    unknown = next((key for key in value if key not in EXTENSION_KEYS), None)
    if unknown is not None:
        raise AdvisorError(f"'advisor' accepts model, max_uses, max_tokens and caching, not {str(unknown)[:64]}")
    for name in ("max_uses", "max_tokens"):
        if name in value and _bound(value, name) is None:
            raise AdvisorError(f"'advisor.{name}' must be a positive integer")
    if "caching" in value and not isinstance(value["caching"], dict):
        raise AdvisorError("'advisor.caching' must be an object such as {\"type\": \"ephemeral\", \"ttl\": \"5m\"}")
    model = payload.get("model")
    if not isinstance(model, str) or not model.strip().lower().startswith(EXECUTOR_PREFIX):
        raise AdvisorError("'advisor' works only with anthropic: models")
    return {"type": TOOL_TYPE, "name": "advisor", **value}


def _replays_advice(body: Any) -> bool:
    messages = body.get("messages") if isinstance(body, dict) else None
    return isinstance(messages, list) and any(
        isinstance(block, dict) and (block.get("type") == "advisor_tool_result" or (
            block.get("type") == "server_tool_use" and block.get("name") == "advisor"))
        for message in messages if isinstance(message, dict) and isinstance(message.get("content"), list)
        for block in message["content"])


def declared_betas(body: Any) -> tuple[str, ...]:
    """The beta a Messages body needs for the advisor tools it declares or the advisor
    blocks its history replays (Claude accepts those without the tool, given the beta)."""
    return (BETA,) if advisor_tools(body) or _replays_advice(body) else ()


def _bound(tool: dict, name: str) -> Optional[int]:
    value = tool.get(name)
    return value if type(value) is int and value > 0 else None


def qualified_model(model: Any, provider: str) -> str:
    """`claude-opus-5-5` -> `anthropic:claude-opus-5-5`; a catalog id must name the
    executor's provider, which is the one that runs the advisor."""
    if not isinstance(model, str) or not model.strip():
        raise AdvisorError("The advisor tool must name a model")
    model = model.strip()
    if ":" not in model:
        return f"{provider}:{model}".lower()
    namespace, bare = model.split(":", 1)
    if namespace.strip().lower() != provider or not bare.strip():
        raise AdvisorError(f"The advisor model {model[:128]} is not served by the request's provider ({provider[:64]})")
    return model.lower()


def _cache_write(tool: dict) -> float:
    caching = tool.get("caching")
    if not isinstance(caching, dict):
        return 0.0
    ttl = caching.get("ttl", "5m")
    # An unknown TTL is priced as the dearer one.
    return CACHE_WRITE_EXTRA.get(ttl, 1.0) if isinstance(ttl, str) else 1.0


def advisors(payload: Any, provider: str, *, extension: bool = False) -> list[Advisor]:
    """Every advisor a request declares, with its catalog id and declared bounds;
    `extension` also reads a Chat Completions or Responses `advisor` field."""
    tools = advisor_tools(payload)
    requested = extension_tool(payload) if extension else None
    if requested is not None:
        tools.append(requested)
    return [Advisor(qualified_model(tool.get("model"), provider), _bound(tool, "max_uses"), _bound(tool, "max_tokens"),
                    _cache_write(tool))
            for tool in tools]


def catalog_models(payload: Any, provider: str) -> list[str]:
    """The catalog ids of a request's advisors. A tool that names no usable model is
    refused when the request is admitted, so it is skipped here."""
    models = []
    for tool in advisor_tools(payload):
        try:
            models.append(qualified_model(tool.get("model"), provider))
        except AdvisorError:
            continue
    return models


def upstream_payload(payload: dict, provider: str) -> dict:
    """Send the provider its own model ids: a catalog id loses its provider prefix."""
    if not advisor_tools(payload):
        return payload
    rewritten = []
    for tool in payload["tools"]:
        model = tool.get("model") if is_advisor_tool(tool) else None
        if isinstance(model, str) and model.strip().lower().startswith(f"{provider}:"):
            tool = {**tool, "model": model.strip().split(":", 1)[1]}
        rewritten.append(tool)
    return {**payload, "tools": rewritten}
