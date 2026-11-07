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
# Executors whose provider is chosen later. A bare advisor id names a Claude model.
ROUTED_PROVIDERS = frozenset({"auto", "free", "cascade", "intelligence"})
DEFAULT_PROVIDER = "anthropic"


class AdvisorError(ValueError):
    """An advisor tool that names no usable model."""


@dataclass(frozen=True)
class Advisor:
    model: str
    max_uses: Optional[int]
    max_tokens: Optional[int]


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
    return isinstance(tool, dict) and isinstance(tool.get("type"), str) and tool["type"].startswith(TOOL_PREFIX)


def advisor_tools(payload: Any) -> list[dict]:
    tools = payload.get("tools") if isinstance(payload, dict) else None
    if not isinstance(tools, list):
        return []
    return [tool for tool in tools if is_advisor_tool(tool)]


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


def advisors(payload: Any, provider: str) -> list[Advisor]:
    """Every advisor a request declares, with its catalog id and declared bounds."""
    return [Advisor(qualified_model(tool.get("model"), provider), _bound(tool, "max_uses"), _bound(tool, "max_tokens"))
            for tool in advisor_tools(payload)]


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
