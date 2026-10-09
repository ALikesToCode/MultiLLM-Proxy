"""Content-free observations of the existing stateless protocol translators."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from services import protocol_translation as translation

HEADER_LIMIT = 2048
BODY_LIMIT = 1024 * 1024
_RANK = {"exact": 0, "semantic": 1, "lossy": 2, "unsupported": 3}
_REASONS = {
    "exact": "Field is preserved.",
    "semantic": "Field is represented using the target protocol's semantics.",
    "lossy": "Field is dropped or only partially represented by this translation.",
    "unsupported": "The existing translator cannot represent this request.",
}
# Destination names describe only the current translator, not provider capability.
_REQUEST_MAP = {
    translation.CHAT: {
        "model": "model", "messages": "messages", "max_tokens": "max_tokens",
        "max_completion_tokens": "max_tokens", "temperature": "temperature", "top_p": "top_p",
        "stream": "stream", "tools": "tools", "tool_choice": "tool_choice", "stop": "stop",
        "parallel_tool_calls": "parallel_tool_calls", "response_format": "response_format",
        "reasoning_effort": "reasoning_effort", "reasoning": "reasoning_effort",
        "thinking": "thinking", "user": "user",
    },
    translation.RESPONSES: {
        "model": "model", "input": "messages", "instructions": "messages",
        "max_output_tokens": "max_tokens", "temperature": "temperature", "top_p": "top_p",
        "stream": "stream", "tools": "tools", "tool_choice": "tool_choice",
        "parallel_tool_calls": "parallel_tool_calls", "text": "response_format",
        "reasoning": "reasoning_effort",
    },
    translation.MESSAGES: {
        "model": "model", "messages": "messages", "system": "messages", "max_tokens": "max_tokens",
        "temperature": "temperature", "top_p": "top_p", "stream": "stream", "tools": "tools",
        "tool_choice": "tool_choice", "stop_sequences": "stop", "thinking": "reasoning_effort",
        "output_config": "response_format", "output_format": "response_format",
    },
}
_KNOWN_FIELDS = frozenset().union(*_REQUEST_MAP.values(), {
    "metadata", "store", "include", "truncation", "prompt_cache_key", "service_tier",
    "logprobs", "top_logprobs", "logit_bias", "frequency_penalty", "presence_penalty", "seed",
    "stream_options", "n", "audio", "modalities", "functions", "function_call", "top_k",
    "context_management", "container", "mcp_servers", "previous_response_id", "conversation",
    "background", "prompt", "routing",
})
_RESPONSE_MAP = {
    translation.CHAT: {"id", "object", "created", "model", "choices", "usage"},
    translation.MESSAGES: {"id", "type", "role", "model", "content", "stop_reason", "usage"},
    translation.RESPONSES: {"id", "object", "created_at", "model", "output", "status", "usage", "incomplete_details"},
}


def _field(path: str, classification: str) -> dict[str, str]:
    return {"path": path, "classification": classification, "reason": _REASONS[classification]}


def combine_reports(*reports: Mapping[str, Any]) -> dict[str, Any]:
    """Deduplicate fixed paths, keeping the worst observed classification."""
    by_path: dict[str, dict] = {}
    for report in reports:
        for field in report["fields"]:
            previous = by_path.get(field["path"])
            if previous is None or _RANK[field["classification"]] > _RANK[previous["classification"]]:
                by_path[field["path"]] = field
    fields = [by_path[path] for path in sorted(by_path)]
    fidelity = max((field["classification"] for field in fields), key=lambda value: _RANK[value], default="exact")
    return {"fidelity": fidelity, "fields": fields}


def _mapped_request(payload: Mapping[str, Any], source: str, target: str) -> list[dict]:
    chat = translation.translate_request(payload, source, translation.CHAT)
    converted = translation.translate_request(payload, source, target)
    mapped = _REQUEST_MAP[source]
    destination = {
        translation.CHAT: {},
        translation.MESSAGES: {"stop": "stop_sequences", "reasoning_effort": "thinking",
                               "reasoning": "thinking", "max_completion_tokens": "max_tokens",
                               "response_format": "output_config", "user": "metadata"},
        translation.RESPONSES: {"messages": "input", "max_tokens": "max_output_tokens",
                                "max_completion_tokens": "max_output_tokens", "reasoning": "reasoning",
                                "response_format": "text", "reasoning_effort": "reasoning"},
    }[target]
    result = []
    for key in payload:
        path = f"request.{key}" if key in _KNOWN_FIELDS else "request.*"
        pivot = mapped.get(key)
        if source == translation.CHAT and key in {"max_completion_tokens", "reasoning"}:
            pivot = key
        if source == translation.MESSAGES and key == "output_config" and "response_format" not in chat:
            pivot = "reasoning_effort"
        dest = destination.get(pivot, pivot)
        if key == "routing":
            classification = "exact"  # Managed dispatch carries this separately.
        elif pivot is None or pivot not in chat or dest not in converted:
            classification = "lossy"
        elif key == dest and payload[key] == converted[dest]:
            classification = "exact"
        else:
            classification = "semantic"
        # Protocol structures may preserve their spelling while changing meaning.
        if classification == "exact" and key in {"messages", "tools", "tool_choice", "reasoning", "thinking"}:
            classification = "semantic"
        result.append(_field(path, classification))
    return result


def _nested_losses(payload: Mapping[str, Any], prefix: str, source: str, target: str) -> list[dict]:
    """Inspect fixed protocol members; never descend into schemas, metadata or arguments."""
    fields: dict[str, dict] = {}

    def add(path: str, classification: str = "lossy") -> None:
        fields[path] = _field(path, classification)
    for parent, supported, known in (
        ("text", {"format"}, {"format", "verbosity"}),
        ("reasoning", {"effort"}, {"effort", "summary", "generate_summary", "encrypted_content"}),
        ("output_config", {"effort", "format"}, {"effort", "format"}),
    ):
        value = payload.get(parent)
        if isinstance(value, Mapping):
            for key in value:
                if key not in supported:
                    name = key if key in known else "*"
                    add(f"{prefix}.{parent}.{name}")
    if source == translation.MESSAGES and isinstance(payload.get("thinking"), Mapping):
        # Only budget-to-effort approximation survives the Chat pivot.
        add(f"{prefix}.thinking", "semantic" if
            payload["thinking"].get("type") == "enabled" else "lossy")
    if prefix == "request" and target == translation.MESSAGES:
        for tool in payload.get("tools") or []:
            if not isinstance(tool, Mapping):
                continue
            function = tool.get("function") if source == translation.CHAT else tool
            if isinstance(function, Mapping) and "strict" in function:
                member = "function.strict" if source == translation.CHAT else "strict"
                add(f"request.tools[].{member}")
    arrays = ("messages", "input", "output", "choices", "content", "system", "tools")
    opaque_members = {"cache_control", "citations", "signature", "logprobs", "annotations",
                      "encrypted_content", "service_tier", "refusal"}

    def visit(value: Any, path: str, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(value, list):
            for item in value:
                visit(item, path + "[]", depth + 1)
        elif isinstance(value, Mapping):
            for name in opaque_members:
                if name in value and value[name] is not None:
                    add(f"{path}.{name}")
            for name in ("content", "message", "delta"):
                if isinstance(value.get(name), (list, Mapping)):
                    visit(value[name], f"{path}.{name}", depth + 1)

    for name in arrays:
        visit(payload.get(name), f"{prefix}.{name}")
    return list(fields.values())


def request_report(payload: Mapping[str, Any], source: str, target: str) -> dict[str, Any]:
    """Validate using the existing translator and report without returning any values."""
    if source not in translation.PROTOCOLS or target not in translation.PROTOCOLS:
        raise ValueError("Unknown conversion protocol")
    if source == target:
        return {"fidelity": "exact", "fields": []}
    try:
        fields = _mapped_request(payload, source, target)
    except translation.TranslationError as error:
        param = error.param if error.param in _KNOWN_FIELDS else "*"
        return {"fidelity": "unsupported", "fields": [_field(f"request.{param}", "unsupported")]}
    fields.extend(_nested_losses(payload, "request", source, target))
    return combine_reports({"fields": fields})


def response_report(payload: Mapping[str, Any] | None, source: str, target: str) -> dict[str, Any]:
    """Report JSON fields, or structural streaming coverage without consuming events."""
    if source == target:
        return {"fidelity": "exact", "fields": []}
    if payload is None:
        return {"fidelity": "semantic", "fields": [_field("response", "semantic")]}
    known = _RESPONSE_MAP[source]
    fields = [_field(f"response.{key}" if key in known | {"stop_sequence", "metadata", "service_tier"}
                     else "response.*", "semantic" if key in known or payload[key] is None else "lossy") for key in payload]
    fields.extend(_nested_losses(payload, "response", source, target))
    return combine_reports({"fields": fields})


def report_headers(report: Mapping[str, Any]) -> dict[str, str]:
    paths = []
    length = 0
    for field in report["fields"]:
        path = field["path"]
        addition = len(path.encode("ascii")) + bool(paths)
        if length + addition > HEADER_LIMIT:
            break
        paths.append(path)
        length += addition
    return {"X-MultiLLM-Conversion-Fidelity": report["fidelity"],
            "X-MultiLLM-Conversion-Fields": ",".join(paths)}
