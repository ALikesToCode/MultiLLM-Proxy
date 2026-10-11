"""Translate request conversations between Responses and Chat Completions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from services.protocol_translation.anthropic_continuation import anthropic_extra
from services.protocol_translation.common import (
    TranslationError,
    as_mapping,
    new_id,
    text_of,
)

# Stateful features need the provider's stored responses or conversations.
_STATEFUL_FIELDS = {
    "previous_response_id": "stored previous responses",
    "conversation": "server-side conversations",
    "background": "background responses",
    "prompt": "stored prompt templates",
}


def _request_extra(value: Any, *, param: str) -> dict | None:
    try:
        return anthropic_extra(value)
    except ValueError as error:
        raise TranslationError("Invalid Anthropic continuation metadata", param=param) from error


# ---------------------------------------------------------------------------
# Requests: Responses -> Chat Completions.


def responses_request_to_chat(payload: Mapping[str, Any]) -> dict:
    from services.protocol_extras import validate_request_extras

    if not isinstance(payload, Mapping):
        raise TranslationError("The request body must be a JSON object")
    validate_request_extras(payload, "responses")
    for field, feature in _STATEFUL_FIELDS.items():
        if payload.get(field):
            raise TranslationError(
                f"'{field}' needs {feature}, which this route does not keep; "
                "send the full conversation in 'input' instead",
                param=field,
            )
    messages: list[dict] = []
    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions:
        messages.append({"role": "system", "content": instructions})
    elif isinstance(instructions, list):
        messages.extend(_input_to_messages(instructions))
    messages.extend(_input_to_messages(payload.get("input", "")))
    if not messages:
        raise TranslationError("'input' must contain at least one message", param="input")

    chat: dict[str, Any] = {"model": payload.get("model"), "messages": messages}
    if payload.get("max_output_tokens") is not None:
        chat["max_tokens"] = payload["max_output_tokens"]
    for key in ("temperature", "top_p"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    if payload.get("stream"):
        chat["stream"] = True
        chat["stream_options"] = {"include_usage": True}

    tools = _tools_to_chat(payload.get("tools"))
    choice = _tool_choice_to_chat(payload.get("tool_choice"))
    if isinstance(choice, tuple):
        allowed, choice = choice
        tools = [tool for tool in tools if tool["function"]["name"] in allowed]
    if tools:
        chat["tools"] = tools
        if choice is not None:
            chat["tool_choice"] = choice
        if payload.get("parallel_tool_calls") is False:
            chat["parallel_tool_calls"] = False

    text = payload.get("text")
    response_format = _text_format_to_chat(
        text.get("format") if isinstance(text, Mapping) else None
    )
    if response_format:
        chat["response_format"] = response_format
    reasoning = payload.get("reasoning")
    effort = reasoning.get("effort") if isinstance(reasoning, Mapping) else None
    if isinstance(effort, str) and effort:
        chat["reasoning_effort"] = effort
    return chat


def _input_to_messages(value: Any) -> list[dict]:
    if isinstance(value, str):
        return [{"role": "user", "content": value}] if value else []
    if not isinstance(value, list):
        raise TranslationError("'input' must be a string or an array of items", param="input")
    messages: list[dict] = []
    pending_reasoning = ""
    for index, item in enumerate(value):
        if isinstance(item, str):
            messages.append({"role": "user", "content": item})
            continue
        if not isinstance(item, Mapping):
            raise TranslationError(f"input[{index}] must be an object", param="input")
        kind = item.get("type")
        if kind in (None, "message") and item.get("role"):
            role = item["role"]
            if role not in {"user", "assistant", "system", "developer"}:
                raise TranslationError(
                    f"input[{index}].role '{role}' is not supported", param="input"
                )
            if role == "assistant":
                _merge_assistant(messages, text=_assistant_text(item.get("content")))
            else:
                content = _content_to_chat(item.get("content"), index)
                # Many chat providers reject "developer"; it has system semantics.
                messages.append(
                    {"role": "system" if role == "developer" else role, "content": content}
                )
                pending_reasoning = ""
        elif kind == "function_call":
            call = {
                "id": str(item.get("call_id") or item.get("id") or new_id("call")),
                "type": "function",
                "function": {
                    "name": str(item.get("name") or ""),
                    "arguments": item.get("arguments") or "{}",
                },
            }
            extra = _request_extra(item.get("extra_content"), param="input")
            if extra:
                call["extra_content"] = extra
            _merge_assistant(messages, call=call, reasoning=pending_reasoning)
            pending_reasoning = ""
        elif kind == "function_call_output":
            output = item.get("output")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": str(item.get("call_id") or ""),
                    "content": output if isinstance(output, str) else text_of(output),
                }
            )
        elif kind == "reasoning":
            # Chat has no reasoning items; thinking chat models only need it on tool turns.
            parts = item.get("content") or item.get("summary") or []
            pending_reasoning = text_of(parts)
        elif kind == "item_reference":
            raise TranslationError(
                "'item_reference' needs stored response items, which this route does not keep",
                param="input",
            )
        else:
            raise TranslationError(
                f"Input item type '{kind}' belongs to a built-in tool or feature that "
                "cannot be translated for this model",
                param="input",
            )
    return messages


def _merge_assistant(
    messages: list[dict], *, text: str = "", call: dict | None = None, reasoning: str = ""
) -> None:
    last = messages[-1] if messages else None
    if not (isinstance(last, dict) and last.get("role") == "assistant"):
        if not text and call is None:
            return
        last = {"role": "assistant", "content": None}
        messages.append(last)
    if text:
        last["content"] = (last.get("content") or "") + text
    if call is not None:
        last.setdefault("tool_calls", []).append(call)
        if reasoning:
            last["reasoning_content"] = reasoning


def _assistant_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    texts = []
    for part in content if isinstance(content, list) else []:
        if isinstance(part, Mapping):
            if part.get("type") in {"output_text", "input_text", "text"}:
                texts.append(str(part.get("text") or ""))
            elif part.get("type") == "refusal":
                texts.append(str(part.get("refusal") or ""))
    return "".join(texts)


def _content_to_chat(content: Any, index: int) -> Any:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        raise TranslationError(
            f"input[{index}].content must be a string or an array", param="input"
        )
    parts: list[dict] = []
    for part in content:
        if not isinstance(part, Mapping):
            raise TranslationError(
                f"input[{index}] contains an invalid content part", param="input"
            )
        kind = part.get("type")
        if kind in {"input_text", "output_text", "text"}:
            parts.append({"type": "text", "text": str(part.get("text") or "")})
        elif kind == "input_image":
            url = part.get("image_url")
            if not isinstance(url, str) or not url:
                raise TranslationError(
                    "Images referenced by file_id need the provider's Files API; send a URL or data URL",
                    param="input",
                )
            image: dict[str, Any] = {"url": url}
            if part.get("detail") in {"low", "high", "auto"}:
                image["detail"] = part["detail"]
            parts.append({"type": "image_url", "image_url": image})
        elif kind == "input_file":
            if part.get("file_url"):
                raise TranslationError(
                    "input_file.file_url cannot be translated; send file_data", param="input"
                )
            file = {key: part[key] for key in ("file_data", "file_id", "filename") if part.get(key)}
            parts.append({"type": "file", "file": file})
        elif kind == "input_audio":
            parts.append({"type": "input_audio", "input_audio": part.get("input_audio") or {}})
        elif kind == "refusal":
            parts.append({"type": "text", "text": str(part.get("refusal") or "")})
        else:
            raise TranslationError(
                f"Content part type '{kind}' cannot be translated", param="input"
            )
    if len(parts) == 1 and parts[0]["type"] == "text":
        return parts[0]["text"]
    return parts


def _tools_to_chat(tools: Any) -> list[dict]:
    if not tools:
        return []
    if not isinstance(tools, list):
        raise TranslationError("'tools' must be an array", param="tools")
    converted = []
    for tool in tools:
        kind = tool.get("type") if isinstance(tool, Mapping) else None
        if kind != "function":
            raise TranslationError(
                f"Built-in tool '{kind}' runs on the provider's server-side Responses runtime "
                "and is not available on this route; use function tools",
                param="tools",
            )
        function: dict[str, Any] = {
            "name": tool.get("name"),
            "parameters": tool.get("parameters") or {"type": "object", "properties": {}},
        }
        if isinstance(tool.get("description"), str):
            function["description"] = tool["description"]
        if isinstance(tool.get("strict"), bool):
            function["strict"] = tool["strict"]
        converted.append({"type": "function", "function": function})
    return converted


def _tool_choice_to_chat(choice: Any) -> Any:
    if choice is None or choice in ("auto", "none", "required"):
        return choice
    if isinstance(choice, Mapping):
        kind = choice.get("type")
        if kind == "function":
            return {"type": "function", "function": {"name": choice.get("name")}}
        if kind == "allowed_tools":
            names = {
                tool.get("name")
                for tool in choice.get("tools") or []
                if isinstance(tool, Mapping) and tool.get("type") == "function"
            }
            return names, "required" if choice.get("mode") == "required" else "auto"
        raise TranslationError(
            f"tool_choice type '{kind}' selects a built-in tool that is not available on this route",
            param="tool_choice",
        )
    raise TranslationError("Unsupported tool_choice value", param="tool_choice")


def _text_format_to_chat(fmt: Any) -> dict | None:
    if not isinstance(fmt, Mapping):
        return None
    if fmt.get("type") == "json_object":
        return {"type": "json_object"}
    if fmt.get("type") == "json_schema":
        schema: dict[str, Any] = {
            "name": fmt.get("name") or "output",
            "schema": fmt.get("schema") or {},
        }
        for key in ("strict", "description"):
            if fmt.get(key) is not None:
                schema[key] = fmt[key]
        return {"type": "json_schema", "json_schema": schema}
    return None


# ---------------------------------------------------------------------------
# Requests: Chat Completions -> Responses.


def chat_request_to_responses(payload: Mapping[str, Any]) -> dict:
    from services.protocol_extras import validate_request_extras

    if not isinstance(payload, Mapping):
        raise TranslationError("The request body must be a JSON object")
    validate_request_extras(payload, "chat")
    if payload.get("n") not in (None, 1):
        raise TranslationError("The Responses API returns one output; n must be 1", param="n")
    if payload.get("audio") or "audio" in (payload.get("modalities") or []):
        raise TranslationError("Audio output is not available for this model", param="modalities")
    if payload.get("functions") or payload.get("function_call"):
        raise TranslationError(
            "Legacy function calling is not supported for this model; use tools", param="functions"
        )
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TranslationError("'messages' must be a non-empty array", param="messages")

    items: list[dict] = []
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise TranslationError(f"messages[{index}] must be an object", param="messages")
        role = message.get("role")
        content = message.get("content")
        if role in {"system", "developer", "user"}:
            items.append({"role": role, "content": _chat_content_to_input(content, index)})
        elif role == "assistant":
            text = content if isinstance(content, str) else text_of(content)
            if text:
                items.append({"role": "assistant", "content": text})
            for call in message.get("tool_calls") or []:
                function = call.get("function") if isinstance(call, Mapping) else None
                if not isinstance(function, Mapping):
                    continue
                item = {
                    "type": "function_call",
                    "call_id": str(call.get("id") or new_id("call")),
                    "name": function.get("name") or "",
                    "arguments": function.get("arguments") or "{}",
                }
                extra = _request_extra(call.get("extra_content"), param="messages")
                if extra:
                    item["extra_content"] = extra
                items.append(item)
        elif role == "tool":
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": str(message.get("tool_call_id") or ""),
                    "output": content if isinstance(content, str) else text_of(content),
                }
            )
        else:
            raise TranslationError(
                f"messages[{index}].role '{role}' cannot be translated for this model",
                param="messages",
            )

    body: dict[str, Any] = {"model": payload.get("model"), "input": items, "store": False}
    max_tokens = payload.get("max_completion_tokens") or payload.get("max_tokens")
    if max_tokens is not None:
        body["max_output_tokens"] = max_tokens
    for key in ("temperature", "top_p"):
        if payload.get(key) is not None:
            body[key] = payload[key]
    if payload.get("stream"):
        body["stream"] = True

    tools = []
    for tool in payload.get("tools") or []:
        function = tool.get("function") if isinstance(tool, Mapping) else None
        if (
            not isinstance(tool, Mapping)
            or tool.get("type") != "function"
            or not isinstance(function, Mapping)
        ):
            raise TranslationError(
                "Only function tools can be translated for this model", param="tools"
            )
        converted: dict[str, Any] = {
            "type": "function",
            "name": function.get("name"),
            "parameters": function.get("parameters") or {"type": "object", "properties": {}},
            # Responses defaults to strict schemas; Chat Completions does not.
            "strict": bool(function.get("strict", False)),
        }
        if isinstance(function.get("description"), str):
            converted["description"] = function["description"]
        tools.append(converted)
    if tools:
        body["tools"] = tools
        choice = payload.get("tool_choice")
        if choice in ("auto", "none", "required"):
            body["tool_choice"] = choice
        elif isinstance(choice, Mapping) and choice.get("type") == "function":
            body["tool_choice"] = {
                "type": "function",
                "name": (choice.get("function") or {}).get("name"),
            }
        elif isinstance(choice, Mapping) and choice.get("type") == "allowed_tools":
            spec = choice.get("allowed_tools") or {}
            body["tool_choice"] = {
                "type": "allowed_tools",
                "mode": spec.get("mode") or "auto",
                "tools": [
                    {"type": "function", "name": (entry.get("function") or {}).get("name")}
                    for entry in spec.get("tools") or []
                    if isinstance(entry, Mapping)
                ],
            }
        if isinstance(payload.get("parallel_tool_calls"), bool):
            body["parallel_tool_calls"] = payload["parallel_tool_calls"]

    response_format = payload.get("response_format")
    if isinstance(response_format, Mapping):
        if response_format.get("type") == "json_object":
            body["text"] = {"format": {"type": "json_object"}}
        elif response_format.get("type") == "json_schema":
            spec = response_format.get("json_schema") or {}
            fmt = {
                "type": "json_schema",
                "name": spec.get("name") or "output",
                "schema": spec.get("schema") or {},
            }
            for key in ("strict", "description"):
                if spec.get(key) is not None:
                    fmt[key] = spec[key]
            body["text"] = {"format": fmt}
    effort = payload.get("reasoning_effort")
    if effort is None and isinstance(payload.get("reasoning"), Mapping):
        effort = payload["reasoning"].get("effort")
    if isinstance(effort, str) and effort:
        body["reasoning"] = {"effort": effort}
    return body


def _chat_content_to_input(content: Any, index: int) -> Any:
    if isinstance(content, str) or content is None:
        return content or ""
    if not isinstance(content, list):
        raise TranslationError(
            f"messages[{index}].content must be a string or an array", param="messages"
        )
    parts: list[dict] = []
    for part in content:
        if isinstance(part, str):
            parts.append({"type": "input_text", "text": part})
            continue
        if not isinstance(part, Mapping):
            raise TranslationError(
                f"messages[{index}] contains an invalid content part", param="messages"
            )
        kind = part.get("type")
        if kind == "text":
            parts.append({"type": "input_text", "text": str(part.get("text") or "")})
        elif kind == "image_url":
            image = part.get("image_url")
            url = image.get("url") if isinstance(image, Mapping) else image
            detail = image.get("detail") if isinstance(image, Mapping) else None
            parts.append({"type": "input_image", "image_url": url, "detail": detail or "auto"})
        elif kind == "file":
            file = as_mapping(part.get("file"))
            parts.append(
                {
                    "type": "input_file",
                    **{k: file[k] for k in ("file_data", "file_id", "filename") if file.get(k)},
                }
            )
        elif kind == "input_audio":
            parts.append({"type": "input_audio", "input_audio": part.get("input_audio") or {}})
        else:
            raise TranslationError(
                f"Content part type '{kind}' cannot be translated", param="messages"
            )
    return parts
