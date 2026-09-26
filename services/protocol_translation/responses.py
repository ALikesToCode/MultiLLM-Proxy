"""OpenAI Responses <-> OpenAI Chat Completions."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from services.protocol_translation.common import (
    ChatItem,
    StreamComment,
    StreamFailure,
    TranslationError,
    UpstreamFailure,
    as_mapping,
    chat_chunk,
    chat_usage,
    comment_item,
    error_details,
    event_json,
    first_chat_choice,
    iter_events,
    message_reasoning,
    new_id,
    non_negative_int,
    sse_comment,
    sse_event,
    text_of,
    unix_time,
    usage_numbers,
)

# Stateful features need the provider's stored responses or conversations.
_STATEFUL_FIELDS = {
    "previous_response_id": "stored previous responses",
    "conversation": "server-side conversations",
    "background": "background responses",
    "prompt": "stored prompt templates",
}
_INCOMPLETE_TO_FINISH = {"max_output_tokens": "length", "content_filter": "content_filter"}
# Documented in docs/protocol-translation.md: an upstream stream that ends
# without a terminal event is reported as incomplete, never as completed.
INTERRUPTED_REASON = "upstream_interrupted"


# ---------------------------------------------------------------------------
# Requests: Responses -> Chat Completions.


def responses_request_to_chat(payload: Mapping[str, Any]) -> dict:
    if not isinstance(payload, Mapping):
        raise TranslationError("The request body must be a JSON object")
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
    if not isinstance(payload, Mapping):
        raise TranslationError("The request body must be a JSON object")
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
                items.append(
                    {
                        "type": "function_call",
                        "call_id": str(call.get("id") or new_id("call")),
                        "name": function.get("name") or "",
                        "arguments": function.get("arguments") or "{}",
                    }
                )
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


# ---------------------------------------------------------------------------
# Responses (non-streaming).


def responses_response_to_chat(
    payload: Mapping[str, Any], *, model: str | None = None, **_: Any
) -> dict:
    status = payload.get("status")
    if status == "failed" or (payload.get("error") and status not in ("completed", "incomplete")):
        reason, error_type, code = error_details({"error": payload.get("error") or {}})
        raise UpstreamFailure(reason, error_type=error_type or "api_error", code=code)
    texts: list[str] = []
    refusals: list[str] = []
    reasoning: list[str] = []
    calls: list[dict] = []
    for item in payload.get("output") or []:
        if not isinstance(item, Mapping):
            continue
        kind = item.get("type")
        if kind == "message":
            for part in item.get("content") or []:
                if isinstance(part, Mapping) and part.get("type") == "output_text":
                    texts.append(str(part.get("text") or ""))
                elif isinstance(part, Mapping) and part.get("type") == "refusal":
                    refusals.append(str(part.get("refusal") or ""))
        elif kind == "reasoning":
            reasoning.append(
                text_of(item.get("content") or [])
                or "\n\n".join(
                    str(part.get("text") or "")
                    for part in item.get("summary") or []
                    if isinstance(part, Mapping)
                )
            )
        elif kind == "function_call":
            calls.append(
                {
                    "id": str(item.get("call_id") or item.get("id") or new_id("call")),
                    "type": "function",
                    "function": {
                        "name": str(item.get("name") or ""),
                        "arguments": item.get("arguments") or "",
                    },
                }
            )
    text = "".join(texts)
    message: dict[str, Any] = {"role": "assistant", "content": text if text or not calls else None}
    if calls:
        message["tool_calls"] = calls
    if refusals:
        message["refusal"] = "".join(refusals)
    if any(reasoning):
        message["reasoning_content"] = "".join(reasoning)
    if status == "incomplete":
        reason = (payload.get("incomplete_details") or {}).get("reason")
        finish = _INCOMPLETE_TO_FINISH.get(reason, "length")
    else:
        finish = "tool_calls" if calls else "stop"
    completion: dict[str, Any] = {
        "id": _chat_id(payload.get("id")),
        "object": "chat.completion",
        "created": int(payload.get("created_at") or unix_time()),
        "model": model or payload.get("model") or "",
        "choices": [{"index": 0, "message": message, "finish_reason": finish, "logprobs": None}],
    }
    if isinstance(payload.get("usage"), Mapping):
        completion["usage"] = responses_usage_to_chat(payload["usage"])
    return completion


def chat_response_to_responses(
    payload: Mapping[str, Any],
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
    **_: Any,
) -> dict:
    message, finish = first_chat_choice(payload)
    output: list[dict] = []
    reasoning = message_reasoning(message)
    if reasoning:
        output.append(_reasoning_item(new_id("rs"), reasoning, "completed"))
    text = (
        message.get("content")
        if isinstance(message.get("content"), str)
        else text_of(message.get("content"))
    )
    refusal = message.get("refusal") if isinstance(message.get("refusal"), str) else ""
    if text or refusal or not message.get("tool_calls"):
        parts: list[dict] = []
        if text or not refusal:
            parts.append(_text_part(text or ""))
        if refusal:
            parts.append({"type": "refusal", "refusal": refusal})
        output.append(_message_item(new_id("msg"), parts, "completed"))
    for call in message.get("tool_calls") or []:
        function = call.get("function") if isinstance(call, Mapping) else None
        if not isinstance(function, Mapping):
            continue
        output.append(
            _function_call_item(
                new_id("fc"),
                str(call.get("id") or new_id("call")),
                function.get("name") or "",
                function.get("arguments") or "",
                "completed",
            )
        )
    status, incomplete = _status_for_finish(finish)
    response = response_object(
        response_id=_response_id(payload.get("id")),
        created_at=int(payload.get("created") or unix_time()),
        model=model or payload.get("model") or "",
        status=status,
        output=output,
        usage=chat_usage_to_responses(payload.get("usage")),
        request=request,
        incomplete_details=incomplete,
    )
    response["output_text"] = text or ""
    return response


def _status_for_finish(finish: Any) -> tuple[str, dict | None]:
    if finish == "length":
        return "incomplete", {"reason": "max_output_tokens"}
    if finish == "content_filter":
        return "incomplete", {"reason": "content_filter"}
    return "completed", None


def _chat_id(value: Any) -> str:
    return f"chatcmpl-{value}" if isinstance(value, str) and value else new_id("chatcmpl")


def _response_id(value: Any) -> str:
    if isinstance(value, str) and value.startswith("resp_"):
        return value
    return f"resp_{value}" if isinstance(value, str) and value else new_id("resp")


def _text_part(text: str) -> dict:
    return {"type": "output_text", "text": text, "annotations": [], "logprobs": []}


def _message_item(item_id: str, content: list, status: str) -> dict:
    return {
        "id": item_id,
        "type": "message",
        "role": "assistant",
        "status": status,
        "content": content,
    }


def _reasoning_item(item_id: str, text: str, status: str) -> dict:
    content = [{"type": "reasoning_text", "text": text}] if text else []
    return {"id": item_id, "type": "reasoning", "summary": [], "content": content, "status": status}


def _function_call_item(item_id: str, call_id: str, name: str, arguments: str, status: str) -> dict:
    return {
        "id": item_id,
        "type": "function_call",
        "status": status,
        "call_id": call_id,
        "name": name,
        "arguments": arguments,
    }


def responses_usage_to_chat(usage: Mapping[str, Any]) -> dict:
    input_details = usage.get("input_tokens_details")
    input_details = input_details if isinstance(input_details, Mapping) else {}
    output_details = usage.get("output_tokens_details")
    output_details = output_details if isinstance(output_details, Mapping) else {}
    return chat_usage(
        non_negative_int(usage.get("input_tokens")),
        non_negative_int(usage.get("output_tokens")),
        cached=non_negative_int(input_details.get("cached_tokens")),
        cache_write=non_negative_int(input_details.get("cache_write_tokens")),
        reasoning=non_negative_int(output_details.get("reasoning_tokens")),
    )


def chat_usage_to_responses(usage: Any) -> dict | None:
    if not isinstance(usage, Mapping):
        return None
    numbers = usage_numbers(usage)
    input_details: dict[str, int] = {"cached_tokens": numbers["cached"]}
    if numbers["cache_write"]:
        input_details["cache_write_tokens"] = numbers["cache_write"]
    return {
        "input_tokens": numbers["prompt"],
        "input_tokens_details": input_details,
        "output_tokens": numbers["completion"],
        "output_tokens_details": {"reasoning_tokens": numbers["reasoning"]},
        "total_tokens": numbers["prompt"] + numbers["completion"],
    }


def response_object(
    *,
    response_id: str,
    created_at: int,
    model: str,
    status: str,
    output: list,
    usage: dict | None,
    request: Mapping[str, Any] | None = None,
    error: dict | None = None,
    incomplete_details: dict | None = None,
) -> dict:
    """A Response resource that echoes the caller's request settings."""
    request = request if isinstance(request, Mapping) else {}
    reasoning = as_mapping(request.get("reasoning"))
    text = as_mapping(request.get("text"))
    return {
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "status": status,
        "error": error,
        "incomplete_details": incomplete_details,
        "instructions": request.get("instructions"),
        "max_output_tokens": request.get("max_output_tokens"),
        "model": model,
        "output": output,
        "parallel_tool_calls": request.get("parallel_tool_calls", True),
        "previous_response_id": None,
        "reasoning": {"effort": reasoning.get("effort"), "summary": reasoning.get("summary")},
        "store": False,
        "temperature": request.get("temperature"),
        "text": {"format": text.get("format") or {"type": "text"}},
        "tool_choice": request.get("tool_choice") or "auto",
        "tools": request.get("tools") or [],
        "top_p": request.get("top_p"),
        "truncation": "disabled",
        "usage": usage,
        "metadata": request.get("metadata") or {},
    }


# ---------------------------------------------------------------------------
# Streams: Responses SSE -> pivot items.


def responses_sse_items(chunks: Iterable[Any]) -> Iterator[ChatItem]:
    state: dict[str, Any] = {
        "id": new_id("chatcmpl"),
        "model": "",
        "created": unix_time(),
        "started": False,
    }
    tools: dict[str, dict] = {}

    def chunk(
        delta: dict | None = None, finish: str | None = None, usage: dict | None = None
    ) -> list[dict]:
        emitted = []
        if not state["started"]:
            state["started"] = True
            emitted.append(
                chat_chunk(
                    state["id"],
                    state["model"],
                    state["created"],
                    {"role": "assistant", "content": ""},
                )
            )
        if delta is not None or finish is not None:
            emitted.append(
                chat_chunk(state["id"], state["model"], state["created"], delta, finish, usage)
            )
        return emitted

    def register(item: Mapping[str, Any]) -> list[dict]:
        key = str(item.get("id") or item.get("call_id") or len(tools))
        if key in tools:
            return []
        arguments = item.get("arguments") if isinstance(item.get("arguments"), str) else ""
        tools[key] = {"index": len(tools), "streamed": bool(arguments)}
        return chunk(
            {
                "tool_calls": [
                    {
                        "index": tools[key]["index"],
                        "id": str(item.get("call_id") or item.get("id") or new_id("call")),
                        "type": "function",
                        "function": {"name": str(item.get("name") or ""), "arguments": arguments},
                    }
                ]
            }
        )

    for event in iter_events(chunks):
        if isinstance(event, StreamFailure):
            yield event
            return
        comment = comment_item(event)
        if comment is not None:
            yield comment
            continue
        if not event.data or event.is_done:
            continue
        data = event_json(event)
        if data is None:
            yield StreamFailure("The upstream stream sent an unreadable event.", interrupted=True)
            return
        kind = data.get("type") or event.event
        response = as_mapping(data.get("response"))
        if kind in {"response.created", "response.in_progress", "response.queued"}:
            if response.get("id"):
                state["id"] = _chat_id(response["id"])
            state["model"] = response.get("model") or state["model"]
            yield from chunk()
        elif kind == "response.output_item.added":
            item = as_mapping(data.get("item"))
            if item.get("type") == "function_call":
                yield from register(item)
        elif kind == "response.output_text.delta" and data.get("delta"):
            yield from chunk({"content": data["delta"]})
        elif kind == "response.refusal.delta" and data.get("delta"):
            yield from chunk({"refusal": data["delta"]})
        elif kind in {
            "response.reasoning_text.delta",
            "response.reasoning_summary_text.delta",
        } and data.get("delta"):
            yield from chunk({"reasoning_content": data["delta"]})
        elif kind == "response.reasoning_summary_part.added" and data.get("summary_index", 0):
            yield from chunk({"reasoning_content": "\n\n"})
        elif kind == "response.function_call_arguments.delta":
            tool = tools.get(str(data.get("item_id")))
            if tool is not None and data.get("delta"):
                tool["streamed"] = True
                yield from chunk(
                    {
                        "tool_calls": [
                            {"index": tool["index"], "function": {"arguments": data["delta"]}}
                        ]
                    }
                )
        elif kind in {"response.function_call_arguments.done", "response.output_item.done"}:
            item = data.get("item") if isinstance(data.get("item"), Mapping) else data
            if kind == "response.output_item.done" and item.get("type") != "function_call":
                continue
            key = str(item.get("id") or data.get("item_id") or "")
            if key not in tools:
                yield from register(item)
            elif not tools[key]["streamed"] and item.get("arguments"):
                tools[key]["streamed"] = True
                yield from chunk(
                    {
                        "tool_calls": [
                            {
                                "index": tools[key]["index"],
                                "function": {"arguments": item["arguments"]},
                            }
                        ]
                    }
                )
        elif kind in {"response.completed", "response.incomplete"}:
            usage = response.get("usage")
            if kind == "response.incomplete":
                reason = (response.get("incomplete_details") or {}).get("reason")
                finish = _INCOMPLETE_TO_FINISH.get(reason, "length")
            else:
                finish = "tool_calls" if tools else "stop"
            yield from chunk(
                finish=finish,
                usage=responses_usage_to_chat(usage) if isinstance(usage, Mapping) else None,
            )
            return
        elif kind == "response.failed":
            message, error_type, code = error_details({"error": response.get("error") or {}})
            yield StreamFailure(message, error_type or "api_error", code)
            return
        elif kind == "error":
            if isinstance(data.get("error"), Mapping):
                message, error_type, code = error_details(data)
            else:
                message = str(data.get("message") or "The upstream provider reported an error.")
                error_type, code = None, data.get("code")
            yield StreamFailure(message, error_type or "api_error", str(code) if code else None)
            return
    yield StreamFailure(interrupted=True)


# ---------------------------------------------------------------------------
# Streams: pivot items -> Responses SSE.


class _ResponsesWriter:
    def __init__(self, model: str | None, request: Mapping[str, Any] | None):
        self.model = model or ""
        self.request = request
        self.response_id = new_id("resp")
        self.created_at = unix_time()
        self.sequence = 0
        self.output: list[dict] = []
        self.current: dict | None = None
        self.tool_items: dict[int, dict] = {}
        self.pending_tools: dict[int, dict] = {}
        self.finish: str | None = None
        self.usage: Any = None

    def event(self, kind: str, **fields: Any) -> str:
        payload = {"type": kind, "sequence_number": self.sequence, **fields}
        self.sequence += 1
        return sse_event(kind, payload)

    def snapshot(self, status: str, **extra: Any) -> dict:
        return response_object(
            response_id=self.response_id,
            created_at=self.created_at,
            model=self.model,
            status=status,
            output=[dict(item) for item in self.output],
            usage=extra.pop("usage", None),
            request=self.request,
            **extra,
        )

    def start(self) -> list[str]:
        snapshot = self.snapshot("in_progress")
        return [
            self.event("response.created", response=snapshot),
            self.event("response.in_progress", response=snapshot),
        ]

    # -- output items -----------------------------------------------------

    def _open_item(self, item: dict, kind: str) -> list[str]:
        events = self.close_current()
        self.output.append(item)
        self.current = {"kind": kind, "item": item, "index": len(self.output) - 1, "part": None}
        events.append(
            self.event(
                "response.output_item.added", output_index=self.current["index"], item=dict(item)
            )
        )
        return events

    def _open_part(self, part: dict) -> list[str]:
        events = self._close_part()
        current = self.current
        if current is None:
            return events
        current["item"]["content"].append(part)
        current["part"] = len(current["item"]["content"]) - 1
        events.append(
            self.event(
                "response.content_part.added",
                item_id=current["item"]["id"],
                output_index=current["index"],
                content_index=current["part"],
                part={**part, "text": ""} if "text" in part else {**part, "refusal": ""},
            )
        )
        return events

    def _close_part(self) -> list[str]:
        current = self.current
        if current is None or current["part"] is None:
            return []
        part = current["item"]["content"][current["part"]]
        base = {
            "item_id": current["item"]["id"],
            "output_index": current["index"],
            "content_index": current["part"],
        }
        events = []
        if part["type"] == "output_text":
            events.append(
                self.event("response.output_text.done", **base, text=part["text"], logprobs=[])
            )
        elif part["type"] == "refusal":
            events.append(self.event("response.refusal.done", **base, refusal=part["refusal"]))
        elif part["type"] == "reasoning_text":
            events.append(self.event("response.reasoning_text.done", **base, text=part["text"]))
        events.append(self.event("response.content_part.done", **base, part=dict(part)))
        current["part"] = None
        return events

    def close_current(self, status: str = "completed") -> list[str]:
        current = self.current
        if current is None:
            return []
        events = self._close_part()
        item = current["item"]
        if current["kind"] == "function_call":
            events.append(
                self.event(
                    "response.function_call_arguments.done",
                    item_id=item["id"],
                    output_index=current["index"],
                    name=item["name"],
                    arguments=item["arguments"],
                )
            )
        item["status"] = status
        events.append(
            self.event("response.output_item.done", output_index=current["index"], item=dict(item))
        )
        self.current = None
        return events

    def _text(self, kind: str, text: str) -> list[str]:
        events: list[str] = []
        if self.current is None or self.current["kind"] != "message":
            events += self._open_item(_message_item(new_id("msg"), [], "in_progress"), "message")
        current = self.current
        if current is None:
            return events
        part_type = "output_text" if kind == "text" else "refusal"
        field = "text" if kind == "text" else "refusal"
        part_index = current["part"]
        if part_index is None or current["item"]["content"][part_index]["type"] != part_type:
            events += self._open_part(
                _text_part("") if kind == "text" else {"type": "refusal", "refusal": ""}
            )
        part = current["item"]["content"][current["part"]]
        part[field] += text
        base = {
            "item_id": current["item"]["id"],
            "output_index": current["index"],
            "content_index": current["part"],
        }
        if kind == "text":
            events.append(self.event("response.output_text.delta", **base, delta=text, logprobs=[]))
        else:
            events.append(self.event("response.refusal.delta", **base, delta=text))
        return events

    def _reasoning(self, text: str) -> list[str]:
        events: list[str] = []
        if self.current is None or self.current["kind"] != "reasoning":
            events += self._open_item(_reasoning_item(new_id("rs"), "", "in_progress"), "reasoning")
            events += self._open_part({"type": "reasoning_text", "text": ""})
        current = self.current
        if current is None:
            return events
        current["item"]["content"][current["part"]]["text"] += text
        events.append(
            self.event(
                "response.reasoning_text.delta",
                item_id=current["item"]["id"],
                output_index=current["index"],
                content_index=current["part"],
                delta=text,
            )
        )
        return events

    def _tool(self, fragment: Mapping[str, Any]) -> list[str]:
        index = fragment.get("index", 0)
        function = as_mapping(fragment.get("function"))
        arguments = function.get("arguments") if isinstance(function.get("arguments"), str) else ""
        if index in self.tool_items:
            record = self.tool_items[index]
            if not arguments:
                return []
            record["item"]["arguments"] += arguments
            return [
                self.event(
                    "response.function_call_arguments.delta",
                    item_id=record["item"]["id"],
                    output_index=record["index"],
                    delta=arguments,
                )
            ]
        pending = self.pending_tools.setdefault(index, {"id": None, "name": "", "arguments": ""})
        if fragment.get("id") and not pending["id"]:
            pending["id"] = fragment["id"]
        if isinstance(function.get("name"), str):
            pending["name"] += function["name"]
        pending["arguments"] += arguments
        return self._open_tool(index) if pending["name"] else []

    def _open_tool(self, index: int) -> list[str]:
        pending = self.pending_tools.pop(index)
        item = _function_call_item(
            new_id("fc"), str(pending["id"] or new_id("call")), pending["name"], "", "in_progress"
        )
        events = self._open_item(item, "function_call")
        output_index = len(self.output) - 1
        self.tool_items[index] = {"item": item, "index": output_index}
        if pending["arguments"]:
            item["arguments"] = pending["arguments"]
            events.append(
                self.event(
                    "response.function_call_arguments.delta",
                    item_id=item["id"],
                    output_index=output_index,
                    delta=pending["arguments"],
                )
            )
        return events

    def feed(self, chunk: Mapping[str, Any]) -> list[str]:
        events: list[str] = []
        if not self.model and chunk.get("model"):
            self.model = chunk["model"]
        if chunk.get("usage"):
            self.usage = chunk["usage"]
        for choice in chunk.get("choices") or []:
            if not isinstance(choice, Mapping) or choice.get("index", 0) != 0:
                continue
            delta = as_mapping(choice.get("delta"))
            thought = delta.get("reasoning_content")
            if not isinstance(thought, str):
                thought = delta.get("reasoning") if isinstance(delta.get("reasoning"), str) else ""
            if thought:
                events += self._reasoning(thought)
            if isinstance(delta.get("content"), str) and delta["content"]:
                events += self._text("text", delta["content"])
            if isinstance(delta.get("refusal"), str) and delta["refusal"]:
                events += self._text("refusal", delta["refusal"])
            for fragment in delta.get("tool_calls") or []:
                if isinstance(fragment, Mapping):
                    events += self._tool(fragment)
            if choice.get("finish_reason"):
                self.finish = choice["finish_reason"]
        return events

    def complete(self) -> list[str]:
        events: list[str] = []
        for index in sorted(self.pending_tools):
            if self.pending_tools[index]["name"] or self.pending_tools[index]["arguments"]:
                events += self._open_tool(index)
        events += self.close_current()
        status, incomplete = _status_for_finish(self.finish)
        snapshot = self.snapshot(
            status, usage=chat_usage_to_responses(self.usage), incomplete_details=incomplete
        )
        name = "response.incomplete" if status == "incomplete" else "response.completed"
        events.append(self.event(name, response=snapshot))
        return events

    def fail(self, failure: StreamFailure) -> list[str]:
        if failure.interrupted:
            events = self.close_current("incomplete")
            snapshot = self.snapshot(
                "incomplete",
                usage=chat_usage_to_responses(self.usage),
                incomplete_details={"reason": INTERRUPTED_REASON},
            )
            events.append(self.event("response.incomplete", response=snapshot))
            return events
        code = failure.code or failure.error_type or "server_error"
        events = [self.event("error", code=code, message=failure.message, param=None)]
        snapshot = self.snapshot("failed", error={"code": code, "message": failure.message})
        events.append(self.event("response.failed", response=snapshot))
        return events


def chat_items_to_responses_sse(
    items: Iterable[ChatItem],
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> Iterator[str]:
    writer = _ResponsesWriter(model, request)
    yield from writer.start()
    for item in items:
        if isinstance(item, StreamComment):
            yield sse_comment(item.text)
        elif isinstance(item, StreamFailure):
            yield from writer.fail(item)
            return
        else:
            yield from writer.feed(item)
    if writer.finish is None:
        yield from writer.fail(StreamFailure(interrupted=True))
        return
    yield from writer.complete()
