"""Anthropic Messages <-> OpenAI Chat Completions."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from services.protocol_translation.common import (
    ChatItem,
    StreamComment,
    StreamFailure,
    TranslationError,
    anthropic_error_type,
    as_mapping,
    chat_chunk,
    chat_usage,
    comment_item,
    dumps,
    event_json,
    first_chat_choice,
    iter_events,
    load_arguments,
    message_reasoning,
    new_id,
    parse_data_url,
    safe_tool_id,
    sse_comment,
    sse_event,
    text_of,
    unix_time,
    usage_numbers,
)

# Messages requires max_tokens; Chat Completions does not.
DEFAULT_MAX_TOKENS = 8192
MIN_THINKING_BUDGET = 1024
THINKING_BUDGETS = {
    "minimal": 1024,
    "low": 2048,
    "medium": 8192,
    "high": 16384,
    "xhigh": 24576,
    "max": 32768,
}
EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})
STOP_TO_FINISH = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "pause_turn": "stop",
    "max_tokens": "length",
    "model_context_window_exceeded": "length",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
}
FINISH_TO_STOP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "content_filter": "refusal",
}
JSON_OBJECT_INSTRUCTION = "Respond with a single valid JSON object and no other text."
# Server-tool history blocks carry results only Anthropic's runtime can replay.
_SERVER_HISTORY_BLOCKS = frozenset(
    {
        "server_tool_use",
        "web_search_tool_result",
        "web_fetch_tool_result",
        "code_execution_tool_result",
        "bash_code_execution_tool_result",
        "text_editor_code_execution_tool_result",
        "tool_search_tool_result",
        "mcp_tool_use",
        "mcp_tool_result",
        "fallback",
    }
)
_STATEFUL_FIELDS = {
    "container": "Anthropic code-execution containers",
    "mcp_servers": "Anthropic-hosted MCP connectors",
}


# ---------------------------------------------------------------------------
# Requests: Messages -> Chat Completions.


def messages_request_to_chat(payload: Mapping[str, Any]) -> dict:
    if not isinstance(payload, Mapping):
        raise TranslationError("The request body must be a JSON object")
    for field, feature in _STATEFUL_FIELDS.items():
        if payload.get(field):
            raise TranslationError(
                f"'{field}' uses {feature}, which this model cannot provide; "
                "choose a native Anthropic Messages model",
                param=field,
            )
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TranslationError("'messages' must be a non-empty array", param="messages")

    chat_messages: list[dict] = []
    system = _system_text(payload.get("system"))
    if system:
        chat_messages.append({"role": "system", "content": system})
    for index, message in enumerate(messages):
        chat_messages.extend(_turn_to_chat(message, index))

    chat: dict[str, Any] = {"model": payload.get("model"), "messages": chat_messages}
    if payload.get("max_tokens") is not None:
        chat["max_tokens"] = payload["max_tokens"]
    for key in ("temperature", "top_p"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    stop = payload.get("stop_sequences")
    if isinstance(stop, list) and stop:
        chat["stop"] = [item for item in stop if isinstance(item, str) and item]
    if payload.get("stream"):
        chat["stream"] = True
        chat["stream_options"] = {"include_usage": True}

    tools = _tools_to_chat(payload.get("tools"))
    choice = payload.get("tool_choice")
    if tools:
        chat["tools"] = tools
        tool_choice, parallel = _tool_choice_to_chat(choice)
        if tool_choice is not None:
            chat["tool_choice"] = tool_choice
        if parallel is False:
            chat["parallel_tool_calls"] = False
    elif isinstance(choice, Mapping) and choice.get("type") in {"any", "tool"}:
        raise TranslationError("tool_choice requires at least one tool", param="tool_choice")

    effort = _reasoning_effort(payload)
    if effort:
        chat["reasoning_effort"] = effort
    response_format = _output_format(payload)
    if response_format:
        chat["response_format"] = response_format
    return chat


def _system_text(system: Any) -> str:
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return "\n\n".join(
            block["text"]
            for block in system
            if isinstance(block, Mapping) and isinstance(block.get("text"), str) and block["text"]
        )
    return ""


def _turn_to_chat(message: Any, index: int) -> list[dict]:
    if not isinstance(message, Mapping):
        raise TranslationError(f"messages[{index}] must be an object", param="messages")
    role = message.get("role")
    content = message.get("content")
    if role not in {"user", "assistant", "system"}:
        raise TranslationError(
            f"messages[{index}].role must be user or assistant", param="messages"
        )
    if isinstance(content, str):
        return [{"role": role, "content": content}] if content or role == "user" else []
    if not isinstance(content, list):
        raise TranslationError(
            f"messages[{index}].content must be a string or an array", param="messages"
        )
    if role == "system":
        text = _system_text(content)
        return [{"role": "system", "content": text}] if text else []
    if role == "assistant":
        assistant = _assistant_to_chat(content, index)
        return [assistant] if assistant else []

    tool_messages: list[dict] = []
    parts: list[dict] = []
    tool_images: list[dict] = []
    for block in content:
        if not isinstance(block, Mapping):
            raise TranslationError(f"messages[{index}] contains an invalid block", param="messages")
        if block.get("type") == "tool_result":
            text, images = _tool_result_to_chat(block, index)
            tool_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": str(block.get("tool_use_id") or ""),
                    "content": text,
                }
            )
            tool_images.extend(images)
        else:
            parts.extend(_user_block_to_parts(block, index))
    if tool_images:
        # Chat tool messages carry text only; images follow in a user turn.
        parts = [
            {"type": "text", "text": "Images returned by the tool calls above:"},
            *tool_images,
            *parts,
        ]
    result = tool_messages
    if parts:
        result.append({"role": "user", "content": _collapse_parts(parts)})
    return result


def _collapse_parts(parts: list[dict]) -> Any:
    if len(parts) == 1 and parts[0].get("type") == "text":
        return parts[0]["text"]
    return parts


def _image_to_part(source: Any, index: int) -> dict:
    if not isinstance(source, Mapping):
        raise TranslationError(f"messages[{index}] has an image without a source", param="messages")
    if source.get("type") == "base64":
        media_type = source.get("media_type") or "image/png"
        return {
            "type": "image_url",
            "image_url": {"url": f"data:{media_type};base64,{source.get('data', '')}"},
        }
    if source.get("type") == "url" and isinstance(source.get("url"), str):
        return {"type": "image_url", "image_url": {"url": source["url"]}}
    raise TranslationError(
        "Image file_id sources need Anthropic's Files API; send base64 or URL images",
        param="messages",
    )


def _user_block_to_parts(block: Mapping[str, Any], index: int) -> list[dict]:
    kind = block.get("type")
    if kind == "text":
        text = block.get("text")
        return [{"type": "text", "text": text}] if isinstance(text, str) and text else []
    if kind == "image":
        return [_image_to_part(block.get("source"), index)]
    if kind == "document":
        return _document_to_parts(block, index)
    if kind == "search_result":
        lines = [
            str(block.get("title") or ""),
            str(block.get("source") or ""),
            text_of(block.get("content")),
        ]
        return [{"type": "text", "text": "\n".join(line for line in lines if line)}]
    if kind in {"thinking", "redacted_thinking"} or kind in _SERVER_HISTORY_BLOCKS:
        return []
    raise TranslationError(
        f"Content block type '{kind}' cannot be translated for this model", param="messages"
    )


def _document_to_parts(block: Mapping[str, Any], index: int) -> list[dict]:
    source = block.get("source")
    if not isinstance(source, Mapping):
        raise TranslationError(
            f"messages[{index}] has a document without a source", param="messages"
        )
    kind = source.get("type")
    title = block.get("title") if isinstance(block.get("title"), str) else None
    if kind == "base64" and source.get("media_type") == "application/pdf":
        return [
            {
                "type": "file",
                "file": {
                    "filename": title or "document.pdf",
                    "file_data": f"data:application/pdf;base64,{source.get('data', '')}",
                },
            }
        ]
    if kind == "text":
        text = str(source.get("data") or "")
        return [{"type": "text", "text": f"{title}\n\n{text}" if title else text}] if text else []
    if kind == "content":
        inner = source.get("content")
        if isinstance(inner, str):
            return [{"type": "text", "text": inner}] if inner else []
        parts: list[dict] = []
        for item in inner if isinstance(inner, list) else []:
            if isinstance(item, Mapping):
                parts.extend(_user_block_to_parts(item, index))
        return parts
    raise TranslationError(
        "Only base64 PDF, text and content documents can be translated for this model",
        param="messages",
    )


def _tool_result_to_chat(block: Mapping[str, Any], index: int) -> tuple[str, list[dict]]:
    content = block.get("content")
    texts: list[str] = []
    images: list[dict] = []
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for item in content:
            if not isinstance(item, Mapping):
                continue
            kind = item.get("type")
            if kind == "image":
                images.append(_image_to_part(item.get("source"), index))
            elif kind in ("text", "document", "search_result"):
                texts.extend(
                    part["text"]
                    for part in _user_block_to_parts(item, index)
                    if part.get("type") == "text"
                )
            # tool_reference and browser_state blocks only mean something to
            # Anthropic's runtime; the text result is what a chat model needs.
    text = "\n".join(texts)
    if block.get("is_error"):
        text = f"Error: {text}" if text else "Error"
    return text, images


def _assistant_to_chat(content: list, index: int) -> dict | None:
    texts: list[str] = []
    reasoning: list[str] = []
    calls: list[dict] = []
    for block in content:
        if not isinstance(block, Mapping):
            raise TranslationError(f"messages[{index}] contains an invalid block", param="messages")
        kind = block.get("type")
        if kind == "text":
            texts.append(str(block.get("text") or ""))
        elif kind == "thinking":
            reasoning.append(str(block.get("thinking") or ""))
        elif kind == "tool_use":
            calls.append(
                {
                    "id": str(block.get("id") or new_id("toolu")),
                    "type": "function",
                    "function": {
                        "name": str(block.get("name") or ""),
                        "arguments": dumps(block.get("input") or {}),
                    },
                }
            )
        elif kind == "redacted_thinking" or kind in _SERVER_HISTORY_BLOCKS:
            continue
        else:
            raise TranslationError(
                f"Assistant content block type '{kind}' cannot be translated", param="messages"
            )
    text = "".join(texts)
    if not text and not calls:
        return None
    message: dict[str, Any] = {"role": "assistant", "content": text or None}
    if calls:
        message["tool_calls"] = calls
        # Thinking chat models (Kimi, DeepSeek) require their reasoning back on tool turns.
        if any(reasoning):
            message["reasoning_content"] = "".join(reasoning)
    return message


def _tools_to_chat(tools: Any) -> list[dict]:
    if not tools:
        return []
    if not isinstance(tools, list):
        raise TranslationError("'tools' must be an array", param="tools")
    converted = []
    for tool in tools:
        if not isinstance(tool, Mapping):
            raise TranslationError("Each tool must be an object", param="tools")
        kind = tool.get("type")
        if kind not in (None, "custom"):
            raise TranslationError(
                f"Anthropic server tool '{kind}' runs only on Anthropic's platform and is not "
                "available on this route; define a custom tool with an input_schema instead",
                param="tools",
            )
        function: dict[str, Any] = {
            "name": tool.get("name"),
            "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
        }
        if isinstance(tool.get("description"), str):
            function["description"] = tool["description"]
        if isinstance(tool.get("strict"), bool):
            function["strict"] = tool["strict"]
        converted.append({"type": "function", "function": function})
    return converted


def _tool_choice_to_chat(choice: Any) -> tuple[Any, bool | None]:
    if not isinstance(choice, Mapping):
        return None, None
    parallel = False if choice.get("disable_parallel_tool_use") else None
    kind = choice.get("type")
    if kind == "auto":
        return "auto", parallel
    if kind == "any":
        return "required", parallel
    if kind == "none":
        return "none", None
    if kind == "tool":
        return {"type": "function", "function": {"name": choice.get("name")}}, parallel
    raise TranslationError(f"tool_choice type '{kind}' is not supported", param="tool_choice")


def _reasoning_effort(payload: Mapping[str, Any]) -> str | None:
    config = payload.get("output_config")
    effort = config.get("effort") if isinstance(config, Mapping) else None
    if effort in EFFORTS and effort != "none":
        # Chat Completions has no "max"; the gateway maps xhigh to each provider's top tier.
        return "xhigh" if effort == "max" else str(effort)
    thinking = payload.get("thinking")
    if isinstance(thinking, Mapping) and thinking.get("type") == "enabled":
        budget = thinking.get("budget_tokens")
        if isinstance(budget, int) and not isinstance(budget, bool):
            if budget < 4096:
                return "low"
            return "medium" if budget < 16384 else "high"
    return None


def _output_format(payload: Mapping[str, Any]) -> dict | None:
    config = payload.get("output_config")
    candidates = [
        config.get("format") if isinstance(config, Mapping) else None,
        payload.get("output_format"),
    ]
    for fmt in candidates:
        if (
            isinstance(fmt, Mapping)
            and fmt.get("type") == "json_schema"
            and isinstance(fmt.get("schema"), Mapping)
        ):
            return {
                "type": "json_schema",
                "json_schema": {"name": "output", "schema": dict(fmt["schema"]), "strict": True},
            }
    return None


# ---------------------------------------------------------------------------
# Requests: Chat Completions -> Messages.


def chat_request_to_messages(payload: Mapping[str, Any]) -> dict:
    if not isinstance(payload, Mapping):
        raise TranslationError("The request body must be a JSON object")
    if payload.get("n") not in (None, 1):
        raise TranslationError("Anthropic Messages returns one choice; n must be 1", param="n")
    if payload.get("audio") or "audio" in (payload.get("modalities") or []):
        raise TranslationError("Audio output is not available for this model", param="modalities")
    if payload.get("functions") or payload.get("function_call"):
        raise TranslationError(
            "Legacy function calling is not supported for this model; use tools", param="functions"
        )
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TranslationError("'messages' must be a non-empty array", param="messages")

    system_parts: list[str] = []
    turns: list[dict] = []
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise TranslationError(f"messages[{index}] must be an object", param="messages")
        role = message.get("role")
        if role in {"system", "developer"}:
            text = text_of(message.get("content"))
            if text:
                system_parts.append(text)
        elif role == "user":
            _append_turn(turns, "user", _chat_user_blocks(message.get("content"), index))
        elif role == "assistant":
            _append_turn(turns, "assistant", _chat_assistant_blocks(message))
        elif role == "tool":
            _append_turn(
                turns,
                "user",
                [
                    {
                        "type": "tool_result",
                        "tool_use_id": safe_tool_id(message.get("tool_call_id")),
                        "content": _tool_message_content(message.get("content"), index),
                    }
                ],
            )
        else:
            raise TranslationError(
                f"messages[{index}].role '{role}' cannot be translated for this model",
                param="messages",
            )
    for turn in turns:
        if turn["role"] == "user":
            # Messages requires tool results before any other user content.
            turn["content"].sort(key=lambda block: block.get("type") != "tool_result")
    if not turns:
        raise TranslationError(
            "At least one user or assistant message is required", param="messages"
        )

    body: dict[str, Any] = {"model": payload.get("model"), "messages": turns}
    max_tokens = (
        payload.get("max_completion_tokens") or payload.get("max_tokens") or DEFAULT_MAX_TOKENS
    )
    body["max_tokens"] = max_tokens
    response_format = payload.get("response_format")
    if isinstance(response_format, Mapping) and response_format.get("type") == "json_object":
        system_parts.append(JSON_OBJECT_INSTRUCTION)
    if system_parts:
        body["system"] = "\n\n".join(system_parts)
    if isinstance(payload.get("temperature"), (int, float)) and not isinstance(
        payload["temperature"], bool
    ):
        # Messages accepts 0-1; Chat Completions accepts 0-2.
        body["temperature"] = min(max(float(payload["temperature"]), 0.0), 1.0)
    if payload.get("top_p") is not None:
        body["top_p"] = payload["top_p"]
    stop = payload.get("stop")
    if isinstance(stop, str) and stop:
        body["stop_sequences"] = [stop]
    elif isinstance(stop, list) and stop:
        body["stop_sequences"] = [item for item in stop if isinstance(item, str) and item]
    if payload.get("stream"):
        body["stream"] = True
    if isinstance(payload.get("user"), str) and payload["user"]:
        body["metadata"] = {"user_id": payload["user"]}

    tools, allowed = _chat_tools_to_messages(payload.get("tools"), payload.get("tool_choice"))
    if tools:
        body["tools"] = tools
        choice = _chat_tool_choice_to_messages(payload.get("tool_choice"), allowed)
        if payload.get("parallel_tool_calls") is False:
            choice = choice or {"type": "auto"}
            if choice.get("type") != "none":
                choice["disable_parallel_tool_use"] = True
        if choice:
            body["tool_choice"] = choice

    if isinstance(response_format, Mapping) and response_format.get("type") == "json_schema":
        schema = (response_format.get("json_schema") or {}).get("schema")
        if isinstance(schema, Mapping):
            body["output_config"] = {"format": {"type": "json_schema", "schema": dict(schema)}}
    _apply_thinking(body, payload)
    return body


def _append_turn(turns: list[dict], role: str, blocks: list[dict]) -> None:
    if not blocks:
        return
    if turns and turns[-1]["role"] == role:
        turns[-1]["content"].extend(blocks)
    else:
        turns.append({"role": role, "content": list(blocks)})


def _chat_part_to_block(part: Any, index: int) -> dict | None:
    if isinstance(part, str):
        return {"type": "text", "text": part} if part else None
    if not isinstance(part, Mapping):
        raise TranslationError(
            f"messages[{index}] contains an invalid content part", param="messages"
        )
    kind = part.get("type")
    if kind in {"text", "input_text", "output_text"}:
        text = part.get("text")
        return {"type": "text", "text": text} if isinstance(text, str) and text else None
    if kind == "refusal":
        text = part.get("refusal")
        return {"type": "text", "text": text} if isinstance(text, str) and text else None
    if kind == "image_url":
        image = part.get("image_url")
        url = image.get("url") if isinstance(image, Mapping) else image
        if not isinstance(url, str) or not url:
            raise TranslationError(
                f"messages[{index}] has an image without a URL", param="messages"
            )
        parsed = parse_data_url(url)
        if parsed:
            return {
                "type": "image",
                "source": {"type": "base64", "media_type": parsed[0], "data": parsed[1]},
            }
        return {"type": "image", "source": {"type": "url", "url": url}}
    if kind == "file":
        file = as_mapping(part.get("file"))
        parsed = parse_data_url(str(file.get("file_data") or ""))
        if parsed and parsed[0] == "application/pdf":
            block: dict[str, Any] = {
                "type": "document",
                "source": {"type": "base64", "media_type": "application/pdf", "data": parsed[1]},
            }
            if isinstance(file.get("filename"), str) and file["filename"]:
                block["title"] = file["filename"]
            return block
        raise TranslationError(
            "Only inline base64 PDF files can be translated for this model", param="messages"
        )
    raise TranslationError(
        f"Content part type '{kind}' cannot be translated for this model", param="messages"
    )


def _chat_user_blocks(content: Any, index: int) -> list[dict]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    if not isinstance(content, list):
        return []
    return [block for block in (_chat_part_to_block(part, index) for part in content) if block]


def _chat_assistant_blocks(message: Mapping[str, Any]) -> list[dict]:
    blocks: list[dict] = []
    content = message.get("content")
    text = (
        content
        if isinstance(content, str)
        else text_of(
            [
                part
                for part in content or []
                if isinstance(part, Mapping) and part.get("type") in {"text", "output_text"}
            ]
        )
    )
    if text:
        blocks.append({"type": "text", "text": text})
    for call in message.get("tool_calls") or []:
        if not isinstance(call, Mapping):
            continue
        function = as_mapping(call.get("function"))
        blocks.append(
            {
                "type": "tool_use",
                "id": safe_tool_id(call.get("id")),
                "name": function.get("name") or "",
                "input": load_arguments(function.get("arguments")),
            }
        )
    return blocks


def _tool_message_content(content: Any, index: int) -> Any:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        blocks = [
            block for block in (_chat_part_to_block(part, index) for part in content) if block
        ]
        return [block for block in blocks if block["type"] in {"text", "image"}]
    return ""


def _chat_tools_to_messages(tools: Any, tool_choice: Any) -> tuple[list[dict], set[Any] | None]:
    if not tools:
        return [], None
    if not isinstance(tools, list):
        raise TranslationError("'tools' must be an array", param="tools")
    allowed = None
    if isinstance(tool_choice, Mapping) and tool_choice.get("type") == "allowed_tools":
        spec = tool_choice.get("allowed_tools") or {}
        allowed = {
            (entry.get("function") or {}).get("name") or entry.get("name")
            for entry in spec.get("tools") or []
            if isinstance(entry, Mapping)
        }
    converted = []
    for tool in tools:
        if not isinstance(tool, Mapping) or tool.get("type") != "function":
            kind = tool.get("type") if isinstance(tool, Mapping) else None
            raise TranslationError(
                f"Tool type '{kind}' cannot be translated for this model; use function tools",
                param="tools",
            )
        function = as_mapping(tool.get("function"))
        name = function.get("name")
        if allowed is not None and name not in allowed:
            continue
        schema = dict(function.get("parameters") or {"type": "object", "properties": {}})
        schema.setdefault("type", "object")
        entry: dict[str, Any] = {"name": name, "input_schema": schema}
        if isinstance(function.get("description"), str):
            entry["description"] = function["description"]
        if isinstance(function.get("strict"), bool):
            entry["strict"] = function["strict"]
        converted.append(entry)
    return converted, allowed


def _chat_tool_choice_to_messages(choice: Any, allowed: set[Any] | None) -> dict | None:
    if choice in (None, "auto"):
        return None if choice is None else {"type": "auto"}
    if choice == "none":
        return {"type": "none"}
    if choice == "required":
        return {"type": "any"}
    if isinstance(choice, Mapping):
        if choice.get("type") == "function":
            name = (choice.get("function") or {}).get("name")
            return {"type": "tool", "name": name}
        if choice.get("type") == "allowed_tools":
            mode = (choice.get("allowed_tools") or {}).get("mode")
            return {"type": "any"} if mode == "required" else {"type": "auto"}
    raise TranslationError("Unsupported tool_choice value", param="tool_choice")


def _apply_thinking(body: dict, payload: Mapping[str, Any]) -> None:
    thinking = payload.get("thinking")
    if isinstance(thinking, Mapping) and thinking.get("type") in {
        "enabled",
        "disabled",
        "adaptive",
    }:
        body["thinking"] = dict(thinking)
    else:
        effort = payload.get("reasoning_effort")
        if effort is None and isinstance(payload.get("reasoning"), Mapping):
            effort = payload["reasoning"].get("effort")
        if effort not in EFFORTS:
            return
        if effort == "none":
            body["thinking"] = {"type": "disabled"}
            return
        body["thinking"] = {"type": "enabled", "budget_tokens": THINKING_BUDGETS[effort]}
    if body["thinking"].get("type") == "disabled":
        return
    budget = body["thinking"].get("budget_tokens")
    max_tokens = body["max_tokens"]
    if (
        isinstance(budget, int)
        and not isinstance(budget, bool)
        and isinstance(max_tokens, int)
        and budget >= max_tokens
    ):
        # budget_tokens must stay below max_tokens; shrink it or drop thinking.
        if max_tokens - 1 < MIN_THINKING_BUDGET:
            body.pop("thinking")
            return
        body["thinking"]["budget_tokens"] = max_tokens - 1
    # Thinking accepts neither a modified temperature nor top_p below 0.95.
    body.pop("temperature", None)
    top_p = body.get("top_p")
    if isinstance(top_p, (int, float)) and top_p < 0.95:
        body.pop("top_p")


# ---------------------------------------------------------------------------
# Responses (non-streaming).


def messages_response_to_chat(
    payload: Mapping[str, Any], *, model: str | None = None, **_: Any
) -> dict:
    texts: list[str] = []
    reasoning: list[str] = []
    calls: list[dict] = []
    for block in payload.get("content") or []:
        if not isinstance(block, Mapping):
            continue
        kind = block.get("type")
        if kind == "text":
            texts.append(str(block.get("text") or ""))
        elif kind == "thinking":
            reasoning.append(str(block.get("thinking") or ""))
        elif kind == "tool_use":
            calls.append(
                {
                    "id": str(block.get("id") or new_id("toolu")),
                    "type": "function",
                    "function": {
                        "name": str(block.get("name") or ""),
                        "arguments": dumps(block.get("input") or {}),
                    },
                }
            )
    text = "".join(texts)
    message: dict[str, Any] = {"role": "assistant", "content": text if text or not calls else None}
    if calls:
        message["tool_calls"] = calls
    if any(reasoning):
        message["reasoning_content"] = "".join(reasoning)
    stop_reason = payload.get("stop_reason")
    completion = {
        "id": _chat_id(payload.get("id")),
        "object": "chat.completion",
        "created": unix_time(),
        "model": model or payload.get("model") or "",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": STOP_TO_FINISH.get(stop_reason, "tool_calls" if calls else "stop"),
                "logprobs": None,
            }
        ],
    }
    usage = payload.get("usage")
    if isinstance(usage, Mapping):
        completion["usage"] = _anthropic_usage_to_chat(usage)
    return completion


def chat_response_to_messages(
    payload: Mapping[str, Any], *, model: str | None = None, **_: Any
) -> dict:
    message, finish = first_chat_choice(payload)
    content: list[dict] = []
    reasoning = message_reasoning(message)
    if reasoning:
        # Translated thinking has no Anthropic signature; native passthrough strips it.
        content.append({"type": "thinking", "thinking": reasoning, "signature": ""})
    text = (
        message.get("content")
        if isinstance(message.get("content"), str)
        else text_of(message.get("content"))
    )
    if text:
        content.append({"type": "text", "text": text})
    if isinstance(message.get("refusal"), str) and message["refusal"]:
        content.append({"type": "text", "text": message["refusal"]})
        finish = finish or "content_filter"
    for call in message.get("tool_calls") or []:
        if not isinstance(call, Mapping):
            continue
        function = as_mapping(call.get("function"))
        content.append(
            {
                "type": "tool_use",
                "id": safe_tool_id(call.get("id")),
                "name": function.get("name") or "",
                "input": load_arguments(function.get("arguments")),
            }
        )
    return {
        "id": _message_id(payload.get("id")),
        "type": "message",
        "role": "assistant",
        "model": model or payload.get("model") or "",
        "content": content,
        "stop_reason": FINISH_TO_STOP.get(finish or "stop", "end_turn"),
        "stop_sequence": None,
        "usage": _chat_usage_to_anthropic(payload.get("usage")),
    }


def _chat_id(value: Any) -> str:
    return f"chatcmpl-{value}" if isinstance(value, str) and value else new_id("chatcmpl")


def _message_id(value: Any) -> str:
    if isinstance(value, str) and value.startswith("msg_"):
        return value
    return (
        f"msg_{safe_tool_id(value, 'msg')}" if isinstance(value, str) and value else new_id("msg")
    )


def _anthropic_usage_to_chat(usage: Mapping[str, Any]) -> dict:
    def count(key: str) -> int:
        value = usage.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0

    cached = count("cache_read_input_tokens")
    cache_write = count("cache_creation_input_tokens")
    # Anthropic's input_tokens excludes cache reads and writes.
    prompt = count("input_tokens") + cached + cache_write
    return chat_usage(prompt, count("output_tokens"), cached=cached, cache_write=cache_write)


def _chat_usage_to_anthropic(usage: Any) -> dict:
    numbers = usage_numbers(usage)
    return {
        "input_tokens": max(0, numbers["prompt"] - numbers["cached"] - numbers["cache_write"]),
        "output_tokens": numbers["completion"],
        "cache_creation_input_tokens": numbers["cache_write"],
        "cache_read_input_tokens": numbers["cached"],
    }


# ---------------------------------------------------------------------------
# Streams: Messages SSE -> pivot items.


def messages_sse_items(chunks: Iterable[Any]) -> Iterator[ChatItem]:
    state: dict[str, Any] = {
        "id": new_id("chatcmpl"),
        "model": "",
        "created": unix_time(),
        "started": False,
        "usage": {},
        "stop_reason": None,
    }
    blocks: dict[Any, dict] = {}
    tool_count = 0

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

    for event in iter_events(chunks):
        if isinstance(event, StreamFailure):
            yield event
            return
        comment = comment_item(event)
        if comment is not None:
            yield comment
            continue
        if not event.data:
            continue
        data = event_json(event)
        if data is None:
            yield StreamFailure("The upstream stream sent an unreadable event.", interrupted=True)
            return
        kind = data.get("type") or event.event
        if kind == "message_start":
            message = as_mapping(data.get("message"))
            if message.get("id"):
                state["id"] = _chat_id(message["id"])
            state["model"] = message.get("model") or state["model"]
            if isinstance(message.get("usage"), Mapping):
                state["usage"].update(message["usage"])
            yield from chunk()
        elif kind == "content_block_start":
            block = as_mapping(data.get("content_block"))
            index = data.get("index")
            block_type = block.get("type")
            if block_type == "tool_use":
                blocks[index] = {
                    "kind": "tool",
                    "tool": tool_count,
                    "streamed": False,
                    "input": block.get("input"),
                }
                tool_count += 1
                yield from chunk(
                    {
                        "tool_calls": [
                            {
                                "index": blocks[index]["tool"],
                                "id": str(block.get("id") or new_id("toolu")),
                                "type": "function",
                                "function": {"name": str(block.get("name") or ""), "arguments": ""},
                            }
                        ]
                    }
                )
            elif block_type == "text":
                blocks[index] = {"kind": "text"}
                if block.get("text"):
                    yield from chunk({"content": block["text"]})
            elif block_type == "thinking":
                blocks[index] = {"kind": "thinking"}
                if block.get("thinking"):
                    yield from chunk({"reasoning_content": block["thinking"]})
            else:
                blocks[index] = {"kind": "other"}
        elif kind == "content_block_delta":
            block = blocks.get(data.get("index"), {})
            delta = as_mapping(data.get("delta"))
            delta_type = delta.get("type")
            if delta_type == "text_delta" and delta.get("text"):
                yield from chunk({"content": delta["text"]})
            elif delta_type == "thinking_delta" and delta.get("thinking"):
                yield from chunk({"reasoning_content": delta["thinking"]})
            elif delta_type == "input_json_delta" and block.get("kind") == "tool":
                partial = delta.get("partial_json") or ""
                if partial:
                    block["streamed"] = True
                    yield from chunk(
                        {
                            "tool_calls": [
                                {"index": block["tool"], "function": {"arguments": partial}}
                            ]
                        }
                    )
        elif kind == "content_block_stop":
            block = blocks.get(data.get("index"), {})
            if block.get("kind") == "tool" and not block["streamed"] and block.get("input"):
                # Some compatible servers send the whole input at block start.
                yield from chunk(
                    {
                        "tool_calls": [
                            {
                                "index": block["tool"],
                                "function": {"arguments": dumps(block["input"])},
                            }
                        ]
                    }
                )
        elif kind == "message_delta":
            delta = as_mapping(data.get("delta"))
            if delta.get("stop_reason"):
                state["stop_reason"] = delta["stop_reason"]
            if isinstance(data.get("usage"), Mapping):
                state["usage"].update({k: v for k, v in data["usage"].items() if v is not None})
        elif kind == "message_stop":
            finish = STOP_TO_FINISH.get(
                state["stop_reason"], "tool_calls" if tool_count else "stop"
            )
            yield from chunk(finish=finish, usage=_anthropic_usage_to_chat(state["usage"]))
            return
        elif kind == "ping":
            yield StreamComment("ping")
        elif kind == "error":
            error = as_mapping(data.get("error"))
            yield StreamFailure(
                str(error.get("message") or "The upstream provider reported an error."),
                str(error.get("type") or "api_error"),
            )
            return
    yield StreamFailure(interrupted=True)


# ---------------------------------------------------------------------------
# Streams: pivot items -> Messages SSE.


class _MessagesWriter:
    def __init__(self, model: str | None):
        self.model = model
        self.message_id = new_id("msg")
        self.started = False
        self.index = -1
        self.open_kind: str | None = None
        self.tool_blocks: dict[int, int] = {}
        self.pending_tools: dict[int, dict] = {}
        self.finish: str | None = None
        self.usage: Any = None

    def _start(self, chunk: Mapping[str, Any]) -> list[str]:
        if self.started:
            return []
        self.started = True
        return [
            sse_event(
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": self.message_id,
                        "type": "message",
                        "role": "assistant",
                        "model": self.model or chunk.get("model") or "",
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 0, "output_tokens": 0},
                    },
                },
            )
        ]

    def _close(self) -> list[str]:
        if self.open_kind is None:
            return []
        self.open_kind = None
        return [
            sse_event("content_block_stop", {"type": "content_block_stop", "index": self.index})
        ]

    def _open(self, kind: str, block: dict) -> list[str]:
        events = self._close()
        self.index += 1
        self.open_kind = kind
        events.append(
            sse_event(
                "content_block_start",
                {"type": "content_block_start", "index": self.index, "content_block": block},
            )
        )
        return events

    def _delta(self, index: int, delta: dict) -> str:
        return sse_event(
            "content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}
        )

    def feed(self, chunk: Mapping[str, Any]) -> list[str]:
        events = self._start(chunk)
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
                if self.open_kind != "thinking":
                    events += self._open(
                        "thinking", {"type": "thinking", "thinking": "", "signature": ""}
                    )
                events.append(
                    self._delta(self.index, {"type": "thinking_delta", "thinking": thought})
                )
            for key in ("content", "refusal"):
                text = delta.get(key)
                if isinstance(text, str) and text:
                    if self.open_kind != "text":
                        events += self._open("text", {"type": "text", "text": ""})
                    events.append(self._delta(self.index, {"type": "text_delta", "text": text}))
            for fragment in delta.get("tool_calls") or []:
                if isinstance(fragment, Mapping):
                    events += self._tool_fragment(fragment)
            if choice.get("finish_reason"):
                self.finish = choice["finish_reason"]
        return events

    def _tool_fragment(self, fragment: Mapping[str, Any]) -> list[str]:
        index = fragment.get("index", 0)
        function = as_mapping(fragment.get("function"))
        arguments = function.get("arguments") if isinstance(function.get("arguments"), str) else ""
        if index in self.tool_blocks:
            if not arguments:
                return []
            return [
                self._delta(
                    self.tool_blocks[index], {"type": "input_json_delta", "partial_json": arguments}
                )
            ]
        pending = self.pending_tools.setdefault(index, {"id": None, "name": "", "arguments": ""})
        if fragment.get("id") and not pending["id"]:
            pending["id"] = fragment["id"]
        if isinstance(function.get("name"), str):
            pending["name"] += function["name"]
        pending["arguments"] += arguments
        # A block cannot be renamed after it starts, so wait until the name arrives.
        return self._open_tool(index) if pending["name"] else []

    def _open_tool(self, index: int) -> list[str]:
        pending = self.pending_tools.pop(index)
        events = self._open(
            "tool",
            {
                "type": "tool_use",
                "id": safe_tool_id(pending["id"]),
                "name": pending["name"],
                "input": {},
            },
        )
        self.tool_blocks[index] = self.index
        if pending["arguments"]:
            events.append(
                self._delta(
                    self.index, {"type": "input_json_delta", "partial_json": pending["arguments"]}
                )
            )
        return events

    def complete(self) -> list[str]:
        events = self._start({})
        for index in sorted(self.pending_tools):
            if self.pending_tools[index]["name"] or self.pending_tools[index]["arguments"]:
                events += self._open_tool(index)
        events += self._close()
        events.append(
            sse_event(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {
                        "stop_reason": FINISH_TO_STOP.get(self.finish or "stop", "end_turn"),
                        "stop_sequence": None,
                    },
                    "usage": _chat_usage_to_anthropic(self.usage),
                },
            )
        )
        events.append(sse_event("message_stop", {"type": "message_stop"}))
        return events


def messages_failure_event(failure: StreamFailure) -> str:
    error_type = (
        "api_error" if failure.interrupted else anthropic_error_type(502, failure.error_type)
    )
    return sse_event(
        "error", {"type": "error", "error": {"type": error_type, "message": failure.message}}
    )


def chat_items_to_messages_sse(
    items: Iterable[ChatItem],
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> Iterator[str]:
    del request
    writer = _MessagesWriter(model)
    for item in items:
        if isinstance(item, StreamComment):
            yield sse_comment(item.text)
        elif isinstance(item, StreamFailure):
            yield messages_failure_event(item)
            return
        else:
            yield from writer.feed(item)
    if writer.finish is None:
        yield messages_failure_event(StreamFailure(interrupted=True))
        return
    yield from writer.complete()


def strip_unsigned_thinking(payload: Mapping[str, Any]) -> dict:
    """Drop translated thinking blocks, which have no signature, before native calls."""
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return dict(payload)
    cleaned = []
    for message in messages:
        content = message.get("content") if isinstance(message, Mapping) else None
        if isinstance(content, list) and message.get("role") == "assistant":
            kept = [
                block
                for block in content
                if not (
                    isinstance(block, Mapping)
                    and block.get("type") == "thinking"
                    and not block.get("signature")
                )
            ]
            if not kept:
                # Messages merges the neighbouring turns once this one is gone.
                continue
            if kept != content:
                message = {**message, "content": kept}
        cleaned.append(message)
    return {**payload, "messages": cleaned}
