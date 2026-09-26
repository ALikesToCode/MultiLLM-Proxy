"""Bounded function-tool contracts for free pools.

Only caller-defined function tools are accepted: no server-side, provider or MCP tools,
which can run paid work on the provider's side. Definitions are size-bounded and their
parameter schemas are checked like response_format schemas, without remote references.
"""

import json
import re

from services.free_json_contract import MAX_SCHEMA_BYTES, JsonOutputError, schema_validator

MAX_TOOLS = 128
MAX_TOOLS_BYTES = MAX_SCHEMA_BYTES
MAX_DESCRIPTION_LENGTH = 8192
MAX_TOOL_CALLS = 128
MAX_ARGUMENT_BYTES = 64 * 1024
TOOL_CHOICES = frozenset({"none", "auto", "required"})
TOOL_FIELDS = frozenset({"tools", "tool_choice", "parallel_tool_calls"})
_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CALL_ID = re.compile(r"[\x21-\x7e]{1,256}")


def _function(tool) -> dict:
    if not isinstance(tool, dict) or set(tool) != {"type", "function"} or tool["type"] != "function":
        raise ValueError("Only function tools are supported")
    function = tool["function"]
    if not isinstance(function, dict) or set(function) - {"name", "description", "parameters", "strict"}:
        raise ValueError("A function accepts name, description, parameters and strict")
    if not isinstance(function.get("name"), str) or not _NAME.fullmatch(function["name"]):
        raise ValueError("Function names use 1-64 letters, digits, underscores or hyphens")
    description = function.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_LENGTH:
        raise ValueError(f"Function descriptions are strings of at most {MAX_DESCRIPTION_LENGTH} characters")
    if "strict" in function and not isinstance(function["strict"], bool):
        raise ValueError("strict must be a boolean")
    if "parameters" in function:
        parameters = function["parameters"]
        if not isinstance(parameters, dict) or parameters.get("type", "object") != "object":
            raise ValueError("Function parameters must be an object schema")
        schema_validator(parameters)
    return function


def validate_tools(payload: dict) -> frozenset[str] | None:
    """The declared function names, or None when the request defines no tools."""
    if "tools" not in payload:
        if TOOL_FIELDS & payload.keys():
            raise ValueError("tool_choice and parallel_tool_calls require tools")
        return None
    tools = payload["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= MAX_TOOLS:
        raise ValueError(f"tools must be a list of 1 to {MAX_TOOLS} function tools")
    if len(json.dumps(tools, allow_nan=False).encode("utf-8")) > MAX_TOOLS_BYTES:
        raise ValueError("Tool definitions exceed 64 KiB")
    names = [_function(tool)["name"] for tool in tools]
    if len(set(names)) != len(names):
        raise ValueError("Function names must be unique")
    if "tool_choice" in payload:
        choice = payload["tool_choice"]
        named = (
            isinstance(choice, dict)
            and set(choice) == {"type", "function"}
            and choice["type"] == "function"
            and isinstance(choice["function"], dict)
            and set(choice["function"]) == {"name"}
            and choice["function"]["name"] in names
        )
        if not named and not (isinstance(choice, str) and choice in TOOL_CHOICES):
            raise ValueError("tool_choice must be none, auto, required or a declared function")
    if "parallel_tool_calls" in payload and not isinstance(payload["parallel_tool_calls"], bool):
        raise ValueError("parallel_tool_calls must be a boolean")
    return frozenset(names)


def _text_content(content, *, allow_empty: bool) -> bool:
    if isinstance(content, str):
        return allow_empty or bool(content.strip())
    return (
        isinstance(content, list)
        and bool(content)
        and all(
            isinstance(part, dict)
            and set(part) == {"type", "text"}
            and part["type"] == "text"
            and isinstance(part["text"], str)
            for part in content
        )
    )


def _call(call, *, request: bool) -> dict:
    # Requests are exact; provider replies may add fields such as index.
    if not isinstance(call, dict) or (request and set(call) - {"id", "type", "function"}):
        raise ValueError("Invalid tool call")
    if not isinstance(call.get("id"), str) or not _CALL_ID.fullmatch(call["id"]):
        raise ValueError("A tool call needs an id")
    if call.get("type", "function") != "function":
        raise ValueError("Only function tool calls are supported")
    function = call.get("function")
    if (
        not isinstance(function, dict)
        or (request and set(function) - {"name", "arguments"})
        or not isinstance(function.get("name"), str)
        or not _NAME.fullmatch(function["name"])
        or not isinstance(function.get("arguments"), str)
        or len(function["arguments"].encode("utf-8")) > MAX_ARGUMENT_BYTES
    ):
        raise ValueError("A tool call needs a function name and string arguments")
    return function


def is_tool_message(message: dict) -> bool:
    return message.get("role") == "tool" or (
        message.get("role") == "assistant" and "tool_calls" in message
    )


def validate_tool_message(message: dict) -> None:
    """An assistant message with tool calls, or a tool result replying to one."""
    if message.get("role") == "tool":
        if set(message) - {"role", "content", "tool_call_id", "name"}:
            raise ValueError("A tool message accepts content, tool_call_id and name")
        if not isinstance(message.get("tool_call_id"), str) or not _CALL_ID.fullmatch(message["tool_call_id"]):
            raise ValueError("A tool message needs the tool_call_id it answers")
        if not _text_content(message.get("content"), allow_empty=True):
            raise ValueError("Tool results are text")
        return
    if set(message) - {"role", "content", "tool_calls", "name"}:
        raise ValueError("Unsupported assistant message fields")
    content = message.get("content")
    if content is not None and not _text_content(content, allow_empty=True):
        raise ValueError("Assistant content must be text or null")
    calls = message["tool_calls"]
    if not isinstance(calls, list) or not 1 <= len(calls) <= MAX_TOOL_CALLS:
        raise ValueError(f"tool_calls must list 1 to {MAX_TOOL_CALLS} calls")
    for call in calls:
        _call(call, request=True)


def _json_object(text: str) -> bool:
    def unique(pairs):
        keys = [key for key, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate JSON property")
        return dict(pairs)

    def finite(value):
        raise ValueError(f"Non-finite JSON number {value}")

    try:
        return isinstance(json.loads(text, object_pairs_hook=unique, parse_constant=finite), dict)
    except (ValueError, RecursionError):
        return False


def check_tool_calls(choices: list, names: frozenset[str], tool_choice) -> None:
    """Tool calls must name declared functions with JSON-object arguments, as requested."""
    required = tool_choice == "required" or isinstance(tool_choice, dict)
    forced = tool_choice["function"]["name"] if isinstance(tool_choice, dict) else None
    called = False
    for choice in choices:
        calls = choice["message"].get("tool_calls")
        if calls is None:
            continue
        if not isinstance(calls, list) or len(calls) > MAX_TOOL_CALLS or tool_choice == "none":
            raise JsonOutputError("invalid_tool_call")
        for call in calls:
            try:
                function = _call(call, request=False)
            except ValueError as error:
                raise JsonOutputError("invalid_tool_call") from error
            if (
                function["name"] not in names
                or (forced and function["name"] != forced)
                or not _json_object(function["arguments"])
            ):
                raise JsonOutputError("invalid_tool_call")
            called = True
    if required and not called:
        raise JsonOutputError("invalid_tool_call")
