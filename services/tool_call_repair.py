"""Deterministic repairs for caller-declared function calls, without inventing values."""

import json
import re

from services.protocol_translation.common import safe_tool_id
from services.tool_argument_parser import MAX_BYTES, check_bounds, single_object, strict_loads, tolerant_loads
from services.tool_argument_schema import coerce, validate_arguments

MAX_CALLS = 128
MAX_TOOLS = 128
MAX_CONTENT_BYTES = 256 * 1024
_FENCE = re.compile(r"```(?:json|jsonc|javascript)?\s*([\s\S]*?)```", re.IGNORECASE)
_TAG_START = re.compile(r"<tool_call>|<function=([^<>\s]+)>|<\|tool_call_begin\|>|<｜tool▁call▁begin｜>", re.IGNORECASE)


def _tagged_candidates(content):
    # Missing end tags stop the scan instead of causing repeated regex backtracking.
    lowered, cursor = content.lower(), 0
    for _ in range(MAX_CALLS):
        match = _TAG_START.search(content, cursor)
        if match is None:
            break
        start = match.group().lower()
        closing = {"<tool_call>": "</tool_call>", "<|tool_call_begin|>": "<|tool_call_end|>",
                   "<｜tool▁call▁begin｜>": "<｜tool▁call▁end｜>"}.get(start, "</function>")
        end = lowered.find(closing, match.end())
        if end < 0:
            break
        text, name = content[match.end():end].strip(), match.group(1)
        cursor = end + len(closing)
        if start == "<｜tool▁call▁begin｜>":
            if not text.startswith("function<｜tool▁sep｜>"):
                continue
            parts = text.removeprefix("function<｜tool▁sep｜>").split(None, 1)
            if len(parts) != 2:
                continue
            name, text = parts
        elif start == "<|tool_call_begin|>" and "<|tool_call_argument_begin|>" in text:
            name, text = text.split("<|tool_call_argument_begin|>", 1)
            name = name.strip().split(":", 1)[0]
        yield _text_call(text, name), (match.start(), cursor)


def empty_report():
    return {"checked": 0, "repaired": 0, "invalid": 0, "extracted": 0, "fixes": [], "errors": []}


def declared_functions(tools):
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        return []
    result = []
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            result.append(function)
    return result


def matching_function(name, functions):
    if not isinstance(name, str):
        return None
    exact = [function for function in functions if function["name"] == name]
    if len(exact) == 1:
        return exact[0]
    candidates = [function for function in functions
                  if function["name"].lower() in {name.lower(), name.rsplit(".", 1)[-1].lower()}]
    return candidates[0] if len(candidates) == 1 else None


def _parse_arguments(arguments, schema):
    fixes = []
    if not isinstance(arguments, str):
        return None, [], ["$: arguments must be a JSON string"]
    if len(arguments.encode("utf-8")) > MAX_BYTES:
        return None, [], ["$: arguments exceed size limit"]
    try:
        value = strict_loads(arguments)
    except (ValueError, RecursionError):
        text = arguments.strip()
        fence = _FENCE.fullmatch(text)
        if fence:
            text = fence.group(1).strip()
            fixes.append("strip_wrapping")
        try:
            unwrapped = single_object(text)
            if unwrapped != text:
                text = unwrapped
                if "strip_wrapping" not in fixes:
                    fixes.append("strip_wrapping")
            try:
                value = strict_loads(text)
            except (ValueError, RecursionError):
                value = tolerant_loads(text)
                fixes.append("tolerant_json")
        except (ValueError, RecursionError):
            return None, [], ["$: arguments are not valid JSON"]
    if isinstance(value, str):
        try:
            decoded = strict_loads(value)
        except (ValueError, RecursionError):
            try:
                decoded = tolerant_loads(value)
            except (ValueError, RecursionError):
                decoded = value
        if isinstance(decoded, dict):
            value = decoded
            fixes.append("decode_json_string")
    if not isinstance(value, dict):
        return None, [], ["$: arguments must be a JSON object"]
    check_bounds(schema)
    check_bounds(value)
    errors = validate_arguments(schema, value)
    if errors:
        coerced = coerce(schema, value)
        if not validate_arguments(schema, coerced):
            value, errors = coerced, []
            fixes.append("coerce_primitives")
    return value, fixes, errors


def _choice_errors(name, tool_choice):
    if tool_choice == "none":
        return ["$: tool_choice forbids calls"]
    if isinstance(tool_choice, dict):
        function = tool_choice.get("function")
        forced = function.get("name") if isinstance(function, dict) else None
        if forced and name != forced:
            return ["$: requested tool was not selected"]
    return []


def _repair_call(call, functions, tool_choice):
    if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
        return call, [], ["$: invalid function call"]
    if call.get("type", "function") != "function":
        return call, [], ["$: only function calls are supported"]
    original = call["function"]
    function = matching_function(original.get("name"), functions)
    if function is None:
        return call, [], ["$: unknown or ambiguous tool name"]
    errors = _choice_errors(function["name"], tool_choice)
    if errors:
        return call, [], errors
    value, fixes, errors = _parse_arguments(original.get("arguments"), function.get("parameters", {"type": "object"}))
    if errors:
        return call, [], errors
    if original.get("name") != function["name"]:
        fixes.append("tool_name")
    if not fixes:
        return call, [], []
    return {**call, "function": {**original, "name": function["name"],
                                "arguments": json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)}}, fixes, []


def _text_call(text, name=None):
    text = text.strip()
    fence = _FENCE.fullmatch(text)
    if name is not None and fence:
        text = fence.group(1).strip()
    try:
        value = tolerant_loads(text)
    except (ValueError, RecursionError):
        if name is None and "\n" in text:
            name, arguments = text.split("\n", 1)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,255}", name.strip()):
                return _text_call(arguments, name.strip())
        return None
    if name is not None:
        return {"name": name, "arguments": text.strip()} if isinstance(value, dict) else None
    if not isinstance(value, dict):
        return None
    function = value.get("function", value)
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        return None
    arguments = function.get("arguments", function.get("parameters"))
    if isinstance(arguments, dict):
        arguments = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if not isinstance(arguments, str):
        return None
    return {"name": function["name"], "arguments": arguments}


def _extract(message, functions, tool_choice):
    content = message.get("content")
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        return message, 0
    spans, calls = [], []
    for candidate, span in _tagged_candidates(content):
        if len(calls) >= MAX_CALLS:
            break
        _add_extraction(candidate, span, functions, tool_choice, calls, spans)
    for scanned, match in enumerate(_FENCE.finditer(content)):
        if scanned >= MAX_CALLS:
            break
        if len(calls) >= MAX_CALLS:
            break
        if any(start <= match.start() < end for start, end in spans):
            continue
        _add_extraction(_text_call(match.group(1)), match.span(), functions, tool_choice, calls, spans)
    if not calls:
        return message, 0
    ordered = sorted(zip(spans, calls))
    pieces, last = [], 0
    for (start, end), _ in ordered:
        pieces.append(content[last:start])
        last = end
    pieces.append(content[last:])
    remaining = "".join(pieces).strip()
    for start, end in (("<｜tool▁calls▁begin｜>", "<｜tool▁calls▁end｜>"),
                       ("<|tool_calls_section_begin|>", "<|tool_calls_section_end|>")):
        remaining = remaining.removeprefix(start).removesuffix(end).strip()
    return {**message, "content": remaining or None, "tool_calls": [call for _, call in ordered]}, len(calls)


def _add_extraction(candidate, span, functions, tool_choice, calls, spans):
    if candidate is None:
        return
    function = matching_function(candidate["name"], functions)
    if function is None or _choice_errors(function["name"], tool_choice):
        return
    calls.append({"id": safe_tool_id(None, prefix="call"), "type": "function", "function": candidate})
    spans.append(span)


def repair_tool_calls(message, tools, *, tool_choice=None, mode="repair", allow_extraction=True):
    """Return a repaired copy and a bounded report. Invalid calls remain unchanged."""
    report = empty_report()
    if mode == "off" or not isinstance(message, dict):
        return message, report
    functions = declared_functions(tools)
    if not functions:
        return message, report
    try:
        result = message
        if not message.get("tool_calls") and allow_extraction and tool_choice != "none":
            result, report["extracted"] = _extract(message, functions, tool_choice)
        calls = result.get("tool_calls")
        if calls is None or calls == []:
            return result, report
        if not isinstance(calls, list) or len(calls) > MAX_CALLS:
            report.update(invalid=1, errors=[{"index": 0, "errors": ["$: tool call limit exceeded"]}])
            return message, report
        repaired_calls = []
        for index, call in enumerate(calls):
            report["checked"] += 1
            repaired, fixes, errors = _repair_call(call, functions, tool_choice)
            repaired_calls.append(repaired)
            if fixes:
                report["repaired"] += 1
                report["fixes"].append({"index": index, "fixes": fixes})
            if errors:
                report["invalid"] += 1
                report["errors"].append({"index": index, "errors": errors})
        if result is not message or repaired_calls != calls:
            result = {**result, "tool_calls": repaired_calls}
        return result, report
    except (ValueError, TypeError, RecursionError, OverflowError, UnicodeError):
        # Malformed provider output must not make an otherwise usable request fail.
        return message, {**empty_report(), "invalid": 1,
                         "errors": [{"index": 0, "errors": ["$: repair limit or invalid shape"]}]}
