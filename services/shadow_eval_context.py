"""Compact judge context; full retained requests are reserved for candidate replays."""

import copy

from services.shadow_eval_contract import encoded

SYSTEM_BYTES = 8192
MESSAGE_BYTES = 24576
JUDGE_BYTES = 65536


def _size(value):
    return len(encoded(value).encode())


def _fit_message(message, budget):
    if _size(message) <= budget:
        return copy.deepcopy(message)
    content = message.get("content", "")
    content = content if isinstance(content, str) else encoded(content)
    result = {"role": message.get("role", "user"), "content": ""}
    if _size(result) > budget:
        return None
    # Binary search accounts for UTF-8 and JSON escaping, without splitting characters.
    low, high = 0, len(content)
    while low < high:
        middle = (low + high + 1) // 2
        result["content"] = content[:middle]
        if _size(result) <= budget:
            low = middle
        else:
            high = middle - 1
    result["content"] = content[:low]
    return result


def _messages(messages, budget):
    kept = []
    for message in messages:
        remaining = budget - _size(kept) - (1 if kept else 0)
        fitted = _fit_message(message, remaining)
        if fitted is None:
            break
        kept.append(fitted)
    return kept


def compact_request(request, answers):
    messages = request.get("messages", [])
    systems = _messages((item for item in messages if item.get("role") == "system"), SYSTEM_BYTES)
    # Select newest first, then restore conversation order for the judge.
    recent = [item for item in messages if item.get("role") != "system"][-8:]
    recent = _messages(reversed(recent), MESSAGE_BYTES)
    view = {"messages": systems + list(reversed(recent))}
    called = {call.get("function", {}).get("name") for answer in answers
              for call in answer.get("tool_calls", []) if isinstance(call, dict)}
    if "tools" in request:
        tools = []
        for tool in request["tools"]:
            function = tool.get("function", {})
            summary = {name: function[name] for name in ("name", "description") if name in function}
            if function.get("name") in called:
                summary = copy.deepcopy(function)
            tools.append({"type": tool.get("type", "function"), "function": summary})
        view["tools"] = tools
    if "response_format" in request:
        view["response_format"] = copy.deepcopy(request["response_format"])
    return view
