"""Bounded native assistant blocks needed to resume Anthropic tool turns."""

import copy
import json
from collections.abc import Mapping

MAX_CONTINUATION_BYTES = 2_000_000
MAX_CONTENT_BLOCKS = 1024


def _validated_content(content):
    if not isinstance(content, list) or not 0 < len(content) <= MAX_CONTENT_BLOCKS:
        raise ValueError("Invalid Anthropic continuation blocks")
    for block in content:
        if not isinstance(block, dict):
            raise ValueError("Invalid Anthropic continuation block")
        kind = block.get("type")
        if kind == "thinking":
            valid = isinstance(block.get("thinking"), str) and isinstance(
                block.get("signature"), str
            )
        elif kind == "redacted_thinking":
            valid = isinstance(block.get("data"), str)
        elif kind == "text":
            valid = isinstance(block.get("text"), str)
        elif kind == "tool_use":
            valid = all(
                isinstance(block.get(key), str) and block[key] for key in ("id", "name")
            ) and isinstance(block.get("input"), dict)
        else:
            valid = False
        if not valid:
            raise ValueError("Invalid Anthropic continuation block")
    try:
        encoded = json.dumps(content, ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("Invalid Anthropic continuation JSON") from error
    if len(encoded) > MAX_CONTINUATION_BYTES:
        raise ValueError("Anthropic continuation exceeds its limit")
    return copy.deepcopy(content)


def continuation_extra(content):
    """Attach complete native blocks only when a signed tool turn needs them."""
    if not any(
        isinstance(block, dict)
        and block.get("type") in {"thinking", "redacted_thinking"}
        for block in content
    ):
        return None
    return {"anthropic": {"content": _validated_content(content)}}


def anthropic_extra(value):
    """Retain only validated Anthropic continuation metadata from a tool call."""
    if not isinstance(value, Mapping) or "anthropic" not in value:
        return None
    native = value["anthropic"]
    if not isinstance(native, Mapping):
        raise ValueError("Invalid Anthropic continuation metadata")
    return {"anthropic": {"content": _validated_content(native.get("content"))}}


def restore_assistant_content(message):
    calls = message.get("tool_calls") or []
    if not calls or not isinstance(calls[0], Mapping):
        return None
    extra = anthropic_extra(calls[0].get("extra_content"))
    if not extra:
        return None
    content = extra["anthropic"]["content"]
    native_calls = [block for block in content if block["type"] == "tool_use"]
    if len(calls) != len(native_calls):
        raise ValueError("Anthropic continuation does not match tool calls")
    for call, native in zip(calls, native_calls):
        function = call.get("function") if isinstance(call, Mapping) else None
        if (
            not isinstance(function, Mapping)
            or call.get("id") != native["id"]
            or function.get("name") != native["name"]
        ):
            raise ValueError("Anthropic continuation does not match tool calls")
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError("Invalid continuation tool arguments") from error
        if arguments != native["input"]:
            raise ValueError("Anthropic continuation does not match tool arguments")
    text = "".join(block["text"] for block in content if block["type"] == "text")
    if text != (message.get("content") or ""):
        raise ValueError("Anthropic continuation does not match assistant text")
    return content


class NativeContent:
    """Collect complete blocks, including signature deltas, without another request."""

    def __init__(self):
        self.blocks = {}
        self.arguments = {}
        self.bytes = 0

    def observe(self, event):
        kind = event.get("type")
        if kind not in {
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
        }:
            return
        index = event.get("index")
        if type(index) is not int or not 0 <= index < MAX_CONTENT_BLOCKS:
            raise ValueError("Invalid Anthropic block index")
        if kind == "content_block_start":
            block = event.get("content_block")
            if not isinstance(block, dict) or index in self.blocks:
                raise ValueError("Invalid Anthropic block start")
            self.blocks[index] = copy.deepcopy(block)
        elif kind == "content_block_delta":
            delta = event.get("delta")
            block = self.blocks.get(index)
            if not isinstance(delta, dict):
                raise ValueError("Invalid Anthropic block delta")
            if block is None:
                # Compatible text streams can omit an empty block start. Signed
                # reasoning and tool inputs still require their native starts.
                if delta.get("type") != "text_delta":
                    raise ValueError("Invalid Anthropic block delta")
                block = self.blocks[index] = {"type": "text", "text": ""}
            field = {
                "text_delta": "text",
                "thinking_delta": "thinking",
                "signature_delta": "signature",
            }.get(delta.get("type"))
            if field:
                value = delta.get(field)
                if not isinstance(value, str):
                    raise ValueError("Invalid Anthropic block field")
                block[field] = block.get(field, "") + value
            elif delta.get("type") == "input_json_delta":
                value = delta.get("partial_json")
                if not isinstance(value, str):
                    raise ValueError("Invalid Anthropic tool arguments")
                self.arguments[index] = self.arguments.get(index, "") + value
        elif self.arguments.get(index):
            # Empty fragments carry no JSON; retain the input from block start.
            # Nonempty malformed JSON must still fail instead of losing arguments.
            self.blocks[index]["input"] = json.loads(self.arguments[index])
        self.bytes += len(json.dumps(event, ensure_ascii=False).encode())
        if self.bytes > MAX_CONTINUATION_BYTES:
            raise ValueError("Anthropic continuation exceeds its limit")

    def extra(self):
        return continuation_extra([block for _, block in sorted(self.blocks.items())])
