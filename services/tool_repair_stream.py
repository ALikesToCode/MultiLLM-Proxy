"""Bounded per-call SSE buffering; content and heartbeat frames remain immediate."""

import copy
import json

from services.tool_call_repair import MAX_CALLS, empty_report, repair_tool_calls
from services.tool_argument_parser import MAX_BYTES, check_bounds
from services.tool_repair_runtime import merge_report
from streaming.sse import iter_sse_events

MAX_FRAME_BYTES = 1024 * 1024
MAX_BUFFER_BYTES = 8 * 1024 * 1024


def sse_chunk(payload):
    return "data: " + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n\n"


class ToolCallBuffer:
    def __init__(self, tools, tool_choice=None, mode="repair"):
        self.tools, self.tool_choice, self.mode = tools, tool_choice, mode
        self.calls = {}
        self.templates = {}
        self.size = 0
        self.disabled = False
        self.report = {**empty_report(), "reasked": 0}

    def flush(self, choice_index=None):
        for index in list(self.calls):
            if choice_index is not None and index != choice_index:
                continue
            calls = self.calls.pop(index)
            template = self.templates.pop(index)
            positions = sorted(calls)
            message = {"role": "assistant", "tool_calls": [calls[key] for key in positions]}
            repaired, report = repair_tool_calls(message, self.tools, tool_choice=self.tool_choice,
                                                  mode=self.mode, allow_extraction=False)
            merge_report(self.report, report)
            for position, call in zip(positions, repaired["tool_calls"]):
                delta = {"tool_calls": [{**call, "index": position}]}
                yield {**template, "choices": [{"index": index, "delta": delta, "finish_reason": None}]}
        if not self.calls:
            self.size = 0

    def process(self, payload):
        if self.mode == "off" or self.disabled or not isinstance(payload, dict):
            yield payload
            return
        choices = payload.get("choices", [])
        if not isinstance(choices, list) or len(choices) > MAX_CALLS:
            yield from self.flush()
            self.disabled = True
            yield payload
            return
        if "error" in payload:
            yield from self.flush()
            yield payload
            return
        # Validate a complete frame before changing state, so fallback loses no fragment.
        try:
            incoming = self._fragments(choices)
        except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
            yield from self.flush()
            self.disabled = True
            yield payload
            return
        if not incoming and not any(isinstance(c, dict) and c.get("finish_reason") is not None for c in choices):
            yield payload
            return
        try:
            updated = copy.deepcopy(self.calls)
            for choice_index, fragments in incoming:
                calls = updated.setdefault(choice_index, {})
                for fragment in fragments:
                    index = fragment.get("index", 0)
                    call = calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                    for key in ("id", "type", "extra_content"):
                        if key in fragment:
                            if key == "id":
                                call[key] += fragment[key]
                            else:
                                call[key] = fragment[key]
                    for key, value in fragment.get("function", {}).items():
                        if key in ("name", "arguments"):
                            call["function"][key] += value
                    if (len(call["function"]["arguments"].encode("utf-8")) > MAX_BYTES
                            or len(call["function"]["name"]) > 256 or len(call["id"]) > 256):
                        raise ValueError("Call limit exceeded")
            size = len(json.dumps(updated, ensure_ascii=False).encode("utf-8"))
            if size > MAX_BUFFER_BYTES or sum(len(calls) for calls in updated.values()) > MAX_CALLS:
                raise ValueError("Buffer limit exceeded")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            yield from self.flush()
            self.disabled = True
            yield payload
            return
        self.calls, self.size = updated, size
        template = {k: v for k, v in payload.items() if k not in ("choices", "usage")}
        for choice_index, _ in incoming:
            self.templates[choice_index] = template
        for choice in choices:
            index = choice.get("index", 0)
            delta = choice.get("delta", {})
            remaining = {k: v for k, v in delta.items() if k != "tool_calls"}
            if remaining:
                yield {**template, "choices": [{**choice, "delta": remaining, "finish_reason": None}]}
            if choice.get("finish_reason") is not None:
                yield from self.flush(index)
                yield {**payload, "choices": [{**choice, "delta": {}}]}
        if payload.get("usage") is not None and not any(c.get("finish_reason") is not None for c in choices):
            yield {**payload, "choices": []}
        elif not choices:
            yield payload

    def _fragments(self, choices):
        incoming = []
        for choice in choices:
            if not isinstance(choice, dict):
                raise ValueError("Invalid choice")
            index = choice.get("index", 0)
            if type(index) is not int or not 0 <= index < MAX_CALLS:
                raise ValueError("Invalid index")
            delta = choice.get("delta", {})
            if not isinstance(delta, dict):
                raise ValueError("Invalid delta")
            fragments = delta.get("tool_calls", [])
            if not isinstance(fragments, list) or len(fragments) > MAX_CALLS:
                raise ValueError("Invalid fragments")
            if len(fragments) > 1 and any("index" not in fragment for fragment in fragments if isinstance(fragment, dict)):
                raise ValueError("Ambiguous fragment positions")
            for fragment in fragments:
                if not isinstance(fragment, dict) or type(fragment.get("index", 0)) is not int or not 0 <= fragment.get("index", 0) < MAX_CALLS:
                    raise ValueError("Invalid fragment")
                function = fragment.get("function", {})
                if not isinstance(function, dict) or any(not isinstance(v, str) for k, v in function.items() if k in ("name", "arguments")):
                    raise ValueError("Invalid function fragment")
                if "id" in fragment and not isinstance(fragment["id"], str):
                    raise ValueError("Invalid identifier")
                if "extra_content" in fragment:
                    check_bounds(fragment["extra_content"])
            if fragments:
                incoming.append((index, fragments))
        return incoming


def repair_sse(chunks, buffer):
    """Preserve raw frames whenever possible; disable repair on oversized frames."""
    pending = b""
    try:
        for chunk in chunks:
            if buffer.disabled:
                yield chunk
                continue
            chunk = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
            pending += chunk
            while b"\n\n" in pending or b"\r\n\r\n" in pending:
                lf, crlf = pending.find(b"\n\n"), pending.find(b"\r\n\r\n")
                end, width = (lf, 2) if lf >= 0 and (crlf < 0 or lf < crlf) else (crlf, 4)
                frame, pending = pending[:end + width], pending[end + width:]
                yield from _frame(frame, buffer)
                if buffer.disabled:
                    if pending:
                        yield pending
                    pending = b""
                    break
            if len(pending) > MAX_FRAME_BYTES:
                yield from (sse_chunk(item) for item in buffer.flush())
                buffer.disabled = True
                yield pending
                pending = b""
        if pending:
            yield from _frame(pending, buffer)
        yield from (sse_chunk(item) for item in buffer.flush())
    finally:
        close = getattr(chunks, "close", None)
        if close:
            close()


def _frame(frame, buffer):
    if len(frame) > MAX_FRAME_BYTES:
        yield from (sse_chunk(item) for item in buffer.flush())
        buffer.disabled = True
        yield frame
        return
    events = list(iter_sse_events([frame]))
    if not events or not events[0].data:
        yield frame
        return
    event = events[0]
    if event.is_done or event.event == "error":
        yield from (sse_chunk(item) for item in buffer.flush())
        yield frame
        return
    try:
        payload = json.loads(event.data)
    except (ValueError, UnicodeError, RecursionError):
        yield frame
        return
    output = list(buffer.process(payload))
    if len(output) == 1 and output[0] is payload:
        yield frame
    else:
        for item in output:
            yield sse_chunk(item)
