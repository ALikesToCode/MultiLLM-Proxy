"""Normalize SSE deltas while retaining indexed tool calls and terminal usage."""

import json

from services.intelligence_contract import GatewayError
from services.intelligence_output import safe_message
from streaming.sse import iter_sse_events


class ChatStream:
    def __init__(self, chunks, model):
        self.chunks, self.model = chunks, model
        self.usage = None
        self.content = ""
        self.refusal = ""
        self.audio = {}
        self.calls = {}
        self.finish = None
        self.done = False

    def events(self):
        for event in iter_sse_events(self.chunks):
            if event.is_done:
                self.done = True
                break
            if not event.data:
                continue
            try:
                body = json.loads(event.data)
                if (
                    not isinstance(body, dict)
                    or "error" in body
                    or event.event == "error"
                ):
                    raise ValueError("Upstream stream failure")
                choices = body.get("choices", [])
                if not isinstance(choices, list) or len(choices) > 1:
                    raise ValueError("Invalid streaming choices")
                if not choices:
                    if self.finish is not None and body.get("usage") is not None:
                        self.usage = body["usage"]
                    continue
                choice = choices[0]
                if not isinstance(choice, dict) or choice.get("index", 0) != 0:
                    raise ValueError("Invalid stream index")
                delta = self._delta(choice.get("delta", {}))
                if self.finish is not None and any(
                    delta.get(key)
                    for key in ("content", "refusal", "audio", "tool_calls")
                ):
                    raise ValueError("Output after completion")
                finish = choice.get("finish_reason")
                if finish is not None:
                    if finish not in {"stop", "length", "tool_calls", "content_filter"}:
                        raise ValueError("Invalid finish reason")
                    self.finish = finish
                if self.finish is not None and body.get("usage") is not None:
                    self.usage = body["usage"]
                if not delta and finish is None:
                    continue
                yield {
                    "id": "chatcmpl-intelligence",
                    "object": "chat.completion.chunk",
                    "model": self.model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
                }
            except (ValueError, TypeError, KeyError, AttributeError):
                raise GatewayError(
                    "stream_interrupted",
                    "The provider stream was interrupted; no replacement was appended.",
                    502,
                ) from None
        if not self.done or self.finish is None:
            raise GatewayError(
                "stream_interrupted",
                "The provider stream ended without a complete result.",
                502,
            )

    def _delta(self, value):
        if not isinstance(value, dict):
            raise ValueError("Invalid delta")
        delta = {}
        if value.get("role") == "assistant":
            delta["role"] = "assistant"
        for key in ("content", "refusal"):
            part = value.get(key)
            if part is not None:
                if not isinstance(part, str):
                    raise ValueError("Invalid text delta")
                delta[key] = part
                if key == "content":
                    self.content += part
                else:
                    self.refusal += part
        if "audio" in value:
            if not isinstance(value["audio"], dict):
                raise ValueError("Invalid audio delta")
            audio = {}
            for key in ("id", "data", "transcript"):
                if key in value["audio"]:
                    part = value["audio"][key]
                    if not isinstance(part, str):
                        raise ValueError("Invalid audio field")
                    audio[key] = part
                    self.audio[key] = self.audio.get(key, "") + part
            delta["audio"] = audio
        if "tool_calls" in value:
            calls = value["tool_calls"]
            if not isinstance(calls, list):
                raise ValueError("Invalid tool delta")
            delta["tool_calls"] = []
            for fragment in calls:
                index = fragment.get("index")
                if type(index) is not int or not 0 <= index < 128:
                    raise ValueError("Invalid tool index")
                call = self.calls.setdefault(
                    index,
                    {
                        "id": "",
                        "type": "function",
                        "function": {"name": "", "arguments": ""},
                    },
                )
                clean = {"index": index}
                if "id" in fragment:
                    if not isinstance(fragment["id"], str):
                        raise ValueError("Invalid tool ID")
                    call["id"] += fragment["id"]
                    clean["id"] = fragment["id"]
                if "type" in fragment:
                    if fragment["type"] != "function":
                        raise ValueError("Invalid tool type")
                    clean["type"] = "function"
                function = fragment.get("function", {})
                clean["function"] = {}
                for name in ("name", "arguments"):
                    if name in function:
                        if not isinstance(function[name], str):
                            raise ValueError("Invalid function delta")
                        call["function"][name] += function[name]
                        clean["function"][name] = function[name]
                delta["tool_calls"].append(clean)
        return delta

    def completion(self):
        message = {"content": self.content or None}
        if self.calls:
            message["tool_calls"] = [call for _, call in sorted(self.calls.items())]
        if self.refusal:
            message["refusal"] = self.refusal
        if self.audio:
            message["audio"] = self.audio
        return {
            "choices": [
                {
                    "index": 0,
                    "message": safe_message(message),
                    "finish_reason": self.finish,
                }
            ]
        }
