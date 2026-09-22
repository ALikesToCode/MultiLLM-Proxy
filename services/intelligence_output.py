"""Usage aggregation and validation of visible Chat Completions output."""

import json
from dataclasses import dataclass, field

from services.free_json_contract import check_json_output, json_output_requested
from services.intelligence_contract import GatewayError

USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")


@dataclass
class Usage:
    values: dict = field(default_factory=dict)
    complete: bool = True

    def add(self, value):
        valid = {
            key: value[key]
            for key in USAGE_FIELDS
            if isinstance(value, dict)
            and type(value.get(key)) is int
            and 0 <= value[key] < 2**31
        }
        consistent = (
            len(valid) == 3
            and valid["total_tokens"]
            == valid["prompt_tokens"] + valid["completion_tokens"]
        )
        self.complete = self.complete and consistent
        for key, count in valid.items():
            self.values[key] = self.values.get(key, 0) + count

    @property
    def total(self):
        return self.values.get("total_tokens", 0)


def safe_message(message):
    if not isinstance(message, dict):
        raise ValueError("Invalid assistant message")
    result = {"role": "assistant"}
    for key in ("content", "refusal", "audio"):
        if key in message:
            result[key] = message[key]
    if "tool_calls" in message:
        calls = message["tool_calls"]
        if not isinstance(calls, list):
            raise ValueError("Invalid tool calls")
        result["tool_calls"] = []
        for call in calls:
            if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                raise ValueError("Invalid tool call")
            result["tool_calls"].append(
                {
                    "id": call.get("id"),
                    "type": call.get("type"),
                    "function": {
                        key: call["function"].get(key) for key in ("name", "arguments")
                    },
                }
            )
    return result


def visible_completion(payload, model):
    choices = payload.get("choices")
    if (
        not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
    ):
        raise ValueError("Invalid choices")
    choice = choices[0]
    if choice.get("finish_reason") not in {
        "stop",
        "length",
        "tool_calls",
        "content_filter",
    }:
        raise ValueError("Missing completion finish reason")
    return {
        "id": "chatcmpl-intelligence",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": safe_message(choice.get("message")),
                "finish_reason": choice["finish_reason"],
            }
        ],
    }


def validate_completion(completion, request):
    message = completion["choices"][0]["message"]
    calls = message.get("tool_calls")
    if calls:
        tools = {
            tool["function"]["name"]: tool["function"]
            for tool in request.payload.get("tools", [])
        }
        if not isinstance(calls, list) or len(calls) > 128:
            raise ValueError("Invalid tool calls")
        choice = request.payload.get("tool_choice")
        if choice == "none" or (
            request.payload.get("parallel_tool_calls") is False and len(calls) != 1
        ):
            raise ValueError("Tool choice was not respected")
        ids = set()
        for call in calls:
            if not isinstance(call, dict) or call.get("type") != "function":
                raise ValueError("Invalid tool call")
            if (
                not isinstance(call.get("id"), str)
                or not call["id"]
                or len(call["id"]) > 256
                or call["id"] in ids
            ):
                raise ValueError("Invalid tool call identifier")
            ids.add(call["id"])
            function = call.get("function", {})
            name = function.get("name")
            if name not in tools:
                raise ValueError("Unknown tool")
            if isinstance(choice, dict) and name != choice.get("function", {}).get(
                "name"
            ):
                raise ValueError("Required tool was not selected")
            check_json_output(
                function.get("arguments"),
                {
                    "type": "json_schema",
                    "json_schema": {
                        "name": name,
                        "schema": tools[name].get("parameters", {"type": "object"}),
                    },
                },
            )
        return
    content = message.get("content")
    if json_output_requested(request.payload.get("response_format")):
        check_json_output(content, request.payload["response_format"])
    elif (
        not (isinstance(content, str) and content.strip())
        and not message.get("refusal")
        and not message.get("audio")
    ):
        raise ValueError("Empty completion")
    if request.payload.get("tool_choice") == "required" or isinstance(
        request.payload.get("tool_choice"), dict
    ):
        raise ValueError("Required tool was not called")


def decode_completion(raw):
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError):
        raise GatewayError(
            "invalid_upstream_response", "The provider returned invalid JSON.", 502
        ) from None
    if not isinstance(payload, dict) or "error" in payload:
        raise GatewayError(
            "upstream_error",
            "The provider returned an error or unsupported response.",
            502,
        )
    return payload


def sse(value):
    return (
        "data: " + json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n\n"
    )
