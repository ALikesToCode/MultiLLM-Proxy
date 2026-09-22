"""Version-one intelligence request limits and safe failure vocabulary."""

import copy
import json
import re
from dataclasses import dataclass

from services.free_json_contract import validate_response_format

TASKS = frozenset(
    {"general", "coding", "reasoning", "planning", "assessment", "research", "writing"}
)
PROFILES = frozenset({"fast", "balanced", "quality"})
CAPABILITIES = frozenset({"tools", "json", "vision", "reasoning", "streaming", "audio"})
MODEL_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,223}$")
ROUTING_FIELDS = frozenset(
    {
        "version",
        "task",
        "profile",
        "source",
        "required_capabilities",
        "max_attempts",
        "max_escalations",
        "deadline_ms",
        "allow_paid_overage",
        "max_total_tokens",
    }
)
CHAT_FIELDS = frozenset(
    {
        "model",
        "messages",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "response_format",
        "reasoning_effort",
        "max_tokens",
        "max_completion_tokens",
        "stream",
        "stream_options",
        "temperature",
        "top_p",
        "stop",
        "seed",
        "frequency_penalty",
        "presence_penalty",
        "logit_bias",
        "logprobs",
        "top_logprobs",
        "n",
        "user",
        "modalities",
        "audio",
        "routing",
    }
)


class GatewayError(Exception):
    def __init__(self, code, message, status=400, *, retryable=False, retry_after=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.retryable = retryable
        self.retry_after = retry_after

    def envelope(self):
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
            }
        }


def integer(value, name, *, minimum=1, maximum=2**31 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {name}")
    return value


def identifier(value):
    if not isinstance(value, str) or not MODEL_ID.fullmatch(value):
        raise ValueError("Invalid model identifier")
    return value


def capabilities(value):
    if not isinstance(value, list) or any(
        not isinstance(v, str) or v not in CAPABILITIES for v in value
    ):
        raise ValueError("Invalid capabilities")
    return frozenset(value)


def _message_requirements(messages):
    if not isinstance(messages, list) or not messages or len(messages) > 1024:
        raise ValueError("Invalid messages")
    required = set()
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {
            "system",
            "developer",
            "user",
            "assistant",
            "tool",
        }:
            raise ValueError("Invalid message")
        if message.get("tool_calls") or message.get("role") == "tool":
            required.add("tools")
        if message.get("role") == "tool" and not isinstance(
            message.get("tool_call_id"), str
        ):
            raise ValueError("Tool result requires tool_call_id")
        content = message.get("content")
        if content is not None and not isinstance(content, (str, list)):
            raise ValueError("Invalid message content")
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    raise ValueError("Invalid content part")
                kind = part.get("type")
                if kind in {"image_url", "input_image"}:
                    required.add("vision")
                elif kind in {"input_audio", "audio"}:
                    required.add("audio")
                elif kind != "text":
                    raise ValueError("Unsupported content part")
    return required


def _validate_tools(tools):
    if not isinstance(tools, list) or len(tools) > 128:
        raise ValueError("Invalid tools")
    names = set()
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if not isinstance(function, dict) or tool.get("type") != "function":
            raise ValueError("Only function tools are supported")
        name = function.get("name")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
            or name in names
        ):
            raise ValueError("Invalid tool name")
        names.add(name)
        validate_response_format(
            {
                "type": "json_schema",
                "json_schema": {
                    "name": name,
                    "schema": function.get("parameters", {"type": "object"}),
                },
            }
        )


@dataclass(frozen=True)
class ChatRequest:
    payload: dict
    task: str
    profile: str
    required: frozenset
    max_attempts: int
    max_escalations: int
    deadline_ms: int
    max_total_tokens: int
    output_tokens: int
    input_tokens: int
    allow_paid: bool
    explicit: bool

    @classmethod
    def parse(cls, body, policy):
        if not isinstance(body, dict) or set(body) - CHAT_FIELDS:
            raise ValueError("Unsupported chat fields")
        routing = body.get("routing", {})
        if not isinstance(routing, dict) or set(routing) - ROUTING_FIELDS:
            raise ValueError("Invalid routing")
        if type(routing.get("version", 1)) is not int or routing.get("version", 1) != 1:
            raise ValueError("Unsupported routing version")
        task, profile = (
            routing.get("task", "general"),
            routing.get("profile", "balanced"),
        )
        if (
            task not in TASKS
            or profile not in PROFILES
            or routing.get("source", "rules") not in {"jev", "rules", "explicit"}
        ):
            raise ValueError("Invalid routing classification")
        allow_paid = routing.get("allow_paid_overage", False)
        if type(allow_paid) is not bool:
            raise ValueError("Invalid allow_paid_overage")
        model = identifier(body.get("model"))
        if model != "auto:intelligence" and model.split(":", 1)[0] in {"auto", "free"}:
            raise ValueError(
                "Routing limits require a concrete model or auto:intelligence"
            )
        required = _message_requirements(body.get("messages")) | set(
            capabilities(routing.get("required_capabilities", []))
        )
        _validate_tools(body.get("tools", []))
        if body.get("tools") or body.get("tool_choice") not in (None, "none"):
            required.add("tools")
        validate_response_format(body.get("response_format"))
        if (body.get("response_format") or {}).get("type") in {
            "json_object",
            "json_schema",
        }:
            required.add("json")
        if "reasoning_effort" in body:
            if body["reasoning_effort"] not in {
                "none",
                "minimal",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            }:
                raise ValueError("Invalid reasoning_effort")
            if body["reasoning_effort"] != "none":
                required.add("reasoning")
        if type(body.get("stream", False)) is not bool or body.get("n", 1) != 1:
            raise ValueError("Invalid stream or n")
        if body.get("stream"):
            required.add("streaming")
        if "audio" in body or "audio" in body.get("modalities", []):
            required.add("audio")
        options = body.get("stream_options") or {}
        if (
            not isinstance(options, dict)
            or set(options) - {"include_usage"}
            or type(options.get("include_usage", False)) is not bool
        ):
            raise ValueError("Invalid stream_options")
        limits = {}
        for name in (
            "max_attempts",
            "max_escalations",
            "deadline_ms",
            "max_total_tokens",
        ):
            limits[name] = min(
                integer(
                    routing.get(name, policy[name]),
                    name,
                    minimum=0 if name == "max_escalations" else 1,
                ),
                policy[name],
            )
        payload = copy.deepcopy(body)
        payload.pop("routing", None)
        output = min(
            integer(
                body.get(
                    "max_completion_tokens",
                    body.get("max_tokens", policy["max_output_tokens"]),
                ),
                "max_tokens",
            ),
            policy["max_output_tokens"],
        )
        if "max_tokens" in body and "max_completion_tokens" in body:
            output = min(output, integer(body["max_tokens"], "max_tokens"))
        output_field = (
            "max_completion_tokens" if "max_completion_tokens" in body else "max_tokens"
        )
        payload.pop("max_tokens", None)
        payload[output_field] = output
        # Byte counting deliberately over-reserves text and tool schemas. Media
        # models additionally reserve their reviewed input ceiling during selection.
        input_tokens = (
            len(
                json.dumps(
                    {
                        k: v
                        for k, v in payload.items()
                        if k in {"messages", "tools", "response_format"}
                    },
                    ensure_ascii=False,
                ).encode()
            )
            + 256
            + 64 * len(body["messages"])
        )
        return cls(
            payload,
            task,
            profile,
            frozenset(required),
            output_tokens=output,
            input_tokens=input_tokens,
            allow_paid=allow_paid and policy["allow_paid_overage"],
            explicit=model != "auto:intelligence",
            **limits,
        )
