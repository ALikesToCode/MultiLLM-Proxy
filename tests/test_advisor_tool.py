"""Claude's advisor tool on /v1/messages: a stronger model advises while the request's
model writes the answer.

The replies below follow the shape the Claude API returned on 7 November 2026 for
Claude Haiku 5.5 with a Claude Sonnet 5.5 advisor: `usage.iterations` lists the
executor's two turns and the advisor's own turn, and top-level usage counts only the
executor.
"""

import io
import json
import os
from unittest.mock import patch

import requests

from services.tool_repair_runtime import HEADER
from tests.unified_api_test_case import UnifiedApiTestCase

HAIKU = "anthropic:claude-haiku-5-5"
SONNET = "anthropic:claude-sonnet-5-5"
BETA = {"anthropic-beta": "advisor-tool-2026-03-01", "anthropic-version": "2023-06-01"}


def advisor_tool(model="claude-sonnet-5-5", **extra):
    return {"type": "advisor_20260301", "name": "advisor", "model": model, "max_uses": 1, "max_tokens": 1500, **extra}


def iteration(kind, input_tokens, output_tokens, *, model=None, read=0, written=0, one_hour=0):
    entry = {"input_tokens": input_tokens, "output_tokens": output_tokens, "cache_read_input_tokens": read,
             "cache_creation_input_tokens": written,
             "cache_creation": {"ephemeral_5m_input_tokens": written - one_hour, "ephemeral_1h_input_tokens": one_hour},
             "type": kind}
    if model:
        entry["model"] = model
    return entry


ITERATIONS = [
    iteration("message", 1097, 92),
    iteration("advisor_message", 2778, 685, model="claude-sonnet-5-5"),
    iteration("message", 1542, 112),
]


def advised_usage(iterations=None):
    iterations = ITERATIONS if iterations is None else iterations
    executor = [entry for entry in iterations if entry["type"] == "message"]
    return {"input_tokens": sum(entry["input_tokens"] for entry in executor),
            "cache_creation_input_tokens": sum(entry["cache_creation_input_tokens"] for entry in executor),
            "cache_read_input_tokens": sum(entry["cache_read_input_tokens"] for entry in executor),
            "output_tokens": sum(entry["output_tokens"] for entry in executor),
            "iterations": iterations}


ADVICE = {"type": "advisor_redacted_result", "encrypted_content": "c3ludGhldGljIGFkdmljZQ==", "stop_reason": "end_turn"}


def advised_message(usage=None):
    return {"id": "msg_advised", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [
                {"type": "server_tool_use", "id": "srvtoolu_synthetic", "name": "advisor", "input": {}},
                {"type": "advisor_tool_result", "tool_use_id": "srvtoolu_synthetic", "content": ADVICE},
                {"type": "text", "text": "A synthetic answer."},
            ],
            "stop_reason": "end_turn", "stop_sequence": None, "usage": usage or advised_usage()}


def advised_frames(usage=None):
    usage = usage or advised_usage()
    first = usage["iterations"][0]
    start = {key: first[key] for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")}
    events = (
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_advised", "type": "message", "role": "assistant", "model": "claude-haiku-5-5", "content": [],
            "stop_reason": None, "stop_sequence": None, "usage": {**start, "output_tokens": 8}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {
            "type": "server_tool_use", "id": "srvtoolu_synthetic", "name": "advisor", "input": {}}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {
            "type": "advisor_tool_result", "tool_use_id": "srvtoolu_synthetic", "content": ADVICE}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        ("content_block_start", {"type": "content_block_start", "index": 2, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 2,
                                 "delta": {"type": "text_delta", "text": "A synthetic answer."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 2}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": usage}),
        ("message_stop", {"type": "message_stop"}),
    )
    return b"".join(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events)


def json_reply(body):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(body).encode()
    response.raw = io.BytesIO(response._content)
    response.headers["Content-Type"] = "application/json"
    return response


def stream_reply(body):
    response = requests.Response()
    response.status_code = 200
    response.raw = io.BytesIO(body)
    response.headers["Content-Type"] = "text/event-stream"
    return response


class AdvisorTestCase(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["ANTHROPIC_API_KEY"] = "anthropic-provider-key"

    def messages(self, body, reply, *, key="admin-test-key", headers=None):
        payload = {"model": HAIKU, "max_tokens": 1024, "messages": [{"role": "user", "content": "A synthetic question"}],
                   "tools": [advisor_tool()], **body}
        with patch.object(self.app_module.ProxyService, "make_request", return_value=reply) as send:
            response = self.client.post("/v1/messages", json=payload,
                                        headers={"Authorization": f"Bearer {key}", **BETA, **(headers or {})})
            data = response.get_data()
            response.close()
        return response, data, send


class AdvisorPassthroughTest(AdvisorTestCase):
    """Tool repair cannot carry server tool blocks, so advisor replies pass through."""

    def test_streamed_advisor_reply_passes_through_unchanged(self):
        body = advised_frames()
        for mode in ("repair", "full"):
            with self.subTest(mode=mode):
                response, data, send = self.messages({"stream": True}, stream_reply(body), headers={HEADER: mode})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(data, body)
                self.assertEqual(response.headers[HEADER], f"mode={mode}; streaming=1")
                self.assertEqual(json.loads(send.call_args.kwargs["data"])["tools"], [advisor_tool()])

    def test_advisor_reply_with_a_function_tool_keeps_its_advice_blocks(self):
        lookup = {"name": "lookup", "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}
        reply = advised_message()
        response, data, _ = self.messages({"tools": [advisor_tool(), lookup]}, json_reply(reply))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(data), reply)
        self.assertEqual(response.headers[HEADER], "checked=0 repaired=0 extracted=0 invalid=0 reasked=0")


ADMIN = {"username": "admin", "is_admin": True}


class AdvisorPolicyTest(AdvisorTestCase):
    """The advisor's model is held to the key's model controls before dispatch."""

    def restricted_key(self, allowed=(HAIKU,), official_only=True):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            key = self.app_module.AuthService.create_user("restricted", scopes=["chat", "models"])["api_key"]
            self.app_module.AuthService.set_key_controls(
                "restricted", {"allowed_models": list(allowed), "official_only": official_only})
        return key

    def test_a_restricted_key_cannot_reach_an_opus_advisor(self):
        key = self.restricted_key()
        for model in ("claude-opus-5-5", "anthropic:claude-opus-5-5", "Claude-Opus-5-5"):
            with self.subTest(model=model):
                response, data, send = self.messages({"tools": [advisor_tool(model)]}, json_reply(advised_message()),
                                                     key=key)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(json.loads(data)["error"]["type"], "permission_error")
                self.assertIn("anthropic:claude-opus-5-5", json.loads(data)["error"]["message"].lower())
                send.assert_not_called()

    def test_the_refusal_matches_a_disallowed_top_level_model(self):
        key = self.restricted_key()
        _, advised, _ = self.messages({"tools": [advisor_tool("claude-opus-5-5")]}, json_reply(advised_message()), key=key)
        _, direct, _ = self.messages({"model": "anthropic:claude-opus-5-5", "tools": []}, json_reply(advised_message()),
                                     key=key)
        advised, direct = json.loads(advised), json.loads(direct)
        self.assertEqual(advised["error"]["type"], direct["error"]["type"])
        self.assertEqual(advised["error"]["message"], direct["error"]["message"])

    def test_an_allowed_advisor_is_sent_under_its_bare_id(self):
        key = self.restricted_key(allowed=(HAIKU, SONNET))
        for model in ("claude-sonnet-5-5", "anthropic:claude-sonnet-5-5"):
            with self.subTest(model=model):
                response, _, send = self.messages({"tools": [advisor_tool(model)]}, json_reply(advised_message()),
                                                  key=key)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(json.loads(send.call_args.kwargs["data"])["tools"], [advisor_tool("claude-sonnet-5-5")])

    def test_a_wildcard_allowlist_admits_its_advisors(self):
        key = self.restricted_key(allowed=("anthropic:*",))
        response, _, _ = self.messages({"tools": [advisor_tool("claude-opus-5-5")]}, json_reply(advised_message()), key=key)
        self.assertEqual(response.status_code, 200)

    def test_an_advisor_from_another_provider_is_refused_before_dispatch(self):
        for model in ("openai:gpt-5.5", "opencode:claude-opus-5-5", "", None, 5):
            with self.subTest(model=model):
                response, data, send = self.messages({"tools": [advisor_tool(model)]}, json_reply(advised_message()))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(json.loads(data)["error"]["type"], "invalid_request_error")
                send.assert_not_called()

    def test_every_advisor_tool_is_checked(self):
        key = self.restricted_key(allowed=(HAIKU, SONNET))
        tools = [advisor_tool("claude-sonnet-5-5"), advisor_tool("claude-fable-5-1", name="second")]
        response, _, send = self.messages({"tools": tools}, json_reply(advised_message()), key=key)
        self.assertEqual(response.status_code, 403)
        send.assert_not_called()
