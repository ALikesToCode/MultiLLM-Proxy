"""The `advisor` field on Chat Completions and Responses for anthropic: models.

The field becomes Claude's advisor tool when the request is translated to Messages;
the reply comes back without advisor blocks, with the advisor's tokens in
`usage.advisor`, and is priced like a native advisor request.
"""

import json
import os
import sys
from unittest.mock import patch

from services import usage_ledger
from services.budget_service import BudgetService
from tests.test_advisor_tool import (
    ADVICE,
    HAIKU,
    HAIKU_COST,
    SONNET,
    SONNET_COST,
    advised_frames,
    advised_message,
    advised_usage,
    json_reply,
    stream_reply,
)
from tests.test_claude_pricing import SHIPPED_PRICES
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"username": "admin", "is_admin": True}
ADVISOR = {"model": "anthropic:claude-sonnet-5-5", "max_uses": 1, "max_tokens": 2048}
TOOL = {"type": "advisor_20260301", "name": "advisor", "model": "claude-sonnet-5-5", "max_uses": 1, "max_tokens": 2048}
QUESTION = [{"role": "user", "content": "A synthetic question"}]
CHAT_PATHS = ("/v1/chat/completions", "/lean/v1/chat/completions")


def frames(text):
    return [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:") and line[5:].strip() != "[DONE]"]


class ExtensionTestCase(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["ANTHROPIC_API_KEY"] = "anthropic-provider-key"

    def post(self, path, body, reply, *, key="admin-test-key"):
        with patch.object(self.app_module.ProxyService, "make_request", return_value=reply) as send:
            response = self.client.post(path, json=body, headers={"Authorization": f"Bearer {key}"})
            data = response.get_data(as_text=True)
            response.close()
        return response, data, send

    def chat(self, body, reply, *, path="/v1/chat/completions", key="admin-test-key"):
        return self.post(path, {"model": HAIKU, "messages": QUESTION, "advisor": ADVISOR, **body}, reply, key=key)

    def responses(self, body, reply, *, key="admin-test-key"):
        return self.post("/v1/responses", {"model": HAIKU, "input": "A synthetic question", "advisor": ADVISOR, **body},
                         reply, key=key)

    def upstream(self, send):
        kwargs = send.call_args.kwargs
        return json.loads(kwargs["data"]), {name.lower(): value for name, value in kwargs["headers"].items()}


class AdvisorExtensionTest(ExtensionTestCase):
    def test_chat_sends_the_advisor_tool_and_its_beta(self):
        for path in CHAT_PATHS:
            with self.subTest(path=path):
                response, data, send = self.chat({}, json_reply(advised_message()), path=path)
                self.assertEqual(response.status_code, 200, data)
                body, headers = self.upstream(send)
                self.assertEqual(body["tools"], [TOOL])
                self.assertIn("advisor-tool-2026-03-01", headers["anthropic-beta"].split(","))
                self.assertNotIn("advisor", body)

    def test_lean_caches_the_tools_without_marking_the_advisor(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        response, _, send = self.chat({"tools": [lookup]}, json_reply(advised_message()), path="/lean/v1/chat/completions")
        self.assertEqual(response.status_code, 200)
        tools = self.upstream(send)[0]["tools"]
        self.assertEqual([tool.get("name") for tool in tools], ["lookup", "advisor"])
        self.assertIn("cache_control", tools[0])
        self.assertEqual(tools[1], TOOL)

    def test_chat_replies_without_advisor_blocks_and_with_advisor_usage(self):
        for path in CHAT_PATHS:
            with self.subTest(path=path):
                response, data, _ = self.chat({}, json_reply(advised_message()), path=path)
                reply = json.loads(data)
                message = reply["choices"][0]["message"]
                self.assertEqual(message["content"], "A synthetic answer.")
                self.assertNotIn("tool_calls", message)
                self.assertNotIn("encrypted_content", data)
                self.assertEqual((reply["usage"]["prompt_tokens"], reply["usage"]["completion_tokens"]), (2639, 204))
                advisor = reply["usage"]["advisor"]
                self.assertEqual((advisor["model"], advisor["calls"]), (SONNET, 1))
                self.assertEqual((advisor["prompt_tokens"], advisor["completion_tokens"]), (2778, 685))
                self.assertEqual(response.headers["X-MultiLLM-Advisor-Model"], SONNET)
                self.assertEqual(response.headers["X-MultiLLM-Advisor-Calls"], "1")
                self.assertEqual(response.headers["X-MultiLLM-Advisor-Input-Tokens"], "2778")
                self.assertEqual(response.headers["X-MultiLLM-Advisor-Output-Tokens"], "685")

    def test_a_streamed_chat_reply_carries_the_advisor_usage_last(self):
        response, data, _ = self.chat({"stream": True}, stream_reply(advised_frames()))
        self.assertEqual(response.status_code, 200)
        chunks = frames(data)
        text = "".join(choice["delta"].get("content") or "" for chunk in chunks for choice in chunk.get("choices", []))
        self.assertEqual(text, "A synthetic answer.")
        self.assertNotIn("encrypted_content", data)
        usage = [chunk["usage"] for chunk in chunks if chunk.get("usage")][-1]
        self.assertEqual((usage["advisor"]["prompt_tokens"], usage["advisor"]["completion_tokens"]), (2778, 685))
        self.assertEqual(response.headers["X-MultiLLM-Advisor-Model"], SONNET)

    def test_responses_sends_the_tool_and_reports_advisor_usage(self):
        response, data, send = self.responses({}, json_reply(advised_message()))
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(self.upstream(send)[0]["tools"], [TOOL])
        reply = json.loads(data)
        texts = [part["text"] for item in reply["output"] if item.get("type") == "message" for part in item["content"]]
        self.assertEqual(texts, ["A synthetic answer."])
        advisor = reply["usage"]["advisor"]
        self.assertEqual((advisor["model"], advisor["input_tokens"], advisor["output_tokens"]), (SONNET, 2778, 685))
        self.assertEqual(response.headers["X-MultiLLM-Advisor-Model"], SONNET)

    def test_a_streamed_responses_reply_reports_advisor_usage(self):
        response, data, _ = self.responses({"stream": True}, stream_reply(advised_frames()))
        self.assertEqual(response.status_code, 200)
        completed = [event for event in frames(data) if event.get("type") == "response.completed"][-1]
        self.assertEqual(completed["response"]["usage"]["advisor"]["output_tokens"], 685)

    def test_function_tools_and_json_schema_keep_working_with_the_advisor(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        schema = {"type": "object", "properties": {"plan": {"type": "string"}}, "required": ["plan"]}
        answer = {**advised_message(), "content": [*advised_message()["content"][:2],
                                                   {"type": "text", "text": json.dumps({"plan": "synthetic"})}]}
        response, data, send = self.chat({"tools": [lookup], "response_format": {
            "type": "json_schema", "json_schema": {"name": "plan", "schema": schema}}}, json_reply(answer))
        self.assertEqual(response.status_code, 200, data)
        body, _ = self.upstream(send)
        self.assertEqual([tool.get("name") for tool in body["tools"]], ["lookup", "advisor"])
        self.assertEqual(body["output_config"]["format"], {"type": "json_schema", "schema": schema})
        self.assertEqual(json.loads(json.loads(data)["choices"][0]["message"]["content"]), {"plan": "synthetic"})

    def test_a_signed_tool_turn_with_advice_replays_its_blocks(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        content = [{"type": "thinking", "thinking": "Synthetic reasoning.", "signature": "c2lnbmF0dXJl"},
                   {"type": "server_tool_use", "id": "srvtoolu_synthetic", "name": "advisor", "input": {}},
                   {"type": "advisor_tool_result", "tool_use_id": "srvtoolu_synthetic", "content": ADVICE},
                   {"type": "tool_use", "id": "toolu_synthetic", "name": "lookup", "input": {"q": "x"}}]
        reply = {**advised_message(), "content": content, "stop_reason": "tool_use"}
        _, data, _ = self.chat({"tools": [lookup]}, json_reply(reply))
        message = json.loads(data)["choices"][0]["message"]
        self.assertEqual(message["tool_calls"][0]["extra_content"]["anthropic"]["content"], content)
        history = [*QUESTION, message, {"role": "tool", "tool_call_id": "toolu_synthetic", "content": "found"}]
        response, data, send = self.chat({"tools": [lookup], "messages": history}, json_reply(advised_message()))
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(self.upstream(send)[0]["messages"][1]["content"], content)
        response, data, send = self.post("/v1/chat/completions", {"model": HAIKU, "tools": [lookup], "messages": history},
                                         json_reply(advised_message()))
        self.assertEqual(response.status_code, 400)
        self.assertIn("'advisor'", json.loads(data)["error"]["message"])
        send.assert_not_called()

    def test_a_streamed_signed_tool_turn_with_advice_keeps_its_blocks(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        events = (
            {"type": "message_start", "message": {"id": "msg_s", "type": "message", "role": "assistant",
                                                  "model": "claude-haiku-5-5", "content": [], "usage": {"input_tokens": 9, "output_tokens": 1}}},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Synthetic."}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "c2ln"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "content_block_start", "index": 1, "content_block": {
                "type": "server_tool_use", "id": "srvtoolu_s", "name": "advisor", "input": {}}},
            {"type": "content_block_stop", "index": 1},
            {"type": "content_block_start", "index": 2, "content_block": {
                "type": "advisor_tool_result", "tool_use_id": "srvtoolu_s", "content": ADVICE}},
            {"type": "content_block_stop", "index": 2},
            {"type": "content_block_start", "index": 3, "content_block": {
                "type": "tool_use", "id": "toolu_s", "name": "lookup", "input": {}}},
            {"type": "content_block_delta", "index": 3, "delta": {"type": "input_json_delta", "partial_json": "{\"q\": \"x\"}"}},
            {"type": "content_block_stop", "index": 3},
            {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": advised_usage()},
            {"type": "message_stop"},
        )
        body = b"".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode() for event in events)
        response, data, _ = self.chat({"stream": True, "tools": [lookup]}, stream_reply(body))
        self.assertEqual(response.status_code, 200)
        extras = [call["extra_content"] for chunk in frames(data) for choice in chunk.get("choices", [])
                  for call in choice["delta"].get("tool_calls") or [] if "extra_content" in call]
        kinds = [block["type"] for block in extras[0]["anthropic"]["content"]]
        self.assertEqual(kinds, ["thinking", "server_tool_use", "advisor_tool_result", "tool_use"])


class AdvisorExtensionValidationTest(ExtensionTestCase):
    def test_a_malformed_advisor_field_is_refused_before_dispatch(self):
        for advisor in ("claude-sonnet-5-5", {"model": "claude-sonnet-5-5", "max_uses": 0},
                        {"model": "claude-sonnet-5-5", "max_tokens": "2048"}, {"model": "claude-sonnet-5-5", "extra": 1},
                        {"model": "claude-sonnet-5-5", "caching": "5m"}, {"max_uses": 1}, {"model": "openai:gpt-5.5"}):
            with self.subTest(advisor=advisor):
                response, data, send = self.chat({"advisor": advisor}, json_reply(advised_message()))
                self.assertEqual(response.status_code, 400, data)
                send.assert_not_called()

    def test_the_advisor_needs_a_claude_executor(self):
        for model in ("opencode:kimi-k2.6", "auto:intelligence"):
            with self.subTest(model=model):
                response, data, send = self.chat({"model": model}, json_reply(advised_message()))
                self.assertEqual(response.status_code, 400, data)
                send.assert_not_called()
        self.assertIn("anthropic:", self.chat({"model": "opencode:kimi-k2.6"}, json_reply(advised_message()))[1])

    def test_a_null_advisor_is_no_advisor(self):
        response, _, send = self.chat({"advisor": None}, json_reply(advised_message()))
        self.assertEqual(response.status_code, 200)
        body, headers = self.upstream(send)
        self.assertNotIn("tools", body)
        self.assertNotIn("X-MultiLLM-Advisor-Model", response.headers)

    def test_a_restricted_key_cannot_reach_an_opus_advisor(self):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            key = self.app_module.AuthService.create_user("restricted", scopes=["chat", "models"])["api_key"]
            self.app_module.AuthService.set_key_controls("restricted", {"allowed_models": [HAIKU], "official_only": True})
        opus = {**ADVISOR, "model": "claude-opus-5-5"}
        for send_request in (lambda: self.chat({"advisor": opus}, json_reply(advised_message()), key=key),
                             lambda: self.chat({"advisor": opus}, json_reply(advised_message()), key=key,
                                               path="/lean/v1/chat/completions"),
                             lambda: self.responses({"advisor": opus}, json_reply(advised_message()), key=key)):
            response, data, send = send_request()
            self.assertEqual(response.status_code, 403, data)
            self.assertIn("anthropic:claude-opus-5-5", data.lower())
            send.assert_not_called()
        response, _, _ = self.chat({}, json_reply(advised_message()), key=key)
        self.assertEqual(response.status_code, 403)

    def test_a_disabled_advisor_model_is_refused(self):
        fable = "anthropic:claude-fable-5-1"
        registry = sys.modules["services.model_registry"].ModelRegistry
        status = lambda model: "disabled" if model == fable else "available"
        with patch.object(registry, "get_model_status", side_effect=status):
            response, data, send = self.chat({"advisor": {**ADVISOR, "model": fable}}, json_reply(advised_message()))
        self.assertEqual(response.status_code, 400, data)
        self.assertIn(f"Model is disabled: {fable}", data)
        send.assert_not_called()


class AdvisorExtensionLedgerTest(ExtensionTestCase):
    def setUp(self):
        super().setUp()
        os.environ.update({
            "USAGE_LEDGER_ENABLED": "true", "USAGE_LEDGER_BACKEND": "sql", "USAGE_LEDGER_FLUSH_SECONDS": "300",
            "USAGE_DB_PATH": os.path.join(self.temp_dir.name, "usage.sqlite3"),
            "CONTROL_PLANE_DATABASE_URL": "",
            "MODEL_PRICING_USD_PER_MILLION": SHIPPED_PRICES,
            "PROMPT_CACHE_USAGE_BUCKETS_ENABLED": "true",
            "PROMPT_CACHE_PRICE_METADATA_JSON": "{}",
        })
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.key = self.app_module.AuthService.create_user("advised", scopes=["chat", "models"])["api_key"]

    def tearDown(self):
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        super().tearDown()

    def rows(self):
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "advised", None, 50)
        return {row["selected_model"]: row for row in rows}

    def assert_priced(self, endpoint):
        rows = self.rows()
        self.assertEqual(set(rows), {HAIKU, SONNET})
        haiku, sonnet = rows[HAIKU], rows[SONNET]
        self.assertEqual((haiku["endpoint"], sonnet["endpoint"]), (endpoint, f"{endpoint}/advisor"))
        self.assertEqual((haiku["input_tokens"], haiku["output_tokens"]), (2639, 204))
        self.assertEqual((sonnet["input_tokens"], sonnet["output_tokens"]), (2778, 685))
        self.assertAlmostEqual(haiku["cost_usd"], HAIKU_COST)
        self.assertAlmostEqual(sonnet["cost_usd"], SONNET_COST)

    def test_chat_replies_are_priced_per_model(self):
        for stream, reply in ((False, lambda: json_reply(advised_message())), (True, lambda: stream_reply(advised_frames()))):
            with self.subTest(stream=stream):
                usage_ledger.LEDGER.reset()
                response, _, _ = self.chat({"stream": stream}, reply(), key=self.key)
                self.assertEqual(response.status_code, 200)
                self.assert_priced("/v1/chat/completions")

    def test_responses_replies_are_priced_per_model(self):
        for stream, reply in ((False, lambda: json_reply(advised_message())), (True, lambda: stream_reply(advised_frames()))):
            with self.subTest(stream=stream):
                usage_ledger.LEDGER.reset()
                response, _, _ = self.responses({"stream": stream}, reply(), key=self.key)
                self.assertEqual(response.status_code, 200)
                self.assert_priced("/v1/responses")

    def test_a_capped_key_must_bound_the_advisor_field(self):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.app_module.AuthService.set_key_controls("advised", {"daily_budget_usd": 5})
        response, data, send = self.chat({"advisor": {"model": "claude-sonnet-5-5"}}, json_reply(advised_message()),
                                         key=self.key)
        self.assertEqual(response.status_code, 400, data)
        self.assertIn("max_uses", data)
        send.assert_not_called()


def test_a_similar_answer_never_stands_in_for_advice():
    from services import semantic_generation_cache

    payload = {"model": HAIKU, "messages": QUESTION}
    assert semantic_generation_cache.eligible(payload)
    assert not semantic_generation_cache.eligible({**payload, "advisor": ADVISOR})
