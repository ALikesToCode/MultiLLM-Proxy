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
PENDING = {"type": "server_tool_use", "id": "srvtoolu_pending", "name": "advisor", "input": {}}


def frames(text):
    return [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:") and line[5:].strip() != "[DONE]"]


def _frames_for(message):
    """A Messages stream for a complete reply's text and tool_use blocks."""
    events = [{"type": "message_start", "message": {**message, "content": [], "stop_reason": None,
                                                   "usage": {"input_tokens": 9, "output_tokens": 1}}}]
    for index, block in enumerate(message["content"]):
        if block["type"] == "tool_use":
            events += [{"type": "content_block_start", "index": index, "content_block": {**block, "input": {}}},
                       {"type": "content_block_delta", "index": index,
                        "delta": {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}}]
        else:
            events.append({"type": "content_block_start", "index": index, "content_block": block})
        events.append({"type": "content_block_stop", "index": index})
    events += [{"type": "message_delta", "delta": {"stop_reason": message["stop_reason"]}, "usage": message["usage"]},
               {"type": "message_stop"}]
    return b"".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode() for event in events)


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

    def test_lean_leaves_tool_results_in_place_with_the_advisor(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        for body, cleared in (({"tools": [lookup]}, True), ({"tools": [lookup], "advisor": ADVISOR}, False),
                              ({"advisor": ADVISOR}, False)):
            with self.subTest(body=list(body)):
                payload = {"model": HAIKU, "messages": QUESTION, **body}
                response, data, send = self.post("/lean/v1/chat/completions", payload, json_reply(advised_message()))
                self.assertEqual(response.status_code, 200, data)
                self.assertEqual("context_management" in self.upstream(send)[0], cleared)

    def test_a_cached_reply_keeps_the_advisor_headers(self):
        payload = {"model": HAIKU, "messages": QUESTION, "advisor": ADVISOR, "temperature": 0}
        headers = {"Authorization": "Bearer admin-test-key", "X-MultiLLM-Cache": "on"}
        with patch.object(self.app_module.ProxyService, "make_request",
                          side_effect=[json_reply(advised_message()), json_reply(advised_message())]) as send:
            replies = [self.client.post("/v1/chat/completions", json=payload, headers=headers) for _ in range(2)]
        self.assertEqual(send.call_count, 1)
        for name in ("X-MultiLLM-Advisor-Model", "X-MultiLLM-Advisor-Calls", "X-MultiLLM-Advisor-Input-Tokens",
                     "X-MultiLLM-Advisor-Output-Tokens"):
            self.assertEqual(replies[1].headers.get(name), replies[0].headers[name], name)

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
        # Without the field the advice still replays: Claude takes the history with the beta.
        response, data, send = self.post("/v1/chat/completions", {"model": HAIKU, "tools": [lookup], "messages": history},
                                         json_reply(advised_message()))
        self.assertEqual(response.status_code, 200, data)
        body, headers = self.upstream(send)
        self.assertEqual(body["messages"][1]["content"], content)
        self.assertEqual([tool["name"] for tool in body["tools"]], ["lookup"])
        self.assertIn("advisor-tool-2026-03-01", headers["anthropic-beta"].split(","))

    def test_a_pending_advisor_call_runs_when_the_tool_results_arrive(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        content = [{"type": "text", "text": "Checking."}, PENDING,
                   {"type": "tool_use", "id": "toolu_synthetic", "name": "lookup", "input": {"q": "x"}}]
        _, data, _ = self.chat({"tools": [lookup]}, json_reply({**advised_message(), "content": content,
                                                                 "stop_reason": "tool_use"}))
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
        # The call's result opened the next reply, which had no tool calls to carry it.
        later = [*history, {"role": "assistant", "content": "A synthetic answer."},
                 {"role": "user", "content": "A synthetic follow-up"}]
        for body in ({"advisor": ADVISOR}, {}):
            with self.subTest(advisor=bool(body)):
                response, data, send = self.post("/v1/chat/completions", {
                    "model": HAIKU, "tools": [lookup], "messages": later, **body}, json_reply(advised_message()))
                self.assertEqual(response.status_code, 200, data)
                self.assertEqual(self.upstream(send)[0]["messages"][1]["content"], [content[0], content[2]])

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


    def test_tool_repair_never_asks_an_advised_request_again(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {
            "type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}}}
        invalid = {**advised_message(), "stop_reason": "tool_use", "content": [
            *advised_message()["content"][:2], {"type": "tool_use", "id": "toolu_bad", "name": "lookup", "input": {}}]}
        for path, body in (("/v1/chat/completions", {"model": HAIKU, "messages": QUESTION}),
                           ("/v1/responses", {"model": HAIKU, "input": "A synthetic question"})):
            with self.subTest(path=path), patch.object(self.app_module.ProxyService, "make_request",
                                                       side_effect=[json_reply(invalid), json_reply(advised_message())]) as send:
                tools = [lookup] if path.endswith("completions") else [{"type": "function", **lookup["function"]}]
                response = self.client.post(path, json={**body, "advisor": ADVISOR, "tools": tools},
                                            headers={"Authorization": "Bearer admin-test-key",
                                                     "X-MultiLLM-Tool-Repair": "full"})
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                self.assertEqual(send.call_count, 1)


    def test_a_paused_turn_is_reported_as_unfinished(self):
        pending = {"type": "server_tool_use", "id": "srvtoolu_pending", "name": "advisor", "input": {}}
        paused = {**advised_message(), "stop_reason": "pause_turn",
                  "content": [{"type": "text", "text": "Let me check."}, pending]}
        _, data, _ = self.chat({}, json_reply(paused))
        choice = json.loads(data)["choices"][0]
        self.assertEqual((choice["finish_reason"], choice["message"]["content"]), ("length", "Let me check."))
        _, data, _ = self.responses({}, json_reply(paused))
        self.assertEqual(json.loads(data)["status"], "incomplete")
        stream = advised_frames().replace(b'"stop_reason": "end_turn", "stop_sequence"', b'"stop_reason": "pause_turn", "stop_sequence"')
        self.assertIn(b"pause_turn", stream)
        _, data, _ = self.chat({"stream": True}, stream_reply(stream))
        finishes = [choice["finish_reason"] for chunk in frames(data) for choice in chunk.get("choices", [])
                    if choice.get("finish_reason")]
        self.assertEqual(finishes, ["length"])


    def test_repair_leaves_calls_that_carry_the_native_turn(self):
        count = {"type": "function", "function": {"name": "count", "parameters": {
            "type": "object", "properties": {"n": {"type": "integer"}}, "required": ["n"]}}}
        content = [{"type": "text", "text": "Counting."}, PENDING,
                   {"type": "tool_use", "id": "toolu_synthetic", "name": "count", "input": {"n": "42"}}]
        reply = {**advised_message(), "content": content, "stop_reason": "tool_use"}
        headers = {"Authorization": "Bearer admin-test-key", "X-MultiLLM-Tool-Repair": "repair"}
        for stream in (False, True):
            with self.subTest(stream=stream):
                upstream = stream_reply(_frames_for(reply)) if stream else json_reply(reply)
                with patch.object(self.app_module.ProxyService, "make_request", return_value=upstream):
                    response = self.client.post("/v1/chat/completions", headers=headers, json={
                        "model": HAIKU, "messages": QUESTION, "advisor": ADVISOR, "tools": [count], "stream": stream})
                    data = response.get_data(as_text=True)
                calls = ([call for chunk in frames(data) for choice in chunk.get("choices", [])
                          for call in choice["delta"].get("tool_calls") or []] if stream
                         else json.loads(data)["choices"][0]["message"]["tool_calls"])
                arguments = "".join(call.get("function", {}).get("arguments", "") for call in calls)
                self.assertEqual(json.loads(arguments), {"n": "42"})
        with patch.object(self.app_module.ProxyService, "make_request", return_value=json_reply(reply)):
            message = json.loads(self.client.post("/v1/chat/completions", headers=headers, json={
                "model": HAIKU, "messages": QUESTION, "advisor": ADVISOR, "tools": [count]}).get_data(as_text=True))["choices"][0]["message"]
        history = [*QUESTION, message, {"role": "tool", "tool_call_id": "toolu_synthetic", "content": "counted"}]
        response, data, send = self.chat({"tools": [count], "messages": history}, json_reply(advised_message()))
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(self.upstream(send)[0]["messages"][1]["content"], content)


    def test_tool_choice_none_rules_out_the_advisor_without_function_tools(self):
        lookup = {"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}
        for extra in ({}, {"tools": [lookup]}):
            with self.subTest(function_tools=bool(extra)):
                _, data, send = self.chat({"tool_choice": "none", **extra}, json_reply(advised_message()))
                self.assertEqual(self.upstream(send)[0]["tool_choice"], {"type": "none"}, data)
        _, data, send = self.responses({"tool_choice": "none"}, json_reply(advised_message()))
        self.assertEqual(self.upstream(send)[0]["tool_choice"], {"type": "none"}, data)


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


def test_a_result_without_its_advisor_call_is_dropped():
    from services.protocol_translation.anthropic import chat_request_to_messages

    orphan = {"type": "advisor_tool_result", "tool_use_id": "srvtoolu_gone", "content": ADVICE}
    use = {"type": "tool_use", "id": "toolu_synthetic", "name": "lookup", "input": {}}
    call = {"id": "toolu_synthetic", "type": "function", "function": {"name": "lookup", "arguments": "{}"},
            "extra_content": {"anthropic": {"content": [orphan, use]}}}
    body = chat_request_to_messages({"model": "claude-haiku-5-5", "messages": [
        *QUESTION, {"role": "assistant", "content": None, "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "toolu_synthetic", "content": "found"}]})
    assert body["messages"][1]["content"] == [use]


def test_repair_usage_joins_the_steps_of_both_replies():
    from services.tool_repair_runtime import add_usage

    first = {"prompt_tokens": 10, "iterations": [{"type": "message", "input_tokens": 10}]}
    second = {"prompt_tokens": 5, "iterations": [{"type": "message", "input_tokens": 5}]}
    assert add_usage(first, second) == {"prompt_tokens": 15, "iterations": [*first["iterations"], *second["iterations"]]}
    assert add_usage({"prompt_tokens": 10}, {"prompt_tokens": 5}) == {"prompt_tokens": 15}
    # A reply without steps becomes one step of the request's model, so advice stays billed.
    advised = {"prompt_tokens": 10, "completion_tokens": 2, "iterations": [
        {"type": "message", "input_tokens": 10, "output_tokens": 2},
        {"type": "advisor_message", "model": "claude-sonnet-5-5", "input_tokens": 50, "output_tokens": 7}]}
    plain = {"prompt_tokens": 9, "completion_tokens": 3,
             "prompt_tokens_details": {"cached_tokens": 4, "cache_write_tokens": 1}}
    step = {"type": "message", "input_tokens": 4, "output_tokens": 3,
            "cache_read_input_tokens": 4, "cache_creation_input_tokens": 1}
    assert add_usage(advised, plain)["iterations"] == [*advised["iterations"], step]
    assert add_usage(plain, advised)["iterations"] == [step, *advised["iterations"]]
