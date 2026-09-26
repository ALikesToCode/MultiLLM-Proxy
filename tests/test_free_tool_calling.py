"""Tool calling on free pools: validation, tool-capable routing and output checks."""

import json
from contextlib import closing
from unittest.mock import patch

import requests
from flask import Response

from services.free_quota_service import FreeQuotaService
from tests.test_free_routes import catalog_row
from tests.unified_api_test_case import UnifiedApiTestCase

WEATHER = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Current weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
            "additionalProperties": False,
        },
    },
}


def tool_row(provider, model, tools, **kwargs):
    row = catalog_row(provider, model, **kwargs)
    if tools is not None:
        row["provider_metadata"]["supports_tools"] = tools
    return row


def clear_cooldowns():
    with closing(FreeQuotaService._connect()) as connection, connection:
        connection.execute("DELETE FROM free_route_cooldowns")


def tool_call_response(name="get_weather", arguments='{"city": "Paris"}', content=None):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({
        "id": "chatcmpl-tools",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": name, "arguments": arguments}},
            ]},
            "finish_reason": "tool_calls",
        }],
    }).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


class FreeToolCallingTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            FREE_ROUTE_FREE_TIER_PROVIDERS="", FREE_ROUTE_EXTRA_PROVIDERS="", FREE_ROUTE_PROVIDER_ORDER=""
        )
        self.rows = [
            tool_row("opencode", "mimo-v2.5-free", True, vision=True),
            tool_row("opencode", "hy3-free", None),
            tool_row("aihubmix", "gemma-4-31b-it-free", False, vision=True),
        ]
        catalog = patch("services.free_model_policy.build_model_catalog", side_effect=lambda _: self.rows)
        catalog.start()
        self.addCleanup(catalog.stop)
        keys = {"opencode": "test-opencode", "aihubmix": "test-aihubmix", "openrouter": "test-openrouter"}
        auth = patch.object(self.app_module.AuthService, "get_api_key", side_effect=keys.get)
        auth.start()
        self.addCleanup(auth.stop)
        self.headers = {"Authorization": "Bearer admin-test-key"}

    def payload(self, **extra):
        return {
            "model": "free:text",
            "messages": [{"role": "user", "content": "Weather in Paris?"}],
            "tools": [WEATHER],
            **extra,
        }

    def post(self, payload):
        return self.client.post("/v1/chat/completions", headers=self.headers, json=payload)

    def test_tools_reach_only_candidates_with_confirmed_support(self):
        with patch("app.ProxyService.make_request", return_value=tool_call_response()) as send:
            response = self.post(self.payload(tool_choice="auto", parallel_tool_calls=False))
        self.assertEqual(response.status_code, 200)
        message = response.get_json()["choices"][0]["message"]
        self.assertEqual(message["tool_calls"][0]["function"]["name"], "get_weather")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "opencode:mimo-v2.5-free")
        sent = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(sent["tools"], [WEATHER])
        self.assertEqual(sent["tool_choice"], "auto")
        self.assertIs(sent["parallel_tool_calls"], False)
        self.assertEqual(sent["model"], "mimo-v2.5-free")

    def test_failover_skips_unknown_and_unsupported_models(self):
        limited = Response("quota", status=429, headers={"Retry-After": "60"})
        with patch("app.ProxyService.make_request", side_effect=[limited, tool_call_response()]) as send:
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 200)
        # hy3-free (unknown) and the AIHubMix model (false) are never tried; the
        # reviewed OpenRouter free router is, with tools as a required parameter.
        self.assertEqual([call.kwargs["api_provider"] for call in send.call_args_list], ["opencode", "openrouter"])
        sent = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(sent["model"], "openrouter/free")
        self.assertEqual(sent["provider"], {"require_parameters": True})

    def test_tool_history_without_definitions_still_needs_tool_support(self):
        history = {
            "model": "free:text",
            "messages": [
                {"role": "user", "content": "Weather in Paris?"},
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "18 C and sunny"},
            ],
        }
        with patch("app.ProxyService.make_request", return_value=self._chat_response("It is 18 C.")) as send:
            response = self.post(history)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_args.kwargs["api_provider"], "opencode")
        self.assertEqual(json.loads(send.call_args.kwargs["data"])["messages"], history["messages"])

    def test_invalid_tool_calls_fail_over_and_cool_only_that_model(self):
        for bad in (
            tool_call_response(name="delete_everything"),
            tool_call_response(arguments="not json"),
            tool_call_response(arguments='["a list"]'),
            tool_call_response(arguments='{"city": "a", "city": "b"}'),
        ):
            with self.subTest(body=bad._content[:60]):
                clear_cooldowns()
                with patch("app.ProxyService.make_request", side_effect=[bad, tool_call_response()]) as send:
                    response = self.post(self.payload())
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
                self.assertGreater(FreeQuotaService.remaining("model:opencode:mimo-v2.5-free"), 0)
                self.assertEqual(FreeQuotaService.remaining("provider:opencode"), 0)
                self.assertEqual(send.call_count, 2)

    def test_required_and_named_tool_choice_are_enforced(self):
        cases = (
            ({"tool_choice": "required"}, self._chat_response("No tool needed."), tool_call_response()),
            ({"tool_choice": {"type": "function", "function": {"name": "get_weather"}}},
             self._chat_response("Sunny."), tool_call_response(content="Checking.")),
            ({"tool_choice": "none"}, tool_call_response(), self._chat_response("Sunny.")),
        )
        for extra, rejected, accepted in cases:
            with self.subTest(extra=extra):
                clear_cooldowns()
                with patch("app.ProxyService.make_request", side_effect=[rejected, accepted]) as send:
                    response = self.post(self.payload(**extra))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(send.call_count, 2)
                self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")

    def test_streamed_tool_calls_are_delivered(self):
        chunks = [
            {"choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_1", "type": "function",
                 "function": {"name": "get_weather", "arguments": ""}}]}}]},
            {"choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": '{"city":"Paris"}'}}]}}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
        ]
        body = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
        with patch("app.ProxyService.make_request",
                   return_value=Response(body, content_type="text/event-stream")):
            response = self.post(self.payload(stream=True))
            text = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('"tool_calls"', text)
        self.assertIn("data: [DONE]", text)
        self.assertNotIn("free_stream_interrupted", text)

    def test_json_output_does_not_apply_to_a_tool_call(self):
        response_format = {"type": "json_object"}
        with patch("app.ProxyService.make_request", return_value=tool_call_response()):
            response = self.post(self.payload(response_format=response_format))
        self.assertEqual(response.status_code, 200)

    def test_no_tool_capable_candidate_is_unavailable_not_paid(self):
        self.rows = [tool_row("opencode", "hy3-free", None)]
        with patch.object(self.app_module.AuthService, "get_api_key",
                          side_effect={"opencode": "test-opencode"}.get), \
                patch("app.ProxyService.make_request") as send:
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 503)
        error = response.get_json()["error"]
        self.assertEqual(error["code"], "free_models_unavailable")
        self.assertIn("tool-calling", error["message"])
        send.assert_not_called()

    def test_provider_tool_incompatibility_moves_on_without_cooling(self):
        refusal = Response(json.dumps({"error": {"message": "This model does not support tools"}}),
                           status=400, content_type="application/json")
        with patch("app.ProxyService.make_request", side_effect=[refusal, tool_call_response()]) as send:
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(FreeQuotaService.remaining("provider:opencode"), 0)

    def test_free_models_listing_reports_tool_support(self):
        listing = self.client.get("/v1/free/text/models", headers=self.headers).get_json()["data"][0]
        self.assertIs(listing["capabilities"]["supports_tools"], True)
        support = {candidate["id"]: candidate["supports_tools"] for candidate in listing["candidates"]}
        self.assertEqual(support["opencode:mimo-v2.5-free"], True)
        self.assertIsNone(support["opencode:hy3-free"])
        self.assertIs(support["aihubmix:gemma-4-31b-it-free"], False)
        self.assertIs(support["openrouter:openrouter/free"], True)

    def test_a_listed_price_excludes_a_free_labelled_model(self):
        self.rows = [tool_row("opencode", "mimo-v2.5-free", True)]
        self.rows[0]["provider_metadata"]["input_cost_per_million"] = 0.5
        listing = self.client.get("/v1/free/text/models", headers=self.headers).get_json()["data"][0]
        self.assertNotIn("opencode:mimo-v2.5-free", [candidate["id"] for candidate in listing["candidates"]])

    def test_invalid_tool_requests_never_dispatch(self):
        base = self.payload()
        invalid = [
            {**base, "tools": None},
            {**base, "tools": []},
            {**base, "tools": [{"type": "web_search"}]},
            {**base, "tools": [{"type": "function", "function": {"name": "bad name"}}]},
            {**base, "tools": [WEATHER, WEATHER]},
            {**base, "tools": [{**WEATHER, "extra": True}]},
            {**base, "tools": [{"type": "function", "function": {"name": "x", "parameters": {"type": "array"}}}]},
            {**base, "tools": [{"type": "function", "function": {
                "name": "x", "parameters": {"type": "object", "$ref": "https://example.test/schema.json"}}}]},
            {**base, "tools": [{"type": "function", "function": {
                "name": "x", "parameters": {"type": "object", "properties": {"a": {"type": 7}}}}}]},
            {**base, "tools": [{"type": "function", "function": {"name": f"f{index}"}} for index in range(129)]},
            {**base, "tools": [{"type": "function", "function": {"name": "x", "description": "d" * 70000}}]},
            {**base, "tool_choice": "sometimes"},
            {**base, "tool_choice": {"type": "function", "function": {"name": "undeclared"}}},
            {**base, "parallel_tool_calls": "yes"},
            {"model": "free:text", "messages": base["messages"], "tool_choice": "auto"},
            {"model": "free:text", "messages": base["messages"], "parallel_tool_calls": True},
            {**base, "messages": [{"role": "tool", "content": "result"}]},
            {**base, "messages": [{"role": "assistant", "tool_calls": []}]},
            {**base, "messages": [{"role": "assistant", "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": {}}}]}]},
            {**base, "messages": [{"role": "assistant", "tool_calls": [
                {"id": "call_1", "type": "retrieval", "function": {"name": "get_weather", "arguments": "{}"}}]}]},
        ]
        with patch("app.ProxyService.make_request") as send:
            for payload in invalid:
                with self.subTest(payload=json.dumps(payload)[:120]):
                    self.assertEqual(self.post(payload).status_code, 400)
        send.assert_not_called()
