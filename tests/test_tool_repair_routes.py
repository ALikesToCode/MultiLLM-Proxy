"""HTTP, protocol, free-pool and intelligence acceptance with synthetic upstreams."""

import json
from unittest.mock import patch

from flask import Response

from services.tool_repair_runtime import HEADER
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream, frames
from tests.test_free_tool_calling import FreeToolCallingTest, tool_call_response
from tests.test_protocol_routes import ANTHROPIC_MESSAGE, RESPONSES_BODY, json_upstream
from tests.test_tool_call_repair import TOOLS
from tests.unified_api_test_case import UnifiedApiTestCase


def call(arguments, name="lookup"):
    return {"id":"call_synthetic","type":"function","function":{"name":name,"arguments":arguments}}


def chat(arguments, name="lookup"):
    result = completion(None, calls=[call(arguments, name)])
    result.update(id="chatcmpl-synthetic", object="chat.completion", model="mimo-v2.5", created=1)
    return result


class ToolRepairRouteTests(UnifiedApiTestCase):
    def payload(self, **kwargs):
        return {"model":"mimo:mimo-v2.5","messages":[{"role":"user","content":"synthetic query"}],"tools":TOOLS, **kwargs}

    def send(self, path, body, responses, mode="repair"):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=responses) as send:
            response = self.client.post(path, json=body, headers={"Authorization":"Bearer admin-test-key", HEADER:mode})
            response.get_data()
        return response, send

    def test_chat_repair_and_body_identical_off(self):
        body = json.dumps(chat('{q:"a",}', "LOOKUP"), indent=2)
        result, send = self.send("/v1/chat/completions", self.payload(), [Response(body, content_type="application/json")])
        assert result.status_code == 200 and send.call_count == 1
        assert result.json["choices"][0]["message"]["tool_calls"][0]["function"] == {"name":"lookup","arguments":'{"q":"a"}'}
        assert result.headers[HEADER] == "checked=1 repaired=1 extracted=0 invalid=0 reasked=0"
        result, _ = self.send("/v1/chat/completions", self.payload(), [Response(body, content_type="application/json")], "off")
        assert result.data.decode() == body

    def test_full_corrects_once_same_model_and_aggregates_usage(self):
        result, send = self.send("/v1/chat/completions", self.payload(), [json_upstream(chat('{}')),json_upstream(chat('{q:"a"}'))], "full")
        assert result.status_code == 200 and send.call_count == 2
        assert result.json["usage"] == {"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}
        assert result.json["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] == '{"q":"a"}'
        assert result.headers[HEADER].endswith("invalid=0 reasked=1")
        assert len({item.kwargs["url"] for item in send.call_args_list}) == 1
        assert len({json.loads(item.kwargs["data"])["model"] for item in send.call_args_list}) == 1

    def test_invalid_reask_and_upstream_failure_keep_original(self):
        for extra in (json_upstream(chat('{}')), Response("error", status=503)):
            result, send = self.send("/v1/chat/completions", self.payload(), [json_upstream(chat('{}')),extra], "full")
            assert result.status_code == 200 and send.call_count == 2
            assert result.json["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] == '{}'
            assert result.headers[HEADER].endswith("invalid=1 reasked=1")

    def test_translated_messages_and_responses_receive_repaired_calls(self):
        for path in ("/v1/messages", "/v1/responses"):
            if path.endswith("messages"):
                payload = {"model":"mimo:mimo-v2.5","messages":[{"role":"user","content":"test"}],"max_tokens":50,
                           "tools":[{"name":"lookup","input_schema":TOOLS[0]["function"]["parameters"]}]}
            else:
                payload = {"model":"mimo:mimo-v2.5","input":"test","tools":[{"type":"function", **TOOLS[0]["function"]}]}
            response, _ = self.send(path, payload, [json_upstream(chat('{q:5}', 'functions.LOOKUP'))])
            assert response.status_code == 200
            if path.endswith("messages"):
                tool = next(item for item in response.json["content"] if item["type"] == "tool_use")
                assert tool["input"] == {"q":"5"}
                assert tool["name"] == "lookup"
            else:
                tool = next(item for item in response.json["output"] if item["type"] == "function_call")
                assert tool["arguments"] == '{"q":"5"}'
                assert tool["name"] == "lookup"
            assert "repaired=1" in response.headers[HEADER]

    def test_native_messages_and_responses_receive_repaired_calls(self):
        message = {**ANTHROPIC_MESSAGE, "content":[{"type":"tool_use","id":"call_synthetic","name":"LOOKUP","input":{"q":5}}], "stop_reason":"tool_use"}
        response = {**RESPONSES_BODY, "output":[{"type":"function_call","id":"fc_synthetic","call_id":"call_synthetic","name":"LOOKUP","arguments":'{q:5}',"status":"completed"}]}
        inputs = [
            ("/v1/messages", {"model":"opencode:minimax-m3","messages":[{"role":"user","content":"test"}],"max_tokens":50,"tools":[{"name":"lookup","input_schema":TOOLS[0]["function"]["parameters"]}]}, message),
            ("/v1/responses", {"model":"opencode:grok-4.6","input":"test","tools":[{"type":"function",**TOOLS[0]["function"]}]}, response),
        ]
        for path, payload, answer in inputs:
            repaired, send = self.send(path, payload, [json_upstream(answer)])
            assert repaired.status_code == 200 and send.call_count == 1
            if path.endswith("messages"):
                assert repaired.json["content"][0]["input"] == {"q":"5"}
            else:
                assert repaired.json["output"][0]["arguments"] == '{"q":"5"}'
            assert "repaired=1" in repaired.headers[HEADER]

    def test_native_full_reask_same_protocol(self):
        payload = {"model":"opencode:grok-4.6","input":"test","tools":[{"type":"function",**TOOLS[0]["function"]}]}
        def response(arguments):
            return {**RESPONSES_BODY,"output":[{"type":"function_call","id":"fc_synthetic","call_id":"call_synthetic","name":"lookup","arguments":arguments,"status":"completed"}]}
        repaired, send = self.send("/v1/responses", payload, [json_upstream(response('{}')),json_upstream(response('{q:"a"}'))], "full")
        assert repaired.status_code == 200 and send.call_count == 2
        assert repaired.json["output"][0]["arguments"] == '{"q":"a"}'
        assert all(item.kwargs["url"].endswith("/responses") for item in send.call_args_list)
        assert repaired.json["usage"]["total_tokens"] == 14

    def test_native_unchanged_calls_preserve_vendor_fields_and_off_bytes(self):
        payload = {"model":"opencode:grok-4.6","input":"test","tools":[{"type":"function",**TOOLS[0]["function"]}]}
        native = {**RESPONSES_BODY,"synthetic_extension":{"preserve":True},"output":[{"type":"function_call","id":"fc_synthetic","call_id":"call_synthetic","name":"lookup","arguments":'{"q":"a"}',"status":"completed"}]}
        body = json.dumps(native, indent=2)
        for mode in ("repair", "off"):
            response, _ = self.send("/v1/responses", payload, [Response(body, content_type="application/json")], mode)
            assert response.data.decode() == body

    def test_stream_repairs_and_preserves_immediate_content(self):
        values = [
            {"choices":[{"index":0,"delta":{"content":"Checking.","tool_calls":[{"index":0,"id":"call_synthetic","type":"function","function":{"name":"LOOKUP","arguments":"{q:"}}]},"finish_reason":None}]},
            {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"5,}"}}]},"finish_reason":None}]},
            {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]},
            {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}},
        ]
        body = b"".join(frames(*values, "[DONE]"))
        response, send = self.send("/v1/chat/completions", self.payload(stream=True), [Response(body,content_type="text/event-stream")], "full")
        text = response.get_data(as_text=True)
        assert response.status_code == 200 and send.call_count == 1
        assert text.index("Checking.") < text.index('"name":"lookup"') < text.index('"finish_reason":"tool_calls"') < text.index('[DONE]')
        assert '"arguments":"{\\"q\\":\\"5\\"}"' in text
        assert '"total_tokens": 6' in text

    def test_logs_contain_counts_only(self):
        value = "private-argument-canary"
        with patch("services.tool_repair_runtime.logger.info") as log:
            response, _ = self.send("/v1/chat/completions", self.payload(), [json_upstream(chat("{q:'"+value+"',}"))])
        assert response.status_code == 200
        assert log.call_count == 1
        rendered = str(log.call_args)
        assert value not in rendered and "arguments" not in rendered and "synthetic query" not in rendered
        assert "tool_call_repair" in rendered and "checked=1" in rendered


class FreeToolRepairTests(FreeToolCallingTest):
    def test_free_deterministic_repair_before_existing_output_gate(self):
        with patch("app.ProxyService.make_request", return_value=tool_call_response(name="GET_WEATHER",arguments="{city:'Paris',}")) as send:
            response = self.post(self.payload())
        assert response.status_code == 200 and send.call_count == 1
        assert response.json["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] == '{"city":"Paris"}'
        assert "repaired=1" in response.headers[HEADER]

    def test_free_full_reask_accounting(self):
        self.headers[HEADER] = "full"
        first, second = tool_call_response(arguments="{}"), tool_call_response()
        for item in (first, second):
            body = json.loads(item.content)
            body["usage"] = {"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}
            item._content = json.dumps(body).encode()
        with patch("app.ProxyService.make_request", side_effect=[first,second]) as send:
            response = self.post(self.payload())
        assert response.status_code == 200 and send.call_count == 2
        assert response.json["usage"]["total_tokens"] == 12
        assert response.headers[HEADER].endswith("invalid=0 reasked=1")
        assert len({item.kwargs["url"] for item in send.call_args_list}) == 1


class IntelligenceToolRepairTests(IntelligenceApiTestCase):
    def test_off_stream_preserves_original_fragments(self):
        from tests.test_intelligence_stream import delta, events
        self.seed()
        self.headers[HEADER] = "off"
        first = {"index":0,"id":"call_synthetic","type":"function","function":{"name":"lookup","arguments":'{"q":'}}
        second = {"index":0,"function":{"arguments":'"a"}'}}
        stream = frames(delta({"tool_calls":[first]}), delta({"tool_calls":[second]}), delta({}, "tool_calls"),
                        {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}, "[DONE]")
        with self.requests(return_value=upstream(headers={"Content-Type":"text/event-stream"}, chunks=stream)):
            response = self.post(tools=TOOLS, stream=True)
            output = events(response)
        assert output[0]["choices"][0]["delta"]["tool_calls"] == [first]
        assert output[1]["choices"][0]["delta"]["tool_calls"] == [second]
        assert response.headers[HEADER] == "checked=0 repaired=0 extracted=0 invalid=0 reasked=0"

    def test_stream_error_flushes_calls_before_terminal_error(self):
        self.seed()
        frame = {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0, **call('{q:"a"}', "LOOKUP")}]}}]}
        with self.requests(return_value=upstream(headers={"Content-Type":"text/event-stream"}, chunks=frames(frame))):
            response = self.post(tools=TOOLS, stream=True)
            text = response.get_data(as_text=True)
        assert text.index('"name":"lookup"') < text.index('"error"')
        assert 'stream_interrupted' in text

    def test_intelligence_deterministic_before_schema_gate(self):
        self.seed()
        with self.requests(return_value=upstream(chat('{q:5}', 'LOOKUP'))) as send:
            response = self.post(tools=TOOLS)
        assert response.status_code == 200 and send.call_count == 1
        assert response.json["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] == '{"q":"5"}'
        assert 'repaired=1' in response.headers[HEADER]

    def test_intelligence_full_same_model_and_settled_usage(self):
        self.seed(max_attempts=3)
        self.headers[HEADER] = "full"
        with self.requests(side_effect=[upstream(chat('{}')),upstream(chat('{q:"a"}'))]) as send:
            response = self.post(tools=TOOLS)
        assert response.status_code == 200 and send.call_count == 2
        assert response.json["usage"]["total_tokens"] == 12
        assert response.json["multillm"]["attempts"] == 2
        assert response.json["multillm"]["usage_complete"]
        assert response.headers[HEADER].endswith("invalid=0 reasked=1")
        assert len({json.loads(item.kwargs["data"])["model"] for item in send.call_args_list}) == 1

    def test_intelligence_full_respects_attempt_limit(self):
        self.seed(max_attempts=1)
        self.headers[HEADER] = "full"
        with self.requests(return_value=upstream(chat('{}'))) as send:
            response = self.post(tools=TOOLS, model="openai:small", routing={})
        assert response.status_code == 502 and send.call_count == 1

    def test_intelligence_stream_repairs_and_never_reasks(self):
        self.seed()
        self.headers[HEADER] = "full"
        values = [
            {"choices":[{"index":0,"delta":{"content":"Checking."}}]},
            {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0, **call("{q:5}","LOOKUP")} ]}}]},
            {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]},
            {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}},
        ]
        with self.requests(return_value=upstream(headers={"Content-Type":"text/event-stream"},chunks=frames(*values,"[DONE]"))) as send:
            response = self.post(tools=TOOLS, stream=True)
            text = response.get_data(as_text=True)
        assert send.call_count == 1
        assert text.index("Checking.") < text.index('"name":"lookup"') < text.index('"finish_reason":"tool_calls"')
        assert 'stream_interrupted' not in text and 'output_validation_failed' not in text
        assert '"usage_complete":true' in text
