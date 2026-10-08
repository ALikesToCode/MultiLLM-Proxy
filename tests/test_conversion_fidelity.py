"""Content-free reports on registered managed conversion routes."""

import copy
import json
from unittest.mock import patch

import pytest
from flask import Flask, Response

from services.conversion_diagnostics import request_report, response_report
from services.protocol_translation import CHAT, MESSAGES, RESPONSES, translate_request
from tests.test_protocol_routes import CHAT_COMPLETION, CHAT_STREAM, json_upstream, sse_upstream
from tests.unified_api_test_case import UnifiedApiTestCase


def fields(report):
    return {field["path"]: field["classification"] for field in report["fields"]}


def test_same_protocol_is_exact_and_does_not_mutate():
    body = {"model": "opencode:kimi-k2.6", "messages": [{"role": "user", "content": "private"}]}
    saved = copy.deepcopy(body)
    assert request_report(body, CHAT, CHAT)["fidelity"] == "exact"
    assert body == saved


def test_semantic_and_dropped_fields_match_translation():
    body = {"model": "x", "input": "private", "max_output_tokens": 20,
            "text": {"verbosity": "high"}, "metadata": {"private-key": "private"}}
    saved = copy.deepcopy(body)
    before = translate_request(body, RESPONSES, CHAT)
    report = request_report(body, RESPONSES, CHAT)
    assert fields(report)["request.input"] == "semantic"
    assert fields(report)["request.max_output_tokens"] == "semantic"
    assert fields(report)["request.text.verbosity"] == "lossy"
    assert fields(report)["request.metadata"] == "lossy"
    assert report["fidelity"] == "lossy"
    assert "private" not in json.dumps(report)
    assert translate_request(body, RESPONSES, CHAT) == before
    assert body == saved


@pytest.mark.parametrize("body,source,target,path,classification", [
    ({"input": "x", "reasoning": {"effort": "high", "summary": "auto"}}, RESPONSES, CHAT,
     "request.reasoning.summary", "lossy"),
    ({"messages": [{"role": "user", "content": "x"}], "container": "private"}, MESSAGES, CHAT,
     "request.container", "unsupported"),
    ({"input": "x", "previous_response_id": "private"}, RESPONSES, CHAT,
     "request.previous_response_id", "unsupported"),
    ({"messages": [{"role": "user", "content": "x"}], "temperature": 2}, CHAT, MESSAGES,
     "request.temperature", "semantic"),
    ({"messages": [{"role": "user", "content": "x"}], "stop": ["x"]}, CHAT, RESPONSES,
     "request.stop", "lossy"),
    ({"messages": [{"role": "user", "content": [{"type": "text", "text": "private",
       "cache_control": {"type": "ephemeral"}}]}]}, MESSAGES, CHAT,
     "request.messages[].content[].cache_control", "lossy"),
    ({"messages": [{"role": "user", "content": "x"}], "thinking": {"type": "adaptive"}},
     MESSAGES, CHAT, "request.thinking", "lossy"),
    ({"messages": [{"role": "user", "content": "x"}], "output_config": {"effort": "high"}},
     MESSAGES, CHAT, "request.output_config", "semantic"),
    ({"messages": [{"role": "user", "content": "x"}], "tools": [
        {"type": "function", "function": {"name": "f", "strict": True, "parameters": {"type": "object"}}}]},
     CHAT, MESSAGES, "request.tools[].function.strict", "lossy"),
    ({"messages": [{"role": "user", "content": "x"}], "max_completion_tokens": 32},
     CHAT, RESPONSES, "request.max_completion_tokens", "semantic"),
    ({"messages": [{"role": "user", "content": "x"}], "reasoning": {"effort": "high"}},
     CHAT, RESPONSES, "request.reasoning", "semantic"),
])
def test_known_conversion_losses(body, source, target, path, classification):
    assert fields(request_report(body, source, target))[path] == classification


def test_response_fields_and_tool_values_are_content_free():
    body = copy.deepcopy(CHAT_COMPLETION)
    body["choices"][0]["logprobs"] = {"content": "private"}
    body["choices"][0]["message"]["tool_calls"] = [
        {"id": "private", "type": "function", "function": {"name": "private", "arguments": "private"}}]
    report = response_report(body, CHAT, RESPONSES)
    assert fields(report)["response.choices[].logprobs"] == "lossy"
    assert "private" not in json.dumps(report)


class ConversionRouteTest(UnifiedApiTestCase):
    def setUp(self):
        self.loader = patch("env_loader.load_runtime_env")
        self.loader.start()
        self.addCleanup(self.loader.stop)
        with patch("config.load_runtime_env"):
            super().setUp()
        self.upstream = patch("app.ProxyService.make_request", side_effect=AssertionError("unexpected dispatch"))
        self.http = self.upstream.start()
        self.addCleanup(self.upstream.stop)
        self.ids = patch("services.protocol_translation.responses.new_id", return_value="fixed-id")
        self.ids.start()
        self.addCleanup(self.ids.stop)

    def report(self, body=None, headers=None, **kwargs):
        return self.client.post("/v1/conversion/report", headers=headers or {
            "Authorization": "Bearer admin-test-key"}, json=body, **kwargs)

    def test_registered_dry_run_is_exact_or_semantic_and_never_dispatches(self):
        for source, target, request_body in [
            (CHAT, CHAT, {"model": "opencode:kimi-k2.6", "messages": [{"role": "user", "content": "private"}]}),
            (RESPONSES, CHAT, {"model": "opencode:kimi-k2.6", "input": "private"}),
        ]:
            response = self.report({"source_protocol": source, "target_protocol": target, "request": request_body})
            assert response.status_code == 200
            assert response.json["fidelity"] == ("exact" if source == target else "semantic")
            assert "private" not in response.get_data(as_text=True)
        self.http.assert_not_called()

    def test_unsupported_dry_run_is_real_400_without_values(self):
        response = self.report({"source_protocol": MESSAGES, "target_protocol": CHAT,
            "request": {"model": "opencode:kimi-k2.6", "container": "private",
                        "messages": [{"role": "user", "content": "private"}]}})
        assert response.status_code == 400
        assert response.json["fidelity"] == "unsupported"
        assert "private" not in response.get_data(as_text=True)
        self.http.assert_not_called()

    def test_dry_run_auth_scope_and_nested_model_allowlist(self):
        from services import key_controls

        body = {"source_protocol": RESPONSES, "target_protocol": CHAT,
                "request": {"model": "opencode:kimi-k2.6", "input": "private"}}
        assert self.report(body, {"Authorization": "Bearer invalid"}).status_code == 401
        with patch.object(key_controls, "model_allowed", return_value=False) as allowed:
            assert self.report(body).status_code == 403
            assert allowed.call_args.args[1] == "opencode:kimi-k2.6"
        with patch("route_helpers.AuthService.verify_api_key", return_value={
            "username": "limited", "scopes": ["knowledge"]}):
            assert self.report(body).status_code == 403
        self.http.assert_not_called()

    def test_dry_run_body_limit_precedes_parsing(self):
        response = self.client.post("/v1/conversion/report", headers={
            "Authorization": "Bearer admin-test-key", "Content-Type": "application/json"},
            data=b" " * (1024 * 1024 + 1))
        assert response.status_code == 413
        self.http.assert_not_called()

    def test_invalid_dry_run_shapes_and_protocols(self):
        for body in ([], {}, {"source_protocol": "private", "target_protocol": CHAT, "request": {}},
                     {"source_protocol": CHAT, "target_protocol": RESPONSES, "request": []},
                     {"source_protocol": CHAT, "target_protocol": CHAT, "request": {}}):
            assert self.report(body).status_code == 400
        self.http.assert_not_called()

    def test_dry_run_limit_without_content_length_and_exact_limit(self):
        body = {"source_protocol": CHAT, "target_protocol": CHAT,
                "request": {"model": "opencode:kimi-k2.6", "messages": [{"role": "user", "content": "private"}]}}
        encoded = json.dumps(body).encode()
        response = self.client.post("/v1/conversion/report", headers={
            "Authorization": "Bearer admin-test-key", "Content-Type": "application/json"},
            data=encoded + b" " * (1024 * 1024 - len(encoded)))
        assert response.status_code == 200
        response = self.client.post("/v1/conversion/report", headers={
            "Authorization": "Bearer admin-test-key", "Content-Type": "application/json"},
            data=b" " * (1024 * 1024 + 1),
            environ_overrides={"CONTENT_LENGTH": "", "wsgi.input_terminated": True})
        assert response.status_code == 413
        self.http.assert_not_called()

    def test_opt_in_headers_do_not_change_request_or_response_bytes(self):
        body = {"model": "opencode:kimi-k2.6", "input": "private", "metadata": {"label": "private"}}
        results, sent = [], []
        for enabled in (False, True):
            self.http.side_effect = None
            self.http.return_value = json_upstream(CHAT_COMPLETION)
            headers = {"Authorization": "Bearer admin-test-key"}
            if enabled:
                headers["X-MultiLLM-Conversion-Report"] = "1"
            response = self.client.post("/v1/responses", json=body, headers=headers)
            results.append(response)
            sent.append(self.http.call_args.kwargs["data"])
        assert results[0].data == results[1].data
        assert sent[0] == sent[1]
        assert "X-MultiLLM-Conversion-Fidelity" not in results[0].headers
        assert results[1].headers["X-MultiLLM-Conversion-Fidelity"] == "lossy"
        assert "private" not in str(results[1].headers)
        assert "request.metadata" in results[1].headers["X-MultiLLM-Conversion-Fields"]

    def test_unsupported_opt_in_remains_400_without_dispatch(self):
        response = self.client.post("/v1/responses", headers={"Authorization": "Bearer admin-test-key",
            "X-MultiLLM-Conversion-Report": "1"}, json={"model": "opencode:kimi-k2.6",
            "input": "private", "previous_response_id": "private"})
        assert response.status_code == 400
        assert response.headers["X-MultiLLM-Conversion-Fidelity"] == "unsupported"
        self.http.assert_not_called()

    def test_default_stream_bytes_headers_and_laziness_are_unchanged(self):
        from routes.protocol_bridge import translate_downstream_response

        app = Flask(__name__)
        seen = []

        def stream():
            seen.append(True)
            yield from CHAT_STREAM

        with app.test_request_context(headers={}):
            response = translate_downstream_response(Response(stream(), content_type="text/event-stream"),
                source=CHAT, target=RESPONSES, stream=True)
            assert not seen
            assert "X-MultiLLM-Conversion-Fidelity" not in response.headers
            assert response.mimetype == "text/event-stream"
            response.close()
        self.http.side_effect = None
        self.http.return_value = sse_upstream(CHAT_STREAM)
        response = self.client.post("/v1/responses", headers={"Authorization": "Bearer admin-test-key"},
            json={"model": "opencode:kimi-k2.6", "input": "private", "stream": True})
        assert response.status_code == 200
        assert "response.completed" in response.get_data(as_text=True)
        assert "X-MultiLLM-Conversion-Fidelity" not in response.headers

    def test_headers_are_bounded_and_do_not_echo_unknown_keys(self):
        body = {"model": "opencode:kimi-k2.6", "input": "private", "private\r\nheader": "private"}
        self.http.side_effect = None
        self.http.return_value = json_upstream(CHAT_COMPLETION)
        response = self.client.post("/v1/responses", json=body, headers={
            "Authorization": "Bearer admin-test-key", "X-MultiLLM-Conversion-Report": "1"})
        header = response.headers["X-MultiLLM-Conversion-Fields"]
        assert len(header.encode("ascii")) <= 2048
        assert "private" not in header

    def test_chat_to_native_bridge_is_reported_and_default_body_is_unchanged(self):
        from tests.test_protocol_routes import ANTHROPIC_MESSAGE

        self.http.side_effect = None
        self.http.return_value = json_upstream(ANTHROPIC_MESSAGE)
        response = self.client.post("/v1/chat/completions", headers={
            "Authorization": "Bearer admin-test-key", "X-MultiLLM-Conversion-Report": "1"},
            json={"model": "opencode:minimax-m3", "messages": [{"role": "user", "content": "private"}],
                  "temperature": 2})
        assert response.status_code == 200
        assert response.headers["X-MultiLLM-Conversion-Fidelity"] == "semantic"
        assert "request.temperature" in response.headers["X-MultiLLM-Conversion-Fields"]

    def test_stream_opt_in_preserves_bytes_and_dispatch_count(self):
        results, sent = [], []
        for enabled in (False, True):
            self.http.reset_mock()
            self.http.side_effect = None
            self.http.return_value = sse_upstream(CHAT_STREAM)
            headers = {"Authorization": "Bearer admin-test-key"}
            if enabled:
                headers["X-MultiLLM-Conversion-Report"] = "1"
            response = self.client.post("/v1/responses", headers=headers,
                json={"model": "opencode:kimi-k2.6", "input": "private", "stream": True})
            results.append(response.get_data())
            sent.append(self.http.call_args.kwargs["data"])
            assert self.http.call_count == 1
            if enabled:
                assert response.headers["X-MultiLLM-Conversion-Fidelity"] == "semantic"
                assert "response" in response.headers["X-MultiLLM-Conversion-Fields"]
        assert results[0] == results[1]
        assert sent[0] == sent[1]

    def test_native_same_protocol_header_and_invalid_opt_in(self):
        from tests.test_protocol_routes import RESPONSES_BODY

        for header, expected in (("1", "exact"), ("true", None), ("0", None)):
            self.http.side_effect = None
            self.http.return_value = json_upstream(RESPONSES_BODY)
            response = self.client.post("/v1/responses", headers={
                "Authorization": "Bearer admin-test-key", "X-MultiLLM-Conversion-Report": header},
                json={"model": "opencode:grok-4.6", "input": "private"})
            assert response.status_code == 200
            assert response.headers.get("X-MultiLLM-Conversion-Fidelity") == expected

    def test_composed_bridge_keeps_inner_and_outer_losses(self):
        from tests.test_protocol_routes import ANTHROPIC_MESSAGE

        self.http.side_effect = None
        self.http.return_value = json_upstream(ANTHROPIC_MESSAGE)
        response = self.client.post("/v1/responses", headers={
            "Authorization": "Bearer admin-test-key", "X-MultiLLM-Conversion-Report": "1"},
            json={"model": "opencode:minimax-m3", "input": "private", "temperature": 2,
                  "metadata": {"label": "private"}})
        assert response.status_code == 200
        assert response.headers["X-MultiLLM-Conversion-Fidelity"] == "lossy"
        header = response.headers["X-MultiLLM-Conversion-Fields"]
        assert "request.metadata" in header
        assert "request.temperature" in header
        assert "private" not in header

    def test_dry_run_does_not_reserve_generation_budget_or_rate_slots(self):
        with patch("services.request_accounting.BudgetService.check_and_reserve") as budget, \
                patch("route_helpers.RateLimitService.enforce_request") as rate:
            response = self.report({"source_protocol": RESPONSES, "target_protocol": CHAT,
                "request": {"model": "opencode:kimi-k2.6", "input": "private"}})
            assert response.status_code == 200
            budget.assert_not_called()
            rate.assert_not_called()
        self.http.assert_not_called()

    def test_raw_traffic_does_not_gain_conversion_headers(self):
        self.http.side_effect = None
        self.http.return_value = json_upstream(CHAT_COMPLETION)
        response = self.client.post("/opencode/v1/chat/completions", headers={
            "Authorization": "Bearer admin-test-key", "X-MultiLLM-Conversion-Report": "1"},
            json={"model": "kimi-k2.6", "messages": [{"role": "user", "content": "private"}]})
        assert response.status_code == 200
        assert "X-MultiLLM-Conversion-Fidelity" not in response.headers

    def test_cached_replays_observe_current_opt_in_without_storing_reports(self):
        from routes.chat_cache import clear

        clear()
        self.http.side_effect = None
        self.http.return_value = json_upstream(CHAT_COMPLETION)
        body = {"model": "opencode:kimi-k2.6", "temperature": 0,
                "messages": [{"role": "user", "content": "private"}]}
        headers = {"Authorization": "Bearer admin-test-key", "X-MultiLLM-Cache": "on"}
        initial = self.client.post("/v1/chat/completions", headers=headers, json=body)
        enabled = self.client.post("/v1/chat/completions", headers={
            **headers, "X-MultiLLM-Conversion-Report": "1"}, json=body)
        disabled = self.client.post("/v1/chat/completions", headers=headers, json=body)
        assert initial.headers["X-MultiLLM-Cache"] == "miss"
        assert enabled.headers["X-MultiLLM-Cache"] == "hit"
        assert enabled.headers["X-MultiLLM-Conversion-Fidelity"] == "exact"
        assert "X-MultiLLM-Conversion-Fidelity" not in disabled.headers
        assert initial.data == enabled.data == disabled.data
        assert self.http.call_count == 1
        clear()


def test_header_cap_truncates_at_field_boundary():
    from services.conversion_diagnostics import report_headers

    report = {"fidelity": "lossy", "fields": [
        {"path": f"request.messages[{index}].content.cache_control"} for index in range(300)]}
    header = report_headers(report)["X-MultiLLM-Conversion-Fields"]
    assert len(header.encode("ascii")) <= 2048
    assert header.split(",")[-1].endswith("cache_control")
