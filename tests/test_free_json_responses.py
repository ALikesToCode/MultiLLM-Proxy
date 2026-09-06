import json
import time
import unittest
from unittest.mock import patch

from flask import Response

from routes.free_response import FreeUpstreamFailure, validated_free_response
from tests.test_free_quota_responses import completion_stream
from tests.unified_api_test_case import UnifiedApiTestCase

FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "color",
        "schema": {
            "type": "object",
            "properties": {"color": {"type": "string"}},
            "required": ["color"],
            "additionalProperties": False,
        },
    },
}


class FreeJsonResponseTest(unittest.TestCase):
    def test_schema_mismatch_never_reaches_client_in_either_mode(self):
        for stream in (False, True):
            for content in (
                '{"wrong_field":123}',
                '{"color":2}',
                '{"color":"red","extra":1}',
            ):
                with self.subTest(stream=stream, content=content):
                    upstream = UnifiedApiTestCase._chat_response(content)
                    if stream:
                        upstream = Response(
                            completion_stream([content]),
                            content_type="text/event-stream",
                        )
                    with self.assertRaises(FreeUpstreamFailure) as error:
                        validated_free_response(
                            upstream,
                            stream=stream,
                            deadline=time.monotonic() + 10,
                            response_format=FORMAT,
                        )
                    self.assertEqual(error.exception.reason, "schema_mismatch")

    def test_rejects_non_json_before_exposing_any_stream_frame(self):
        for content in ("User Safety: safe", '{"color":', '{"color": NaN}'):
            with self.subTest(content=content):
                response = Response(
                    completion_stream([content]), content_type="text/event-stream"
                )
                with self.assertRaises(FreeUpstreamFailure):
                    validated_free_response(
                        response,
                        stream=True,
                        deadline=time.monotonic() + 10,
                        response_format=FORMAT,
                    )

    def test_valid_json_stream_retains_frames_usage_and_done(self):
        body = completion_stream(['{"color":', '"red"}'])
        usage = 'data: {"choices":[],"usage":{"total_tokens":12}}\n\n'
        body = body.replace("data: [DONE]", usage + "data: [DONE]")
        response = validated_free_response(
            Response(body, content_type="text/event-stream"),
            stream=True,
            deadline=time.monotonic() + 10,
            response_format=FORMAT,
        )
        self.assertEqual(response.get_data(as_text=True), body)
        self.assertEqual(response.headers["X-MultiLLM-JSON-Buffered"], "true")

    def test_json_object_rejects_scalar_even_when_it_is_valid_json(self):
        with self.assertRaises(FreeUpstreamFailure):
            validated_free_response(
                UnifiedApiTestCase._chat_response('"red"'),
                stream=False,
                deadline=time.monotonic() + 10,
                response_format={"type": "json_object"},
            )

    def test_explicit_refusal_is_preserved(self):
        body = {
            "choices": [
                {"message": {"refusal": "Cannot answer"}, "finish_reason": "stop"}
            ]
        }
        response = validated_free_response(
            Response(json.dumps(body)),
            stream=False,
            deadline=time.monotonic() + 10,
            response_format=FORMAT,
        )
        self.assertEqual(response.get_json(), body)

    def test_plain_text_stream_is_not_buffered(self):
        response = validated_free_response(
            Response(completion_stream(["hello"]), content_type="text/event-stream"),
            stream=True,
            deadline=time.monotonic() + 10,
        )
        self.assertNotIn("X-MultiLLM-JSON-Buffered", response.headers)
        self.assertIn("hello", response.get_data(as_text=True))


class FreeJsonFallbackTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            FREE_ROUTE_PROVIDER_ORDER="openrouter,llm7",
            FREE_ROUTE_EXTRA_PROVIDERS="llm7",
            FREE_ROUTE_FREE_TIER_PROVIDERS="llm7",
        )
        catalog = patch(
            "services.free_model_policy.build_model_catalog", return_value=[]
        )
        keys = patch.object(
            self.app_module.AuthService,
            "get_api_key",
            side_effect={
                "openrouter": "test-router",
                "llm7": "test-llm7",
            }.get,
        )
        for mocked in (catalog, keys):
            mocked.start()
            self.addCleanup(mocked.stop)

    def assert_fallback(self, stream, invalid="User Safety: safe"):
        texts = (invalid, '{"color":"red"}')
        responses = [self._chat_response(text) for text in texts]
        if stream:
            responses = [
                Response(completion_stream([text]), content_type="text/event-stream")
                for text in texts
            ]
        with patch("app.ProxyService.make_request", side_effect=responses) as send:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "free:text",
                    "messages": [{"role": "user", "content": "Return JSON"}],
                    "response_format": FORMAT,
                    "stream": stream,
                },
            )
            body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("User Safety", body)
        self.assertNotIn("wrong_field", body)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        first = json.loads(send.call_args_list[0].kwargs["data"])
        second = json.loads(send.call_args_list[1].kwargs["data"])
        self.assertEqual(first["provider"], {"require_parameters": True})
        self.assertNotIn("provider", second)
        self.assertEqual(first["response_format"], FORMAT)

    def test_non_json_completion_fails_over(self):
        self.assert_fallback(False)

    def test_non_json_stream_fails_over_before_any_frame_is_exposed(self):
        self.assert_fallback(True)

    def test_schema_mismatch_completion_fails_over(self):
        self.assert_fallback(False, '{"wrong_field":123}')

    def test_schema_mismatch_stream_fails_over(self):
        self.assert_fallback(True, '{"wrong_field":123}')

    def test_parameter_mismatch_does_not_cool_ordinary_text_routes(self):
        payload = {
            "model": "free:text",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                Response(status=404),
                self._chat_response('{"color":"red"}'),
                self._chat_response("hello"),
            ],
        ) as send:
            first = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={**payload, "response_format": FORMAT},
            )
            second = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=payload,
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            [c.kwargs["api_provider"] for c in send.call_args_list],
            ["openrouter", "llm7", "openrouter"],
        )
