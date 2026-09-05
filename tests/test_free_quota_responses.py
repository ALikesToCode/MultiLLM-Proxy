import json
from unittest.mock import patch

import requests
from flask import Response

from services.free_quota_service import FreeQuotaService
from tests.unified_api_test_case import UnifiedApiTestCase

QUOTA_NOTICE = (
    "Sorry, to prevent abuse of free resources, accounts that have not been "
    "recharged can only try 10 times. You can increase the free quota after "
    "recharging; https://console.aihubmix.com/topup"
)


def completion_stream(parts):
    events = [{"choices": [{"delta": {"role": "assistant"}}]}]
    events.extend({"choices": [{"delta": {"content": part}}]} for part in parts)
    events.append({"choices": [{"delta": {}, "finish_reason": "stop"}]})
    return (
        "".join(f"data: {json.dumps(event)}\n\n" for event in events)
        + "data: [DONE]\n\n"
    )


class FreeQuotaResponseTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            FREE_ROUTE_FREE_TIER_PROVIDERS="",
            FREE_ROUTE_PROVIDER_ORDER="aihubmix,opencode,openrouter",
        )
        self.rows = [
            {
                "id": "aihubmix:gemma-4-31b-it-free",
                "provider": "aihubmix",
                "model": "gemma-4-31b-it-free",
            },
            {
                "id": "opencode:mimo-v2.5-free",
                "provider": "opencode",
                "model": "mimo-v2.5-free",
            },
        ]
        for row in self.rows:
            row.update(status="available", provider_metadata={})
        catalog = patch(
            "services.free_model_policy.build_model_catalog", return_value=self.rows
        )
        catalog.start()
        self.addCleanup(catalog.stop)
        keys = patch.object(
            self.app_module.AuthService,
            "get_api_key",
            side_effect={"aihubmix": "test-aihubmix", "opencode": "test-opencode"}.get,
        )
        keys.start()
        self.addCleanup(keys.stop)

    def post(self, stream=False):
        return self.client.post(
            "/v1/free/text/chat/completions",
            headers={"Authorization": "Bearer admin-test-key"},
            json={"messages": [{"role": "user", "content": "Hello"}], "stream": stream},
        )

    def test_quota_notice_in_200_json_falls_back_and_cools_provider(self):
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                self._chat_response(QUOTA_NOTICE),
                self._chat_response("real answer"),
            ],
        ) as send:
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["choices"][0]["message"]["content"], "real answer"
        )
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "opencode")
        self.assertEqual(send.call_count, 2)
        self.assertGreater(FreeQuotaService.remaining("provider:aihubmix"), 0)

    def assert_stream_fallback(self, parts):
        success = completion_stream(["real answer"])
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                Response(completion_stream(parts), content_type="text/event-stream"),
                Response(success, content_type="text/event-stream"),
            ],
        ) as send:
            response = self.post(stream=True)
            self.assertEqual(response.get_data(as_text=True), success)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(send.call_count, 2)
        self.assertGreater(FreeQuotaService.remaining("provider:aihubmix"), 0)

    def test_quota_notice_stream_falls_back_before_any_frame_is_exposed(self):
        self.assert_stream_fallback([QUOTA_NOTICE])

    def test_quota_notice_split_across_single_character_chunks_falls_back(self):
        self.assert_stream_fallback(list(QUOTA_NOTICE))

    def test_normal_apology_and_short_prefix_are_preserved(self):
        for content in ("Sorry, I cannot answer that.", "Sorry", "ordinary answer"):
            body = completion_stream(list(content))
            with (
                self.subTest(content=content),
                patch(
                    "app.ProxyService.make_request",
                    return_value=Response(
                        body,
                        content_type="text/event-stream",
                    ),
                ) as send,
            ):
                self.assertEqual(self.post(stream=True).get_data(as_text=True), body)
                self.assertEqual(send.call_count, 1)

    def test_other_provider_content_is_not_classified_as_aihubmix_quota(self):
        self.app.config["FREE_ROUTE_PROVIDER_ORDER"] = "opencode,aihubmix"
        for stream in (False, True):
            body = completion_stream([QUOTA_NOTICE])
            upstream = (
                Response(body, content_type="text/event-stream")
                if stream
                else self._chat_response(QUOTA_NOTICE)
            )
            with (
                self.subTest(stream=stream),
                patch("app.ProxyService.make_request", return_value=upstream) as send,
            ):
                response = self.post(stream=stream)
                if stream:
                    self.assertEqual(response.get_data(as_text=True), body)
                else:
                    self.assertEqual(
                        response.get_json()["choices"][0]["message"]["content"],
                        QUOTA_NOTICE,
                    )
                self.assertEqual(send.call_count, 1)

    def test_ambiguous_prefix_buffer_is_bounded_and_closed_before_fallback(self):
        success = completion_stream(["real answer"])
        upstream = Response(
            'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n' * 257,
            content_type="text/event-stream",
        )
        with (
            patch.object(upstream, "close", wraps=upstream.close) as close,
            patch(
                "app.ProxyService.make_request",
                side_effect=[
                    upstream,
                    Response(success, content_type="text/event-stream"),
                ],
            ) as send,
        ):
            self.assertEqual(self.post(stream=True).get_data(as_text=True), success)
        self.assertTrue(close.called)
        self.assertEqual(send.call_count, 2)

    def test_aihubmix_failure_after_ordinary_content_never_appends_fallback(self):
        def chunks():
            yield 'data: {"choices":[{"delta":{"content":"ordinary answer"}}]}\n\n'
            raise requests.ConnectionError("private upstream detail")

        with patch(
            "app.ProxyService.make_request",
            return_value=Response(chunks(), content_type="text/event-stream"),
        ) as send:
            body = self.post(stream=True).get_data(as_text=True)
        self.assertIn("ordinary answer", body)
        self.assertIn("free_stream_interrupted", body)
        self.assertNotIn("private upstream detail", body)
        self.assertNotIn("[DONE]", body)
        self.assertEqual(send.call_count, 1)
