import importlib
import json
import os
import sys
import unittest
from unittest.mock import patch

import requests


class GeminiProviderRequestTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        os.environ["ADMIN_API_KEY"] = "admin-test-key"
        os.environ["GEMINI_API_KEY"] = "AIza-provider-key"

        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_openai_style_streaming_uses_stream_generate_content_endpoint(self):
        class FakeGeminiStream:
            status_code = 200
            headers = {"content-type": "text/event-stream"}
            closed = False

            def iter_lines(self):
                yield (
                    b'data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]},'
                    b'"finishReason":"STOP"}]}'
                )
                yield b"data: [DONE]"
                yield b'data: {"candidates":[{"content":{"parts":[{"text":"late"}]}}]}'

            def close(self):
                self.closed = True

        upstream = FakeGeminiStream()
        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream,
        ) as base_request:
            response = self.proxy_module.ProxyService.make_request(
                method="POST",
                url=(
                    "https://generativelanguage.googleapis.com/v1beta/"
                    "chat/completions?key=AIza-query-key"
                ),
                headers={"Authorization": "Bearer admin-test-key"},
                params={},
                data=json.dumps(
                    {
                        "model": "gemini-2.0-flash",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    }
                ).encode("utf-8"),
                api_provider="gemini",
                use_cache=False,
            )

        request_kwargs = base_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            (
                "https://generativelanguage.googleapis.com/v1beta/"
                "models/gemini-2.0-flash:streamGenerateContent"
            ),
        )
        self.assertEqual(request_kwargs["params"], {"alt": "sse"})
        self.assertEqual(request_kwargs["headers"]["x-goog-api-key"], "AIza-query-key")
        self.assertNotIn("Authorization", request_kwargs["headers"])

        upstream_payload = json.loads(request_kwargs["data"])
        self.assertNotIn("stream", upstream_payload)
        self.assertEqual(upstream_payload["contents"][0]["parts"][0]["text"], "Hello")

        chunks = list(response.response)
        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["object"], "chat.completion.chunk")
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], "Hello")
        self.assertEqual(chunks[1], "data: [DONE]\n\n")
        self.assertEqual(len(chunks), 2)
        self.assertTrue(upstream.closed)

    def test_openai_style_non_streaming_response_is_converted_after_url_rewrite(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = json.dumps(
            {
                "candidates": [
                    {
                        "content": {"parts": [{"text": "Hello from Gemini"}]},
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 3,
                    "candidatesTokenCount": 4,
                    "totalTokenCount": 7,
                },
            }
        ).encode("utf-8")
        upstream.headers["Content-Type"] = "application/json"

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream,
        ) as base_request:
            response = self.proxy_module.ProxyService.make_request(
                method="POST",
                url="https://generativelanguage.googleapis.com/v1beta/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                params={},
                data=json.dumps(
                    {
                        "model": "gemini-2.0-flash",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "webSearch": True,
                    }
                ).encode("utf-8"),
                api_provider="gemini",
                use_cache=False,
            )

        request_kwargs = base_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            (
                "https://generativelanguage.googleapis.com/v1beta/"
                "models/gemini-2.0-flash:generateContent"
            ),
        )
        self.assertEqual(request_kwargs["headers"]["x-goog-api-key"], "AIza-provider-key")
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["tools"], [{"google_search": {}}])
        self.assertNotIn("webSearch", upstream_payload)

        payload = response.json()
        self.assertEqual(payload["object"], "chat.completion")
        self.assertEqual(payload["choices"][0]["message"]["content"], "Hello from Gemini")
        self.assertEqual(payload["usage"]["total_tokens"], 7)


if __name__ == "__main__":
    unittest.main()
