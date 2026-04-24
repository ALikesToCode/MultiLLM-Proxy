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

    def test_system_and_developer_messages_map_to_system_instruction(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = json.dumps(
            {"candidates": [{"content": {"parts": [{"text": "Done"}]}}]}
        ).encode("utf-8")
        upstream.headers["Content-Type"] = "application/json"

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream,
        ) as base_request:
            self.proxy_module.ProxyService.make_request(
                method="POST",
                url="https://generativelanguage.googleapis.com/v1beta/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                params={},
                data=json.dumps(
                    {
                        "model": "gemini-2.0-flash",
                        "messages": [
                            {"role": "system", "content": "System rules"},
                            {"role": "developer", "content": "Developer rules"},
                            {"role": "user", "content": "Hello"},
                        ],
                    }
                ).encode("utf-8"),
                api_provider="gemini",
                use_cache=False,
            )

        upstream_payload = json.loads(base_request.call_args.kwargs["data"])
        system_parts = upstream_payload["system_instruction"]["parts"]
        self.assertEqual(
            [part["text"] for part in system_parts],
            ["System rules", "Developer rules"],
        )
        self.assertEqual(upstream_payload["contents"], [
            {"role": "user", "parts": [{"text": "Hello"}]},
        ])

    def test_multimodal_function_call_ids_and_thought_signatures_are_preserved(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = json.dumps(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "functionCall": {
                                        "id": "call_2",
                                        "name": "lookup",
                                        "args": {"q": "y"},
                                    },
                                    "thoughtSignature": "sig-B",
                                }
                            ]
                        }
                    }
                ]
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
                        "model": "gemini-3-flash-preview",
                        "tools": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "description": "Look up a value",
                                    "parameters": {
                                        "type": "object",
                                        "properties": {
                                            "q": {"type": "string"},
                                        },
                                        "required": ["q"],
                                    },
                                },
                            }
                        ],
                        "messages": [
                            {
                                "role": "user",
                                "content": [
                                    {"type": "text", "text": "Look at this"},
                                    {
                                        "type": "image_url",
                                        "image_url": {
                                            "url": "data:image/png;base64,QUJD",
                                        },
                                    },
                                ],
                            },
                            {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "lookup",
                                            "arguments": "{\"q\":\"x\"}",
                                        },
                                        "extra_content": {
                                            "google": {
                                                "thought_signature": "sig-A",
                                            }
                                        },
                                    }
                                ],
                            },
                            {
                                "role": "tool",
                                "tool_call_id": "call_1",
                                "name": "lookup",
                                "content": "{\"ok\":true}",
                            },
                        ],
                    }
                ).encode("utf-8"),
                api_provider="gemini",
                use_cache=False,
            )

        upstream_payload = json.loads(base_request.call_args.kwargs["data"])
        user_parts = upstream_payload["contents"][0]["parts"]
        self.assertEqual(user_parts[0], {"text": "Look at this"})
        self.assertEqual(
            user_parts[1],
            {"inlineData": {"mimeType": "image/png", "data": "QUJD"}},
        )

        assistant_part = upstream_payload["contents"][1]["parts"][0]
        self.assertEqual(
            assistant_part,
            {
                "functionCall": {
                    "name": "lookup",
                    "args": {"q": "x"},
                    "id": "call_1",
                },
                "thoughtSignature": "sig-A",
            },
        )

        tool_part = upstream_payload["contents"][2]["parts"][0]
        self.assertEqual(
            tool_part,
            {
                "functionResponse": {
                    "name": "lookup",
                    "response": {"ok": True},
                    "id": "call_1",
                }
            },
        )
        self.assertEqual(
            upstream_payload["tools"],
            [
                {
                    "functionDeclarations": [
                        {
                            "name": "lookup",
                            "description": "Look up a value",
                            "parameters": {
                                "type": "object",
                                "properties": {"q": {"type": "string"}},
                                "required": ["q"],
                            },
                        }
                    ]
                }
            ],
        )

        payload = response.json()
        tool_call = payload["choices"][0]["message"]["tool_calls"][0]
        self.assertEqual(tool_call["id"], "call_2")
        self.assertEqual(tool_call["function"]["name"], "lookup")
        self.assertEqual(json.loads(tool_call["function"]["arguments"]), {"q": "y"})
        self.assertEqual(
            tool_call["extra_content"]["google"]["thought_signature"],
            "sig-B",
        )

    def test_gemini_count_tokens_preflight_runs_before_generate(self):
        count_response = requests.Response()
        count_response.status_code = 200
        count_response._content = json.dumps({"totalTokens": 42}).encode("utf-8")
        count_response.headers["Content-Type"] = "application/json"

        generate_response = requests.Response()
        generate_response.status_code = 200
        generate_response._content = json.dumps(
            {"candidates": [{"content": {"parts": [{"text": "Hello"}]}}]}
        ).encode("utf-8")
        generate_response.headers["Content-Type"] = "application/json"

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            side_effect=[count_response, generate_response],
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
                        "preflight_count_tokens": True,
                    }
                ).encode("utf-8"),
                api_provider="gemini",
                use_cache=False,
            )

        self.assertEqual(response.json()["choices"][0]["message"]["content"], "Hello")
        self.assertEqual(base_request.call_count, 2)
        count_call = base_request.call_args_list[0].kwargs
        self.assertEqual(
            count_call["url"],
            (
                "https://generativelanguage.googleapis.com/v1beta/"
                "models/gemini-2.0-flash:countTokens"
            ),
        )
        count_payload = json.loads(count_call["data"])
        self.assertEqual(
            count_payload["generateContentRequest"]["contents"],
            [{"role": "user", "parts": [{"text": "Hello"}]}],
        )


if __name__ == "__main__":
    unittest.main()
