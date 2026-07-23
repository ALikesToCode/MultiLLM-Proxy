import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests


class NanoGPTProviderRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "NANOGPT_API_KEY": "nanogpt-provider-key",
                "ALLOWED_ORIGINS": "https://example.com",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(self.temp_dir.name, "limits.sqlite3"),
                "MODEL_REGISTRY_DB_PATH": os.path.join(self.temp_dir.name, "models.sqlite3"),
            }
        )

        for module_name in list(sys.modules):
            if module_name.startswith(("routes.", "providers.")):
                sys.modules.pop(module_name, None)
        for module_name in (
            "app",
            "config",
            "route_helpers",
            "services.auth_service",
            "services.model_registry",
            "services.proxy_service",
            "services.rate_limit_service",
        ):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.client = self.app_module.create_app().test_client()

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _chat_response(text="Hello from NanoGPT"):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = json.dumps(
            {
                "id": "chatcmpl-nanogpt",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "x_nanogpt_pricing": {
                    "amount": "0.0001",
                    "currency": "USD",
                    "usage": {"total_tokens": 4},
                },
            }
        ).encode("utf-8")
        upstream_response.headers["Content-Type"] = "application/json"
        return upstream_response

    def test_nanogpt_chat_completions_routes_to_api_v1_endpoint(self):
        with patch("app.ProxyService.make_request", return_value=self._chat_response()) as make_request:
            response = self.client.post(
                "/nanogpt/v1/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Content-Type": "application/json",
                    "Origin": "https://example.com",
                    "memory": "true",
                    "memory_expiration_days": "30",
                    "anthropic-beta": "prompt-caching-2024-07-31",
                    "x-use-byok": "true",
                },
                json={
                    "model": "gpt-4o-mini:online:memory-30",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "reasoning": {"enabled": True, "effort": "low"},
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Hello from NanoGPT")
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://example.com")

        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://nano-gpt.com/api/v1/chat/completions",
        )
        self.assertEqual(request_kwargs["api_provider"], "nanogpt")
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer nanogpt-provider-key",
        )
        self.assertEqual(
            request_kwargs["headers"]["X-Api-Key"],
            "nanogpt-provider-key",
        )
        self.assertEqual(request_kwargs["headers"]["memory"], "true")
        self.assertEqual(request_kwargs["headers"]["memory_expiration_days"], "30")
        self.assertEqual(request_kwargs["headers"]["anthropic-beta"], "prompt-caching-2024-07-31")
        self.assertEqual(request_kwargs["headers"]["x-use-byok"], "true")

    def test_nanogpt_models_route_passes_detailed_query_to_live_catalog(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = b'{"object":"list","data":[]}'
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.get(
                "/nanogpt/v1/models?detailed=true",
                headers={"Authorization": "Bearer admin-test-key"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            make_request.call_args.kwargs["url"],
            "https://nano-gpt.com/api/v1/models",
        )
        self.assertIn(
            ("detailed", "true"),
            make_request.call_args.kwargs["params"],
        )

    def test_v1_chat_completions_allows_nanogpt_dynamic_model_suffixes(self):
        with patch("app.ProxyService.make_request", return_value=self._chat_response("dynamic ok")) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "nanogpt:gpt-4o-mini:online:memory-30",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "dynamic ok")
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "nanogpt")
        self.assertEqual(
            request_kwargs["url"],
            "https://nano-gpt.com/api/v1/chat/completions",
        )
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["model"], "gpt-4o-mini:online:memory-30")

    def test_v1_models_does_not_guess_nanogpt_model_ids(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        model_ids = {model["id"] for model in response.get_json()["data"]}
        self.assertNotIn("nanogpt:gpt-4o-mini", model_ids)


class NanoGPTStreamingNormalizationTest(unittest.TestCase):
    def setUp(self):
        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")

    def test_nanogpt_streaming_preserves_reasoning_and_pricing_frames(self):
        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}
            closed = False

            def iter_content(self, chunk_size=1024):
                yield (
                    b'data: {"choices":[{"delta":{"reasoning":"plan",'
                    b'"content":""}}]}\n\n'
                    b'data: {"x_nanogpt_pricing":{"amount":"0.0001",'
                    b'"currency":"USD","usage":{"total_tokens":4}}}\n\n'
                    b'data: {"choices":[{"delta":{"content":"answer"}}]}\n\n'
                    b'data: [DONE]\n\n'
                )

            def iter_lines(self, decode_unicode=True):
                raise AssertionError("SSE streams should use iter_content")

            def close(self):
                self.closed = True

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "nanogpt",
            )
        )

        self.assertEqual(len(chunks), 4)
        reasoning_payload = json.loads(chunks[0][6:].strip())
        self.assertEqual(reasoning_payload["choices"][0]["delta"]["reasoning"], "plan")
        pricing_payload = json.loads(chunks[1][6:].strip())
        self.assertEqual(pricing_payload["x_nanogpt_pricing"]["currency"], "USD")
        answer_payload = json.loads(chunks[2][6:].strip())
        self.assertEqual(answer_payload["choices"][0]["delta"]["content"], "answer")
        self.assertEqual(chunks[3], "data: [DONE]\n\n")


class NanoGPTRawCapabilityRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "NANOGPT_API_KEY": "nanogpt-provider-key",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(self.temp_dir.name, "limits.sqlite3"),
                "MODEL_REGISTRY_DB_PATH": os.path.join(
                    self.temp_dir.name,
                    "models.sqlite3",
                ),
            }
        )

        for module_name in list(sys.modules):
            if module_name.startswith(("routes.", "providers.")):
                sys.modules.pop(module_name, None)
        for module_name in (
            "app",
            "config",
            "route_helpers",
            "services.auth_service",
            "services.model_registry",
            "services.proxy_service",
            "services.rate_limit_service",
        ):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.client = self.app_module.create_app().test_client()

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _json_response(payload=None, status=200):
        upstream_response = requests.Response()
        upstream_response.status_code = status
        upstream_response._content = json.dumps(payload or {"ok": True}).encode("utf-8")
        upstream_response.headers["Content-Type"] = "application/json"
        return upstream_response

    def test_batch_file_upload_uses_dedicated_host_and_preserves_multipart(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=self._json_response({"id": "file_123"}),
        ) as make_request:
            response = self.client.post(
                "/nanogpt/v1/files",
                headers={"Authorization": "Bearer admin-test-key"},
                data={
                    "purpose": "batch",
                    "file": (io.BytesIO(b'{"custom_id":"one"}\n'), "requests.jsonl"),
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://api.nano-gpt.com/api/v1/files",
        )
        self.assertIn(
            "multipart/form-data; boundary=",
            request_kwargs["headers"]["Content-Type"],
        )
        self.assertIn(b'{"custom_id":"one"}', request_kwargs["data"])
        self.assertIn(b"requests.jsonl", request_kwargs["data"])

    def test_binary_speech_response_is_preserved(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = b"ID3\x04\x00\x00native-audio"
        upstream_response.headers["Content-Type"] = "audio/mpeg"

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ):
            response = self.client.post(
                "/nanogpt/v1/audio/speech",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "tts-model",
                    "voice": "alloy",
                    "input": "Hello",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "audio/mpeg")
        self.assertEqual(response.get_data(), b"ID3\x04\x00\x00native-audio")

    def test_accountless_x402_quote_omits_configured_key_and_exposes_challenge(self):
        upstream_response = self._json_response({"error": "payment_required"}, status=402)
        upstream_response.headers["WWW-Authenticate"] = "L402 macaroon=quote"
        upstream_response.headers["X-Poll-After"] = "2"

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/nanogpt/v1/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "x-x402": "true",
                },
                json={"model": "paid-model", "messages": []},
            )

        request_headers = make_request.call_args.kwargs["headers"]
        self.assertEqual(response.status_code, 402)
        self.assertEqual(response.headers["WWW-Authenticate"], "L402 macaroon=quote")
        self.assertEqual(response.headers["X-Poll-After"], "2")
        self.assertEqual(request_headers["x-x402"], "true")
        self.assertNotIn("Authorization", request_headers)
        self.assertNotIn("X-Api-Key", request_headers)

    def test_l402_credential_is_forwarded_separately_from_proxy_key(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=self._json_response(),
        ) as make_request:
            response = self.client.post(
                "/nanogpt/v1/chat/completions",
                headers={
                    "X-MultiLLM-Api-Key": "admin-test-key",
                    "Authorization": "L402 macaroon:preimage",
                },
                json={"model": "paid-model", "messages": []},
            )

        self.assertEqual(response.status_code, 200)
        request_headers = make_request.call_args.kwargs["headers"]
        self.assertEqual(
            request_headers["Authorization"],
            "L402 macaroon:preimage",
        )
        self.assertNotIn("X-MultiLLM-Api-Key", request_headers)
        self.assertNotIn("X-Api-Key", request_headers)

    def test_caller_bearer_can_override_configured_nanogpt_key(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=self._json_response(),
        ) as make_request:
            response = self.client.post(
                "/nanogpt/v1/chat/completions",
                headers={
                    "X-MultiLLM-Api-Key": "admin-test-key",
                    "Authorization": "Bearer sk-nano-user-key",
                },
                json={"model": "user-model", "messages": []},
            )

        self.assertEqual(response.status_code, 200)
        request_headers = make_request.call_args.kwargs["headers"]
        self.assertEqual(
            request_headers["Authorization"],
            "Bearer sk-nano-user-key",
        )
        self.assertNotIn("X-Api-Key", request_headers)

    def test_oauth_token_exchange_uses_nanogpt_origin_without_provider_key(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=self._json_response({"access_token": "sk-nano-user-key"}),
        ) as make_request:
            response = self.client.post(
                "/nanogpt/oauth/token",
                headers={"Authorization": "Bearer admin-test-key"},
                data={
                    "grant_type": "authorization_code",
                    "client_id": "ngpt_client",
                    "code": "one-time-code",
                    "code_verifier": "v" * 43,
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://nano-gpt.com/oauth/token",
        )
        self.assertNotIn("Authorization", request_kwargs["headers"])
        self.assertNotIn("X-Api-Key", request_kwargs["headers"])

    def test_public_model_catalog_works_without_configured_nanogpt_key(self):
        with patch.object(
            self.app_module.AuthService,
            "get_api_key",
            return_value=None,
        ), patch(
            "app.ProxyService.make_request",
            return_value=self._json_response({"object": "list", "data": []}),
        ) as make_request:
            response = self.client.get(
                "/nanogpt/v1/models",
                headers={"Authorization": "Bearer admin-test-key"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(
            "Authorization",
            make_request.call_args.kwargs["headers"],
        )

    def test_interactive_oauth_authorize_is_direct_only(self):
        with patch("app.ProxyService.make_request") as make_request:
            response = self.client.get(
                "/nanogpt/oauth/authorize",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Accept": "application/json",
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("https://nano-gpt.com/oauth/authorize", response.get_data(as_text=True))
        make_request.assert_not_called()

    def test_unified_responses_uses_nanogpt_native_endpoint(self):
        upstream_response = self._json_response(
            {
                "id": "resp_native",
                "object": "response",
                "output": [],
            }
        )
        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "nanogpt:provider/model:thinking",
                    "input": "Hello",
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://nano-gpt.com/api/v1/responses",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "provider/model:thinking",
        )


if __name__ == "__main__":
    unittest.main()
