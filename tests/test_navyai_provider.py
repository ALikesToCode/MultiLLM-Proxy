import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests


class NavyAIProviderRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "NAVYAI_API_KEY": "sk-navy-provider-key",
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
            "proxy",
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
    def _response(payload=None, status=200, content_type="application/json"):
        upstream_response = requests.Response()
        upstream_response.status_code = status
        upstream_response._content = (
            json.dumps(payload or {"ok": True}).encode("utf-8")
            if "json" in content_type
            else bytes(payload or b"")
        )
        upstream_response.headers["Content-Type"] = content_type
        return upstream_response

    def test_chat_completions_uses_raw_navyai_endpoint_and_server_key(self):
        raw_response = b'{  "id": "chatcmpl_navy", "choices": [] }\n'
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = raw_response
        upstream_response.headers["Content-Type"] = "application/json"

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/navyai/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "gpt-5",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(), raw_response)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://api.navy/v1/chat/completions",
        )
        self.assertEqual(request_kwargs["api_provider"], "navyai")
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer sk-navy-provider-key",
        )
        self.assertEqual(
            request_kwargs["headers"]["X-Api-Key"],
            "sk-navy-provider-key",
        )

    def test_anthropic_messages_accepts_native_proxy_api_key_header(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=self._response({"type": "message", "content": []}),
        ) as make_request:
            response = self.client.post(
                "/navyai/v1/messages",
                headers={
                    "X-Api-Key": "admin-test-key",
                    "Anthropic-Version": "2023-06-01",
                },
                json={
                    "model": "claude-sonnet-4",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        request_headers = make_request.call_args.kwargs["headers"]
        self.assertEqual(request_headers["Anthropic-Version"], "2023-06-01")
        self.assertEqual(request_headers["X-Api-Key"], "sk-navy-provider-key")
        self.assertEqual(
            request_headers["Authorization"],
            "Bearer sk-navy-provider-key",
        )

    def test_openai_sse_bytes_are_preserved(self):
        raw_sse = (
            b'event: response.output_text.delta\n'
            b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'
            b'event: response.completed\n'
            b'data: {"type":"response.completed"}\n\n'
        )
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = raw_sse
        upstream_response.headers["Content-Type"] = "text/event-stream"

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ):
            response = self.client.post(
                "/navyai/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "gpt-5", "input": "Hello", "stream": True},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(), raw_sse)

    def test_transcription_preserves_multipart_boundary_and_file_bytes(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=self._response({"text": "hello"}),
        ) as make_request:
            response = self.client.post(
                "/navyai/v1/audio/transcriptions",
                headers={"Authorization": "Bearer admin-test-key"},
                data={
                    "model": "whisper-1",
                    "file": (io.BytesIO(b"\x00\x01native-audio"), "audio.mp3"),
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertIn(
            "multipart/form-data; boundary=",
            request_kwargs["headers"]["Content-Type"],
        )
        self.assertIn(b"\x00\x01native-audio", request_kwargs["data"])
        self.assertIn(b"audio.mp3", request_kwargs["data"])

    def test_binary_speech_and_transcript_downloads_are_preserved(self):
        cases = (
            (
                "POST",
                "/navyai/v1/audio/speech",
                {"model": "tts-1", "voice": "alloy", "input": "Hello"},
                b"ID3native-audio",
                "audio/mpeg",
            ),
            (
                "GET",
                "/navyai/v1/audio/transcriptions/jobs/job_123/download",
                None,
                b"1\n00:00:00,000 --> 00:00:01,000\nHello\n",
                "text/vtt",
            ),
        )

        for method, path, payload, expected_body, content_type in cases:
            upstream_response = requests.Response()
            upstream_response.status_code = 200
            upstream_response._content = expected_body
            upstream_response.headers["Content-Type"] = content_type
            with self.subTest(path=path), patch(
                "app.ProxyService.make_request",
                return_value=upstream_response,
            ):
                if method == "POST":
                    response = self.client.post(
                        path,
                        headers={"Authorization": "Bearer admin-test-key"},
                        json=payload,
                    )
                else:
                    response = self.client.get(
                        path,
                        headers={"Authorization": "Bearer admin-test-key"},
                    )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_data(), expected_body)
            self.assertEqual(response.content_type, content_type)

    def test_async_image_and_transcription_job_paths_are_forwarded_exactly(self):
        cases = (
            (
                "POST",
                "/navyai/v1/images/generations",
                {"model": "veo-3.1", "prompt": "Harbor", "sync": False},
                "https://api.navy/v1/images/generations",
            ),
            (
                "GET",
                "/navyai/v1/images/generations/job_image",
                None,
                "https://api.navy/v1/images/generations/job_image",
            ),
            (
                "POST",
                "/navyai/v1/audio/transcriptions/jobs",
                {"model": "whisper-1", "file_url": "https://example.com/a.mp3"},
                "https://api.navy/v1/audio/transcriptions/jobs",
            ),
            (
                "GET",
                "/navyai/v1/audio/transcriptions/jobs/job_audio/status",
                None,
                "https://api.navy/v1/audio/transcriptions/jobs/job_audio/status",
            ),
        )

        for method, path, payload, expected_url in cases:
            with self.subTest(path=path), patch(
                "app.ProxyService.make_request",
                return_value=self._response({"id": "job_123"}),
            ) as make_request:
                if method == "POST":
                    response = self.client.post(
                        path,
                        headers={"Authorization": "Bearer admin-test-key"},
                        json=payload,
                    )
                else:
                    response = self.client.get(
                        path,
                        headers={"Authorization": "Bearer admin-test-key"},
                    )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(make_request.call_args.kwargs["url"], expected_url)

    def test_public_catalog_and_status_work_without_navyai_key(self):
        for path in ("/navyai/v1/models", "/navyai/v1/models/status"):
            with self.subTest(path=path), patch.object(
                self.app_module.AuthService,
                "get_api_key",
                return_value=None,
            ), patch(
                "app.ProxyService.make_request",
                return_value=self._response({"object": "list", "data": []}),
            ) as make_request:
                response = self.client.get(
                    path,
                    headers={"Authorization": "Bearer admin-test-key"},
                )

            self.assertEqual(response.status_code, 200)
            request_headers = make_request.call_args.kwargs["headers"]
            self.assertNotIn("Authorization", request_headers)
            self.assertNotIn("X-Api-Key", request_headers)

    def test_caller_oauth_bearer_is_forwarded_without_server_key(self):
        with patch.object(
            self.app_module.AuthService,
            "get_api_key",
            return_value=None,
        ), patch(
            "app.ProxyService.make_request",
            return_value=self._response({"id": "navy-user"}),
        ) as make_request:
            response = self.client.get(
                "/navyai/v1/oauth/me",
                headers={
                    "X-MultiLLM-Api-Key": "admin-test-key",
                    "Authorization": "Bearer navy-oat-user-token",
                },
            )

        self.assertEqual(response.status_code, 200)
        request_headers = make_request.call_args.kwargs["headers"]
        self.assertEqual(
            request_headers["Authorization"],
            "Bearer navy-oat-user-token",
        )
        self.assertNotIn("X-MultiLLM-Api-Key", request_headers)

    def test_oauth_token_exchange_is_public_upstream_and_redacts_server_key(self):
        with patch.object(
            self.app_module.AuthService,
            "get_api_key",
            return_value=None,
        ), patch(
            "app.ProxyService.make_request",
            return_value=self._response({"access_token": "navy-oat-token"}),
        ) as make_request:
            response = self.client.post(
                "/navyai/v1/oauth/token",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "grant_type": "authorization_code",
                    "code": "one-time-code",
                    "client_id": "navy-client",
                    "client_secret": "navy-secret",
                    "code_verifier": "verifier",
                },
            )

        self.assertEqual(response.status_code, 200)
        request_headers = make_request.call_args.kwargs["headers"]
        self.assertNotIn("Authorization", request_headers)
        self.assertNotIn("X-Api-Key", request_headers)

    def test_interactive_oauth_authorize_is_direct_only(self):
        with patch("app.ProxyService.make_request") as make_request:
            response = self.client.get(
                "/navyai/v1/oauth/authorize",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Accept": "application/json",
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("https://api.navy/v1/oauth/authorize", response.get_data(as_text=True))
        make_request.assert_not_called()

    def test_unified_chat_and_responses_accept_dynamic_navyai_models(self):
        cases = (
            (
                "/v1/chat/completions",
                {
                    "model": "navyai:claude-sonnet-4.6",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                "https://api.navy/v1/chat/completions",
            ),
            (
                "/v1/responses",
                {
                    "model": "navyai:gpt-5.2",
                    "input": "Hello",
                },
                "https://api.navy/v1/responses",
            ),
        )

        for path, payload, expected_url in cases:
            with self.subTest(path=path), patch(
                "app.ProxyService.make_request",
                return_value=self._response(
                    {"id": "native", "object": "response", "output": []}
                ),
            ) as make_request:
                response = self.client.post(
                    path,
                    headers={"Authorization": "Bearer admin-test-key"},
                    json=payload,
                )

            self.assertEqual(response.status_code, 200)
            request_kwargs = make_request.call_args.kwargs
            self.assertEqual(request_kwargs["url"], expected_url)
            self.assertNotIn("navyai:", json.loads(request_kwargs["data"])["model"])


if __name__ == "__main__":
    unittest.main()
