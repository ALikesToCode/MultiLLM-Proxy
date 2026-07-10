import importlib
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import requests
from werkzeug.datastructures import MultiDict


class RawPassthroughTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        os.environ["ADMIN_API_KEY"] = "admin-test-key"
        os.environ["FLASK_SECRET_KEY"] = "flask-test-secret"
        os.environ["JWT_SECRET"] = "jwt-test-secret"

        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_make_base_request_preserves_binary_non_json_response(self):
        binary_response = requests.Response()
        binary_response.status_code = 200
        binary_response._content = b"\x89PNG\r\n\x1a\n\x00\x00raw-image"
        binary_response.headers["Content-Type"] = "image/png"
        binary_response.headers["X-Upstream"] = "kept"

        with patch("services.proxy_service.requests.Session.request", return_value=binary_response):
            response = self.proxy_module.ProxyService._make_base_request(
                method="GET",
                url="https://example.invalid/v1/files/file-123/content",
                headers={},
                params={},
                data=None,
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"\x89PNG\r\n\x1a\n\x00\x00raw-image")
        self.assertEqual(response.headers["Content-Type"], "image/png")
        self.assertNotIn("application/json", response.headers["Content-Type"])

    def test_make_base_request_preserves_text_non_json_response(self):
        text_response = requests.Response()
        text_response.status_code = 202
        text_response._content = b"queued"
        text_response.headers["Content-Type"] = "text/plain; charset=utf-8"

        with patch("services.proxy_service.requests.Session.request", return_value=text_response):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://example.invalid/v1/jobs",
                headers={"Content-Type": "application/json"},
                params={},
                data=json.dumps({"input": "hello"}).encode("utf-8"),
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.content, b"queued")
        self.assertEqual(response.headers["Content-Type"], "text/plain; charset=utf-8")

    def test_make_base_request_preserves_invalid_json_response_body(self):
        invalid_json_response = requests.Response()
        invalid_json_response.status_code = 502
        invalid_json_response._content = b"{not valid json"
        invalid_json_response.headers["Content-Type"] = "application/json"

        with patch("services.proxy_service.requests.Session.request", return_value=invalid_json_response):
            response = self.proxy_module.ProxyService._make_base_request(
                method="GET",
                url="https://example.invalid/v1/models",
                headers={},
                params={},
                data=None,
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.content, b"{not valid json")
        self.assertEqual(response.headers["Content-Type"], "application/json")

    def test_linkapi_preserves_json_bytes_without_normalization(self):
        raw_body = b'{  "event": "response.completed", "text": "caf\\u00e9" }\n'
        upstream_response = requests.Response()
        upstream_response.status_code = 201
        upstream_response._content = raw_body
        upstream_response.headers["Content-Type"] = "application/json"

        with patch(
            "services.proxy_service.requests.Session.request",
            return_value=upstream_response,
        ):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://api.linkapi.ai/v1/responses",
                headers={"Content-Type": "application/json"},
                params=[],
                data=b'{"model":"gpt-test","input":"hello"}',
                api_provider="linkapi",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, raw_body)

    def test_linkapi_post_status_is_never_retried_even_with_idempotency_key(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 503
        upstream_response._content = b'{"error":"busy"}'
        upstream_response.headers["Content-Type"] = "application/json"

        with patch(
            "services.proxy_service.requests.Session.request",
            return_value=upstream_response,
        ) as request_call, patch("services.proxy_service.time.sleep") as sleep:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://api.linkapi.ai/v1/responses",
                headers={"Idempotency-Key": "request-123"},
                params=[],
                data=b'{"model":"gpt-test","input":"hello"}',
                api_provider="linkapi",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(request_call.call_count, 1)
        sleep.assert_not_called()

    def test_linkapi_post_connect_timeout_is_never_retried(self):
        with patch(
            "services.proxy_service.requests.Session.request",
            side_effect=requests.exceptions.ConnectTimeout("timed out"),
        ) as request_call, patch("services.proxy_service.time.sleep") as sleep:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://api.linkapi.ai/v1/messages",
                headers={"X-Api-Key": "provider-key"},
                params=[],
                data=b'{"model":"claude-test","messages":[]}',
                api_provider="linkapi",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(request_call.call_count, 1)
        sleep.assert_not_called()

    def test_linkapi_transport_error_never_exposes_prepared_url_or_query_key(self):
        upstream_secret = "upstream-linkapi-secret"
        prepared_url = (
            "https://api.linkapi.ai/v1beta/models/gemini-test:generateContent"
            f"?key={upstream_secret}"
        )
        transport_error = requests.exceptions.ConnectionError(
            f"connection failed for {prepared_url}"
        )

        with self.assertLogs("services.proxy_service", level="ERROR") as captured_logs, patch(
            "services.proxy_service.requests.Session.request",
            side_effect=transport_error,
        ):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://api.linkapi.ai/v1beta/models/gemini-test:generateContent",
                headers={"Content-Type": "application/json"},
                params=[("key", upstream_secret)],
                data=b'{"contents":[]}',
                api_provider="linkapi",
                use_cache=False,
            )

        serialized_response = response.content + repr(dict(response.headers)).encode("utf-8")
        log_output = "\n".join(captured_logs.output)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json(),
            {
                "error": {
                    "message": "LinkAPI upstream transport request failed",
                    "type": "upstream_transport_error",
                    "code": 502,
                }
            },
        )
        self.assertNotIn(upstream_secret.encode("utf-8"), serialized_response)
        self.assertNotIn(upstream_secret, log_output)
        self.assertNotIn("?key=", log_output)
        self.assertNotIn(prepared_url, log_output)

    def test_linkapi_gemini_provider_key_never_enters_request_url_or_logs(self):
        upstream_secret = "upstream-linkapi-secret"
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received["path"] = self.path
                received["api_key"] = self.headers.get("X-Goog-Api-Key")
                content_length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(content_length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            upstream_path = "v1beta/models/gemini-test:generateContent"
            params = self.proxy_module.ProxyService.prepare_params(
                MultiDict(
                    [
                        ("alt", "json"),
                        ("key", "downstream-proxy-key"),
                    ]
                ),
                "linkapi",
                upstream_secret,
                upstream_path=upstream_path,
            )
            headers = self.proxy_module.ProxyService.prepare_headers(
                {"X-Goog-Api-Key": "downstream-proxy-key"},
                "linkapi",
                upstream_secret,
                upstream_path=upstream_path,
            )
            url = f"http://127.0.0.1:{server.server_port}/{upstream_path}"
            prepared_url = requests.Request("POST", url, params=params).prepare().url

            with self.assertLogs(level="DEBUG") as captured_logs:
                response = self.proxy_module.ProxyService.make_request(
                    method="POST",
                    url=url,
                    headers=headers,
                    params=params,
                    data=b'{"contents":[]}',
                    api_provider="linkapi",
                    use_cache=False,
                )
                self.assertEqual(response.content, b"{}")
                response.close()
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

        log_output = "\n".join(captured_logs.output)
        self.assertEqual(received["path"], f"/{upstream_path}?alt=json")
        self.assertEqual(received["api_key"], upstream_secret)
        self.assertNotIn(upstream_secret, prepared_url)
        self.assertNotIn(upstream_secret, log_output)
        self.assertTrue(
            any("urllib3.connectionpool" in entry for entry in captured_logs.output)
        )

    def test_linkapi_redirect_is_returned_without_automatic_replay(self):
        redirect_response = requests.Response()
        redirect_response.status_code = 308
        redirect_response._content = b""
        redirect_response.headers["Location"] = "https://api.linkapi.ai/v1/responses"

        with patch(
            "services.proxy_service.requests.Session.request",
            return_value=redirect_response,
        ) as request_call:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://api.linkapi.ai/v1/responses",
                headers={"Authorization": "Bearer provider-key"},
                params=[],
                data=b'{"model":"gpt-test","input":"hello"}',
                api_provider="linkapi",
                use_cache=False,
            )

        self.assertIs(response, redirect_response)
        self.assertEqual(response.status_code, 308)
        self.assertEqual(request_call.call_count, 1)
        self.assertFalse(request_call.call_args.kwargs["allow_redirects"])

    def test_make_request_returns_native_linkapi_sse_without_synthetic_done(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = (
            b"event: response.output_text.delta\n"
            b'data: {"type":"response.output_text.delta","delta":"hi"}\n\n'
        )
        upstream_response.headers["Content-Type"] = "text/event-stream"

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream_response,
        ):
            response = self.proxy_module.ProxyService.make_request(
                method="POST",
                url="https://api.linkapi.ai/v1/responses",
                headers={"Authorization": "Bearer provider-key"},
                params=[],
                data=b'{"model":"gpt-test","stream":true}',
                api_provider="linkapi",
                use_cache=False,
            )

        self.assertIs(response, upstream_response)
        self.assertNotIn(b"[DONE]", response.content)


if __name__ == "__main__":
    unittest.main()
