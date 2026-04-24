import importlib
import json
import os
import sys
import unittest
from unittest.mock import patch

import requests


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


if __name__ == "__main__":
    unittest.main()
