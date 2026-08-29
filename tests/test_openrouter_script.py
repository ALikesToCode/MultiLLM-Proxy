import importlib.util
import io
import os
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

import requests


class OpenRouterScriptConfigTest(unittest.TestCase):
    def setUp(self):
        script_path = Path(__file__).resolve().parents[1] / "scripts" / "openrouter_integration.py"
        spec = importlib.util.spec_from_file_location("openrouter_integration", script_path)
        self.script_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.script_module)

    def test_resolve_api_key_prefers_explicit_flag(self):
        with patch.dict(os.environ, {"ADMIN_API_KEY": "env-admin-key"}, clear=False):
            args = SimpleNamespace(key="cli-admin-key")
            self.assertEqual(self.script_module.resolve_api_key(args), "cli-admin-key")

    def test_resolve_api_key_uses_environment_variable(self):
        with patch.dict(os.environ, {"ADMIN_API_KEY": "env-admin-key"}, clear=False):
            args = SimpleNamespace(key=None)
            self.assertEqual(self.script_module.resolve_api_key(args), "env-admin-key")

    def test_resolve_api_key_requires_explicit_or_environment_value(self):
        with patch.dict(os.environ, {"ADMIN_API_KEY": ""}, clear=False):
            args = SimpleNamespace(key=None)
            with self.assertRaisesRegex(ValueError, "ADMIN_API_KEY"):
                self.script_module.resolve_api_key(args)

    def test_non_streaming_request_has_connect_and_read_timeout(self):
        response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"choices": [{"message": {"content": "ok"}}]},
        )
        with patch.object(self.script_module.requests, "post", return_value=response) as post:
            self.assertTrue(
                self.script_module.test_openrouter_non_streaming(
                    "http://localhost:1400",
                    "test/model",
                    "hello",
                    "test-key",
                )
            )

        self.assertEqual(post.call_args.kwargs["timeout"], (5, 120))

    def test_non_streaming_content_is_hidden_by_default(self):
        response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "choices": [{"message": {"content": "sensitive response"}}]
            },
        )
        output = io.StringIO()

        with (
            patch.object(self.script_module.requests, "post", return_value=response),
            redirect_stdout(output),
        ):
            self.assertTrue(
                self.script_module.test_openrouter_non_streaming(
                    "http://localhost:1400",
                    "test/model",
                    "sensitive prompt",
                    "test-key",
                )
            )

        diagnostics = output.getvalue()
        self.assertNotIn("sensitive prompt", diagnostics)
        self.assertNotIn("sensitive response", diagnostics)
        self.assertIn("content: [hidden", diagnostics)

    def test_non_streaming_content_can_be_shown_explicitly(self):
        response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "choices": [{"message": {"content": "visible response"}}]
            },
        )
        output = io.StringIO()

        with (
            patch.object(self.script_module.requests, "post", return_value=response),
            redirect_stdout(output),
        ):
            self.assertTrue(
                self.script_module.test_openrouter_non_streaming(
                    "http://localhost:1400",
                    "test/model",
                    "visible prompt",
                    "test-key",
                    show_content=True,
                )
            )

        diagnostics = output.getvalue()
        self.assertIn("visible prompt", diagnostics)
        self.assertIn("visible response", diagnostics)

    def test_streaming_request_has_bounded_read_timeout(self):
        response = SimpleNamespace(raise_for_status=lambda: None)
        with (
            patch.object(self.script_module.requests, "post", return_value=response) as post,
            patch.object(self.script_module, "SSEClient", return_value=[]),
        ):
            self.assertTrue(
                self.script_module.test_openrouter_streaming(
                    "http://localhost:1400",
                    "test/model",
                    "hello",
                    "test-key",
                )
            )

        self.assertEqual(post.call_args.kwargs["timeout"], (5, 300))

    def test_streaming_content_is_hidden_by_default(self):
        response = SimpleNamespace(raise_for_status=lambda: None)
        event = SimpleNamespace(
            data='{"choices":[{"delta":{"content":"sensitive stream"}}]}'
        )
        output = io.StringIO()

        with (
            patch.object(self.script_module.requests, "post", return_value=response),
            patch.object(self.script_module, "SSEClient", return_value=[event]),
            redirect_stdout(output),
        ):
            self.assertTrue(
                self.script_module.test_openrouter_streaming(
                    "http://localhost:1400",
                    "test/model",
                    "sensitive prompt",
                    "test-key",
                )
            )

        diagnostics = output.getvalue()
        self.assertNotIn("sensitive prompt", diagnostics)
        self.assertNotIn("sensitive stream", diagnostics)
        self.assertIn("content: [hidden", diagnostics)

    def test_credit_request_has_connect_and_read_timeout(self):
        response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"data": {"credits": 1, "used": 0}},
        )
        with patch.object(self.script_module.requests, "get", return_value=response) as get:
            self.assertTrue(
                self.script_module.test_openrouter_credits(
                    "http://localhost:1400",
                    "test-key",
                )
            )

        self.assertEqual(get.call_args.kwargs["timeout"], (5, 30))

    def test_request_errors_redact_structured_secret_fields(self):
        response = requests.Response()
        response.status_code = 401
        response._content = b'{"api_key":"secret-provider-key","error":"denied"}'
        response.headers["Content-Type"] = "application/json"
        error = requests.HTTPError("request failed with secret-provider-key")
        error.response = response
        output = io.StringIO()

        with redirect_stdout(output):
            self.script_module.print_request_error(error)

        diagnostics = output.getvalue()
        self.assertIn("HTTPError", diagnostics)
        self.assertIn("Status code: 401", diagnostics)
        self.assertIn("Structured error response: dict", diagnostics)
        self.assertNotIn("secret-provider-key", diagnostics)

    def test_request_errors_do_not_print_unstructured_response_bodies(self):
        response = requests.Response()
        response.status_code = 502
        response._content = b"upstream failed with secret-provider-key"
        response.headers["Content-Type"] = "text/plain"
        error = requests.HTTPError("request failed")
        error.response = response
        output = io.StringIO()

        with redirect_stdout(output):
            self.script_module.print_request_error(error)

        diagnostics = output.getvalue()
        self.assertIn("Response body length:", diagnostics)
        self.assertNotIn("secret-provider-key", diagnostics)


if __name__ == "__main__":
    unittest.main()
