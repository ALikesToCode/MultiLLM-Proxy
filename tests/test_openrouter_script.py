import importlib.util
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch


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


if __name__ == "__main__":
    unittest.main()
