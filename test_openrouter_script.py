import importlib.util
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class OpenRouterScriptConfigTest(unittest.TestCase):
    def setUp(self):
        script_path = Path(__file__).resolve().parent / "scripts" / "openrouter_integration.py"
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


if __name__ == "__main__":
    unittest.main()
