import importlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class OpenRouterScriptConfigTest(unittest.TestCase):
    def setUp(self):
        self.script_module = importlib.import_module("test_openrouter")
        self.script_module = importlib.reload(self.script_module)

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
