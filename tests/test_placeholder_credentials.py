"""Template placeholders from .env.example are treated as missing credentials."""

import os
import unittest
from unittest.mock import patch

from services.auth_primitives import is_placeholder_credential, usable_credential
from services.nanogpt_key_pool import configured_nanogpt_keys
from tests.unified_api_test_case import UnifiedApiTestCase


class PlaceholderCredentialTest(unittest.TestCase):
    def test_template_values_are_placeholders_and_real_keys_are_not(self):
        for value in ("your-openai-api-key", "YOUR_GGUU_API_KEY", " your-xai-api-key ", "<openai-key>",
                      "changeme", "replace-me"):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder_credential(value))
                self.assertIsNone(usable_credential(value, "OPENAI_API_KEY"))
        for value in ("sk-proj-abc123", "gsk_live_123", "AIzaSyExample", "nano-1234"):
            with self.subTest(value=value):
                self.assertFalse(is_placeholder_credential(value))
                self.assertEqual(usable_credential(value), value)

    def test_nanogpt_pool_skips_placeholders(self):
        keys = configured_nanogpt_keys({"NANOGPT_API_KEY": "your-nanogpt-api-key", "NANOGPT_API_KEY_1": "nano-real"})
        self.assertEqual(keys, ["nano-real"])


class PlaceholderProviderTest(UnifiedApiTestCase):
    def test_a_placeholder_key_leaves_the_provider_unconfigured(self):
        auth = self.app_module.AuthService
        with patch.dict(os.environ, {"OPENAI_API_KEY": "your-openai-api-key"}):
            self.assertIsNone(auth.get_api_key("openai"))
            with patch.object(self.app_module.ProxyService, "make_request") as make_request:
                response = self.client.post("/v1/images/generations", headers={"Authorization": "Bearer admin-test-key"},
                                            json={"model": "openai:gpt-image-2.5", "prompt": "A red fox"})
            make_request.assert_not_called()
            self.assertNotEqual(response.status_code, 200)
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-proj-real"}):
            self.assertEqual(auth.get_api_key("openai"), "sk-proj-real")
