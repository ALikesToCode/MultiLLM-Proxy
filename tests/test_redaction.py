import unittest

from services.redaction import (
    REDACTED,
    redact_headers,
    redact_payload,
    redact_query_params,
    redact_text,
)


class RedactionTest(unittest.TestCase):
    def test_redact_headers_hides_auth_material(self):
        redacted = redact_headers(
            {
                "Authorization": "Bearer sk-secret123456",
                "x-goog-api-key": "AIza-provider-secret",
                "Content-Type": "application/json",
            }
        )

        self.assertEqual(redacted["Authorization"], REDACTED)
        self.assertEqual(redacted["x-goog-api-key"], REDACTED)
        self.assertEqual(redacted["Content-Type"], "application/json")

    def test_redact_payload_hides_nested_prompts_and_secrets(self):
        payload = {
            "model": "openai/gpt-4o-mini",
            "messages": [{"role": "user", "content": "private prompt"}],
            "metadata": {
                "api_key": "sk-secret123456",
                "safe": "visible",
            },
        }

        redacted = redact_payload(payload)

        self.assertEqual(redacted["messages"], REDACTED)
        self.assertEqual(redacted["metadata"]["api_key"], REDACTED)
        self.assertEqual(redacted["metadata"]["safe"], "visible")
        self.assertNotIn("private prompt", str(redacted))
        self.assertNotIn("sk-secret", str(redacted))

    def test_redact_query_params_hides_keys(self):
        redacted = redact_query_params(
            {
                "key": "AIza-query-secret",
                "model": "gemini-2.0-flash",
            }
        )

        self.assertEqual(redacted["key"], REDACTED)
        self.assertEqual(redacted["model"], "gemini-2.0-flash")

    def test_redact_text_masks_common_secret_shapes(self):
        redacted = redact_text(
            'Authorization: Bearer sk-secret123456 and {"api_key":"AIza-provider-secret"}'
        )

        self.assertNotIn("sk-secret", redacted)
        self.assertNotIn("AIza-provider-secret", redacted)
        self.assertIn(REDACTED, redacted)


if __name__ == "__main__":
    unittest.main()
