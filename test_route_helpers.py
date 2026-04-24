import unittest

from route_helpers import extract_bearer_token, mask_authorization_header, mask_secret


class RouteHelperSecretMaskingTest(unittest.TestCase):
    def test_mask_secret_keeps_only_short_prefix_and_suffix(self):
        self.assertEqual(mask_secret("sk-1234567890abcdef"), "sk-1...cdef")

    def test_mask_secret_redacts_short_values(self):
        self.assertEqual(mask_secret("short"), "<redacted>")

    def test_mask_authorization_header_preserves_scheme_without_token_leak(self):
        masked = mask_authorization_header("Bearer sk-1234567890abcdef")

        self.assertEqual(masked, "Bearer sk-1...cdef")
        self.assertNotIn("1234567890ab", masked)

    def test_extract_bearer_token_accepts_case_insensitive_scheme(self):
        self.assertEqual(extract_bearer_token("bearer token-value"), "token-value")

    def test_extract_bearer_token_rejects_missing_or_wrong_scheme(self):
        self.assertIsNone(extract_bearer_token(None))
        self.assertIsNone(extract_bearer_token("Basic token-value"))
        self.assertIsNone(extract_bearer_token("Bearer "))


if __name__ == "__main__":
    unittest.main()
