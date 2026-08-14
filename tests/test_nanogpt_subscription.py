import unittest

from providers.nanogpt import (
    nanogpt_subscription_only,
    sanitize_nanogpt_subscription_headers,
    sanitize_nanogpt_subscription_payload,
)


class NanoGPTSubscriptionPolicyTest(unittest.TestCase):
    def test_subscription_mode_is_explicit(self):
        self.assertTrue(
            nanogpt_subscription_only(
                {"NANOGPT_BILLING_MODE": "subscription"}
            )
        )
        self.assertFalse(
            nanogpt_subscription_only({"NANOGPT_BILLING_MODE": "standard"})
        )

    def test_subscription_payload_removes_paygo_routing_fields(self):
        payload = sanitize_nanogpt_subscription_payload(
            {
                "model": "zai-org/glm-5.2:thinking",
                "messages": [{"role": "user", "content": "Continue."}],
                "reasoning_effort": "max",
                "caching": True,
                "provider": "example-provider",
                "billing_mode": "paygo",
            }
        )

        self.assertEqual(payload["reasoning_effort"], "max")
        self.assertNotIn("caching", payload)
        self.assertNotIn("provider", payload)
        self.assertNotIn("billing_mode", payload)

    def test_subscription_headers_remove_provider_and_billing_overrides(self):
        headers = sanitize_nanogpt_subscription_headers(
            {
                "Accept": "application/json",
                "X-Provider": "example-provider",
                "X-Billing-Mode": "paygo",
                "X-BYOK-Provider": "example-provider",
                "x-use-byok": "true",
            }
        )

        self.assertEqual(headers, {"Accept": "application/json"})


if __name__ == "__main__":
    unittest.main()
