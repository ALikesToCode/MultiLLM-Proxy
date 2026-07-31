import unittest

from services.transport_policy import (
    provider_circuit_mode,
    request_bypasses_circuit,
)


class TransportPolicyTest(unittest.TestCase):
    def test_raw_provider_circuits_are_labeled_bypassed(self):
        self.assertEqual(provider_circuit_mode("navyai"), "bypassed")
        self.assertTrue(
            request_bypasses_circuit(
                "navyai",
                "/navyai/v1/chat/completions",
            )
        )

    def test_opencode_labels_direct_and_unified_routes_separately(self):
        self.assertEqual(provider_circuit_mode("opencode"), "mixed")
        self.assertTrue(
            request_bypasses_circuit(
                "opencode",
                "/opencode/v1/chat/completions",
            )
        )
        self.assertFalse(
            request_bypasses_circuit(
                "opencode",
                "/v1/chat/completions",
            )
        )

    def test_normalized_provider_uses_managed_circuit(self):
        self.assertEqual(provider_circuit_mode("openai"), "managed")
        self.assertFalse(
            request_bypasses_circuit(
                "openai",
                "/openai/v1/chat/completions",
            )
        )


if __name__ == "__main__":
    unittest.main()
