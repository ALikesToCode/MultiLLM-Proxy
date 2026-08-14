import unittest

from services.reasoning_policy import apply_glm_52_reasoning_policy


class ReasoningPolicyTest(unittest.TestCase):
    def test_omitted_effort_maps_to_each_providers_maximum(self):
        cases = {
            "opencode": {"reasoning_effort": "max"},
            "nanogpt": {"reasoning_effort": "xhigh"},
            "navyai": {"reasoning_effort": "xhigh"},
            "linkapi": {"reasoning_effort": "high"},
            "openrouter": {"reasoning": {"effort": "xhigh"}},
            "another-provider": {"reasoning_effort": "max"},
        }

        for provider, expected_fields in cases.items():
            with self.subTest(provider=provider):
                result = apply_glm_52_reasoning_policy(
                    {"model": "glm-5.2", "messages": []},
                    provider,
                    "glm-5.2",
                )
                for field, value in expected_fields.items():
                    self.assertEqual(result[field], value)

    def test_literal_max_means_the_providers_maximum(self):
        self.assertEqual(
            apply_glm_52_reasoning_policy(
                {"reasoning_effort": "max"},
                "nanogpt",
                "glm-5.2",
            )["reasoning_effort"],
            "xhigh",
        )
        self.assertEqual(
            apply_glm_52_reasoning_policy(
                {"reasoning_effort": "max"},
                "linkapi",
                "glm-5.2",
            )["reasoning_effort"],
            "high",
        )

    def test_explicit_lower_effort_is_preserved_within_provider_ceiling(self):
        self.assertEqual(
            apply_glm_52_reasoning_policy(
                {"reasoning_effort": "low"},
                "navyai",
                "glm-5.2",
            )["reasoning_effort"],
            "low",
        )
        self.assertEqual(
            apply_glm_52_reasoning_policy(
                {"reasoning_effort": "xhigh"},
                "linkapi",
                "glm-5.2",
            )["reasoning_effort"],
            "high",
        )

    def test_openrouter_uses_nested_reasoning_and_preserves_other_options(self):
        result = apply_glm_52_reasoning_policy(
            {"reasoning": {"effort": "max", "exclude": True}},
            "openrouter",
            "vendor/glm-5.2",
        )

        self.assertNotIn("reasoning_effort", result)
        self.assertEqual(
            result["reasoning"],
            {"effort": "xhigh", "exclude": True},
        )

    def test_non_glm_and_invalid_explicit_values_remain_unchanged(self):
        non_glm = {"model": "kimi-k2.6"}
        invalid = {"model": "glm-5.2", "reasoning_effort": "turbo"}

        self.assertEqual(
            apply_glm_52_reasoning_policy(non_glm, "opencode", "kimi-k2.6"),
            non_glm,
        )
        self.assertEqual(
            apply_glm_52_reasoning_policy(invalid, "opencode", "glm-5.2"),
            invalid,
        )


if __name__ == "__main__":
    unittest.main()
