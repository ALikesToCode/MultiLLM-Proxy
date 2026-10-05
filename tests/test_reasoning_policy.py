import unittest

from services.reasoning_policy import apply_glm_52_reasoning_policy


class ReasoningPolicyTest(unittest.TestCase):
    def test_omitted_effort_maps_to_other_providers_maximum(self):
        cases = {
            "opencode": {"reasoning_effort": "max"},
            "navyai": {"reasoning_effort": "max"},
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
            "max",
        )
        self.assertEqual(
            apply_glm_52_reasoning_policy(
                {"reasoning_effort": "max"},
                "linkapi",
                "glm-5.2",
            )["reasoning_effort"],
            "high",
        )

    def test_namespaced_thinking_suffix_keeps_nanogpt_native_default(self):
        result = apply_glm_52_reasoning_policy(
            {"model": "zai-org/glm-5.2:thinking"},
            "nanogpt",
            "zai-org/glm-5.2:thinking",
        )

        self.assertNotIn("reasoning_effort", result)
        self.assertNotIn("reasoning", result)

    def test_glm_53_variants_keep_provider_specific_defaults(self):
        full = apply_glm_52_reasoning_policy(
            {"model": "zai-org/glm-5.3"},
            "nanogpt",
            "zai-org/glm-5.3",
        )
        flash = apply_glm_52_reasoning_policy(
            {"model": "glm-5.3-flash"},
            "opencode",
            "glm-5.3-flash",
        )
        uncensored = apply_glm_52_reasoning_policy(
            {"model": "z-ai/glm-5.3-flash-uncensored"},
            "nanogpt",
            "z-ai/glm-5.3-flash-uncensored",
        )

        self.assertNotIn("reasoning_effort", full)
        self.assertEqual(flash["reasoning_effort"], "max")
        self.assertNotIn("reasoning_effort", uncensored)

    def test_nanogpt_omitted_effort_preserves_native_thinking_options(self):
        for options in ({}, {"thinking": {"type": "enabled"}}, {"reasoning": {"exclude": False}}):
            with self.subTest(options=options):
                payload = {"model": "z-ai/glm-5.3-flash", **options}
                self.assertEqual(
                    apply_glm_52_reasoning_policy(payload, "nanogpt", payload["model"]),
                    payload,
                )

    def test_nanogpt_explicit_effort_still_uses_supported_ceiling(self):
        for model, expected in (
            ("z-ai/glm-5.1", "high"),
            ("z-ai/glm-5.2", "max"),
            ("zai-org/glm-5.2:thinking", "max"),
            ("z-ai/glm-5.3", "max"),
            ("z-ai/glm-5.3-flash", "max"),
            ("z-ai/glm-5.3-flash-uncensored", "high"),
        ):
            with self.subTest(model=model):
                self.assertEqual(
                    apply_glm_52_reasoning_policy(
                        {"reasoning_effort": "max"}, "nanogpt", model,
                    )["reasoning_effort"],
                    expected,
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

    def test_xhigh_alias_maps_to_each_direct_providers_maximum(self):
        expected_efforts = {
            "opencode": "max",
            "nanogpt": "max",
            "navyai": "max",
        }
        for provider, expected_effort in expected_efforts.items():
            with self.subTest(provider=provider):
                result = apply_glm_52_reasoning_policy(
                    {"reasoning_effort": "xhigh"},
                    provider,
                    "glm-5.2",
                )

                self.assertEqual(result["reasoning_effort"], expected_effort)

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



def test_gemini_effort_fits_its_four_thinking_levels():
    from services.reasoning_policy import apply_gemini_reasoning_policy

    for requested, expected in {"none": "minimal", "minimal": "minimal", "low": "low",
                                "medium": "medium", "xhigh": "high", "max": "high"}.items():
        assert apply_gemini_reasoning_policy({"reasoning_effort": requested}, "gemini") == {
            "reasoning_effort": expected
        }
    assert apply_gemini_reasoning_policy({"reasoning": {"effort": "max"}}, "gemini") == {
        "reasoning_effort": "high"
    }
    assert apply_gemini_reasoning_policy({}, "gemini") == {}, "the model default stays"
    assert apply_gemini_reasoning_policy({"reasoning_effort": "max"}, "nanogpt") == {
        "reasoning_effort": "max"
    }


def test_gemini_models_without_minimal_think_at_low():
    from services.reasoning_policy import (
        apply_gemini_reasoning_policy,
        gemini_rejects_minimal,
    )

    for model in ("gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.9-flash", "gemini-3.1-pro-preview",
                  "models/gemini-3.8-flash"):
        assert gemini_rejects_minimal(model), model
    for model in ("gemini-3.6-flash", "gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite",
                  "gemini-3.8-flash-lite", "gemini-3-flash-preview", "gemini-2.5-flash", "", None):
        assert not gemini_rejects_minimal(model), model
    for requested in ("none", "minimal"):
        assert apply_gemini_reasoning_policy(
            {"reasoning_effort": requested}, "gemini", "gemini-3.8-flash"
        ) == {"reasoning_effort": "low"}
        assert apply_gemini_reasoning_policy(
            {"reasoning_effort": requested}, "gemini", "gemini-3.5-flash-lite"
        ) == {"reasoning_effort": "minimal"}
    assert apply_gemini_reasoning_policy(
        {"reasoning_effort": "max"}, "gemini", "gemini-3.8-flash"
    ) == {"reasoning_effort": "high"}


if __name__ == "__main__":
    unittest.main()


def test_sol_raises_only_minimal_to_low():
    from services.reasoning_policy import apply_sol_reasoning_policy

    for provider in ("ce-gpt-pro", "ce-gpt-plus"):
        assert apply_sol_reasoning_policy(
            {"reasoning_effort": "minimal"}, provider, "gpt-6.1-sol"
        ) == {"reasoning_effort": "low"}
        assert apply_sol_reasoning_policy(
            {"reasoning": {"effort": "minimal", "summary": "auto"}}, provider, "gpt-6.1-sol"
        ) == {"reasoning": {"effort": "low", "summary": "auto"}}
    for effort in ("none", "low", "high", "max"):
        assert apply_sol_reasoning_policy(
            {"reasoning_effort": effort}, "ce-gpt-pro", "gpt-6.1-sol"
        ) == {"reasoning_effort": effort}
    for provider, model in (("ce-gpt-pro", "gpt-6-luna"), ("ce-grok-heavy", "grok-4.7"),
                            ("openrouter", "openai/gpt-6.1-sol")):
        assert apply_sol_reasoning_policy(
            {"reasoning_effort": "minimal"}, provider, model
        ) == {"reasoning_effort": "minimal"}
    assert apply_sol_reasoning_policy({}, "ce-gpt-pro", "gpt-6.1-sol") == {}
