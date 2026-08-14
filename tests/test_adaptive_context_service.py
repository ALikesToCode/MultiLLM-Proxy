import os
import unittest
from unittest.mock import patch

from services.adaptive_context_service import apply_adaptive_glm_context
from services.context_analysis_cache import ContextAnalysisCache
from services.context_optimizer import EARLIER_IMAGE_PROMPT_PLACEHOLDER
from tests.test_context_optimizer import roleplay_response


class AdaptiveContextServiceTest(unittest.TestCase):
    def setUp(self):
        ContextAnalysisCache.clear()

    def test_non_glm_and_disabled_glm_requests_are_unchanged(self):
        payload = {
            "model": "kimi-k2.6",
            "messages": [{"role": "user", "content": "Hello"}],
        }

        self.assertIsNone(
            apply_adaptive_glm_context(
                payload,
                model="kimi-k2.6",
                default_target_tokens=96_000,
            )
        )
        with patch.dict(os.environ, {"GLM_AUTO_OPTIMIZE": "false"}):
            self.assertIsNone(
                apply_adaptive_glm_context(
                    payload,
                    model="glm-5.2",
                    default_target_tokens=96_000,
                )
            )

    def test_short_glm_context_bypasses_optimization(self):
        payload = {
            "model": "glm-5.2",
            "messages": [
                {"role": "system", "content": "Keep this directive."},
                {"role": "user", "content": "Hello"},
            ],
        }

        with patch.dict(
            os.environ,
            {"GLM_AUTO_OPTIMIZE_TRIGGER_TOKENS": "8000"},
        ):
            result = apply_adaptive_glm_context(
                payload,
                model="glm-5.2",
                default_target_tokens=96_000,
            )

        self.assertIsNone(result)

    def test_long_glm_context_compacts_prompt_blocks_without_dropping_text(self):
        ordinary_history = "The blue key remains under the third floorboard."
        payload = {
            "model": "glm-5.2",
            "messages": [
                {"role": "system", "content": "Preserve continuity exactly."},
                {"role": "user", "content": "Remember the key."},
                {"role": "assistant", "content": ordinary_history},
                {"role": "user", "content": "Begin the first scene."},
                {
                    "role": "assistant",
                    "content": roleplay_response(
                        "Celia waits beside the old window.",
                        "Celia in the older scene",
                    ),
                },
                {"role": "user", "content": "Advance the scene."},
                {
                    "role": "assistant",
                    "content": roleplay_response(
                        "Celia remains beside the old window.",
                        "Celia in the latest scene",
                    ),
                },
                {"role": "user", "content": "Continue."},
            ],
        }

        with patch.dict(
            os.environ,
            {
                "GLM_AUTO_OPTIMIZE_TRIGGER_TOKENS": "0",
                "GLM_AUTO_OPTIMIZE_KEEP_RECENT_TURNS": "1",
            },
        ):
            result = apply_adaptive_glm_context(
                payload,
                model="glm-5.2",
                default_target_tokens=96_000,
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.status, "applied")
        self.assertEqual(result.payload["messages"][2]["content"], ordinary_history)
        self.assertIn(
            EARLIER_IMAGE_PROMPT_PLACEHOLDER,
            result.payload["messages"][4]["content"],
        )
        self.assertEqual(
            result.payload["messages"][6]["content"],
            payload["messages"][6]["content"],
        )
        self.assertNotIn("optimization", result.payload)

    def test_normal_route_does_not_consume_explicit_optimizer_options(self):
        payload = {
            "model": "glm-5.2",
            "messages": [{"role": "user", "content": "Hello"}],
            "optimization": {"mode": "deterministic"},
        }

        self.assertIsNone(
            apply_adaptive_glm_context(
                payload,
                model="glm-5.2",
                default_target_tokens=96_000,
            )
        )


if __name__ == "__main__":
    unittest.main()
