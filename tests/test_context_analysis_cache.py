import os
import unittest
from unittest.mock import patch

from services.context_analysis_cache import ContextAnalysisCache


class ContextAnalysisCacheTest(unittest.TestCase):
    def setUp(self):
        ContextAnalysisCache.clear()

    def test_content_hash_cache_reuses_span_without_retaining_source_text(self):
        source = "private roleplay context " * 80
        calls = 0

        def analyze():
            nonlocal calls
            calls += 1
            return (12, len(source))

        first, first_status = ContextAnalysisCache.image_prompt_span(
            "assistant",
            source,
            analyze,
        )
        second, second_status = ContextAnalysisCache.image_prompt_span(
            "assistant",
            source,
            analyze,
        )

        self.assertEqual(first, second)
        self.assertEqual(first_status, "miss")
        self.assertEqual(second_status, "hit")
        self.assertEqual(calls, 1)
        self.assertNotIn(source, repr(ContextAnalysisCache._entries))
        self.assertTrue(
            all(len(key) == 64 for key in ContextAnalysisCache._entries)
        )

    def test_content_change_invalidates_and_disabled_cache_bypasses(self):
        _, first_status = ContextAnalysisCache.image_prompt_span(
            "assistant",
            "first content",
            lambda: None,
        )
        _, changed_status = ContextAnalysisCache.image_prompt_span(
            "assistant",
            "changed content",
            lambda: None,
        )
        with patch.dict(
            os.environ,
            {"CONTEXT_ANALYSIS_CACHE_ENABLED": "false"},
        ):
            _, bypass_status = ContextAnalysisCache.image_prompt_span(
                "assistant",
                "first content",
                lambda: None,
            )

        self.assertEqual(first_status, "miss")
        self.assertEqual(changed_status, "miss")
        self.assertEqual(bypass_status, "bypass")


if __name__ == "__main__":
    unittest.main()
