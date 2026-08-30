import unittest


class GPTImageModerationPolicyTest(unittest.TestCase):
    def test_defaults_supported_gpt_image_families_to_low(self):
        from providers.gpt_image_moderation import apply_gpt_image_moderation_default

        model_ids = (
            "gpt-image-1",
            "gpt-image-1-mini",
            "gpt-image-1.5",
            "gpt-image-2",
            "gpt-image-2-2026-04-21",
            "gpt-image-2-c",
            "gpt-image-2-free",
            "openai/gpt-image-2",
            "linkapi:gpt-image-2-c",
        )

        for model_id in model_ids:
            with self.subTest(model=model_id):
                original = {"model": model_id, "prompt": "A green triangle"}
                normalized, changed = apply_gpt_image_moderation_default(original)

                self.assertTrue(changed)
                self.assertEqual(normalized["moderation"], "low")
                self.assertNotIn("moderation", original)

    def test_preserves_explicit_supported_moderation(self):
        from providers.gpt_image_moderation import apply_gpt_image_moderation_default

        for moderation in ("auto", "low"):
            with self.subTest(moderation=moderation):
                original = {
                    "model": "gpt-image-2",
                    "prompt": "A green triangle",
                    "moderation": moderation,
                }

                normalized, changed = apply_gpt_image_moderation_default(original)

                self.assertFalse(changed)
                self.assertEqual(normalized, original)

    def test_rejects_unknown_gpt_image_moderation(self):
        from providers.gpt_image_moderation import apply_gpt_image_moderation_default

        with self.assertRaisesRegex(
            ValueError,
            "GPT Image moderation must be one of: auto, low",
        ):
            apply_gpt_image_moderation_default(
                {
                    "model": "gpt-image-2",
                    "prompt": "A green triangle",
                    "moderation": "disabled",
                }
            )

    def test_does_not_change_non_gpt_image_models(self):
        from providers.gpt_image_moderation import apply_gpt_image_moderation_default

        original = {
            "model": "gemini-3.1-flash-image-preview-free",
            "prompt": "A green triangle",
        }

        normalized, changed = apply_gpt_image_moderation_default(original)

        self.assertFalse(changed)
        self.assertEqual(normalized, original)


if __name__ == "__main__":
    unittest.main()
