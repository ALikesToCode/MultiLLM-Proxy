import unittest

from services.context_optimizer import (
    EARLIER_IMAGE_PROMPT_PLACEHOLDER,
    ContextOptimizationError,
    optimize_chat_payload,
    validate_summary_digest,
)


def image_prompt(subject: str) -> str:
    sections = (
        f"Create a high-detail modern anime image of {subject}.\n"
        "Background/setting: A rain-soaked urban intersection with weathered "
        "brick apartments, shuttered storefronts, wet asphalt, faded crossings, "
        "and a distant red billboard under an overcast sky.\n"
        f"Main character (focus): {subject}, shown head to toe with a precise "
        "expression, distinctive facial features, and an immediately readable "
        "silhouette in the center of the intersection.\n"
        "Outfit: A carefully layered municipal uniform with textured fabric, "
        "frayed hems, dark epaulets, scuffed boots, a belt, and a silver badge.\n"
        "Accessories: A shoulder radio, wristwatch, holstered baton, and subtle "
        "metal reflections that remain secondary to the character.\n"
        "Hair & makeup: Natural hair detail, realistic skin texture, no glamour "
        "makeup, and restrained color variation appropriate to the weather.\n"
        "Pose/expression: Frozen mid-turn with tense shoulders, bent knees, wide "
        "eyes, and an expression of horrified recognition.\n"
        "Lighting: Flat diffused daylight with cool reflections on wet pavement, "
        "soft grey fill, and no hard shadows.\n"
        "Composition/camera: Cinematic 16:9 long shot from standing eye level, "
        "full body visible, shallow depth of field, strong leading lines, and a "
        "balanced foreground detail near the curb.\n"
        "Visible mood/atmosphere: Dread, stillness, institutional collapse, "
        "desaturated grey and tan colors, mist, and restrained environmental detail."
    )
    return sections + " Detailed texture continuity." * 12


class ContextOptimizerTest(unittest.TestCase):
    def test_compacts_single_line_labeled_prompt_from_real_client_shape(self):
        older_prompt = image_prompt("Inspector Voss in the first scene").replace("\n", ".")
        newest_prompt = image_prompt("Inspector Voss in the revised scene").replace("\n", ".")
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "user", "content": older_prompt},
                {"role": "assistant", "content": "Done."},
                {"role": "user", "content": newest_prompt},
                {"role": "assistant", "content": "Done."},
                {"role": "user", "content": "Give the final title."},
            ],
            "optimization": {
                "trigger_input_tokens": 0,
                "target_input_tokens": 100000,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertEqual(result.image_prompts_compacted, 1)
        self.assertEqual(
            result.payload["messages"][0]["content"],
            EARLIER_IMAGE_PROMPT_PLACEHOLDER,
        )
        self.assertEqual(result.payload["messages"][2]["content"], newest_prompt)

    def test_deterministic_mode_compacts_only_older_image_prompts(self):
        older_prompt = image_prompt("Inspector Voss in the first scene")
        newest_prompt = image_prompt("Inspector Voss in the revised scene")
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "system", "content": "Keep character continuity."},
                {"role": "user", "content": older_prompt},
                {"role": "assistant", "content": "The first image is ready."},
                {"role": "user", "content": newest_prompt},
                {"role": "assistant", "content": "The revision is ready."},
                {"role": "user", "content": "Now describe the final mood briefly."},
            ],
            "prompt_cache_key": "scene-session-1",
            "reasoning_effort": "max",
            "optimization": {
                "mode": "deterministic",
                "trigger_input_tokens": 0,
                "target_input_tokens": 100000,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertEqual(result.status, "applied")
        self.assertEqual(result.image_prompts_compacted, 1)
        self.assertEqual(
            result.payload["messages"][1]["content"],
            EARLIER_IMAGE_PROMPT_PLACEHOLDER,
        )
        self.assertEqual(result.payload["messages"][3]["content"], newest_prompt)
        self.assertEqual(
            result.payload["messages"][0],
            {"role": "system", "content": "Keep character continuity."},
        )
        self.assertEqual(result.payload["prompt_cache_key"], "scene-session-1")
        self.assertEqual(result.payload["reasoning_effort"], "max")
        self.assertNotIn("optimization", result.payload)
        self.assertLess(result.estimated_input_after, result.estimated_input_before)

    def test_reference_to_earlier_visual_history_skips_image_compaction(self):
        older_prompt = image_prompt("the first version")
        newest_prompt = image_prompt("the second version")
        payload = {
            "model": "openrouter:test",
            "messages": [
                {"role": "user", "content": older_prompt},
                {"role": "assistant", "content": "Done."},
                {"role": "user", "content": newest_prompt},
                {"role": "assistant", "content": "Done."},
                {
                    "role": "user",
                    "content": "Compare this with the earlier image prompt before changing it.",
                },
            ],
            "optimization": {
                "trigger_input_tokens": 0,
                "target_input_tokens": 100000,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.image_prompts_compacted, 0)
        self.assertEqual(result.payload["messages"][0]["content"], older_prompt)
        self.assertIn("referenced_image_history", result.reasons)

    def test_reference_to_old_visual_detail_skips_image_compaction(self):
        older_prompt = image_prompt("the first version")
        newest_prompt = image_prompt("the second version")
        payload = {
            "model": "openrouter:test",
            "messages": [
                {"role": "user", "content": older_prompt},
                {"role": "assistant", "content": "Done."},
                {"role": "user", "content": newest_prompt},
                {"role": "assistant", "content": "Done."},
                {"role": "user", "content": "Bring back the outfit from two prompts ago."},
            ],
            "optimization": {
                "trigger_input_tokens": 0,
                "target_input_tokens": 100000,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertEqual(result.image_prompts_compacted, 0)
        self.assertIn("referenced_image_history", result.reasons)

    def test_summary_candidates_exclude_instructions_tools_reasoning_and_media(self):
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "system", "content": "System instruction."},
                {"role": "developer", "content": "Developer instruction."},
                {"role": "user", "content": "Remember the client prefers blue."},
                {"role": "assistant", "content": "Preference noted."},
                {"role": "user", "content": "Call the lookup tool."},
                {
                    "role": "assistant",
                    "content": "",
                    "reasoning_content": "I need the tool.",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{}"},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "secret result"},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Inspect this image."},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}},
                    ],
                },
                {"role": "assistant", "content": "The image is grey."},
                {"role": "user", "content": "Give me the final recommendation."},
            ],
            "tools": [{"type": "function", "function": {"name": "lookup"}}],
            "optimization": {
                "mode": "summarize",
                "summary_model": "linkapi:summary-model",
                "trigger_input_tokens": 0,
                "target_input_tokens": 64,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertTrue(result.needs_summary)
        self.assertEqual(
            result.summary_source_messages,
            (
                {"role": "user", "content": "Remember the client prefers blue."},
                {"role": "assistant", "content": "Preference noted."},
            ),
        )
        self.assertEqual(result.payload["messages"][0], payload["messages"][0])
        self.assertEqual(result.payload["messages"][1], payload["messages"][1])
        self.assertEqual(result.payload["messages"][5], payload["messages"][5])
        self.assertEqual(result.payload["messages"][6], payload["messages"][6])
        self.assertEqual(result.payload["messages"][7], payload["messages"][7])
        self.assertEqual(result.payload["tools"], payload["tools"])

    def test_summary_candidates_exclude_reasoning_details(self):
        reasoning_message = {
            "role": "assistant",
            "content": "Visible answer.",
            "reasoning_details": [{"text": "private chain of thought"}],
        }
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "user", "content": "Old safe fact."},
                {"role": "assistant", "content": "Fact noted."},
                {"role": "user", "content": "Question with hidden reasoning."},
                reasoning_message,
                {"role": "user", "content": "Give the final answer."},
            ],
            "optimization": {
                "mode": "summarize",
                "summary_model": "linkapi:summary-model",
                "trigger_input_tokens": 0,
                "target_input_tokens": 64,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertNotIn(reasoning_message, result.summary_source_messages)
        self.assertEqual(result.payload["messages"][3], reasoning_message)

    def test_summary_candidates_preserve_messages_with_unknown_extra_state(self):
        audio_message = {
            "role": "assistant",
            "content": "Audio transcript.",
            "audio": {"id": "audio_123"},
        }
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "user", "content": "Old safe fact."},
                {"role": "assistant", "content": "Fact noted."},
                {"role": "user", "content": "Play the prior audio."},
                audio_message,
                {"role": "user", "content": "Give the final answer."},
            ],
            "optimization": {
                "mode": "summarize",
                "summary_model": "linkapi:summary-model",
                "trigger_input_tokens": 0,
                "target_input_tokens": 64,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertNotIn(audio_message, result.summary_source_messages)
        self.assertIn(audio_message, result.payload["messages"])

    def test_summary_candidates_do_not_cross_protected_history_boundaries(self):
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "system", "content": "Keep this."},
                {"role": "user", "content": "Old fact before the tool cycle."},
                {"role": "assistant", "content": "Old fact recorded."},
                {"role": "user", "content": "Call the lookup tool."},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{}"},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "tool answer"},
                {"role": "assistant", "content": "The tool returned a result."},
                {"role": "user", "content": "Later fact after the tool cycle. " * 20},
                {"role": "assistant", "content": "Later fact recorded. " * 20},
                {"role": "user", "content": "Give the final answer."},
            ],
            "optimization": {
                "mode": "summarize",
                "summary_model": "linkapi:summary-model",
                "trigger_input_tokens": 0,
                "target_input_tokens": 64,
                "keep_recent_turns": 1,
            },
        }

        result = optimize_chat_payload(payload, default_target_tokens=96000)

        self.assertEqual(
            result.summary_source_messages,
            (
                {"role": "user", "content": "Later fact after the tool cycle. " * 20},
                {"role": "assistant", "content": "Later fact recorded. " * 20},
            ),
        )

    def test_validated_summary_replaces_only_planned_plain_text_messages(self):
        payload = {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "system", "content": "Keep this."},
                {"role": "user", "content": "The user chose blue."},
                {"role": "assistant", "content": "Choice recorded."},
                {"role": "user", "content": "The deadline is Friday."},
                {"role": "assistant", "content": "Deadline recorded."},
                {"role": "user", "content": "What should happen next?"},
            ],
            "optimization": {
                "mode": "summarize",
                "summary_model": "linkapi:summary-model",
                "trigger_input_tokens": 0,
                "target_input_tokens": 64,
                "keep_recent_turns": 1,
            },
        }
        digest = validate_summary_digest(
            {
                "facts": ["The deadline is Friday."],
                "requirements": ["Use blue."],
                "decisions": [],
                "open_tasks": ["Choose the next action."],
                "visual_continuity": [],
            }
        )

        result = optimize_chat_payload(
            payload,
            default_target_tokens=96000,
            summary_digest=digest,
        )

        self.assertEqual(result.messages_summarized, 4)
        self.assertEqual(result.payload["messages"][0], payload["messages"][0])
        self.assertEqual(result.payload["messages"][-1], payload["messages"][-1])
        self.assertEqual(result.payload["messages"][1]["role"], "assistant")
        self.assertIn("untrusted historical conversation memory", result.payload["messages"][1]["content"])
        self.assertIn('"requirements":["Use blue."]', result.payload["messages"][1]["content"])

    def test_invalid_options_and_unreachable_required_target_fail_closed(self):
        with self.assertRaisesRegex(ContextOptimizationError, "optimization.mode"):
            optimize_chat_payload(
                {
                    "model": "openai:test",
                    "messages": [{"role": "user", "content": "hello"}],
                    "optimization": {"mode": "magical"},
                },
                default_target_tokens=96000,
            )

        with self.assertRaisesRegex(ContextOptimizationError, "optimization.mode"):
            optimize_chat_payload(
                {
                    "model": "openai:test",
                    "messages": [{"role": "user", "content": "hello"}],
                    "optimization": {"mode": []},
                },
                default_target_tokens=96000,
            )

        with self.assertRaisesRegex(ContextOptimizationError, "target"):
            optimize_chat_payload(
                {
                    "model": "openai:test",
                    "messages": [
                        {"role": "system", "content": "x" * 8000},
                        {"role": "user", "content": "keep me"},
                    ],
                    "optimization": {
                        "trigger_input_tokens": 0,
                        "target_input_tokens": 256,
                        "require_target": True,
                    },
                },
                default_target_tokens=96000,
            )


if __name__ == "__main__":
    unittest.main()
