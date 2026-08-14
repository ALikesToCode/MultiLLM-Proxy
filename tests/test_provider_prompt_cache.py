import unittest

from services.provider_prompt_cache import apply_prompt_cache_policy


class ProviderPromptCacheTest(unittest.TestCase):
    long_text = "persistent roleplay context " * 250

    def payload(self):
        return {
            "model": "model",
            "messages": [
                {"role": "system", "content": self.long_text},
                {"role": "user", "content": "Begin."},
            ],
        }

    def test_nanogpt_enables_documented_cache_routing_for_long_chat(self):
        decision = apply_prompt_cache_policy(
            self.payload(),
            provider="nanogpt",
            model="zai-org/glm-5.2:thinking",
        )

        self.assertEqual(decision.status, "applied")
        self.assertEqual(decision.mode, "nanogpt-routing")
        self.assertIs(decision.payload["caching"], True)

    def test_caller_cache_controls_are_preserved_without_override(self):
        payload = {**self.payload(), "caching": False}

        decision = apply_prompt_cache_policy(
            payload,
            provider="nanogpt",
            model="zai-org/glm-5.2:thinking",
        )

        self.assertEqual(decision.status, "caller")
        self.assertIs(decision.payload["caching"], False)

    def test_nanogpt_subscription_mode_removes_paygo_cache_routing(self):
        decision = apply_prompt_cache_policy(
            {**self.payload(), "caching": True},
            provider="nanogpt",
            model="zai-org/glm-5.2:thinking",
            nanogpt_subscription_only=True,
        )

        self.assertEqual(decision.status, "skipped")
        self.assertEqual(decision.mode, "nanogpt-subscription-only")
        self.assertNotIn("caching", decision.payload)

    def test_known_cache_key_transport_gets_a_stable_hashed_prefix_key(self):
        first = apply_prompt_cache_policy(
            self.payload(),
            provider="kimi-code",
            model="k3",
        )
        continued = self.payload()
        continued["messages"].extend(
            [
                {"role": "assistant", "content": "Opening response."},
                {"role": "user", "content": "Continue."},
            ]
        )
        second = apply_prompt_cache_policy(
            continued,
            provider="kimi-code",
            model="k3",
        )

        self.assertEqual(
            first.payload["prompt_cache_key"], second.payload["prompt_cache_key"]
        )
        self.assertRegex(first.payload["prompt_cache_key"], r"^mllm-[0-9a-f]{48}$")
        self.assertNotIn("persistent", first.payload["prompt_cache_key"])

    def test_grok_chat_uses_conversation_affinity_header(self):
        decision = apply_prompt_cache_policy(
            self.payload(),
            provider="linkapi",
            model="grok-4.5",
        )

        self.assertEqual(decision.mode, "conversation-affinity")
        self.assertRegex(
            decision.request_headers["X-Grok-Conv-Id"],
            r"^mllm-[0-9a-f]{48}$",
        )
        self.assertNotIn("prompt_cache_key", decision.payload)

    def test_implicit_cache_provider_receives_no_unsupported_fields(self):
        decision = apply_prompt_cache_policy(
            self.payload(),
            provider="navyai",
            model="glm-5.2",
        )

        self.assertEqual(decision.status, "implicit")
        self.assertEqual(decision.mode, "implicit-prefix")
        self.assertEqual(decision.payload, self.payload())
        self.assertEqual(decision.request_headers, {})

    def test_short_context_does_not_receive_an_automatic_hint(self):
        decision = apply_prompt_cache_policy(
            {
                "messages": [
                    {"role": "user", "content": "Short request"},
                ]
            },
            provider="nanogpt",
            model="zai-org/glm-5.2:thinking",
        )

        self.assertEqual(decision.status, "skipped")
        self.assertEqual(decision.mode, "below-threshold")
        self.assertNotIn("caching", decision.payload)

    def test_responses_cache_key_uses_input_when_messages_are_absent(self):
        decision = apply_prompt_cache_policy(
            {"input": self.long_text},
            provider="codex-easy",
            model="grok-4.5",
            endpoint="responses",
        )

        self.assertEqual(decision.mode, "cache-key")
        self.assertRegex(
            decision.payload["prompt_cache_key"],
            r"^mllm-[0-9a-f]{48}$",
        )


if __name__ == "__main__":
    unittest.main()
