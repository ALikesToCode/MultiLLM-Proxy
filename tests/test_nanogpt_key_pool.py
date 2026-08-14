import unittest

from services.nanogpt_key_pool import (
    NanoGPTKeyPool,
    NanoGPTKeyPoolExhausted,
    NanoGPTUnifiedKeyPool,
    configured_nanogpt_keys,
)


class NanoGPTConfiguredKeysTest(unittest.TestCase):
    def test_loads_aliases_lists_and_numbered_keys_without_duplicates(self):
        keys = configured_nanogpt_keys(
            {
                "NANOGPT_API_KEY": "primary",
                "NANO_GPT_KEY": "alias",
                "NANOGPT_API_KEYS": '["listed", "primary"]',
                "NANO_GPT_KEYS": "comma-one,comma-two",
                "NANO_GPT_KEY_2": "numbered-two",
                "NANO_GPT_KEY_1": "numbered-one",
                "NANOGPT_API_KEY_1": "canonical-numbered-one",
            }
        )

        self.assertEqual(
            keys,
            [
                "primary",
                "alias",
                "listed",
                "comma-one",
                "comma-two",
                "canonical-numbered-one",
                "numbered-one",
                "numbered-two",
            ],
        )


class NanoGPTKeyPoolTest(unittest.TestCase):
    def setUp(self):
        NanoGPTKeyPool.reset()
        NanoGPTUnifiedKeyPool.reset()

    def tearDown(self):
        NanoGPTKeyPool.reset()
        NanoGPTUnifiedKeyPool.reset()

    def test_selects_first_usable_key_and_reuses_it_until_ttl(self):
        probes = []

        def probe(key):
            probes.append(key)
            return {"invalid": 401, "working": 200}[key]

        selected = NanoGPTKeyPool.select_key(
            ["invalid", "working"],
            probe,
            check_ttl_seconds=300,
            now=100,
        )
        cached = NanoGPTKeyPool.select_key(
            ["invalid", "working"],
            probe,
            check_ttl_seconds=300,
            now=200,
        )

        self.assertEqual(selected, "working")
        self.assertEqual(cached, "working")
        self.assertEqual(probes, ["invalid", "working"])

    def test_uses_a_single_key_without_an_initial_catalog_probe(self):
        probes = []

        selected = NanoGPTKeyPool.select_key(
            ["only-key"],
            lambda key: probes.append(key) or 200,
            now=100,
        )

        self.assertEqual(selected, "only-key")
        self.assertEqual(probes, [])

    def test_revalidates_the_active_key_after_the_request_interval(self):
        probes = []

        selected = NanoGPTKeyPool.select_key(
            ["working"],
            lambda key: probes.append(key) or 200,
            check_every_requests=2,
            now=100,
        )
        NanoGPTKeyPool.record_result(selected, 200)
        cached = NanoGPTKeyPool.select_key(
            ["working"],
            lambda key: probes.append(key) or 200,
            check_every_requests=2,
            now=101,
        )
        NanoGPTKeyPool.record_result(cached, 500)
        revalidated = NanoGPTKeyPool.select_key(
            ["working"],
            lambda key: probes.append(key) or 200,
            check_every_requests=2,
            now=102,
        )

        self.assertEqual(revalidated, "working")
        self.assertEqual(probes, ["working"])

    def test_ambiguous_revalidation_keeps_the_last_working_key(self):
        selected = NanoGPTKeyPool.select_key(
            ["working"],
            lambda _key: 200,
            check_every_requests=1,
            now=100,
        )
        NanoGPTKeyPool.record_result(selected, 200)

        retained = NanoGPTKeyPool.select_key(
            ["working"],
            lambda _key: 503,
            check_every_requests=1,
            now=101,
        )

        self.assertEqual(retained, "working")

    def test_rate_limit_invalidates_active_key_and_selects_the_next_one(self):
        probes = []

        def probe(key):
            probes.append(key)
            return 200

        selected = NanoGPTKeyPool.select_key(
            ["first", "second"],
            probe,
            now=100,
        )
        NanoGPTKeyPool.record_result(
            selected,
            429,
            rejected_cooldown_seconds=60,
            now=101,
        )
        replacement = NanoGPTKeyPool.select_key(
            ["first", "second"],
            probe,
            now=102,
        )

        self.assertEqual(selected, "first")
        self.assertEqual(replacement, "second")
        self.assertEqual(probes, ["first", "second"])

    def test_insufficient_balance_invalidates_key_for_the_catalog_ttl(self):
        probes = []

        def probe(key):
            probes.append(key)
            return 200

        selected = NanoGPTKeyPool.select_key(
            ["empty", "funded"],
            probe,
            check_ttl_seconds=300,
            now=100,
        )
        NanoGPTKeyPool.record_result(
            selected,
            402,
            check_ttl_seconds=300,
            now=101,
        )
        replacement = NanoGPTKeyPool.select_key(
            ["empty", "funded"],
            probe,
            check_ttl_seconds=300,
            now=102,
        )

        self.assertEqual(selected, "empty")
        self.assertEqual(replacement, "funded")
        self.assertEqual(probes, ["empty", "funded"])

    def test_single_rejected_key_remains_in_cooldown(self):
        selected = NanoGPTUnifiedKeyPool.select_key(
            ["subscription-key"],
            lambda _key: 200,
            check_ttl_seconds=300,
            now=100,
        )
        NanoGPTUnifiedKeyPool.record_result(
            selected,
            402,
            check_ttl_seconds=300,
            now=101,
        )

        with self.assertRaisesRegex(
            NanoGPTKeyPoolExhausted,
            "All configured NanoGPT keys are cooling down",
        ):
            NanoGPTUnifiedKeyPool.select_key(
                ["subscription-key"],
                lambda _key: 200,
                check_ttl_seconds=300,
                now=102,
            )

    def test_raises_without_exposing_keys_when_every_probe_fails(self):
        with self.assertRaisesRegex(
            NanoGPTKeyPoolExhausted,
            "No configured NanoGPT API key passed validation",
        ) as raised:
            NanoGPTKeyPool.select_key(
                ["secret-one", "secret-two"],
                lambda _key: 401,
                now=100,
            )

        self.assertNotIn("secret-one", str(raised.exception))
        self.assertNotIn("secret-two", str(raised.exception))

    def test_unified_subscription_health_is_independent_from_raw_health(self):
        raw = NanoGPTKeyPool.select_key(
            ["raw-key", "subscription-key"],
            lambda key: 200 if key == "raw-key" else 401,
            now=100,
        )
        subscription = NanoGPTUnifiedKeyPool.select_key(
            ["raw-key", "subscription-key"],
            lambda key: 200 if key == "subscription-key" else 403,
            now=100,
        )

        self.assertEqual(raw, "raw-key")
        self.assertEqual(subscription, "subscription-key")


if __name__ == "__main__":
    unittest.main()
