import unittest

from services.nanogpt_key_pool import (
    NanoGPTKeyPool,
    NanoGPTKeyPoolExhausted,
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

    def tearDown(self):
        NanoGPTKeyPool.reset()

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
        NanoGPTKeyPool.invalidate(
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


if __name__ == "__main__":
    unittest.main()
