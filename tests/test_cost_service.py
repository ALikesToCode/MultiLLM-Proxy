import json
import os
import unittest
from unittest.mock import patch

from services.cost_service import CostService


class CostServiceTest(unittest.TestCase):
    def test_estimate_uses_exact_model_pricing(self):
        pricing = json.dumps(
            {
                "openai:gpt-4.1": {
                    "input": 2,
                    "output": 8,
                }
            }
        )
        with patch.dict(
            os.environ,
            {CostService.ENV_NAME: pricing},
            clear=False,
        ):
            estimate = CostService.estimate(
                "openai:gpt-4.1",
                1_000_000,
                500_000,
            )

        self.assertEqual(estimate, 6.0)

    def test_provider_wildcard_supports_new_models_without_guessing_prices(self):
        pricing = json.dumps(
            {
                "openrouter:*": {
                    "input_cost_per_million": "1.5",
                    "output_cost_per_million": "3.5",
                }
            }
        )
        with patch.dict(
            os.environ,
            {CostService.ENV_NAME: pricing},
            clear=False,
        ):
            estimate = CostService.estimate(
                "new-model",
                1_000,
                2_000,
                provider="openrouter",
            )

        self.assertEqual(estimate, 0.0085)

    def test_missing_or_invalid_pricing_remains_unpriced(self):
        invalid_tables = (
            "",
            "not-json",
            json.dumps({"openai:gpt": {"input": -1, "output": 3}}),
        )
        for pricing in invalid_tables:
            with self.subTest(pricing=pricing), patch.dict(
                os.environ,
                {CostService.ENV_NAME: pricing},
                clear=False,
            ):
                self.assertIsNone(
                    CostService.estimate("openai:gpt", 100, 100)
                )

    def test_invalid_token_counts_are_treated_as_zero(self):
        pricing = json.dumps(
            {
                "openai:gpt": {
                    "input": 2,
                    "output": 8,
                }
            }
        )
        with patch.dict(
            os.environ,
            {CostService.ENV_NAME: pricing},
            clear=False,
        ):
            estimate = CostService.estimate(
                "openai:gpt",
                "not-a-number",
                -100,
            )

        self.assertEqual(estimate, 0.0)


if __name__ == "__main__":
    unittest.main()
