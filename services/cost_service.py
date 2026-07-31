import json
import os
from decimal import Decimal, InvalidOperation
from typing import Any


class CostService:
    """Estimate request exposure from operator-supplied model pricing."""

    ENV_NAME = "MODEL_PRICING_USD_PER_MILLION"

    @staticmethod
    def _decimal(value: Any) -> Decimal | None:
        try:
            result = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            return None
        if not result.is_finite() or result < 0:
            return None
        return result

    @staticmethod
    def _token_count(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError, OverflowError):
            return 0

    @classmethod
    def pricing_table(cls) -> dict[str, dict[str, Decimal]]:
        raw_pricing = os.environ.get(cls.ENV_NAME, "").strip()
        if not raw_pricing:
            return {}
        try:
            payload = json.loads(raw_pricing)
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}

        pricing: dict[str, dict[str, Decimal]] = {}
        for model_id, raw_entry in payload.items():
            if not isinstance(model_id, str) or not isinstance(raw_entry, dict):
                continue
            input_price = cls._decimal(
                raw_entry.get(
                    "input",
                    raw_entry.get("input_cost_per_million"),
                )
            )
            output_price = cls._decimal(
                raw_entry.get(
                    "output",
                    raw_entry.get("output_cost_per_million"),
                )
            )
            if input_price is None or output_price is None:
                continue
            pricing[model_id.strip().lower()] = {
                "input": input_price,
                "output": output_price,
            }
        return pricing

    @classmethod
    def pricing_for(
        cls,
        model_id: str | None,
        provider: str | None = None,
    ) -> dict[str, Decimal] | None:
        if not model_id:
            return None

        normalized_model = str(model_id).strip().lower()
        normalized_provider = str(provider or "").strip().lower()
        if ":" in normalized_model:
            normalized_provider = normalized_model.split(":", 1)[0]
        elif normalized_provider:
            normalized_model = f"{normalized_provider}:{normalized_model}"

        pricing = cls.pricing_table()
        for candidate in (
            normalized_model,
            f"{normalized_provider}:*" if normalized_provider else "",
            "*",
        ):
            if candidate and candidate in pricing:
                return pricing[candidate]
        return None

    @classmethod
    def estimate(
        cls,
        model_id: str | None,
        input_tokens: int | None,
        output_tokens: int | None,
        *,
        provider: str | None = None,
    ) -> float | None:
        prices = cls.pricing_for(model_id, provider=provider)
        if prices is None:
            return None

        safe_input_tokens = cls._token_count(input_tokens)
        safe_output_tokens = cls._token_count(output_tokens)
        total = (
            Decimal(safe_input_tokens) * prices["input"]
            + Decimal(safe_output_tokens) * prices["output"]
        ) / Decimal(1_000_000)
        return float(total.quantize(Decimal("0.0000000001")))
