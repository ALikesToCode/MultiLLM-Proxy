import json
import os
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from typing import Any

from services import price_tiers


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
    @lru_cache(maxsize=8)
    def _parse_pricing_table(
        cls,
        raw_pricing: str,
    ) -> dict[str, dict[str, Any]]:
        if not raw_pricing:
            return {}
        try:
            payload = json.loads(raw_pricing)
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}

        pricing: dict[str, dict[str, Any]] = {}
        for model_id, raw_entry in payload.items():
            if not isinstance(model_id, str) or not isinstance(raw_entry, dict):
                continue
            # An optional flat price per request (per generated image on image routes)
            # prices media models that report no tokens. It may stand alone.
            request_price = cls._decimal(raw_entry["request"]) if "request" in raw_entry else Decimal(0)
            per_request_only = "request" in raw_entry and not any(
                key in raw_entry for key in ("input", "output", "input_cost_per_million", "output_cost_per_million")
            )
            input_price = Decimal(0) if per_request_only else cls._decimal(
                raw_entry.get(
                    "input",
                    raw_entry.get("input_cost_per_million"),
                )
            )
            output_price = Decimal(0) if per_request_only else cls._decimal(
                raw_entry.get(
                    "output",
                    raw_entry.get("output_cost_per_million"),
                )
            )
            if input_price is None or output_price is None or request_price is None:
                continue
            entry: dict[str, Any] = {
                "input": input_price,
                "output": output_price,
                "request": request_price,
            }
            # A malformed long-prompt tier leaves the model unpriced rather than
            # charging long prompts the short-prompt price.
            try:
                tier = price_tiers.tier(raw_entry)
            except price_tiers.InvalidTier:
                continue
            if tier is not None:
                tier_prices = {name: cls._decimal(value) for name, value in tier[1].items()}
                if any(price is None for price in tier_prices.values()):
                    continue
                entry[price_tiers.TIER_KEY] = {price_tiers.THRESHOLD_KEY: tier[0], **tier_prices}
            pricing[model_id.strip().lower()] = entry
        return pricing

    @classmethod
    def pricing_table(cls) -> dict[str, dict[str, Any]]:
        raw_pricing = os.environ.get(cls.ENV_NAME, "").strip()
        return cls._parse_pricing_table(raw_pricing)

    @classmethod
    def pricing_for(
        cls,
        model_id: str | None,
        provider: str | None = None,
    ) -> dict[str, Any] | None:
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
    def prices_for_prompt(cls, prices: dict[str, Any], input_tokens: Any) -> dict[str, Any]:
        """The entry's prices for a request whose prompt holds `input_tokens`: its
        long-prompt tier's prices when the prompt is over the tier's threshold."""
        tier = prices.get(price_tiers.TIER_KEY)
        if tier is None or input_tokens is None:
            return prices
        if cls._token_count(input_tokens) <= tier[price_tiers.THRESHOLD_KEY]:
            return prices
        return {**prices, **{name: value for name, value in tier.items() if name != price_tiers.THRESHOLD_KEY}}

    @classmethod
    def estimate(
        cls,
        model_id: str | None,
        input_tokens: int | None,
        output_tokens: int | None,
        *,
        provider: str | None = None,
        requests: int = 1,
    ) -> float | None:
        prices = cls.pricing_for(model_id, provider=provider)
        if prices is None:
            return None
        prices = cls.prices_for_prompt(prices, input_tokens)

        # A missing count is unknown when it contributes to the invoice. Flat-only
        # and explicitly free components do not require provider token counts.
        if ((input_tokens is None and prices["input"] != 0)
                or (output_tokens is None and prices["output"] != 0)):
            return None

        safe_input_tokens = cls._token_count(input_tokens)
        safe_output_tokens = cls._token_count(output_tokens)
        total = (
            Decimal(safe_input_tokens) * prices["input"]
            + Decimal(safe_output_tokens) * prices["output"]
        ) / Decimal(1_000_000) + Decimal(cls._token_count(requests)) * prices.get("request", Decimal(0))
        return float(total.quantize(Decimal("0.0000000001")))

    @classmethod
    def price_buckets(cls, model_id, usage, *, requests: int = 1) -> dict:
        """Return nullable bucket costs without changing legacy estimate semantics."""
        from services.prompt_cache_cost import price_buckets

        return price_buckets(model_id, usage, requests=requests)
