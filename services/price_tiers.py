"""Long-prompt price tiers in `MODEL_PRICING_USD_PER_MILLION` entries.

Some models bill a whole request at higher prices once its prompt passes a size,
for example Claude Haiku 5.5 above 100,000 prompt tokens. An entry describes that
with a `long_context` object:

    {"input": 0.1, "output": 0.5,
     "long_context": {"above_input_tokens": 100000, "input": 0.5, "output": 2.5}}

The prompt size is every input token of the request, cache reads and writes
included. A request over `above_input_tokens` pays the tier's prices for all of
its tokens, output included; a price the tier does not name keeps the base price.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

TIER_KEY = "long_context"
THRESHOLD_KEY = "above_input_tokens"
TIER_PRICE_NAMES = ("input", "output", "cache_read", "cache_write", "cache_write_1h")


class InvalidTier(ValueError):
    """A `long_context` object that cannot be applied without guessing."""


def tier(entry: Mapping[str, Any]) -> tuple[int, dict[str, Any]] | None:
    """The entry's threshold and raw tier prices, or None when it has no tier.

    A malformed tier raises InvalidTier: a missing or non-integer threshold, no
    prices, or an unknown key (a misspelt price would otherwise be ignored and the
    request under-priced). Callers validate the price values themselves.
    """
    if TIER_KEY not in entry:
        return None
    raw = entry[TIER_KEY]
    if not isinstance(raw, Mapping):
        raise InvalidTier(TIER_KEY)
    threshold = raw.get(THRESHOLD_KEY)
    if type(threshold) is not int or threshold < 0:
        raise InvalidTier(THRESHOLD_KEY)
    unknown = set(raw) - {THRESHOLD_KEY, *TIER_PRICE_NAMES}
    prices = {name: raw[name] for name in TIER_PRICE_NAMES if name in raw}
    if unknown or not prices:
        raise InvalidTier(TIER_KEY)
    return threshold, prices


def applies(found: tuple[int, dict[str, Any]] | None, input_tokens: int | None) -> bool:
    """Whether a request whose prompt holds `input_tokens` pays the tier's prices."""
    return found is not None and input_tokens is not None and input_tokens > found[0]
