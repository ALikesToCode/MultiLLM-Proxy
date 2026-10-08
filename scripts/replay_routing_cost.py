#!/usr/bin/env python3
"""Offline token-cost counterfactuals from content-free observations and prices."""

import argparse
import json
import math
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
MAX_OBSERVATIONS = 10000
MAX_CANDIDATES = 128
OBSERVATION_FIELDS = {"sample_id", "production_model", "route", "task_type", "created_at", "usage", "latency_ms", "cost_usd"}
USAGE_FIELDS = {"prompt_tokens", "completion_tokens", "total_tokens"}


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _observations(values):
    if not isinstance(values, list) or len(values) > MAX_OBSERVATIONS:
        raise ValueError("Use at most 10000 content-free observations")
    for value in values:
        if not isinstance(value, dict) or set(value) - OBSERVATION_FIELDS:
            raise ValueError("Observations must contain only content-free metadata and usage")
        usage = value.get("usage", {})
        if (not isinstance(usage, dict) or set(usage) - USAGE_FIELDS
                or any(type(amount) is not int or not 0 <= amount <= 2**31 - 1 for amount in usage.values())):
            raise ValueError("Invalid observed token usage")
        for name in ("latency_ms", "cost_usd", "created_at"):
            if value.get(name) is not None and not _number(value[name]):
                raise ValueError("Invalid numeric observation")
        for name in ("sample_id", "production_model", "route", "task_type"):
            if name in value and (not isinstance(value[name], str) or len(value[name]) > 256):
                raise ValueError("Invalid observation metadata")
    return values


def _prices(values):
    if not isinstance(values, dict) or len(values) > MAX_CANDIDATES:
        raise ValueError("Use at most 128 candidate prices")
    for model, value in values.items():
        if not isinstance(model, str) or not 1 <= len(model) <= 256:
            raise ValueError("Invalid candidate model")
        if value is None:
            continue
        if not isinstance(value, dict) or set(value) != {"input_per_million", "output_per_million"}:
            raise ValueError("Prices require input_per_million and output_per_million")
        if any(amount is not None and not _number(amount) for amount in value.values()):
            raise ValueError("Invalid candidate price")
    return values


def _cost(observation, price):
    usage = observation.get("usage", {})
    if (price is None or any(price[name] is None for name in price)
            or not {"prompt_tokens", "completion_tokens"} <= usage.keys()):
        return None
    value = (usage["prompt_tokens"] * price["input_per_million"]
             + usage["completion_tokens"] * price["output_per_million"]) / 1000000
    return round(value, 12) if math.isfinite(value) else None


def replay(observations, prices):
    observations, prices = _observations(observations), _prices(prices)
    candidates = {}
    for model, price in sorted(prices.items()):
        cells = [_cost(observation, price) for observation in observations]
        known = [value for value in cells if value is not None]
        try:
            subtotal = round(math.fsum(known), 12)
        except OverflowError:
            subtotal = None
        candidates[model] = {"cells": cells, "known_subtotal_usd": subtotal,
            "total_usd": subtotal if len(known) == len(cells) else None,
            "known_cells": len(known), "unknown_cells": len(cells) - len(known),
            "coverage": len(known) / len(cells) if cells else None}
    return {"version": 1, "observation_count": len(observations), "candidates": candidates,
        "observed_latency_ms": [value.get("latency_ms") for value in observations],
        "counterfactual_latency_ms": None,
        "assumption": "Observed token counts held fixed; no candidate output or latency prediction"}


def _read(path):
    with Path(path).open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Input exceeds 16 MiB")
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", required=True, help="JSON array of content-free sample metadata and usage")
    parser.add_argument("--prices", required=True, help="JSON mapping of model IDs to USD prices per million tokens")
    args = parser.parse_args()
    try:
        result = replay(_read(args.observations), _read(args.prices))
    except (OSError, ValueError, OverflowError):
        parser.error("Invalid or unavailable replay inputs")
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
