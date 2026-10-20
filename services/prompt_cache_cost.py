"""Opt-in cache bucket normalization and bounded catalog price estimates."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from functools import lru_cache
from typing import Any

from services.usage_types import StreamUsageObserver, UsageObservation

logger = logging.getLogger(__name__)
MAX_TOKENS = 2**53 - 1
MAX_MICROUSD = 1_000_000_000_000
TOKEN_FIELDS = ("ordinary_input_tokens", "cache_read_input_tokens", "cache_write_input_tokens", "output_tokens")
COST_FIELDS = ("ordinary_input_cost_microusd", "cache_read_input_cost_microusd",
               "cache_write_input_cost_microusd", "output_cost_microusd")
ROW_FIELDS = TOKEN_FIELDS[:3] + COST_FIELDS + ("bucket_basis", "bucket_source")
_warned: set[str] = set()


def _warn(name: str) -> None:
    if name not in _warned:
        _warned.add(name)
        logger.warning("Invalid %s; prompt cache buckets disabled", name)


@lru_cache(maxsize=8)
def _metadata(raw: str) -> dict | None:
    if len(raw) > 262144:
        return None
    try:
        value = json.loads(raw or "{}")
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or any(not isinstance(v, dict) for v in value.values()):
        return None
    if any(_price(price) is None for entry in value.values() for price in entry.values()):
        return None
    return value


def enabled() -> bool:
    flag = os.environ.get("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "").strip().lower()
    if flag in {"", "false", "0", "no", "off"}:
        return False
    if flag not in {"true", "1", "yes", "on"}:
        _warn("PROMPT_CACHE_USAGE_BUCKETS_ENABLED")
        return False
    if _metadata(os.environ.get("PROMPT_CACHE_PRICE_METADATA_JSON", "").strip()) is None:
        _warn("PROMPT_CACHE_PRICE_METADATA_JSON")
        return False
    return True


def count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= MAX_TOKENS else None


def _sum(values: tuple) -> int | None:
    return count(sum(values)) if all(value is not None for value in values) else None


@dataclass(frozen=True)
class CacheObservation(UsageObservation):
    raw_input: int | None = None
    cache_read: int | None = None
    cache_write: int | None = None
    source: str = "unknown"

    @classmethod
    def from_body(cls, value: Any) -> CacheObservation | None:
        if not isinstance(value, dict):
            return None
        native = value
        if not isinstance(native.get("usage"), dict):
            native = next((value[key] for key in ("response", "message")
                           if isinstance(value.get(key), dict) and isinstance(value[key].get("usage"), dict)), {})
        usage = native.get("usage")
        if not isinstance(usage, dict):
            return None
        typed = UsageObservation.from_body(value)
        if typed is None:
            return None
        anthropic = native.get("type") == "message" or "message" in value or str(value.get("type", "")).startswith("message_") or any(
            key in usage for key in ("cache_read_input_tokens", "cache_creation_input_tokens"))
        details = usage.get("prompt_tokens_details", usage.get("input_tokens_details"))
        details = details if isinstance(details, dict) else {}
        raw = count(typed.input_tokens)
        read = count(usage.get("cache_read_input_tokens")) if anthropic else count(details.get("cached_tokens"))
        write = count(usage.get("cache_creation_input_tokens")) if anthropic else count(details.get("cache_write_tokens", 0 if raw is not None or details else None))
        source = "anthropic" if anthropic else "openai" if raw is not None or details else "unknown"
        total = _sum((raw, read, write)) if anthropic else raw
        return cls(total, count(typed.output_tokens), typed.basis, typed.provenance, raw, read, write, source)

    def merge(self, later: UsageObservation) -> CacheObservation:
        if not isinstance(later, CacheObservation):
            return self
        def latest(old, new):
            return new if new is not None else old
        raw = latest(self.raw_input, later.raw_input)
        read = latest(self.cache_read, later.cache_read)
        # An output-only delta must not imply a new cache-write observation.
        write = latest(self.cache_write, later.cache_write) if later.source != "unknown" else self.cache_write
        source = later.source if later.source != "unknown" else self.source
        total = _sum((raw, read, write)) if source == "anthropic" else raw
        output = latest(self.output_tokens, later.output_tokens)
        known = any(v is not None for v in (raw, read, write, output))
        return CacheObservation(total, output, "provider" if known else "unknown", ("provider",) if known else (),
                                raw, read, write, source)


def buckets_from(usage: UsageObservation | None) -> dict:
    ordinary, read, write, output, source = None, None, None, None, "unknown"
    if isinstance(usage, CacheObservation):
        read, write, output, source = usage.cache_read, usage.cache_write, usage.output_tokens, usage.source
        if source == "anthropic":
            ordinary = usage.raw_input
        elif usage.raw_input is not None and read is not None and write is not None:
            ordinary = count(usage.raw_input - read - write)
    elif usage is not None:
        output = count(usage.output_tokens)
    basis = "measured" if any(v is not None for v in (ordinary, read, write, output)) else "unknown"
    if usage is not None and usage.basis == "estimated":
        basis, source = "estimated", "request_estimate"
    return dict(zip(TOKEN_FIELDS, (ordinary, read, write, output)), bucket_basis=basis, bucket_source=source)


class CacheStreamObserver(StreamUsageObserver):
    _pending: bytes
    _oversized: bool
    observation: UsageObservation | None

    def _line(self) -> None:
        line, self._pending = self._pending.strip(), b""
        if self._oversized:
            self._oversized = False
            return
        if not line.startswith(b"data:") or b'"usage"' not in line:
            return
        try:
            found = CacheObservation.from_body(json.loads(line[5:]))
        except (ValueError, RecursionError):
            return
        if found is not None:
            self.observation = self.observation.merge(found) if self.observation is not None else found


def _entry(table: dict, model: str) -> dict | None:
    provider = model.split(":", 1)[0] if ":" in model else ""
    return next((table[key] for key in (model, f"{provider}:*" if provider else "", "*")
                 if key and isinstance(table.get(key), dict)), None)


def _price(value: Any) -> Decimal | None:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return number if number.is_finite() and 0 <= number <= MAX_MICROUSD else None


def price_buckets(model: str | None, usage: UsageObservation | None, *, requests: int = 1) -> dict:
    buckets = buckets_from(usage)
    result = {**buckets, **dict.fromkeys(COST_FIELDS), "cost_usd": None}
    try:
        table = json.loads(os.environ.get("MODEL_PRICING_USD_PER_MILLION", "") or "{}")
    except (ValueError, RecursionError):
        return result
    if not isinstance(table, dict) or not model:
        return result
    model = model.strip().lower()
    table = {key.strip().lower(): value for key, value in table.items() if isinstance(key, str)}
    explicit = _entry(table, model)
    if explicit is None:
        return result
    metadata = _metadata(os.environ.get("PROMPT_CACHE_PRICE_METADATA_JSON", "").strip()) or {}
    supplement = metadata.get(model, {})
    names = ("input", "cache_read", "cache_write", "output")
    aliases = {"input": "input_cost_per_million", "output": "output_cost_per_million"}
    flat_only = "request" in explicit and not any(key in explicit for key in (*names, *aliases.values()))
    costs = []
    with localcontext() as ctx:
        ctx.prec = 40
        for tokens, cost_name, name in zip(TOKEN_FIELDS, COST_FIELDS, names):
            alias = aliases.get(name, name)
            value = explicit.get(name, explicit.get(alias, supplement.get(name)))
            unit = Decimal(0) if flat_only else _price(value)
            amount = buckets[tokens]
            if amount == 0 or unit == 0:
                cost = Decimal(0)
            elif amount is None or unit is None:
                cost = None
            else:
                cost = Decimal(amount) * unit
                if cost > MAX_MICROUSD:
                    cost = None
            result[cost_name] = float(cost) if cost is not None else None
            costs.append(cost)
        flat = _price(explicit.get("request", 0))
        if flat is not None and count(requests) is not None and all(v is not None for v in costs):
            total = sum((cost for cost in costs if cost is not None), Decimal(0)) + flat * requests * 1_000_000
            if total <= MAX_MICROUSD:
                result["cost_usd"] = float(total / 1_000_000)
    return result


def anthropic_to_chat(usage: dict) -> dict:
    observed = CacheObservation.from_body({"type": "message", "usage": usage}) or CacheObservation()
    return {"prompt_tokens": observed.input_tokens, "completion_tokens": observed.output_tokens,
            "total_tokens": _sum((observed.input_tokens, observed.output_tokens)),
            "prompt_tokens_details": {"cached_tokens": observed.cache_read, "cache_write_tokens": observed.cache_write}}


def chat_to_anthropic(usage: Any) -> dict:
    observed = CacheObservation.from_body({"usage": usage})
    buckets = buckets_from(observed)
    return {"input_tokens": buckets["ordinary_input_tokens"], "output_tokens": buckets["output_tokens"],
            "cache_creation_input_tokens": buckets["cache_write_input_tokens"],
            "cache_read_input_tokens": buckets["cache_read_input_tokens"]}


def budget_price(models: list[str], usage: UsageObservation, requests: int) -> float | None:
    """Bound a conservative budget estimate, without persisting assumed cache zeros."""
    estimated = CacheObservation(usage.input_tokens, usage.output_tokens, "estimated", ("request_estimate",),
                                 count(usage.input_tokens), 0, 0, "request_estimate")
    prices = [price_buckets(model, estimated, requests=requests)["cost_usd"] for model in models]
    known = [price for price in prices if price is not None]
    return max(known) if known else None
