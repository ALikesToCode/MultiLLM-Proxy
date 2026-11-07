"""Token observations and bounded stream parsing, independent of durable row fields."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

UsageBasis = Literal["provider", "estimated", "unknown"]


def _component(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


MAX_ITERATIONS = 256
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")


@dataclass(frozen=True)
class IterationUsage:
    """One sampling step of a Claude request (`usage.iterations[]`), such as an advisor
    call, with Anthropic's buckets: `input_tokens` excludes cache reads and writes.
    `model` is set when the step ran on another model than the request's."""

    kind: str
    model: str | None
    input_tokens: int | None
    output_tokens: int | None
    cache_read_input_tokens: int | None
    cache_creation_input_tokens: int | None
    cache_write_1h_tokens: int | None

    @classmethod
    def parse(cls, value: Any) -> IterationUsage | None:
        if not isinstance(value, dict):
            return None
        kind = value.get("type")
        kind = kind if isinstance(kind, str) else "message"
        model = value.get("model")
        model = model if isinstance(model, str) and _MODEL_ID.fullmatch(model) else None
        creation = value.get("cache_creation")
        one_hour = _component(creation.get("ephemeral_1h_input_tokens")) if isinstance(creation, dict) else None
        return cls(kind[:64], model, _component(value.get("input_tokens")), _component(value.get("output_tokens")),
                   _component(value.get("cache_read_input_tokens", 0)),
                   _component(value.get("cache_creation_input_tokens", 0)), one_hour)

    def as_usage(self) -> dict:
        """The step as a Claude Messages `usage` object."""
        usage = {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                 "cache_read_input_tokens": self.cache_read_input_tokens,
                 "cache_creation_input_tokens": self.cache_creation_input_tokens}
        if self.cache_write_1h_tokens:
            usage["cache_creation"] = {"ephemeral_1h_input_tokens": self.cache_write_1h_tokens}
        return usage


UNKNOWN_STEP = IterationUsage("unknown", None, None, None, None, None, None)


def _sum(values: list[int | None]) -> int | None:
    return sum(value for value in values if value is not None) if all(value is not None for value in values) else None


def _summed(steps: list[IterationUsage]) -> IterationUsage:
    return IterationUsage(
        steps[0].kind, steps[0].model,
        input_tokens=_sum([step.input_tokens for step in steps]),
        output_tokens=_sum([step.output_tokens for step in steps]),
        cache_read_input_tokens=_sum([step.cache_read_input_tokens for step in steps]),
        cache_creation_input_tokens=_sum([step.cache_creation_input_tokens for step in steps]),
        cache_write_1h_tokens=sum(step.cache_write_1h_tokens or 0 for step in steps) or None)


def iterations_from(usage: Any) -> tuple[IterationUsage, ...]:
    entries = usage.get("iterations") if isinstance(usage, dict) else None
    if not isinstance(entries, list) or not entries:
        return ()
    # An entry that cannot be read is kept as unknown, so its cost is unknown too.
    steps = [IterationUsage.parse(entry) or UNKNOWN_STEP for entry in entries[:MAX_ITERATIONS]]
    # Steps past the cap are summed per kind and model rather than dropped, so they are
    # still billed; a sum can only reach a higher long-prompt tier, never a lower one.
    overflow: dict[tuple[str, str | None], list[IterationUsage]] = {}
    for entry in entries[MAX_ITERATIONS:]:
        step = IterationUsage.parse(entry) or UNKNOWN_STEP
        key = (step.kind, step.model)
        if key not in overflow and len(overflow) >= MAX_ITERATIONS:
            key, step = ("unknown", None), UNKNOWN_STEP
        overflow.setdefault(key, []).append(step)
    return tuple(steps) + tuple(_summed(group) for group in overflow.values())


@dataclass(frozen=True)
class UsageObservation:
    input_tokens: int | None = None
    output_tokens: int | None = None
    basis: UsageBasis = "unknown"
    provenance: tuple[str, ...] = ()
    cached_input_tokens: int | None = field(default=None, kw_only=True)
    reasoning_tokens: int | None = field(default=None, kw_only=True)
    # Per-model sampling steps, when the provider reports them (Claude's advisor tool).
    iterations: tuple[IterationUsage, ...] = field(default=(), kw_only=True)

    @classmethod
    def from_body(cls, value: Any) -> UsageObservation | None:
        if not isinstance(value, dict):
            return None
        usage = value.get("usage")
        if not isinstance(usage, dict):
            for key in ("response", "message"):
                nested = value.get(key)
                if isinstance(nested, dict) and isinstance(nested.get("usage"), dict):
                    usage = nested["usage"]
                    break
        if not isinstance(usage, dict):
            return None
        input_tokens = _component(usage.get("prompt_tokens", usage.get("input_tokens")))
        output_tokens = _component(usage.get("completion_tokens", usage.get("output_tokens")))
        input_details = usage.get("prompt_tokens_details", usage.get("input_tokens_details"))
        output_details = usage.get("completion_tokens_details", usage.get("output_tokens_details"))
        cached = _component(input_details.get("cached_tokens")) if isinstance(input_details, dict) else None
        reasoning = _component(output_details.get("reasoning_tokens")) if isinstance(output_details, dict) else None
        if "cache_read_input_tokens" in usage or "cache_creation_input_tokens" in usage:
            cached = _component(usage.get("cache_read_input_tokens"))
            written = _component(usage.get("cache_creation_input_tokens"))
            if input_tokens is not None:
                input_tokens += (cached or 0) + (written or 0)
        data = value.get("data")
        if isinstance(data, list) and any(isinstance(item, dict) and "embedding" in item for item in data):
            output_tokens = 0
        known = input_tokens is not None or output_tokens is not None
        return cls(input_tokens, output_tokens, "provider" if known else "unknown",
                   ("provider",) if known else (), cached_input_tokens=cached, reasoning_tokens=reasoning,
                   iterations=iterations_from(usage))

    def merge(self, later: UsageObservation) -> UsageObservation:
        """Use the latest valid value for each component; null never erases a count."""
        input_tokens = later.input_tokens if later.input_tokens is not None else self.input_tokens
        output_tokens = later.output_tokens if later.output_tokens is not None else self.output_tokens
        provenance = tuple(dict.fromkeys((*self.provenance, *later.provenance)))
        basis: UsageBasis = "estimated" if "request_estimate" in provenance else (
            "provider" if input_tokens is not None or output_tokens is not None else "unknown")
        return UsageObservation(input_tokens, output_tokens, basis, provenance,
                                cached_input_tokens=later.cached_input_tokens if later.cached_input_tokens is not None else self.cached_input_tokens,
                                reasoning_tokens=later.reasoning_tokens if later.reasoning_tokens is not None else self.reasoning_tokens,
                                iterations=later.iterations or self.iterations)

    def with_estimates(self, input_tokens: int | None, output_tokens: int | None) -> UsageObservation:
        """Fill missing components explicitly, retaining measured zero and provenance."""
        estimated_input = _component(input_tokens) if self.input_tokens is None else None
        estimated_output = _component(output_tokens) if self.output_tokens is None else None
        if estimated_input is None and estimated_output is None:
            return self
        return UsageObservation(self.input_tokens if self.input_tokens is not None else estimated_input,
                                self.output_tokens if self.output_tokens is not None else estimated_output,
                                "estimated", tuple(dict.fromkeys((*self.provenance, "request_estimate"))),
                                cached_input_tokens=self.cached_input_tokens, reasoning_tokens=self.reasoning_tokens)

    def storage_basis(self, cost: float | None) -> str | None:
        """Map internal provenance to the existing strict SQL/D1 cost-basis vocabulary."""
        if cost is None or self.basis == "unknown":
            return None
        return "estimate" if self.basis == "estimated" else "usage"


class StreamUsageObserver:
    """Observe single-line SSE JSON with bounded buffering and content-free counts."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.observation: UsageObservation | None = None
        self._pending = b""
        self._oversized = False

    def _line(self) -> None:
        line = self._pending.strip()
        self._pending = b""
        if self._oversized:
            self._oversized = False
            return
        if not line.startswith(b"data:") or b'"usage"' not in line:
            return
        try:
            found = UsageObservation.from_body(json.loads(line[5:]))
        except (ValueError, RecursionError):
            return
        if found is not None:
            self.observation = self.observation.merge(found) if self.observation is not None else found

    def feed(self, data: bytes) -> None:
        parts = data.split(b"\n")
        for index, part in enumerate(parts):
            if not self._oversized:
                if len(self._pending) + len(part) <= self.limit:
                    self._pending += part
                else:
                    self._pending = b""
                    self._oversized = True
            if index < len(parts) - 1:
                self._line()

    def finish(self) -> UsageObservation | None:
        self._line()
        return self.observation
