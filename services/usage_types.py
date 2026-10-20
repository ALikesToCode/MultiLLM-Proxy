"""Token observations and bounded stream parsing, independent of durable row fields."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

UsageBasis = Literal["provider", "estimated", "unknown"]


def _component(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


@dataclass(frozen=True)
class UsageObservation:
    input_tokens: int | None = None
    output_tokens: int | None = None
    basis: UsageBasis = "unknown"
    provenance: tuple[str, ...] = ()

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
        data = value.get("data")
        if isinstance(data, list) and any(isinstance(item, dict) and "embedding" in item for item in data):
            output_tokens = 0
        known = input_tokens is not None or output_tokens is not None
        return cls(input_tokens, output_tokens, "provider" if known else "unknown",
                   ("provider",) if known else ())

    def merge(self, later: UsageObservation) -> UsageObservation:
        """Use the latest valid value for each component; null never erases a count."""
        input_tokens = later.input_tokens if later.input_tokens is not None else self.input_tokens
        output_tokens = later.output_tokens if later.output_tokens is not None else self.output_tokens
        provenance = tuple(dict.fromkeys((*self.provenance, *later.provenance)))
        basis: UsageBasis = "estimated" if "request_estimate" in provenance else (
            "provider" if input_tokens is not None or output_tokens is not None else "unknown")
        return UsageObservation(input_tokens, output_tokens, basis, provenance)

    def with_estimates(self, input_tokens: int | None, output_tokens: int | None) -> UsageObservation:
        """Fill missing components explicitly, retaining measured zero and provenance."""
        estimated_input = _component(input_tokens) if self.input_tokens is None else None
        estimated_output = _component(output_tokens) if self.output_tokens is None else None
        if estimated_input is None and estimated_output is None:
            return self
        return UsageObservation(self.input_tokens if self.input_tokens is not None else estimated_input,
                                self.output_tokens if self.output_tokens is not None else estimated_output,
                                "estimated", tuple(dict.fromkeys((*self.provenance, "request_estimate"))))

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
