"""Split a reply's usage by the model that ran each sampling step.

Claude reports a server-side loop, such as an advisor call, in `usage.iterations`:
`message` steps ran on the request's model, and an `advisor_message` step names the
advisor's model. Top-level usage counts only the request's model, so the advisor's
tokens are visible, and billable at its own prices, only through these steps.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Optional

from services.prompt_cache_cost import CacheObservation
from services.usage_types import IterationUsage, UsageObservation


def _qualified(model: str, provider: str) -> str:
    return model if ":" in model or not provider else f"{provider}:{model}"


def _total(values) -> Optional[int]:
    values = list(values)
    return sum(values) if all(value is not None for value in values) else None


def _aggregate(usage: UsageObservation, steps: list[IterationUsage], *, executor: bool) -> UsageObservation:
    one_hour = sum(step.cache_write_1h_tokens or 0 for step in steps)
    totals = {
        "input_tokens": _total(step.input_tokens for step in steps),
        "output_tokens": _total(step.output_tokens for step in steps),
        "cache_read_input_tokens": _total(step.cache_read_input_tokens for step in steps),
        "cache_creation_input_tokens": _total(step.cache_creation_input_tokens for step in steps),
        **({"cache_creation": {"ephemeral_1h_input_tokens": one_hour}} if one_hour else {}),
    }
    body = {"type": "message", "usage": totals}
    observed = (CacheObservation.from_body(body) if isinstance(usage, CacheObservation)
                else UsageObservation.from_body(body)) or type(usage)()
    # Reasoning is reported for the whole reply, which the request's model wrote.
    return replace(observed, iterations=tuple(steps),
                   reasoning_tokens=usage.reasoning_tokens if executor else None)


def by_model(executor: Optional[str], usage: Optional[UsageObservation]) -> list[tuple[Optional[str], Optional[UsageObservation]]]:
    """[(request model, its usage), (other model, its usage), ...]; one entry when the
    reply lists no steps."""
    if usage is None or not usage.iterations or not executor:
        return [(executor, usage)]
    provider = executor.split(":", 1)[0] if ":" in executor else ""
    groups: dict[str, tuple[str, list[IterationUsage]]] = {}
    for step in usage.iterations:
        # A `message` step is the request's own model, whatever id (a dated snapshot,
        # say) it reports; other steps without a model ran on it too.
        model = _qualified(step.model, provider) if step.model and step.kind != "message" else executor
        groups.setdefault(model.lower(), (model.lower(), []))[1].append(step)
    own = groups.pop(executor.lower(), None)
    parts: list[tuple[Optional[str], Optional[UsageObservation]]] = [
        (executor, _aggregate(usage, own[1], executor=True) if own else replace(usage, iterations=()))]
    parts.extend((model, _aggregate(usage, steps, executor=False)) for model, steps in groups.values())
    return parts
