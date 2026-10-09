"""Deterministic probe exposure from an explicit, content-free configuration snapshot."""

from __future__ import annotations

import math
import re
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
from typing import Any

HORIZONS = ("daily", "month", "max_run")
MAX_COUNT = 2**53 - 1
MAX_ITEMS = 512
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@*-]{0,255}$")
MICRO = Decimal("0.000001")


class PlanError(ValueError):
    """A plan cannot be bounded or interpreted safely."""


def _object(value: Any, allowed: set[str], location: str) -> dict:
    if not isinstance(value, dict) or set(value) - allowed:
        raise PlanError(f"Invalid fields in {location}")
    return value


def _integer(value: Any, location: str, minimum: int = 0, maximum: int = MAX_COUNT) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PlanError(f"Invalid integer in {location}")
    return value


def _flag(value: Any, location: str) -> bool:
    if type(value) is not bool:
        raise PlanError(f"Invalid boolean in {location}")
    return value


def _decimal(value: Any, location: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise PlanError(f"Invalid decimal in {location}")
    raw = str(value)
    if len(raw) > 64:
        raise PlanError(f"Decimal too long in {location}")
    try:
        number = Decimal(raw)
    except InvalidOperation as error:
        raise PlanError(f"Invalid decimal in {location}") from error
    if (not number.is_finite() or not 0 <= number <= Decimal("1e12")
            or not -18 <= number.as_tuple().exponent <= 12):
        raise PlanError(f"Decimal out of bounds in {location}")
    return number


def _identifier(value: Any, location: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise PlanError(f"Invalid identifier in {location}")
    return value


def _items(value: Any, location: str) -> list:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise PlanError(f"Invalid list in {location}")
    return value


def _counts(values: dict[str, int | None]) -> dict[str, int | None]:
    for value in values.values():
        if value is not None:
            _integer(value, "computed calls")
    return values


def _recurring(interval: int, multiplier: int, days: int, run_minutes: int) -> dict:
    # Unknown cron phase: ceil bounds ticks in any half-open window of this length.
    return _counts({name: ((minutes + interval - 1) // interval) * multiplier
                    for name, minutes in zip(HORIZONS, (1440, days * 1440, run_minutes))})


def _pricing(raw: Any) -> dict[str, dict[str, Decimal | None]]:
    if not isinstance(raw, dict) or len(raw) > MAX_ITEMS:
        raise PlanError("Invalid pricing table")
    table = {}
    for model, value in raw.items():
        model = "*" if model == "*" else _identifier(model, "pricing model").lower()
        if model in table:
            raise PlanError("Duplicate normalized pricing model")
        entry = _object(value, {"input", "output", "request", "input_cost_per_million",
                                "output_cost_per_million"}, "pricing entry")
        parsed = {key: _decimal(price, "pricing entry") for key, price in entry.items()}
        request_only = "request" in parsed and len(parsed) == 1
        table[model] = {
            "input": Decimal(0) if request_only else parsed.get("input", parsed.get("input_cost_per_million")),
            "output": Decimal(0) if request_only else parsed.get("output", parsed.get("output_cost_per_million")),
            "request": parsed.get("request", Decimal(0)),
        }
    return table


def _price(provider: str, model: str, pricing: dict) -> dict | None:
    for key in (f"{provider}:{model}".lower(), f"{provider}:*", "*"):
        if key in pricing:
            return pricing[key]
    return None


def _per_call(provider: str, model: str, pricing: dict, input_cap: int, output_cap: int) -> Decimal | None:
    prices = _price(provider, model, pricing)
    if prices is None or any(value is None for value in prices.values()):
        return None
    return (Decimal(input_cap) * prices["input"] + Decimal(output_cap) * prices["output"]) / 1_000_000 + prices["request"]


def _component(kind: str, provider: str, models: list[str], keys: int, calls: dict,
               per_call: Decimal | None, *, input_cap: int = 0, output_cap: int = 0,
               probes: int = 1, interval: int | None = None, enabled: bool = True) -> dict:
    return {
        "kind": kind, "provider": provider, "models": models, "key_count": keys,
        "input_token_cap": input_cap, "output_token_cap": output_cap,
        "probes_per_interval": probes, "interval_minutes": interval, "enabled": enabled,
        "calls": calls,
        "generation_calls": {name: 0 if kind in {"model_list", "keep_warm"} else count
                             for name, count in calls.items()},
        "_cost": {name: Decimal(0) if count == 0 else (
            None if count is None or per_call is None else count * per_call
        ) for name, count in calls.items()},
        "max_cost_per_call_usd": None if per_call is None else format(per_call, "f"),
    }


def _routes(raw: Any) -> dict[str, list[str]]:
    candidates: dict[str, set[str]] = {}
    total = 0
    for value in _items(raw, "routes"):
        route = _object(value, {"id", "candidates"}, "route")
        _identifier(route.get("id"), "route id")
        for candidate in _items(route.get("candidates", []), "route candidates"):
            candidate = _identifier(candidate, "candidate")
            provider, separator, model = candidate.partition(":")
            if not separator or not model or "*" in candidate:
                raise PlanError("Candidates need explicit provider:model identifiers")
            candidates.setdefault(provider.lower(), set()).add(model)
            total += 1
    if total > MAX_ITEMS:
        raise PlanError("Too many route candidates")
    return {provider: sorted(models) for provider, models in sorted(candidates.items())}


def _providers(raw: Any) -> dict[str, dict]:
    if not isinstance(raw, dict) or len(raw) > MAX_ITEMS:
        raise PlanError("Invalid provider descriptors")
    providers = {}
    for name, value in raw.items():
        name = _identifier(name, "provider").lower()
        if ":" in name or "*" in name or name in providers:
            raise PlanError("Invalid or duplicate provider identifier")
        entry = _object(value, {"catalog_check", "base_url_configured", "public_catalog",
                                "key_count", "model_list_request_usd"}, "provider descriptor")
        descriptor = {key: _flag(entry.get(key, False), "provider descriptor")
                      for key in ("catalog_check", "base_url_configured", "public_catalog")}
        descriptor["key_count"] = _integer(entry.get("key_count", 0), "key_count", maximum=10**9)
        price = entry.get("model_list_request_usd")
        descriptor["price"] = None if price is None else _decimal(price, "model list price")
        providers[name] = descriptor
    return providers


def _scheduled(plan: dict, days: int, run_minutes: int) -> tuple[list[dict], dict]:
    raw = _object(plan.get("schedule", {}), {"enabled", "admin_configured", "container_running",
        "checks_wake", "keep_warm", "interval_minutes", "keep_warm_request_usd"}, "schedule")
    settings = {key: _flag(raw.get(key, False), "schedule") for key in (
        "enabled", "admin_configured", "container_running", "checks_wake", "keep_warm")}
    settings["interval_minutes"] = _integer(raw.get("interval_minutes", 30), "schedule interval", 5, 1440)
    # The checked-in cron fires every five minutes. A seven-minute setting runs every 35.
    interval = math.lcm(5, settings["interval_minutes"])
    settings["effective_interval_minutes"] = interval
    routes, providers = _routes(plan.get("routes", [])), _providers(plan.get("providers", {}))
    eligible = settings["enabled"] and settings["admin_configured"] and (
        settings["container_running"] or settings["checks_wake"] or settings["keep_warm"])
    rows = []
    for provider, models in routes.items():
        if provider not in providers:
            raise PlanError("A route provider is missing its nonsecret descriptor")
        descriptor = providers[provider]
        included = eligible and descriptor["catalog_check"] and descriptor["base_url_configured"] and (
            descriptor["public_catalog"] or descriptor["key_count"] > 0)
        rows.append(_component("model_list", provider, models, descriptor["key_count"],
            _recurring(interval, int(included), days, run_minutes), descriptor["price"],
            interval=interval, enabled=bool(included)))
    warm_price = raw.get("keep_warm_request_usd")
    price = None if warm_price is None else _decimal(warm_price, "keep warm price")
    if settings["keep_warm"]:
        included = settings["enabled"]
        rows.append(_component("keep_warm", "gateway", [], 0,
            _recurring(5, int(included), days, run_minutes), price, interval=5, enabled=included))
    return rows, settings


def _probes(raw: Any, prices: dict, days: int, run_minutes: int) -> list[dict]:
    rows = []
    for value in _items(raw, "probes"):
        probe = _object(value, {"kind", "enabled", "provider", "models", "key_count",
            "probes_per_interval", "interval_minutes", "input_token_cap", "output_token_cap",
            "calls_per_day", "max_run_calls"}, "probe")
        kind = probe.get("kind", "generation")
        if not isinstance(kind, str) or kind not in {"generation", "half_open"}:
            raise PlanError("Unknown probe kind")
        provider = _identifier(probe.get("provider"), "probe provider").lower()
        if ":" in provider or "*" in provider:
            raise PlanError("Probe provider must be explicit")
        models = [_identifier(model, "probe model") for model in _items(probe.get("models"), "models")]
        if not models or len({model.lower() for model in models}) != len(models):
            raise PlanError("Models must be nonempty and unique")
        if any(model.lower().startswith(provider + ":") or "*" in model for model in models):
            raise PlanError("Probe models must be bare model identifiers")
        # Preserve native suffixes such as ':thinking' and ':free' in bare model IDs.
        enabled = _flag(probe.get("enabled", False), "probe enabled")
        keys = _integer(probe.get("key_count", 1), "key_count", maximum=10**9)
        probes = _integer(probe.get("probes_per_interval", 1), "probes_per_interval", maximum=10**9)
        interval = _integer(probe.get("interval_minutes", 30), "probe interval", 1, 525600)
        input_cap = _integer(probe.get("input_token_cap"), "input_token_cap", maximum=10**9)
        output_cap = _integer(probe.get("output_token_cap"), "output_token_cap", maximum=10**9)
        if kind == "generation":
            if "calls_per_day" in probe or "max_run_calls" in probe:
                raise PlanError("Traffic bounds apply only to half_open probes")
            calls = _recurring(interval, keys * probes if enabled else 0, days, run_minutes)
            for model in models:
                rows.append(_component(kind, provider, [model], keys, calls,
                    _per_call(provider, model, prices, input_cap, output_cap), input_cap=input_cap,
                    output_cap=output_cap, probes=probes, interval=interval, enabled=enabled))
        else:
            bounds = {key: None if probe.get(key) is None else _integer(probe[key], key)
                      for key in ("calls_per_day", "max_run_calls")}
            daily = bounds["calls_per_day"]
            calls = _counts({"daily": daily, "month": None if daily is None else daily * days,
                             "max_run": bounds["max_run_calls"]}) if enabled and keys else dict.fromkeys(HORIZONS, 0)
            costs = [_per_call(provider, model, prices, input_cap, output_cap) for model in models]
            known_prices = [cost for cost in costs if cost is not None]
            price = max(known_prices) if len(known_prices) == len(costs) else None
            rows.append(_component(kind, provider, models, keys, calls, price,
                input_cap=input_cap, output_cap=output_cap, probes=0, enabled=enabled))
        if len(rows) > MAX_ITEMS:
            raise PlanError("Too many probe components")
    return rows


def _money(value: Decimal | None) -> str | None:
    return None if value is None else format(value.quantize(MICRO, rounding=ROUND_CEILING), ".6f")


def _totals(rows: list[dict], field: str) -> dict:
    return {name: None if any(row[field][name] is None for row in rows) else
            sum((row[field][name] for row in rows), Decimal(0) if field == "_cost" else 0)
            for name in HORIZONS}


def forecast(plan: Any, *, max_calls: int | None = None, max_cost_usd: Any = None) -> dict:
    """Bound a snapshot without reading environment, storage, clocks or upstreams.

    Limits apply to the declared max-run horizon. USD uses decimal strings and rounds
    upward to microUSD only for display; the limit comparison uses the unrounded total.
    """
    plan = _object(plan, {"version", "days", "run_minutes", "schedule", "routes", "providers",
                          "probes", "pricing"}, "plan")
    if _integer(plan.get("version", 1), "version") != 1:
        raise PlanError("Unsupported plan version")
    days = _integer(plan.get("days", 30), "days", 1, 366)
    run_minutes = _integer(plan.get("run_minutes", 30), "run_minutes", 1, 527040)
    if max_calls is not None:
        _integer(max_calls, "max_calls")
    limit = None if max_cost_usd is None else _decimal(max_cost_usd, "max_cost_usd")
    with localcontext() as context:
        context.prec = 80
        rows, schedule = _scheduled(plan, days, run_minutes)
        rows.extend(_probes(plan.get("probes", []), _pricing(plan.get("pricing", {})), days, run_minutes))
        if len(rows) > MAX_ITEMS:
            raise PlanError("Too many combined components")
        calls = _counts(_totals(rows, "calls"))
        generation_calls = _counts(_totals(rows, "generation_calls"))
        costs = _totals(rows, "_cost")
        known = {name: sum((row["_cost"][name] or Decimal(0) for row in rows), Decimal(0)) for name in HORIZONS}
        failures = []
        for value, bound, label in ((calls["max_run"], max_calls, "max_calls"),
                                    (costs["max_run"], limit, "max_cost_usd")):
            if bound is not None and (value is None or value > bound):
                failures.append({"limit": label, "reason": "unverifiable" if value is None else "exceeded"})
        unknown = [index for index, row in enumerate(rows) if None in row["_cost"].values()]
        priced = [index for index in range(len(rows)) if index not in unknown]
        for row in rows:
            row["cost_usd"] = {name: _money(cost) for name, cost in row.pop("_cost").items()}
        return {
            "version": 1, "offline": True, "days": days, "run_minutes": run_minutes,
            "cost_scope": "probe API charges; excludes infrastructure and network tariffs",
            "schedule": schedule, "components": rows, "calls": calls,
            "generation_calls": generation_calls,
            "zero_generation": None if None in generation_calls.values() else not any(generation_calls.values()),
            "cost_usd": {name: _money(cost) for name, cost in costs.items()},
            "cost_micro_usd": {name: None if cost is None else int((cost / MICRO).to_integral_value(
                rounding=ROUND_CEILING)) for name, cost in costs.items()},
            "known_cost_usd": {name: _money(cost) for name, cost in known.items()},
            "priced_components": priced, "unknown_components": unknown,
            "incomplete": bool(unknown) or None in calls.values(),
            "limits": {"scope": "max_run", "ok": not failures, "failures": failures},
        }
