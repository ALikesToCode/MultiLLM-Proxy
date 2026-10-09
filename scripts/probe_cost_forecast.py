"""Forecast a JSON probe plan offline. This command never executes probes."""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import TextIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.probe_cost_forecast import PlanError, forecast

MAX_PLAN_BYTES = 1_048_576


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PlanError("Duplicate JSON field")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise PlanError("Nonfinite JSON number")


def _read(path: str, stdin: TextIO) -> str:
    if path == "-":
        payload = stdin.read(MAX_PLAN_BYTES + 1)
    else:
        target = Path(path).resolve()
        # Only a purpose-built plan file, never an application environment or key file.
        if target.suffix.lower() != ".json" or any(part.startswith(".env") for part in target.parts):
            raise PlanError("Use a nonsecret .json plan file or stdin")
        with target.open(encoding="utf-8") as source:
            payload = source.read(MAX_PLAN_BYTES + 1)
    if len(payload.encode("utf-8")) > MAX_PLAN_BYTES:
        raise PlanError("Plan exceeds 1 MiB")
    return payload


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None,
         stdout: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-json", default="-", help="Nonsecret JSON snapshot; '-' reads stdin (default)")
    parser.add_argument("--max-calls", type=int, help="Maximum probe API calls in the max-run horizon")
    parser.add_argument("--max-cost-usd", help="Maximum probe API USD in the max-run horizon")
    args = parser.parse_args(argv)
    output = sys.stdout if stdout is None else stdout
    try:
        plan = json.loads(_read(args.plan_json, sys.stdin if stdin is None else stdin),
                          parse_float=Decimal, parse_constant=_constant, object_pairs_hook=_pairs)
        report = forecast(plan, max_calls=args.max_calls, max_cost_usd=args.max_cost_usd)
    except (PlanError, OSError, ValueError, RecursionError):
        # Never echo a malformed plan, filenames, values or parser excerpts.
        json.dump({"error": {"code": "invalid_probe_plan", "message":
            "Provide a bounded, nonsecret JSON plan; see docs/probe-cost-forecast.md."}}, output)
        output.write("\n")
        return 2
    json.dump(report, output, sort_keys=True, allow_nan=False)
    output.write("\n")
    return 0 if report["limits"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
