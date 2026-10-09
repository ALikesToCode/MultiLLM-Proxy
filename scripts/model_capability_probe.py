"""Plan or explicitly execute bounded capability probes without changing live state."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Mapping, TextIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.capability_probes import (
    FlaskGatewayAdapter, ProbeConfig, ProbeFixtures, ProbeLimits, ProbePrice,
    ProbeRefused, ProbeTransport, WorkerGatewayAdapter, build_plan, parse_probe_json, run_probes,
)


def _load_document(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if resolved.suffix != ".json" or any(part.startswith(".env") for part in resolved.parts) or any(word in resolved.name.lower() for word in ("credential", "secret", "api-key")):
        raise ProbeRefused("Inputs must be non-credential JSON descriptors and synthetic fixtures")
    with resolved.open("rb") as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ProbeRefused("Input document exceeds 64 KiB")
    document = parse_probe_json(raw)
    if not isinstance(document, dict):
        raise ProbeRefused("Input document must be a JSON object")
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Redacted effective configuration JSON")
    parser.add_argument("--fixtures", required=True, type=Path, help="Versioned synthetic fixture JSON")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--allow-generation", action="store_true")
    parser.add_argument("--max-requests", type=int, default=4)
    parser.add_argument("--max-output-tokens", type=int, default=64)
    parser.add_argument("--max-input-tokens", type=int, default=4096, help="Reviewed per-request input allowance, including vision billing")
    parser.add_argument("--max-cost-usd", default="0.01")
    parser.add_argument("--timeout-seconds", type=float, default=10)
    parser.add_argument("--input-usd-per-million", help="Known effective input price, including any runtime premium")
    parser.add_argument("--output-usd-per-million", help="Known effective output price")
    parser.add_argument("--key-env", default="MULTILLM_API_KEY", help="Environment variable name; never a key value")
    parser.add_argument("--output", type=Path, help="Create a new receipt file; existing files are never replaced")
    return parser


def _prepare(args: argparse.Namespace, environ: Mapping[str, str], transport: ProbeTransport | None):
    if args.execute != args.allow_generation:
        raise ProbeRefused("Generation requires both --execute and --allow-generation")
    config = ProbeConfig.from_dict(_load_document(args.config))
    fixtures = ProbeFixtures.from_dict(_load_document(args.fixtures))
    limits = ProbeLimits(args.max_requests, args.max_output_tokens, args.max_cost_usd,
                         args.max_input_tokens, args.timeout_seconds)
    if (args.input_usd_per_million is None) != (args.output_usd_per_million is None):
        raise ProbeRefused("Provide both effective input and output prices")
    price = None if args.input_usd_per_million is None else ProbePrice(args.input_usd_per_million, args.output_usd_per_million)
    plan = build_plan(config, fixtures, limits=limits, price=price)
    if args.execute:
        if price is None:
            raise ProbeRefused("Known input and output prices are required before generation")
        key = environ.get(args.key_env, "")
        if not key:
            raise ProbeRefused("Set the gateway key through the selected environment variable")
        if transport is None:
            adapter = FlaskGatewayAdapter if config.descriptor["runtime"] == "flask" else WorkerGatewayAdapter
            transport = adapter(key)
    return config, fixtures, limits, price, plan, transport


def main(argv: list[str] | None = None, *, transport: ProbeTransport | None = None,
         environ: Mapping[str, str] | None = None, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    args = _parser().parse_args(argv)
    out, err = stdout or sys.stdout, stderr or sys.stderr
    try:
        config, fixtures, limits, price, plan, transport = _prepare(
            args, os.environ if environ is None else environ, transport)
        with ExitStack() as stack:
            # Reserve output before dispatch, so an existing file cannot waste a paid probe.
            destination = stack.enter_context(args.output.open("x", encoding="utf-8")) if args.output else out
            print(f"Planned requests: {plan['planned_requests']}; sending: {plan['planned_requests'] if args.execute else 0}", file=err, flush=True)
            receipt = run_probes(config, fixtures, limits=limits, price=price, execute=args.execute,
                                 allow_generation=args.allow_generation, transport=transport)
            print(json.dumps(receipt, sort_keys=True, allow_nan=False), file=destination)
    except ProbeRefused as error:
        print(f"Probe refused: {error}", file=err)
        return 2
    except ValueError:
        print("Probe refused (ValueError); no document or credential values logged", file=err)
        return 2
    except Exception as error:
        print(f"Probe operation failed ({type(error).__name__}); no document or credential values logged", file=err)
        return 1
    if receipt["stop_reason"] or any(row["status"] == "inconclusive" for row in receipt["observations"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
