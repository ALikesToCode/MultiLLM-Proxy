"""Inspect an explicit gateway model using bounded, content-free diagnostics."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import NoReturn, TextIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.provider_authenticity import (
    ConfigError,
    RequestsTransport,
    Transport,
    diagnostic_plan,
    new_nonce,
    run_diagnostics,
    validate_target,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # Argument errors can include a mistyped key or private URL.
        raise ConfigError("invalid_arguments")


def _arguments(argv: Sequence[str] | None, stdout: TextIO):
    parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
    parser.add_argument("--base-url", required=True, help="Gateway origin or deployment prefix")
    parser.add_argument("--model", required=True, help="Explicit provider:model identifier")
    parser.add_argument("--allow-generation", action="store_true", help="Allow up to two synthetic Chat requests")
    parser.add_argument("--allow-loopback-http", action="store_true", help="Allow HTTP only on a loopback target")
    parser.add_argument("--help", "-h", action="store_true", help="Show this help")
    if argv is None:
        argv = sys.argv[1:]
    if "--help" in argv or "-h" in argv:
        parser.print_help(file=stdout)
        return None
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, *, client: Transport | None = None,
         environ: Mapping[str, str] | None = None, stdout: TextIO | None = None,
         stderr: TextIO | None = None, nonce_factory: Callable[[], str] = new_nonce) -> int:
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    environment = os.environ if environ is None else environ
    owned = None
    try:
        args = _arguments(argv, stdout)
        if args is None:
            return 0
        validate_target(args.base_url, args.model, allow_loopback_http=args.allow_loopback_http)
        key = environment.get("MULTILLM_API_KEY", "")
        if not key or not key.strip() or any(ord(char) < 32 or ord(char) == 127 for char in key):
            raise ConfigError("operator_key_required")
        plan = diagnostic_plan(allow_generation=args.allow_generation)
        print(json.dumps(plan, sort_keys=True), file=stderr, flush=True)
        if client is None:
            owned = RequestsTransport()
            client = owned
        report = run_diagnostics(
            args.base_url, args.model, client=client, api_key=key,
            allow_generation=args.allow_generation, allow_loopback_http=args.allow_loopback_http,
            nonce_factory=nonce_factory,
        )
    except ConfigError as error:
        print(json.dumps({"error": str(error)}), file=stderr)
        return 1
    except Exception:
        print(json.dumps({"error": "diagnostic_setup_failed"}), file=stderr)
        return 1
    finally:
        if owned is not None:
            try:
                owned.close()
            except Exception:
                print(json.dumps({"error": "transport_cleanup_failed"}), file=stderr)
                return 1
    print(json.dumps(report, sort_keys=True, allow_nan=False), file=stdout)
    return {"supported": 0, "contradicted": 2, "unknown": 3}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
