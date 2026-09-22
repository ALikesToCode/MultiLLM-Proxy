"""Validate or seed a reviewed intelligence policy without replacing stored priorities."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.intelligence_policy import validate_policy
from services.intelligence_store import IntelligenceStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("validate", "seed"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.path.stat().st_size > 1024 * 1024:
            raise ValueError("Policy too large")
        policy = validate_policy(json.loads(args.path.read_text()))
        inserted = IntelligenceStore.seed(policy) if args.operation == "seed" else None
    except Exception as error:
        print(
            f"Policy operation failed ({type(error).__name__}); no policy values logged",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {"valid": True, "seeded": inserted, "candidates": len(policy["candidates"])}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
