"""Write the edge Worker's copy of the Knowledge MCP catalogue; --check only verifies it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routes.knowledge_mcp import CATALOGUE_PATH, catalogue, catalogue_json
from services.mcp_contract_drift import CONTRACT_VERSION, FORMAT, baseline_json, diff_contracts


def main(argv):
    if len(argv) == 2 and argv[0] in {"--baseline", "--diff"}:
        path = Path(argv[1]).resolve()
        if path == CATALOGUE_PATH.resolve():
            print("Contract baseline operations cannot overwrite the Worker catalogue.", file=sys.stderr)
            return 2
        definitions = [entry["definition"] for entry in catalogue()["tools"]]
        try:
            if argv[0] == "--baseline":
                path.write_text(baseline_json(definitions), encoding="utf-8")
                return 0
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("Contract baseline exceeds the 4 MiB limit.")
            previous = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(previous, dict) or previous.get("format") != FORMAT
                    or not isinstance(previous.get("tools"), list)):
                raise ValueError("Unsupported contract baseline format.")
            report = diff_contracts([entry["definition"] for entry in previous["tools"]], definitions,
                                    old_version=previous.get("contract_version"), new_version=CONTRACT_VERSION)
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"Contract baseline operation failed: {type(error).__name__}.", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["classification"] == "compatible" else 1
    expected = catalogue_json()
    if argv == ["--check"]:
        current = CATALOGUE_PATH.read_text(encoding="utf-8") if CATALOGUE_PATH.exists() else None
        if current != expected:
            print(f"{CATALOGUE_PATH.name} is out of date; run python scripts/build_knowledge_mcp_catalogue.py",
                  file=sys.stderr)
            return 1
        return 0
    if argv:
        print("Usage: python scripts/build_knowledge_mcp_catalogue.py [--check | --baseline PATH | --diff PATH]", file=sys.stderr)
        return 2
    CATALOGUE_PATH.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
