"""Write the edge Worker's copy of the Knowledge MCP catalogue; --check only verifies it."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routes.knowledge_mcp import CATALOGUE_PATH, catalogue_json


def main(argv):
    expected = catalogue_json()
    if argv == ["--check"]:
        current = CATALOGUE_PATH.read_text(encoding="utf-8") if CATALOGUE_PATH.exists() else None
        if current != expected:
            print(f"{CATALOGUE_PATH.name} is out of date; run python scripts/build_knowledge_mcp_catalogue.py",
                  file=sys.stderr)
            return 1
        return 0
    if argv:
        print("Usage: python scripts/build_knowledge_mcp_catalogue.py [--check]", file=sys.stderr)
        return 2
    CATALOGUE_PATH.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
