"""Provider tool contracts shared with the Knowledge Worker (worker/knowledge/native-tools.json)."""

import json
from pathlib import Path

NATIVE_TOOLS_PATH = Path(__file__).resolve().parents[1] / "worker" / "knowledge" / "native-tools.json"
NATIVE_TOOLS = json.loads(NATIVE_TOOLS_PATH.read_text(encoding="utf-8"))
NATIVE_OPERATIONS = tuple(f"native.{name}" for name in NATIVE_TOOLS)
