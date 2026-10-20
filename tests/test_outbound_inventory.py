"""Reviewed outbound surfaces: additions or edits require another boundary review.

This intentionally pins the complete transport module, not just a line containing
fetch: moving admission after a call must also invalidate the inventory. The
manifest records why each transport is guarded or is not a provider dispatch.
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/outbound_inventory.json"
NETWORK = re.compile(
    r"\b(?:import|from)\s+(?:requests|httpx|aiohttp|urllib|http|socket|openai|anthropic|google|azure)\b|node:https?|[\"\x27]undici[\"\x27]"
    r"|\b(?:fetch|fetcher|fetchImpl|provider_http|providerOperation|AI|KNOWLEDGE_SEARCH_AI|KNOWLEDGE_INDEX)\b")


def inventory(sources):
    return {name: hashlib.sha256(text.encode()).hexdigest()
            for name, text in sources.items() if NETWORK.search(text)}


def sources():
    files = [*ROOT.glob("*.py"), *ROOT.glob("*.mjs")]
    for directory in ("services", "routes", "providers", "utils", "worker"):
        for suffix in ("*.py", "*.mjs"):
            files.extend((ROOT / directory).rglob(suffix))
    return {str(path.relative_to(ROOT)): path.read_text() for path in files}


def test_every_outbound_surface_has_an_unchanged_reviewed_boundary():
    reviewed = json.loads(MANIFEST.read_text())
    assert all(item["reason"] and item["kind"] in {"guarded", "internal", "non-provider"} for item in reviewed.values())
    assert inventory(sources()) == {name: item["sha256"] for name, item in reviewed.items()}, (
        "Outbound transport changed: review every call and update its explicit inventory classification only after checking admission.")


def test_inventory_catches_new_modules_and_bypasses_inside_existing_transports():
    original = {"services/example.py": "value = 1\n"}
    assert inventory(original) == {}
    assert inventory({**original, "services/bypass.py": "import requests as network\nnetwork.post(url, json=body)\n"})
    worker = {"worker/example.mjs": "providerOperation('cloudflare', run)"}
    assert inventory(worker) != inventory({"worker/example.mjs": worker["worker/example.mjs"] + "\nreturn fetch(url, {body});"})
    assert inventory({"worker/new.mjs": "return env.AI.fetch(url);"})
    assert inventory({"services/new.py": "from http import client as network\nnetwork.HTTPSConnection(host).request(method, path)"})
