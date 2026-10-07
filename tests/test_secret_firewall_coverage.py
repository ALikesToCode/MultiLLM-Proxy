"""Any added HTTP route requires a dispatch coverage review."""
import ast
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_flask_route_inventory_requires_firewall_review():
    current = {}
    for path in sorted((ROOT / "routes").glob("*.py")):
        calls = [ast.unparse(node) for node in ast.walk(ast.parse(path.read_text()))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and node.func.attr in {"route", "add_url_rule"}]
        if calls: current[str(path.relative_to(ROOT))] = sorted(calls)
    expected = json.loads((ROOT / "tests/fixtures/secret_firewall_coverage.json").read_text())["flask_routes"]
    assert current == expected, "Review each added route's provider dispatch, then update the inventory"


def test_provider_dispatches_keep_their_guard():
    checks = {"services/proxy_service.py": {"_make_base_request": "protect_body", "_make_request_with_timeout": "protect_body"},
              "services/intelligence_transport.py": {"start": "protect_body"},
              "services/cloudflare_ai.py": {"post": "protect_payload"},
              "services/video_generation.py": {"_send": "protect_payload"},
              "services/knowledge_client.py": {"dispatch": "protect_payload"}}
    for file, functions in checks.items():
        tree = ast.parse((ROOT / file).read_text())
        for name, guard in functions.items():
            matched = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
            assert matched and any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == guard
                                   for function in matched for node in ast.walk(function)), (file, name)
