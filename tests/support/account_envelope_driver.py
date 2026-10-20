"""Registered Container routes, using actual HTTP to the disposable main Worker."""
import json
import os
import sys
import tempfile
import types
from pathlib import Path

root = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, root)
# The child receives only explicit synthetic configuration, never a host dotenv.
sys.modules["env_loader"] = types.SimpleNamespace(load_runtime_env=lambda *a, **kw: None)
os.environ.update(json.loads(sys.argv[2]))
scratch = tempfile.TemporaryDirectory(prefix="multillm-account-envelope-")
os.environ.update({
    "CONTROL_PLANE_DATABASE_URL": "", "PROVIDER_CATALOG_AUTO_REFRESH": "false", "USAGE_LEDGER_ENABLED": "false",
    "AUTH_DB_PATH": scratch.name + "/auth.sqlite3", "MODEL_REGISTRY_DB_PATH": scratch.name + "/registry.sqlite3",
    "RATE_LIMIT_DB_PATH": scratch.name + "/limits.sqlite3",
})

from services import intelligence_d1_store  # noqa: E402

base = sys.argv[1]
for name, url in intelligence_d1_store._ENDPOINTS.items():
    intelligence_d1_store._ENDPOINTS[name] = base + url.removeprefix("http://intelligence.internal")

import requests  # noqa: E402

seen = []
original = requests.sessions.Session.request


def transport(self, method, url, **kwargs):
    if url.startswith(base + "/"):
        return original(self, method, url, **kwargs)
    if url.startswith("https://openrouter.ai/"):
        from services.dispatch_network import network_admitted
        assert network_admitted()
        payload = kwargs.get("json") or json.loads(kwargs.get("data") or "{}")
        if "messages" in payload:
            seen.append(payload)
        response = requests.Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps({"data": [], "choices": [{
            "message": {"content": "synthetic"}, "finish_reason": "stop",
        }]}).encode()
        return response
    raise AssertionError("Unexpected external request")


# Only the external provider is mocked. Account/control requests travel over HTTP.
requests.sessions.Session.request = transport
from app import app  # noqa: E402

client = app.test_client()
headers = {"Authorization": "Bearer mllm_synthetic_incident_key_long_enough"}
for path, method in [("/v1/models", "get"), ("/v1/chat/completions", "post")]:
    arguments = {"json": {"model": "openrouter:openai/gpt-6-luna", "messages": [
        {"role": "user", "content": "synthetic"},
    ]}} if method == "post" else {}
    response = getattr(client, method)(path, headers=headers, **arguments)
    print(json.dumps({"path": path, "status": response.status_code,
        "error": response.json.get("error") if isinstance(response.json, dict) else None,
        "dispatches": len(seen), "preferences": seen[-1].get("provider") if seen else None}))
scratch.cleanup()
