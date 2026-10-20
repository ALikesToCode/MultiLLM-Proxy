"""Registered Container routes, using actual HTTP to the disposable main Worker."""
import json
import os
import re
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

# Load a pinned earlier runtime in memory for actual mixed-version route probes.
revision = sys.argv[3] if len(sys.argv) > 3 else ""
if revision:
    import importlib.abc
    import importlib.util
    import subprocess

    class RuntimeModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] not in {"app", "config", "error_handlers", "route_helpers", "services", "routes", "providers", "streaming"}:
                return None
            name = fullname.replace(".", "/")
            for relative, package in [(name + ".py", False), (name + "/__init__.py", True)]:
                result = subprocess.run(["git", "show", revision + ":" + relative], cwd=root, capture_output=True, text=True)
                if result.returncode == 0:
                    spec = importlib.util.spec_from_loader(fullname, self, origin=root + "/" + relative, is_package=package)
                    spec.loader_state = (relative, result.stdout)
                    return spec
            return None

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            relative, source = module.__spec__.loader_state
            module.__file__ = root + "/" + relative
            if module.__spec__.submodule_search_locations is not None:
                module.__path__ = [root + "/" + relative.rsplit("/", 1)[0]]
            exec(compile(source, module.__file__, "exec"), module.__dict__)

    sys.meta_path.insert(0, RuntimeModules())

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
        if revision != "544bf49ba3b3d03d185ec5b5a71b2b1877dda786":
            assert network_admitted()
        if os.environ.get("ACCOUNT_DRIVER_OUTBOUND_ADMISSION") == "true":
            admitted = original(self, "GET", base + "/probe-provider")
            if admitted.status_code != 200:
                return admitted
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

if revision:
    from jinja2 import FunctionLoader

    def versioned_template(name):
        if ".." in name or name.startswith("/"):
            return None
        result = subprocess.run(["git", "show", revision + ":templates/" + name],
                                cwd=root, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else None

    app.jinja_loader = FunctionLoader(versioned_template)
client = app.test_client()
headers = {"Authorization": "Bearer mllm_synthetic_incident_key_long_enough"}
requests_to_run = json.loads(sys.argv[4]) if len(sys.argv) > 4 else [("/v1/models", "get"), ("/v1/chat/completions", "post")]
for operation in requests_to_run:
    path, method = operation[:2]
    if path == "/login":
        username = operation[2]
        client = app.test_client()
        page = client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
        response = client.post("/login", data={"username": username, "csrf_token": token,
            "api_key": "mllm_synthetic_incident_key_long_enough" if username == "synthetic" else os.environ["ADMIN_API_KEY"]})
        print(json.dumps({"path": path, "status": response.status_code, "dispatches": len(seen)}))
        continue
    arguments = {"json": {"model": "openrouter:openai/gpt-6-luna", "messages": [
        {"role": "user", "content": "synthetic"},
    ]}} if method == "post" else {}
    request_headers = {"Authorization": "Bearer " + os.environ["ADMIN_API_KEY"]} if len(operation) > 2 and operation[2] == "admin" else headers
    response = getattr(client, method)(path, headers=request_headers, **arguments)
    print(json.dumps({"path": path, "status": response.status_code,
        "error": response.json.get("error") if isinstance(response.json, dict) else None,
        "dispatches": len(seen), "preferences": seen[-1].get("provider") if seen else None}))
scratch.cleanup()
