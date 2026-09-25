"""Drive the Container's account and auto-route code against a Worker serving real D1.

Run by tests/test_d1_integration.mjs with PRIVATE_BASE_URL pointing at a local Miniflare
Worker. The repository .env is never read: env_loader is replaced before config loads.
"""

import json
import logging
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.modules["env_loader"] = types.SimpleNamespace(load_runtime_env=lambda *args, **kwargs: None)
logging.disable(logging.CRITICAL)

scratch = tempfile.mkdtemp(prefix="d1-driver-")
os.environ.update({
    "AUTH_STORAGE_BACKEND": "d1", "INTELLIGENCE_STORAGE_BACKEND": "d1", "CONTROL_PLANE_DATABASE_URL": "",
    "ADMIN_USERNAME": "admin", "ADMIN_API_KEY": "synthetic-integration-admin-key",
    "AUTH_DB_PATH": os.path.join(scratch, "auth.sqlite3"), "MODEL_REGISTRY_DB_PATH": os.path.join(scratch, "registry.sqlite3"),
})

from error_handlers import APIError
from services import auto_route_d1, intelligence_d1_store
from services.auth_service import AuthService
from services.auto_route_service import AutoRouteService

base = os.environ["PRIVATE_BASE_URL"].rstrip("/")
for name, url in intelligence_d1_store._ENDPOINTS.items():
    intelligence_d1_store._ENDPOINTS[name] = base + url.removeprefix("http://intelligence.internal")
ADMIN = {"username": "admin", "is_admin": True}


def restart():
    """A new Container: empty process memory, then normal startup."""
    AuthService._users, AuthService._api_key_prefix_index = {}, {}
    AuthService._forget_verified_keys()
    auto_route_d1.reset_cache()
    AuthService.initialize()


def status(action):
    try:
        action()
        return 200
    except APIError as error:
        return error.status_code


def migrated():
    restart()
    with patch.object(AuthService, "get_current_user", return_value=ADMIN):
        key = AuthService.create_user("agent", scopes=["knowledge:read"])["api_key"]
        refused = status(lambda: AuthService.create_user("mallory", is_admin=True))
    restart()
    agent = AuthService.verify_api_key(key, "203.0.113.5")
    AutoRouteService.save_route("auto:gpt-image-2.5", ["gguu:gpt-image-2.5", "openai:gpt-image-2.5"],
                                {"gguu": "https://gguu.example", "openai": "https://api.openai.com"})
    restart()
    route = AutoRouteService.get_route("auto:gpt-image-2.5")
    return {"agent": agent and agent["username"], "wrong_key": AuthService.verify_api_key(key + "x"),
            "admin": AuthService.verify_api_key(os.environ["ADMIN_API_KEY"])["is_admin"],
            "admin_refused": refused, "route": list(route.candidates), "users": AuthService.count_users()}


def unmigrated():
    restart()  # startup tolerates the missing table and serves without a boot-time copy
    return {"dashboard_key": status(lambda: AuthService.verify_api_key("mllm_unknown-dashboard-key-000000")),
            "admin": AuthService.verify_api_key(os.environ["ADMIN_API_KEY"])["username"],
            "route": list(AutoRouteService.get_route("auto:gpt-image-2.5").candidates),
            "save_route": status(lambda: AutoRouteService.save_route("auto:x", ["gguu:gpt-image-2.5"], {"gguu": "https://gguu.example"}))}


print(json.dumps({"migrated": migrated, "unmigrated": unmigrated}[sys.argv[1]]()))
