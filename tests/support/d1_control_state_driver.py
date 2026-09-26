"""Drive the Container's control-state stores against a Worker serving real D1.

Run by tests/test_d1_integration.mjs with PRIVATE_BASE_URL pointing at a local Miniflare
Worker. Every step that crosses a "restart" forgets this process's memory first, so the
state that survives came back from D1. The repository .env is never read.
"""

import json
import logging
import os
import sys
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.modules["env_loader"] = types.SimpleNamespace(load_runtime_env=lambda *args, **kwargs: None)
logging.disable(logging.CRITICAL)

scratch = tempfile.mkdtemp(prefix="d1-state-driver-")
os.environ.update({
    "INTELLIGENCE_STORAGE_BACKEND": "d1", "CONTROL_PLANE_DATABASE_URL": "", "JWT_SECRET": "synthetic-integration-secret",
    "RATE_LIMIT_ENABLED": "true", "DAILY_REQUEST_LIMIT": "2", "LOGIN_MAX_ATTEMPTS": "2",
    "RATE_LIMIT_DB_PATH": os.path.join(scratch, "first", "limits.sqlite3"),
    "MODEL_REGISTRY_DB_PATH": os.path.join(scratch, "registry.sqlite3"),
    "CONNECTION_PROFILES_DB_PATH": os.path.join(scratch, "workbench.sqlite3"),
})

from services import (  # noqa: E402 - the environment above must be set first.
    control_state_d1, free_quota_d1, intelligence_d1_store, model_override_d1, provider_catalog_d1, rate_limit_d1,
    workbench_d1,
)
from services.connection_profiles import WorkbenchStore  # noqa: E402
from services.free_quota_service import FreeQuotaService  # noqa: E402
from services.login_attempt_service import LoginAttemptService  # noqa: E402
from services.model_registry import ModelRegistry  # noqa: E402
from services.provider_catalog_service import ProviderCatalogModel, ProviderCatalogService  # noqa: E402
from services.rate_limit_service import RateLimitService  # noqa: E402
from error_handlers import APIError  # noqa: E402

control_state_d1.BACKGROUND = False
base = os.environ["PRIVATE_BASE_URL"].rstrip("/")
for name, url in intelligence_d1_store._ENDPOINTS.items():
    intelligence_d1_store._ENDPOINTS[name] = base + url.removeprefix("http://intelligence.internal")
USER = {"username": "agent", "api_key_prefix": "mllm_agent"}
PROFILE = dict(name="Flash", kind="roleplay", provider="nanogpt", model="z-ai/glm-5.3-flash", mode="pinned",
               effort="high", billing="configured", fallback="none", memory="auto", recovery="off")


def restart():
    """A new Container: empty process memory and a new local disk."""
    rate_limit_d1.reset()
    free_quota_d1.reset()
    model_override_d1.reset_cache()
    workbench_d1.reset_cache()
    provider_catalog_d1.reset()
    os.environ["RATE_LIMIT_DB_PATH"] = tempfile.mkdtemp(dir=scratch) + "/limits.sqlite3"


def enforce():
    decision = RateLimitService.enforce_request("openai", USER, b"{}", {"messages": [{"role": "user", "content": "hi"}]}, "192.0.2.9")
    return decision.error or "allowed"


def scenario():
    usage = [enforce(), enforce(), enforce()]
    rate_limit_d1.sync()
    restart()
    usage.append(enforce())  # Admitted before the first refresh after a restart.
    rate_limit_d1.sync()
    usage.append(enforce())

    login = [LoginAttemptService.record_failure("192.0.2.9", "admin").allowed]
    restart()
    login.append(LoginAttemptService.record_failure("192.0.2.9", "admin").allowed)
    restart()
    login.append(LoginAttemptService.check("192.0.2.9", "admin").allowed)

    ModelRegistry.disable_model("openai:gpt-4.1")
    FreeQuotaService.block("provider:groq", 120)
    control_state_d1.run_tasks()
    WorkbenchStore.save_profile("owner", PROFILE)
    ProviderCatalogService.replace_provider_models("nanogpt", (
        ProviderCatalogModel("nanogpt", "z-ai/glm-5.3", "", 200_000, None, {"description": "x" * 400}),
        *(ProviderCatalogModel("nanogpt", f"model-{index}", "", None, None, {"description": f"model {index} " * 40})
          for index in range(400))))
    restart()
    FreeQuotaService.remaining("provider:groq")
    control_state_d1.run_tasks()
    return {"usage": usage, "login": login, "status": ModelRegistry.get_model_status("openai:gpt-4.1"),
            "cooldown": 100 <= FreeQuotaService.remaining("provider:groq", now=time.time()) <= 120,
            "profiles": [profile["name"] for profile in WorkbenchStore.profiles("owner")],
            "catalog": len(ProviderCatalogService.list_models()),
            "catalog_limit": ProviderCatalogService.list_models()[-1].context_window,
            "local_files": sorted(path.name for path in Path(scratch).glob("*.sqlite3"))}


def status(action):
    try:
        action()
        return 200
    except APIError as error:
        return error.status_code


def unmigrated():
    """Code deployed before migration 0006: requests and sign-in keep working, admin saves fail visibly."""
    usage = [enforce(), enforce(), enforce()]
    rate_limit_d1.sync()
    login = [LoginAttemptService.record_failure("192.0.2.9", "admin").allowed,
             LoginAttemptService.record_failure("192.0.2.9", "admin").allowed]
    FreeQuotaService.block("provider:groq", 120)
    control_state_d1.run_tasks()
    return {"usage": usage, "login": login, "status": ModelRegistry.get_model_status("openai:gpt-4.1"),
            "disable": status(lambda: ModelRegistry.disable_model("openai:gpt-4.1")),
            "profile": status(lambda: WorkbenchStore.save_profile("owner", PROFILE)),
            "cooldown": FreeQuotaService.remaining("provider:groq") > 0,
            "catalog": ProviderCatalogService.replace_provider_models(
                "nanogpt", (ProviderCatalogModel("nanogpt", "z-ai/glm-5.3", ""),)),
            "catalog_models": len(ProviderCatalogService.list_models())}


print(json.dumps({"migrated": scenario, "unmigrated": unmigrated}[sys.argv[1]]()))
