"""Login throttling, model overrides, cooldowns, workbench records and catalog snapshots in D1."""

import base64
import logging
import time
import zlib

import pytest

from error_handlers import APIError
from services import (
    control_state_d1,
    free_quota_d1,
    intelligence_d1_store,
    model_override_d1,
    provider_catalog_d1,
    workbench_d1,
)
from services.connection_profiles import WorkbenchStore
from services.free_quota_service import FreeQuotaService
from services.login_attempt_service import LoginAttemptService
from services.model_registry import ModelRegistry
from services.provider_catalog_service import ProviderCatalogModel, ProviderCatalogService
from services.release_status import container_release
from tests.control_state_fake import FakeControlState

PROFILE = dict(name="Flash - high", kind="roleplay", provider="nanogpt", model="z-ai/glm-5.3-flash", mode="pinned",
               effort="max", billing="subscription-only", fallback="none", memory="auto", recovery="off")
MEASUREMENT = dict(provider="nanogpt", model="z-ai/glm-5.3-flash", case="continuity", effort="high", status="completed",
                   rating=4, ttft_ms=100.5, duration_ms=1000, output_tokens=100, tps=111.0)


@pytest.fixture
def d1(monkeypatch, tmp_path):
    for name, value in {"INTELLIGENCE_STORAGE_BACKEND": "d1", "CONTROL_PLANE_DATABASE_URL": "", "JWT_SECRET": "control-state-test",
                        "LOGIN_MAX_ATTEMPTS": "3", "LOGIN_ATTEMPT_WINDOW_SECONDS": "60", "LOGIN_LOCKOUT_SECONDS": "120",
                        "RATE_LIMIT_DB_PATH": str(tmp_path / "a" / "limits.sqlite3"),
                        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "registry.sqlite3"),
                        "CONNECTION_PROFILES_DB_PATH": str(tmp_path / "workbench.sqlite3")}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(control_state_d1, "BACKGROUND", False)
    fake = FakeControlState()
    monkeypatch.setattr(intelligence_d1_store, "request_private_intelligence", fake)
    restart()
    yield fake
    restart()
    for name in ("registry.sqlite3", "workbench.sqlite3"):
        assert not (tmp_path / name).exists(), f"D1 mode never creates the Container-local {name}"


def restart():
    """A new Container process: empty memory."""
    model_override_d1.reset_cache()
    free_quota_d1.reset()
    workbench_d1.reset_cache()
    provider_catalog_d1.reset()


def test_login_failures_on_any_instance_count_toward_one_lockout(d1, monkeypatch, tmp_path):
    assert LoginAttemptService.record_failure("192.0.2.4", "admin", now=10).allowed
    assert LoginAttemptService.record_failure("192.0.2.4", "admin", now=11).allowed
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "b" / "limits.sqlite3"))  # Another instance.
    decision = LoginAttemptService.record_failure("192.0.2.4", "admin", now=12)
    assert (decision.allowed, decision.retry_after) == (False, 120)
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "c" / "limits.sqlite3"))  # A restarted Container.
    blocked = LoginAttemptService.check("192.0.2.4", "admin", now=20)
    assert (blocked.allowed, blocked.retry_after) == (False, 112)
    assert "admin" not in str(d1.login) and "192.0.2.4" not in str(d1.login)
    LoginAttemptService.record_success("192.0.2.4", "admin")
    assert d1.login == {}


def test_login_throttling_still_applies_locally_when_d1_is_down(d1, caplog):
    d1.down.add("login_attempts")
    with caplog.at_level(logging.WARNING, logger="services.login_attempt_d1"):
        for now in (10, 11):
            assert LoginAttemptService.record_failure("192.0.2.5", "admin", now=now).allowed
        assert not LoginAttemptService.record_failure("192.0.2.5", "admin", now=12).allowed
        assert not LoginAttemptService.check("192.0.2.5", "admin", now=13).allowed
    assert "this Container's record still applies" in caplog.text
    d1.down.clear()
    assert LoginAttemptService.check("192.0.2.6", "admin", now=13).allowed, "an outage never blocks other sign-ins"


def test_model_overrides_are_shared_cached_and_survive_restarts(d1):
    ModelRegistry.disable_model("openai:gpt-4.1")
    assert d1.overrides == {"openai:gpt-4.1": "disabled"}
    restart()
    for _ in range(3):
        assert ModelRegistry.get_model_status("openai:gpt-4.1") == "disabled"
    assert ModelRegistry.get_model_statuses(["openai:gpt-4.1", "openai:gpt-4.1-mini"]) == {
        "openai:gpt-4.1": "disabled", "openai:gpt-4.1-mini": "available"}
    assert d1.count("model_overrides", "list") == 1, "reads are cached"


def test_model_override_outage_keeps_the_last_copy_and_refuses_saves(d1):
    ModelRegistry.disable_model("openai:gpt-4.1")
    assert ModelRegistry.get_model_status("openai:gpt-4.1") == "disabled"
    d1.down.add("model_overrides")
    model_override_d1._cache["expires"] = 0
    assert ModelRegistry.get_model_status("openai:gpt-4.1") == "disabled"
    with pytest.raises(APIError) as caught:
        ModelRegistry.disable_model("openai:gpt-4.1-mini")
    assert caught.value.status_code == 503
    restart()
    assert ModelRegistry.get_model_status("openai:gpt-4.1") == "available", "without any copy nothing is disabled"
    with pytest.raises(APIError) as caught:
        model_override_d1.save("openai:bad id", "disabled")
    assert caught.value.status_code == 400


def test_cooldowns_apply_at_once_and_reach_other_instances_through_d1(d1):
    now = time.time()
    FreeQuotaService.block("provider:groq", 120, now=now)
    assert FreeQuotaService.remaining("provider:groq", now=now) == 120
    assert d1.calls == [], "a cooldown is written in the background"
    control_state_d1.run_tasks()
    assert d1.cooldowns == {"provider:groq": now + 120}
    FreeQuotaService.block("provider:groq", 5, now=now + 10)
    control_state_d1.run_tasks()
    assert d1.cooldowns == {"provider:groq": now + 120}, "a shorter cooldown never replaces a longer one"
    restart()  # Another instance.
    assert FreeQuotaService.remaining("provider:groq", now=now) == 0, "no D1 call on the request path"
    control_state_d1.run_tasks()
    assert FreeQuotaService.remaining("provider:groq", now=now + 20) == 100
    assert FreeQuotaService.remaining("model:groq:llama", now=now) == 0


def test_cooldowns_survive_a_d1_outage_and_are_written_later(d1, caplog):
    now = time.time()
    d1.down.add("free_quotas")
    FreeQuotaService.block("model:groq:llama", 60, now=now)
    with caplog.at_level(logging.WARNING, logger="services.free_quota_d1"):
        control_state_d1.run_tasks()
    assert "using this Container's cooldowns" in caplog.text
    assert FreeQuotaService.remaining("model:groq:llama", now=now) == 60
    d1.down.clear()
    free_quota_d1._state["retry_at"] = 0
    control_state_d1.run_tasks()
    assert d1.cooldowns == {"model:groq:llama": now + 60}


def test_workbench_records_survive_restarts_and_keep_owner_limits(d1):
    identifier = WorkbenchStore.save_profile("owner", PROFILE)
    report = WorkbenchStore.save_report("owner", [MEASUREMENT, MEASUREMENT])
    restart()
    [profile] = WorkbenchStore.profiles("owner")
    assert profile["id"] == identifier and profile["name"] == PROFILE["name"]
    assert WorkbenchStore.profiles("other") == []
    [stored] = WorkbenchStore.reports("owner")
    assert stored["id"] == report and stored["measurements"] == [MEASUREMENT, MEASUREMENT]
    for _ in range(49):
        WorkbenchStore.save_profile("owner", PROFILE)
    with pytest.raises(APIError) as caught:
        WorkbenchStore.save_profile("owner", PROFILE)
    assert caught.value.status_code == 409


def test_workbench_outage_serves_the_last_copy_and_refuses_saves(d1):
    WorkbenchStore.save_profile("owner", PROFILE)
    assert len(WorkbenchStore.profiles("owner")) == 1
    d1.down.add("workbench")
    workbench_d1._cache[("profiles", "owner")] = (workbench_d1._cache[("profiles", "owner")][0], 0)
    assert len(WorkbenchStore.profiles("owner")) == 1
    with pytest.raises(APIError) as caught:
        WorkbenchStore.save_profile("owner", PROFILE)
    assert caught.value.status_code == 503
    restart()
    with pytest.raises(APIError) as caught:
        WorkbenchStore.profiles("owner")
    assert caught.value.status_code == 503, "an unread list is reported unavailable, not empty"


def catalog_models():
    return (ProviderCatalogModel("nanogpt", "z-ai/glm-5.3", "2026-09-26T00:00:00+00:00", 200_000, 8192,
                                 {"description": "GLM", "supports_tools": True}),
            ProviderCatalogModel("nanogpt", "moonshotai/kimi-k2.6", "2026-09-26T00:00:00+00:00"))


def test_catalog_snapshots_survive_restarts(d1):
    assert ProviderCatalogService.replace_provider_models("nanogpt", catalog_models(),
                                                          discovered_at="2026-09-26T00:00:00+00:00") is True
    restart()
    models = ProviderCatalogService.list_models()
    assert [model.model_id for model in models] == ["moonshotai/kimi-k2.6", "z-ai/glm-5.3"]
    assert models[1].context_window == 200_000 and models[1].metadata == {"description": "GLM", "supports_tools": True}
    assert ProviderCatalogService.has_model("nanogpt", "z-ai/glm-5.3")
    assert not ProviderCatalogService.has_model("openai", "z-ai/glm-5.3")
    ProviderCatalogService.list_models()
    assert d1.count("provider_catalog", "get") == 1, "snapshots are downloaded once and then only listed when due"


def test_catalog_outage_keeps_the_refresh_in_this_container(d1, caplog):
    d1.down.add("provider_catalog")
    with caplog.at_level(logging.WARNING, logger="services.provider_catalog_d1"):
        assert ProviderCatalogService.replace_provider_models("nanogpt", catalog_models()) is False
    assert "kept in this Container only" in caplog.text
    assert len(ProviderCatalogService.list_models()) == 2
    restart()
    assert ProviderCatalogService.list_models() == []


def test_catalog_snapshots_are_bounded_when_decoded():
    bomb = base64.b64encode(zlib.compress(b"[" + b" " * (provider_catalog_d1.MAX_DECODED_BYTES + 1) + b"]")).decode()
    with pytest.raises(ValueError):
        provider_catalog_d1.decode(bomb)
    with pytest.raises(ValueError):
        provider_catalog_d1.decode(provider_catalog_d1.encode([("bad model id", None, None, None)]))
    assert provider_catalog_d1.decode(provider_catalog_d1.encode([("a/b", 1, None, None)])) == (("a/b", 1, None, None),)


def test_release_status_reports_d1_state(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "d1")
    assert (container_release()["storage"], container_release()["durability_warning"]) == ("d1", None)
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "sql")
    assert container_release()["storage"] == "sqlite+d1-state"
