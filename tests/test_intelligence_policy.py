import copy
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from services.control_plane_backup import capture, restore_empty
from services.intelligence_contract import ChatRequest, GatewayError
from services.intelligence_policy import (
    DEFAULT_POLICY,
    model_advertisement,
    select_candidates,
    validate_policy,
)
from services.intelligence_store import IntelligenceStore


def candidate(model="openai:test", **overrides):
    return {
        "model": model,
        "capabilities": ["tools", "json", "streaming", "reasoning"],
        "enabled": True,
        "entitled": True,
        "privacy_allowed": True,
        "billing": "allowance",
        "context_window": 32768,
        "max_output_tokens": 4096,
        "quality_tier": 1,
        **overrides,
    }


def policy(**overrides):
    return validate_policy(
        {**DEFAULT_POLICY, "enabled": True, "candidates": [candidate()], **overrides}
    )


def test_model_identifiers_fit_the_shared_client_contract():
    assert policy(candidates=[candidate("openai:" + "m" * 121)])
    with pytest.raises(ValueError):
        policy(candidates=[candidate("openai:" + "m" * 122)])


@pytest.mark.parametrize("capability", ["vision", "audio"])
def test_catalog_only_advertises_media_with_a_reviewed_input_ceiling(capability):
    for ceiling in (0, 8192):
        configured = policy(
            candidates=[
                candidate(
                    capabilities=["streaming", capability], media_input_tokens=ceiling
                )
            ]
        )
        advertised = model_advertisement(configured)
        assert (capability in advertised["capabilities"]) == bool(ceiling)
        assert "streaming" in advertised["capabilities"]
        assert advertised["availability"] == "unverified"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("INTELLIGENCE_REQUIRE_DURABLE_STORAGE", "false")
    monkeypatch.delenv("INTELLIGENCE_POLICY_JSON", raising=False)
    for name in ("AUTH", "MODEL_REGISTRY", "RATE_LIMIT", "CONNECTION_PROFILES"):
        monkeypatch.setenv(f"{name}_DB_PATH", str(tmp_path / f"{name}.sqlite3"))
    return IntelligenceStore


def test_policy_seed_is_additive_and_survives_new_store(store):
    assert store.seed(policy())
    assert not store.seed(policy(candidates=[candidate("openai:replacement")]))
    assert IntelligenceStore().policy()["candidates"][0]["model"] == "openai:test"


def test_concurrent_admission_never_overspends(store):
    limits = policy(principal_daily_tokens=100, global_daily_tokens=100)

    def admit(_):
        try:
            return store.reserve("caller", 60, limits)
        except GatewayError as error:
            assert error.code == "allowance_exhausted"
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(admit, range(8)))
    assert len([item for item in reservations if item]) == 1
    store.settle(next(item for item in reservations if item), 10, True)
    assert store.reserve("caller", 60, limits)


def test_unknown_and_pending_reservations_survive_restarts_and_day_boundary(store):
    limits = policy(global_daily_tokens=100, principal_daily_tokens=100)
    identifier = store.reserve("caller", 70, limits, now=1)
    store.settle(identifier, 0, False)
    with pytest.raises(GatewayError):
        IntelligenceStore().reserve("caller", 31, limits, now=172800)


def test_unknown_usage_never_discards_a_known_lower_bound(store):
    limits = policy(global_daily_tokens=100, principal_daily_tokens=100)
    identifier = store.reserve("caller", 50, limits)
    store.settle(identifier, 90, False)
    with pytest.raises(GatewayError):
        store.reserve("caller", 11, limits)


def test_backup_contains_policy_reservations_and_preserves_legacy_inventory(
    store, tmp_path, monkeypatch
):
    store.seed(policy())
    reservation = store.reserve("caller", 70, policy())
    store.settle(reservation, 0, False)
    document = capture()
    assert document["tables"]["intelligence_reservations"][0]["state"] == "unknown"
    for name in ("AUTH", "MODEL_REGISTRY", "RATE_LIMIT", "CONNECTION_PROFILES"):
        monkeypatch.setenv(f"{name}_DB_PATH", str(tmp_path / f"new-{name}.sqlite3"))
    restore_empty(document)
    assert store.policy()["candidates"][0]["model"] == "openai:test"
    assert (
        capture()["tables"]["intelligence_reservations"]
        == document["tables"]["intelligence_reservations"]
    )
    legacy = copy.deepcopy(document)
    legacy["tables"].pop("intelligence_policy")
    legacy["tables"].pop("intelligence_reservations")
    for name in ("AUTH", "MODEL_REGISTRY", "RATE_LIMIT", "CONNECTION_PROFILES"):
        monkeypatch.setenv(f"{name}_DB_PATH", str(tmp_path / f"legacy-{name}.sqlite3"))
    restore_empty(legacy)
    assert not store.policy()["enabled"]


def test_container_refuses_ephemeral_policy_store(store, monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_REQUIRE_DURABLE_STORAGE", "true")
    with pytest.raises(GatewayError, match="external"):
        store.policy()


def test_request_limits_only_tighten_and_routing_never_survives():
    body = {
        "model": "auto:intelligence",
        "messages": [{"role": "user", "content": "test"}],
        "routing": {
            "max_attempts": 999,
            "deadline_ms": 999999,
            "allow_paid_overage": True,
        },
    }
    request = ChatRequest.parse(body, policy())
    assert request.max_attempts == 3 and request.deadline_ms == 45000
    assert not request.allow_paid and "routing" not in request.payload


@pytest.mark.parametrize(
    "routing",
    [
        {"version": True},
        {"version": 2},
        {"max_total_tokens": 0},
        {"max_attempts": True},
        {"source": "admin"},
        {"task": "execution"},
        {"allow_paid_overage": "false"},
        {"required_capabilities": ["anything"]},
        {"unknown": 1},
    ],
)
def test_invalid_contract_is_rejected(routing):
    with pytest.raises(ValueError):
        ChatRequest.parse(
            {
                "model": "auto:intelligence",
                "messages": [{"role": "user", "content": "test"}],
                "routing": routing,
            },
            policy(),
        )


def test_payload_capabilities_cannot_be_removed_and_explicit_selection_is_fixed(store):
    body = {
        "model": "openai:test",
        "messages": [{"role": "tool", "tool_call_id": "id", "content": "result"}],
        "reasoning_effort": "high",
        "response_format": {"type": "json_object"},
        "stream": True,
    }
    request = ChatRequest.parse(body, policy())
    assert request.required == {"tools", "reasoning", "json", "streaming"}
    config = {"API_BASE_URLS": {"openai": "https://example.invalid"}}
    models = policy(
        candidates=[
            candidate("openai:other"),
            candidate(capabilities=[]),
            candidate("navyai:test"),
        ]
    )
    assert not select_candidates(models, request, config)
    assert request.payload["reasoning_effort"] == "high"


def test_policy_requires_exact_capabilities_capacity_privacy_and_entitlement(store):
    request = ChatRequest.parse(
        {
            "model": "auto:intelligence",
            "messages": [{"role": "user", "content": "test"}],
            "routing": {"required_capabilities": ["tools"]},
        },
        policy(),
    )
    choices = [
        candidate("openai:a", capabilities=[]),
        candidate("openai:b", entitled=False),
        candidate("openai:c", privacy_allowed=False),
        candidate("openai:d", billing="payg"),
        candidate("openai:e", context_window=5),
        candidate(),
    ]
    assert [
        c["model"]
        for c in select_candidates(
            policy(candidates=choices),
            request,
            {"API_BASE_URLS": {"openai": "https://example.invalid"}},
        )
    ] == ["openai:test"]


def test_policy_env_seed_is_only_applied_once(store, monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_POLICY_JSON", json.dumps(policy()))
    assert store.policy()["enabled"]
    monkeypatch.setenv("INTELLIGENCE_POLICY_JSON", "malformed replacement")
    assert store.policy()["enabled"]


def test_postgres_concurrent_allowance_and_restart_when_configured(store, monkeypatch):
    database_url = os.environ.get("TEST_CONTROL_PLANE_DATABASE_URL")
    if not database_url:
        pytest.skip("Requires an isolated PostgreSQL test database")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", database_url)
    limits = policy(global_daily_tokens=100, principal_daily_tokens=100)
    store.seed(limits)

    def reserve(_):
        try:
            return IntelligenceStore().reserve(
                "postgres-intelligence-principal", 60, limits
            )
        except GatewayError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        reservations = [
            identifier for identifier in pool.map(reserve, range(4)) if identifier
        ]
    assert len(reservations) == 1
    store.settle(reservations[0], 0, False)
    assert IntelligenceStore().policy()["global_daily_tokens"] == 100
    assert capture()["tables"]["intelligence_reservations"][0]["state"] == "unknown"
    with pytest.raises(GatewayError):
        store.reserve("another-principal", 41, limits)
