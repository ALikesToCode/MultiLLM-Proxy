"""Declared precision never expands reviewed model eligibility."""

import json
from unittest.mock import patch

import pytest

from services.intelligence_contract import ChatRequest
from services.intelligence_policy import select_candidates
from services.intelligence_store import IntelligenceStore
from services.model_precision import declared_precision, validate_preference
from services.provider_catalog_metadata import (
    decode_provider_metadata,
    encode_provider_metadata,
    sanitize_provider_metadata,
)
from services.provider_catalog_service import (
    ProviderCatalogModel,
    ProviderCatalogService,
)
from services.route_health import RouteHealth
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate, policy


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.delenv("MODEL_PRECISION_PREFERENCE", raising=False)
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "models.sqlite3"))
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")

    def no_network(*args, **kwargs):
        raise AssertionError("Live HTTP is forbidden in precision tests")

    monkeypatch.setattr("requests.sessions.Session.request", no_network)
    RouteHealth.reset()
    yield
    RouteHealth.reset()


def test_unknown_is_not_inferred_from_names_or_quantization_scheme():
    for metadata in (None, {"id": "model-int4-fp8"}, {"quantization_scheme": "AWQ"}):
        assert declared_precision(metadata) == "unknown"
    assert declared_precision({"precision": "unsupported"}) == "unknown"


@pytest.mark.parametrize(
    "precision", ["fp32", "fp16", "bf16", "fp8", "int8", "int4", "unknown"]
)
def test_declared_precision_round_trips_with_provenance(monkeypatch, precision):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4"]')
    metadata = {
        "precision": precision,
        "quantization_scheme": "AWQ",
        "precision_source": "provider-catalog",
    }
    assert decode_provider_metadata(encode_provider_metadata(metadata)) == metadata


@pytest.mark.parametrize("value", [None, 4, True, "FP16", "float16", "int3", "fp16\n"])
def test_invalid_precision_is_omitted(monkeypatch, value):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4"]')
    assert sanitize_provider_metadata({"precision": value, "object": "model"}) == {
        "object": "model"
    }


@pytest.mark.parametrize(
    "field, value",
    [
        ("quantization_scheme", "x" * 129),
        ("precision_source", "x" * 513),
        ("precision_source", "private\nvalue"),
        ("quantization_scheme", {}),
        ("precision_source", ""),
    ],
)
def test_precision_strings_are_bounded(monkeypatch, field, value):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["bf16"]')
    assert field not in (sanitize_provider_metadata({field: value}) or {})


def test_unset_preserves_metadata_and_default_policy_bytes():
    assert sanitize_provider_metadata(
        {"object": "model", "precision": "int4", "quantization_scheme": "AWQ"}
    ) == {"object": "model"}
    assert "precision_preference" not in policy()


def test_default_catalog_keeps_preexisting_provenance():
    from services.model_catalog_service import _model_provider_metadata

    metadata = {"metadata_provenance": {"precision": "existing-provider-source"}}
    assert _model_provider_metadata("openai", "fixture", metadata) == metadata


@pytest.mark.parametrize(
    "value", ["int4", None, [True], ["INT4"], ["int4", "int4"], ["int3"], ["int4"] * 9]
)
def test_preference_rejects_unvalidated_extensions(value):
    with pytest.raises(ValueError, match="precision"):
        validate_preference(value)
    with pytest.raises(ValueError, match="precision"):
        policy(precision_preference=value)


def choices():
    return [
        candidate("openai:base"),
        candidate("openai:preferred"),
        candidate("openai:weaker", quality_tier=0),
    ]


def catalog():
    return [
        ProviderCatalogModel(
            "openai", name, "fixture", metadata={"precision": precision}
        )
        for name, precision in [
            ("base", "fp16"),
            ("preferred", "int4"),
            ("weaker", "int4"),
            ("not-approved", "int4"),
        ]
    ]


def ranked(items=None, profile="quality", model="auto:intelligence", **settings):
    reviewed = policy(candidates=items if items is not None else choices(), **settings)
    request = ChatRequest.parse(
        {
            "model": model,
            "messages": [{"role": "user", "content": "test"}],
            "routing": {"profile": profile},
        },
        reviewed,
    )
    with patch.object(ProviderCatalogService, "list_models", return_value=catalog()):
        return [
            item["model"]
            for item in select_candidates(
                reviewed,
                request,
                {"API_BASE_URLS": {"openai": "https://example.invalid"}},
            )
        ]


def test_unset_and_empty_preference_never_read_catalog(monkeypatch):
    for setting in (None, "[]"):
        if setting is not None:
            monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", setting)
        with patch.object(
            ProviderCatalogService,
            "list_models",
            side_effect=AssertionError("unexpected lookup"),
        ):
            reviewed = policy(candidates=choices())
            request = ChatRequest.parse(
                {
                    "model": "auto:intelligence",
                    "messages": [{"role": "user", "content": "test"}],
                },
                reviewed,
            )
            assert (
                select_candidates(
                    reviewed,
                    request,
                    {"API_BASE_URLS": {"openai": "https://example.invalid"}},
                )
                == reviewed["candidates"]
            )


def test_preference_breaks_only_quality_ties_and_preserves_balanced_chain(monkeypatch):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4", "fp16"]')
    assert ranked() == ["openai:preferred", "openai:base", "openai:weaker"]
    assert ranked(profile="balanced") == [
        "openai:base",
        "openai:preferred",
        "openai:weaker",
    ]
    assert ranked(model="openai:base") == ["openai:base"]


def test_unknown_and_unlisted_candidates_are_not_guessed_or_added(monkeypatch):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4"]')
    items = [candidate("openai:base"), candidate("openai:missing-int4")]
    assert ranked(items) == ["openai:base", "openai:missing-int4"]


def test_environment_preference_is_strict_and_bounded(monkeypatch):
    from services.model_precision import environment_preference

    for setting in ("int4", "null", '["int3"]', "x" * 257, " " * 257):
        monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", setting)
        with pytest.raises(ValueError, match="precision"):
            environment_preference()


def test_validated_policy_preference_round_trips_and_overrides_environment(monkeypatch):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4"]')
    configured = policy(precision_preference=["fp16"], candidates=choices())
    assert IntelligenceStore.seed(configured)
    assert IntelligenceStore.policy() == configured
    assert ranked(precision_preference=["fp16"])[:2] == [
        "openai:base",
        "openai:preferred",
    ]
    assert ranked(precision_preference=[])[:2] == ["openai:base", "openai:preferred"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"enabled": False},
        {"entitled": False},
        {"privacy_allowed": False},
        {"billing": "payg"},
        {"context_window": 1},
        {"max_output_tokens": 1},
        {"capabilities": []},
    ],
)
def test_eligibility_dominates_precision(monkeypatch, overrides):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4"]')
    items = [candidate("openai:base"), candidate("openai:preferred", **overrides)]
    reviewed = policy(candidates=items)
    request = ChatRequest.parse(
        {
            "model": "auto:intelligence",
            "messages": [{"role": "user", "content": "test"}],
            "routing": {"profile": "quality", "required_capabilities": ["tools"]},
        },
        reviewed,
    )
    with patch.object(ProviderCatalogService, "list_models", return_value=catalog()):
        result = select_candidates(
            reviewed, request, {"API_BASE_URLS": {"openai": "https://example.invalid"}}
        )
    assert [item["model"] for item in result] == ["openai:base"]


def test_disabled_model_and_health_and_speed_dominate_preference(monkeypatch):
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["int4"]')
    items = [
        candidate("openai:base", latency_ms=500),
        candidate("openai:preferred", latency_ms=1000),
    ]
    assert ranked(items, profile="fast") == ["openai:base", "openai:preferred"]
    for _ in range(5):
        RouteHealth.record("openai:preferred", ok=False, outcome="http_503", status=503)
    assert ranked(profile="fast")[0] == "openai:base"
    with patch(
        "services.intelligence_policy.ModelRegistry.get_model_status",
        side_effect=lambda model: (
            "disabled" if model == "openai:preferred" else "enabled"
        ),
    ):
        assert "openai:preferred" not in ranked()


class PrecisionHttpTests(IntelligenceApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()

    def test_registered_catalog_default_and_enabled_declarations(self):
        ProviderCatalogService.replace_provider_models("openai", catalog())

        def payload():
            response = self.client.get("/v1/models", headers=self.headers)
            assert response.status_code == 200
            return next(
                item
                for item in response.json["data"]
                if item["id"] == "openai:preferred"
            )

        baseline = payload()
        assert "precision" not in baseline
        with patch.dict("os.environ", {"MODEL_PRECISION_PREFERENCE": '["int4"]'}):
            ProviderCatalogService.replace_provider_models("openai", catalog())
            enabled = payload()
            assert enabled["precision"] == "int4"
            assert enabled["precision_source"] == "provider_catalog:openai"
            assert (
                enabled["metadata_provenance"]["precision"] == "provider_catalog:openai"
            )
        assert payload() == baseline

    def test_registered_managed_route_selects_tie_without_changing_explicit(self):
        with patch.dict("os.environ", {"MODEL_PRECISION_PREFERENCE": '["int4"]'}):
            ProviderCatalogService.replace_provider_models("openai", catalog())
            IntelligenceStore.seed(policy(candidates=choices()))
            for model, expected, profile in [
                ("auto:intelligence", "openai:preferred", "quality"),
                ("auto:intelligence", "openai:base", "balanced"),
                ("openai:base", "openai:base", "quality"),
            ]:
                with self.requests(return_value=upstream(completion())) as send:
                    response = self.post(model=model, routing={"profile": profile})
                assert response.status_code == 200, response.data
                assert response.json["model"] == expected
                assert send.call_count == 1
                assert "precision_preference" not in json.loads(
                    send.call_args.kwargs["data"]
                )

    def test_unset_and_empty_registered_route_response_and_dispatch_bytes_match(self):
        IntelligenceStore.seed(policy(candidates=choices()))
        results = []
        for setting in ("", "[]"):
            with (
                patch.dict("os.environ", {"MODEL_PRECISION_PREFERENCE": setting}),
                patch("services.intelligence_gateway.time.time", return_value=1000),
                self.requests(return_value=upstream(completion())) as send,
                patch.object(
                    ProviderCatalogService,
                    "list_models",
                    side_effect=AssertionError("unexpected lookup"),
                ),
            ):
                response = self.post(routing={"profile": "quality"})
            assert response.status_code == 200, response.data
            results.append((response.data, send.call_args.kwargs["data"]))
        assert results[0] == results[1]

    def test_default_catalog_bytes_match_empty_preference(self):
        ProviderCatalogService.replace_provider_models("openai", catalog())
        baseline = self.client.get("/v1/models", headers=self.headers)
        with patch.dict("os.environ", {"MODEL_PRECISION_PREFERENCE": "[]"}):
            disabled = self.client.get("/v1/models", headers=self.headers)
        assert baseline.status_code == disabled.status_code == 200
        assert baseline.data == disabled.data

    def test_invalid_environment_is_ignored_for_routing_and_catalog(self):
        IntelligenceStore.seed(policy(candidates=choices()))
        ProviderCatalogService.replace_provider_models("openai", catalog())
        baseline_models = self.client.get("/v1/models", headers=self.headers)
        results = []
        for setting in ("", "invalid"):
            with (
                patch.dict("os.environ", {"MODEL_PRECISION_PREFERENCE": setting}),
                patch("services.intelligence_gateway.time.time", return_value=1000),
                self.requests(return_value=upstream(completion())) as send,
                patch.object(
                    ProviderCatalogService,
                    "list_models",
                    side_effect=AssertionError("unexpected lookup"),
                ),
            ):
                response = self.post(routing={"profile": "quality"})
            assert response.status_code == 200, response.data
            assert send.call_count == 1
            results.append((response.data, send.call_args.kwargs["data"]))
        assert results[0] == results[1]
        with patch.dict("os.environ", {"MODEL_PRECISION_PREFERENCE": "invalid"}):
            ProviderCatalogService.replace_provider_models("openai", catalog())
            invalid_models = self.client.get("/v1/models", headers=self.headers)
        assert invalid_models.status_code == 200
        assert invalid_models.data == baseline_models.data
