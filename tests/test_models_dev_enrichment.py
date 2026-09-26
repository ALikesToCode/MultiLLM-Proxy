"""models.dev enrichment against a trimmed copy of the public catalog; no network."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from services import provider_capability_discovery as discovery
from services.provider_capability_discovery import (
    MODELS_DEV_URL,
    enrich_model_capabilities,
    reset_public_capability_cache,
)
from services.provider_catalog_metadata import (
    model_supports_tools,
    model_supports_vision,
    sanitize_provider_metadata,
)
from services.provider_catalog_service import ProviderCatalogModel, ProviderCatalogService
from tests.unified_api_test_case import UnifiedApiTestCase

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "models_dev_subset.json").read_text(encoding="utf-8")
)
FETCH = "services.provider_capability_discovery.fetch_public_capabilities"


def models(provider, *entries):
    return tuple(
        entry if isinstance(entry, ProviderCatalogModel) else ProviderCatalogModel(provider, entry, "now")
        for entry in entries
    )


def enrich(provider, base_url, *entries):
    with patch(FETCH, return_value=FIXTURE) as fetch:
        result = enrich_model_capabilities(provider, base_url, models(provider, *entries))
    return {model.model_id: model for model in result}, fetch


class ModelsDevEnrichmentTest(unittest.TestCase):
    def test_fills_limits_tools_vision_and_price_with_provenance(self):
        result, fetch = enrich("groq", "https://api.groq.com", "qwen/qwen3.8-27b", "whisper-large-v3")
        fetch.assert_called_once_with("groq")
        qwen = result["qwen/qwen3.8-27b"]
        self.assertEqual((qwen.context_window, qwen.max_output_tokens), (131042, 16384))
        self.assertIs(model_supports_tools(qwen.metadata), True)
        self.assertIs(model_supports_vision(qwen.metadata), True)
        self.assertEqual(qwen.metadata["input_cost_per_million"], 0.8)
        self.assertEqual(qwen.metadata["output_cost_per_million"], 4)
        source = f"{MODELS_DEV_URL}#groq"
        self.assertEqual(qwen.metadata["metadata_provenance"]["context_window"], source)
        self.assertEqual(qwen.metadata["metadata_provenance"]["input_cost_per_million"], source)
        self.assertEqual(qwen.metadata["vision_metadata_source"], MODELS_DEV_URL)
        # A zero limit is unknown, not a limit; an explicit false tool flag is kept.
        whisper = result["whisper-large-v3"]
        self.assertIsNone(whisper.context_window)
        self.assertIs(model_supports_tools(whisper.metadata), False)
        self.assertIs(model_supports_vision(whisper.metadata), False)
        # Enriched metadata survives the storage sanitizer.
        self.assertEqual(sanitize_provider_metadata(qwen.metadata), qwen.metadata)

    def test_explicit_provider_values_win(self):
        upstream = ProviderCatalogModel(
            "groq", "qwen/qwen3.8-27b", "now", context_window=1000,
            metadata={"supports_tools": False, "input_modalities": ["text"], "pricing": {"prompt": "0"}},
        )
        result, _ = enrich("groq", "https://api.groq.com", upstream)
        model = result["qwen/qwen3.8-27b"]
        self.assertEqual(model.context_window, 1000)
        self.assertEqual(model.max_output_tokens, 16384)
        self.assertIs(model_supports_tools(model.metadata), False)
        self.assertIs(model_supports_vision(model.metadata), False)
        self.assertNotIn("input_cost_per_million", model.metadata)
        self.assertEqual(set(model.metadata["metadata_provenance"]),
                         {"max_output_tokens", "output_modalities", "supports_reasoning"})

    def test_ids_match_exactly_within_the_endpoint_section(self):
        # crof publishes "qwen3.8-27b"; groq does not, and case differences never match.
        result, _ = enrich("groq", "https://api.groq.com", "qwen3.8-27b", "Qwen/Qwen3.8-27b")
        for model in result.values():
            self.assertIsNone(model.metadata)
            self.assertIsNone(model.context_window)

    def test_opencode_go_and_zen_use_their_own_sections(self):
        go, _ = enrich("opencode", "https://opencode.ai/zen/go/v1", "glm-5", "qwen3.6-plus-free")
        self.assertEqual(go["glm-5"].context_window, 202752)
        # Go is a subscription, so its entries carry no per-token price.
        self.assertNotIn("input_cost_per_million", go["glm-5"].metadata)
        self.assertIn("#opencode-go", go["glm-5"].metadata["metadata_provenance"]["context_window"])
        # Free Zen models merged into a Go catalog are described by the Zen section.
        free = go["qwen3.6-plus-free"].metadata
        self.assertEqual(free["input_cost_per_million"], 0)
        self.assertIn("#opencode", free["metadata_provenance"]["supports_tools"])
        zen, _ = enrich("opencode", "https://opencode.ai/zen/v1", "glm-5")
        self.assertEqual(zen["glm-5"].context_window, 204800)
        self.assertEqual(zen["glm-5"].metadata["input_cost_per_million"], 1)

    def test_subscription_endpoints_get_capabilities_without_prices(self):
        result, fetch = enrich("nanogpt", "https://nano-gpt.com/api/subscription", "z-ai/glm-5")
        fetch.assert_called_once_with("nanogpt")
        model = result["z-ai/glm-5"]
        self.assertIs(model_supports_tools(model.metadata), True)
        self.assertNotIn("input_cost_per_million", model.metadata)

    def test_image_models_declare_image_output(self):
        result, _ = enrich("xai", "https://api.x.ai", "grok-imagine-image", "grok-4.7")
        self.assertNotIn("text", result["grok-imagine-image"].metadata["output_modalities"])
        self.assertEqual(result["grok-4.7"].metadata["output_modalities"], ["text"])

    def test_unreviewed_providers_and_custom_origins_are_not_enriched(self):
        with patch(FETCH) as fetch:
            for provider, origin in (
                ("linkapi", "https://hk.linkapi.ai"),
                ("kimi-code", "https://api.kimi.com/coding/v1"),
                ("navyai", "https://api.navy"),
                ("groq", "https://groq.example"),
                ("opencode", "https://opencode.ai/custom/v1"),
                ("xai", "http://api.x.ai"),
            ):
                unknown = models(provider, "grok-4.7")
                self.assertIs(enrich_model_capabilities(provider, origin, unknown), unknown)
            fetch.assert_not_called()

    def test_malformed_sections_and_entries_are_ignored(self):
        payload = {
            "groq": {"models": {
                "qwen/qwen3.8-27b": {"id": "other", "tool_call": True},
                "openai/gpt-oss-120b": {"tool_call": "yes", "limit": {"context": -1, "output": True},
                                         "cost": {"input": float("inf"), "output": 1}},
            }},
            "xai": [],
        }
        with patch(FETCH, return_value=payload):
            result = enrich_model_capabilities(
                "groq", "https://api.groq.com", models("groq", "qwen/qwen3.8-27b", "openai/gpt-oss-120b")
            )
        for model in result:
            self.assertIsNone(model.metadata)
            self.assertIsNone(model.context_window)


class ModelsDevCacheTest(unittest.TestCase):
    def test_one_read_serves_every_provider_within_the_ttl(self):
        with patch(FETCH, return_value=FIXTURE) as fetch:
            enrich_model_capabilities("groq", "https://api.groq.com", models("groq", "openai/gpt-oss-120b"))
            enriched = enrich_model_capabilities("xai", "https://api.x.ai", models("xai", "grok-4.7"))
        fetch.assert_called_once_with("groq")
        self.assertIs(model_supports_tools(enriched[0].metadata), True)

    def test_failure_uses_the_last_good_copy_then_expires(self):
        clock = [1000.0]
        unknown = models("groq", "openai/gpt-oss-120b")
        with patch("services.provider_capability_discovery.time.monotonic", side_effect=lambda: clock[0]):
            with patch(FETCH, return_value=FIXTURE):
                enrich_model_capabilities("groq", "https://api.groq.com", unknown)
            clock[0] += discovery.CACHE_TTL_SECONDS + 1
            with patch(FETCH, side_effect=requests.Timeout()) as fetch:
                stale = enrich_model_capabilities("groq", "https://api.groq.com", unknown)
                fetch.assert_called_once()
            self.assertEqual(stale[0].context_window, 131072)
            clock[0] += discovery.STALE_FALLBACK_SECONDS
            with patch(FETCH, side_effect=ValueError("malformed")):
                self.assertIs(enrich_model_capabilities("groq", "https://api.groq.com", unknown), unknown)

    def test_reset_forgets_the_cached_index(self):
        with patch(FETCH, return_value=FIXTURE) as fetch:
            enrich_model_capabilities("groq", "https://api.groq.com", models("groq", "openai/gpt-oss-120b"))
            reset_public_capability_cache()
            enrich_model_capabilities("groq", "https://api.groq.com", models("groq", "openai/gpt-oss-120b"))
        self.assertEqual(fetch.call_count, 2)


class UpstreamToolMetadataTest(unittest.TestCase):
    def test_supported_parameters_declare_tool_support(self):
        catalog = ProviderCatalogService.extract_models("openrouter", {"data": [
            {"id": "tools-fixture:free", "supported_parameters": ["tools", "tool_choice", "max_tokens"]},
            {"id": "plain-fixture:free", "supported_parameters": ["max_tokens"]},
            {"id": "explicit-fixture:free", "supported_parameters": ["tools"], "supports_tools": False},
            {"id": "unknown-fixture:free"},
        ]})
        support = {model.model_id: model_supports_tools(model.metadata) for model in catalog}
        self.assertEqual(support, {"tools-fixture:free": True, "plain-fixture:free": False,
                                   "explicit-fixture:free": False, "unknown-fixture:free": None})
        self.assertNotIn("supported_parameters", catalog[0].metadata)


class EnrichedCatalogSerializationTest(UnifiedApiTestCase):
    def test_unified_models_expose_enriched_fields(self):
        with patch(FETCH, return_value=FIXTURE):
            enriched = enrich_model_capabilities(
                "groq", "https://api.groq.com",
                models("groq", "qwen/qwen3.8-27b", "whisper-large-v3"),
            )
        ProviderCatalogService.replace_provider_models("groq", enriched)
        response = self.client.get("/v1/models", headers={"Authorization": "Bearer admin-test-key"})
        catalog = {item["id"]: item for item in response.get_json()["data"]}
        qwen = catalog["groq:qwen/qwen3.8-27b"]
        self.assertEqual(qwen["context_window"], 131042)
        self.assertEqual(qwen["max_output_tokens"], 16384)
        self.assertEqual(qwen["input_cost_per_million"], 0.8)
        self.assertIs(qwen["supports_tools"], True)
        self.assertIs(qwen["supports_vision"], True)
        self.assertEqual(qwen["metadata_provenance"]["supports_tools"], f"{MODELS_DEV_URL}#groq")
        whisper = catalog["groq:whisper-large-v3"]
        self.assertIs(whisper["capabilities"]["supports_tools"], False)
        self.assertNotIn("context_window", whisper)
