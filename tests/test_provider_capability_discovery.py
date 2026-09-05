import json
import unittest
from unittest.mock import MagicMock, patch

import requests

from services.provider_capability_discovery import (
    PUBLIC_CAPABILITY_SOURCES,
    enrich_model_capabilities,
    extract_public_capabilities,
    fetch_public_capabilities,
)
from services.provider_catalog_metadata import (
    model_supports_vision,
    sanitize_provider_metadata,
)
from services.provider_catalog_service import (
    ProviderCatalogModel,
    ProviderCatalogService,
)


class ProviderCapabilityDiscoveryTest(unittest.TestCase):
    def test_extract_models_normalizes_supported_catalog_shapes(self):
        for metadata in (
            {"input_modalities": " text, image "},
            {"input_modalities": ["text", "IMAGE", "image"]},
            {"architecture": {"input_modalities": ["text", "image"]}},
            {"modalities": {"input": ["text", "image"]}},
        ):
            with self.subTest(metadata=metadata):
                model = ProviderCatalogService.extract_models(
                    "aihubmix",
                    {"data": [{"id": "vision-fixture-free", **metadata}]},
                )[0]
                self.assertEqual(model.metadata["input_modalities"], ["text", "image"])
                self.assertIs(model_supports_vision(model.metadata), True)

    def test_unknown_fields_and_image_output_do_not_establish_vision(self):
        for metadata in (
            {},
            {"supports_vision": "true"},
            {"input_modalities": []},
            {"input_modalities": [1, "image"]},
            {"input_modalities": "text,,image"},
            {"input_modalities": "x" * 1025},
            {"input_modalities": ["image"] * 33},
            {"modalities": "multimodal"},
            {"output_modalities": ["image"]},
            {"supports_images": True},
            {"attachment": True},
        ):
            with self.subTest(metadata=metadata):
                sanitized = sanitize_provider_metadata(metadata)
                self.assertIsNone(model_supports_vision(sanitized))
        self.assertIs(model_supports_vision({"input_modalities": ["text"]}), False)

    def test_public_lookup_is_provider_scoped_and_exact(self):
        result = extract_public_capabilities(
            "opencode",
            {
                "opencode": {
                    "models": {
                        "mimo-v2.5-free": {"modalities": {"input": ["text", "image"]}},
                        "wrong-id": {"id": "other", "modalities": {"input": ["image"]}},
                    }
                },
                "other": {
                    "models": {"other-model": {"modalities": {"input": ["image"]}}}
                },
            },
        )
        self.assertEqual(set(result), {"mimo-v2.5-free"})
        self.assertNotIn("mimo-v2.5", result)
        self.assertNotIn("supports_images", result["mimo-v2.5-free"])
        self.assertIs(model_supports_vision(result["mimo-v2.5-free"]), True)

    def test_malformed_public_payloads_are_ignored(self):
        for provider in ("aihubmix", "opencode"):
            for payload in (None, [], "html", {}, {"data": {}}, {"opencode": []}):
                with self.subTest(provider=provider, payload=payload):
                    self.assertEqual(extract_public_capabilities(provider, payload), {})

    def test_enrichment_keeps_explicit_model_decisions_and_does_not_add_models(self):
        models = tuple(
            ProviderCatalogModel("aihubmix", model_id, "now", metadata=metadata)
            for model_id, metadata in (
                ("vision-fixture-free", {"supports_vision": None}),
                ("text-fixture-free", {"supports_vision": False}),
                ("unknown-vision-free", None),
            )
        )
        payload = {
            "data": [
                {
                    "model_id": model_id,
                    "input_modalities": "text,image",
                    "pricing": {"input": 0},
                }
                for model_id in (
                    "vision-fixture-free",
                    "text-fixture-free",
                    "not-available-free",
                )
            ]
        }
        with patch(
            "services.provider_capability_discovery.fetch_public_capabilities",
            return_value=payload,
        ):
            result = enrich_model_capabilities(
                "aihubmix", "https://aihubmix.com", models
            )
        self.assertEqual(
            [model.model_id for model in result], [model.model_id for model in models]
        )
        self.assertIs(model_supports_vision(result[0].metadata), True)
        self.assertNotIn("pricing", result[0].metadata)
        self.assertIs(result[1], models[1])
        self.assertIsNone(model_supports_vision(result[2].metadata))

    def test_public_failure_keeps_primary_catalog(self):
        models = (ProviderCatalogModel("opencode", "fixture-free", "now"),)
        for error in (requests.Timeout(), ValueError("malformed json")):
            with patch(
                "services.provider_capability_discovery.fetch_public_capabilities",
                side_effect=error,
            ):
                self.assertIs(
                    enrich_model_capabilities(
                        "opencode", "https://opencode.ai/zen/v1", models
                    ),
                    models,
                )

    def test_custom_origins_and_complete_metadata_do_not_trigger_public_requests(self):
        unknown = (ProviderCatalogModel("opencode", "fixture-free", "now"),)
        with patch(
            "services.provider_capability_discovery.fetch_public_capabilities"
        ) as fetch:
            for origin in (
                "http://opencode.ai",
                "https://opencode.example",
                "https://opencode.ai.evil.test",
                "https://user:pass@opencode.ai",
                "https://opencode.ai:1234",
                "https://[broken",
            ):
                self.assertIs(
                    enrich_model_capabilities("opencode", origin, unknown), unknown
                )
            known = (
                ProviderCatalogModel(
                    "opencode",
                    "fixture-free",
                    "now",
                    metadata={"supports_vision": False},
                ),
            )
            self.assertIs(
                enrich_model_capabilities(
                    "opencode", "https://opencode.ai/zen/v1", known
                ),
                known,
            )
            fetch.assert_not_called()


class PublicCapabilityTransportTest(unittest.TestCase):
    def _session(self, status=200, chunks=None):
        session = MagicMock()
        session.__enter__.return_value = session
        response = session.get.return_value.__enter__.return_value
        response.status_code = status
        response.iter_content.return_value = (
            chunks if chunks is not None else [b'{"data":[]}']
        )
        return session, response

    def test_public_get_has_no_auth_environment_or_redirects(self):
        session, response = self._session()
        with patch(
            "services.provider_capability_discovery.requests.Session",
            return_value=session,
        ):
            self.assertEqual(fetch_public_capabilities("aihubmix"), {"data": []})
        self.assertIs(session.trust_env, False)
        session.get.assert_called_once_with(
            PUBLIC_CAPABILITY_SOURCES["aihubmix"],
            headers={"Accept": "application/json"},
            timeout=(3, 10),
            allow_redirects=False,
            stream=True,
        )
        session.get.return_value.__exit__.assert_called_once()
        session.__exit__.assert_called_once()
        response.iter_content.assert_called_once_with(chunk_size=65536)

    def test_non_success_response_is_not_parsed(self):
        session, response = self._session(status=302)
        with (
            patch(
                "services.provider_capability_discovery.requests.Session",
                return_value=session,
            ),
            self.assertRaises(ValueError),
        ):
            fetch_public_capabilities("opencode")
        response.iter_content.assert_not_called()

    def test_malformed_oversize_and_slow_payloads_are_rejected(self):
        for chunks, size, elapsed in (
            ([b"not json"], 20, 0),
            ([b"123", b"456"], 5, 0),
            ([b"{}"], 10, 31),
        ):
            with self.subTest(chunks=chunks, size=size, elapsed=elapsed):
                session, _ = self._session(chunks=chunks)
                with (
                    patch(
                        "services.provider_capability_discovery.requests.Session",
                        return_value=session,
                    ),
                    patch(
                        "services.provider_capability_discovery._MAX_CATALOG_BYTES",
                        size,
                    ),
                    patch(
                        "services.provider_capability_discovery.time.monotonic",
                        side_effect=[0, elapsed, elapsed],
                    ),
                    self.assertRaises((ValueError, json.JSONDecodeError)),
                ):
                    fetch_public_capabilities("opencode")
