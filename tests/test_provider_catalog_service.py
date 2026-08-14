import json
import os
import sqlite3
import tempfile
import unittest
from typing import ClassVar

import requests

from services.provider_catalog_service import (
    ProviderCatalogModel,
    ProviderCatalogService,
)


class _FakeAuthService:
    @classmethod
    def get_api_key(cls, provider):
        return "opencode-key" if provider == "opencode" else None

    @classmethod
    def get_api_keys(cls, provider):
        if provider == "nanogpt":
            return ["rejected-nano-key", "working-nano-key"]
        api_key = cls.get_api_key(provider)
        return [api_key] if api_key else []


class _FakeProxyService:
    status_code = 200
    status_codes: ClassVar[list[int]] = []
    authorizations: ClassVar[list[str | None]] = []

    @classmethod
    def prepare_headers(cls, request_headers, provider, token, upstream_path=""):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @classmethod
    def make_request(cls, **kwargs):
        response = requests.Response()
        response.status_code = (
            cls.status_codes.pop(0) if cls.status_codes else cls.status_code
        )
        cls.authorizations.append(kwargs["headers"].get("Authorization"))
        response._content = json.dumps(
            {
                "object": "list",
                "data": [
                    {
                        "id": "glm-5.2",
                        "context_window": 1_048_576,
                        "max_output_tokens": 131_072,
                    },
                    {"id": "kimi-k3"},
                    {"id": "invalid model with spaces"},
                ],
            }
        ).encode("utf-8")
        response._content_consumed = True
        response.headers["Content-Type"] = "application/json"
        return response


class ProviderCatalogServiceTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["MODEL_REGISTRY_DB_PATH"] = os.path.join(
            self.temp_dir.name,
            "models.sqlite3",
        )
        _FakeProxyService.status_code = 200
        _FakeProxyService.status_codes = []
        _FakeProxyService.authorizations = []

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_refresh_caches_safe_model_ids_from_configured_provider(self):
        results = ProviderCatalogService.refresh_configured(
            {"opencode": "https://opencode.example/v1"},
            _FakeAuthService,
            _FakeProxyService,
        )

        self.assertEqual(
            results,
            [
                {
                    "provider": "opencode",
                    "status": "updated",
                    "truncated": False,
                    "model_count": 2,
                }
            ],
        )
        self.assertEqual(
            [model.model_id for model in ProviderCatalogService.list_models()],
            ["glm-5.2", "kimi-k3"],
        )
        glm = ProviderCatalogService.list_models()[0]
        self.assertEqual(glm.context_window, 1_048_576)
        self.assertEqual(glm.max_output_tokens, 131_072)

    def test_failed_refresh_preserves_last_good_catalog(self):
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("last-good-model",),
        )
        _FakeProxyService.status_code = 503

        results = ProviderCatalogService.refresh_configured(
            {"opencode": "https://opencode.example/v1"},
            _FakeAuthService,
            _FakeProxyService,
        )

        self.assertEqual(results[0]["status"], "failed")
        self.assertEqual(
            [model.model_id for model in ProviderCatalogService.list_models()],
            ["last-good-model"],
        )

    def test_nanogpt_catalog_tries_each_key_without_returning_credentials(self):
        _FakeProxyService.status_codes = [401, 200]

        results = ProviderCatalogService.refresh_configured(
            {"nanogpt": "https://nano.example/api"},
            _FakeAuthService,
            _FakeProxyService,
        )

        self.assertEqual(results[0]["status"], "updated")
        self.assertEqual(
            _FakeProxyService.authorizations,
            ["Bearer rejected-nano-key", "Bearer working-nano-key"],
        )
        self.assertNotIn("nano-key", str(results))

    def test_navyai_public_catalog_refresh_does_not_require_or_send_a_key(self):
        results = ProviderCatalogService.refresh_configured(
            {"navyai": "https://api.navy"},
            _FakeAuthService,
            _FakeProxyService,
        )

        self.assertEqual(results[0]["status"], "updated")
        self.assertEqual(_FakeProxyService.authorizations, [None])

    def test_extract_model_ids_accepts_standard_catalog_shapes(self):
        self.assertEqual(
            ProviderCatalogService.extract_model_ids(
                "navyai",
                {
                    "models": [
                        "navyai:glm-5.2",
                        {"model_id": "provider/model-v1"},
                        {"name": "bad model"},
                    ]
                },
            ),
            ("glm-5.2", "provider/model-v1"),
        )

    def test_extract_models_uses_the_effective_gateway_limits(self):
        models = ProviderCatalogService.extract_models(
            "openrouter",
            {
                "data": [
                    {
                        "id": "zai-org/glm-5.2",
                        "context_length": 1_048_576,
                        "max_output_tokens": 131_072,
                        "top_provider": {
                            "context_length": 262_144,
                            "max_completion_tokens": 65_536,
                        },
                    }
                ]
            },
            discovered_at="2026-08-14T10:00:00+00:00",
        )

        self.assertEqual(len(models), 1)
        self.assertEqual(models[0].context_window, 262_144)
        self.assertEqual(models[0].max_output_tokens, 65_536)

    def test_existing_catalog_schema_is_migrated_without_losing_models(self):
        database_path = os.environ["MODEL_REGISTRY_DB_PATH"]
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                """
                CREATE TABLE provider_model_catalog (
                    provider TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    PRIMARY KEY (provider, model_id)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO provider_model_catalog
                    (provider, model_id, discovered_at)
                VALUES (?, ?, ?)
                """,
                ("navyai", "glm-5.2", "2026-08-14T10:00:00+00:00"),
            )

        models = ProviderCatalogService.list_models()

        self.assertEqual(models[0].model_id, "glm-5.2")
        self.assertIsNone(models[0].context_window)
        self.assertIsNone(models[0].max_output_tokens)

    def test_replace_provider_models_persists_reported_limits(self):
        ProviderCatalogService.replace_provider_models(
            "navyai",
            (
                ProviderCatalogModel(
                    provider="navyai",
                    model_id="glm-5.2",
                    discovered_at="ignored-on-write",
                    context_window=1_048_576,
                    max_output_tokens=131_072,
                ),
            ),
            discovered_at="2026-08-14T10:00:00+00:00",
        )

        model = ProviderCatalogService.list_models()[0]
        self.assertEqual(model.discovered_at, "2026-08-14T10:00:00+00:00")
        self.assertEqual(model.context_window, 1_048_576)
        self.assertEqual(model.max_output_tokens, 131_072)

    def test_has_model_reads_the_last_successful_catalog(self):
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("glm-5.2",),
        )

        self.assertTrue(ProviderCatalogService.has_model("opencode", "glm-5.2"))
        self.assertFalse(ProviderCatalogService.has_model("opencode", "missing"))


if __name__ == "__main__":
    unittest.main()
