import json
import os
import tempfile
import unittest
from typing import ClassVar

import requests

from services.provider_catalog_service import ProviderCatalogService


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
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

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
                    {"id": "glm-5.2"},
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

    def test_has_model_reads_the_last_successful_catalog(self):
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("glm-5.2",),
        )

        self.assertTrue(ProviderCatalogService.has_model("opencode", "glm-5.2"))
        self.assertFalse(ProviderCatalogService.has_model("opencode", "missing"))


if __name__ == "__main__":
    unittest.main()
