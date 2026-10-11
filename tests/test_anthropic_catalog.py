import io
import json
import os
from unittest.mock import Mock, patch

import requests

from services import anthropic_catalog
from tests.unified_api_test_case import UnifiedApiTestCase


def page(data, *, more=False, cursor=None, status=200):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(
        {"data": data, "has_more": more, "last_id": cursor}
    ).encode()
    response.raw = io.BytesIO(response._content)
    response.close = Mock(wraps=response.close)
    return response


class AnthropicCatalogTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        from services.provider_catalog_service import ProviderCatalogService

        self.catalog = ProviderCatalogService
        os.environ["ANTHROPIC_API_KEY"] = "catalog-test-key"
        self.catalog.replace_provider_models("anthropic", ("existing-model",))

    def refresh(self, responses):
        with patch("app.ProxyService.make_request", side_effect=responses) as send:
            results = self.catalog.refresh_configured(
                {"anthropic": "https://api.anthropic.com"},
                self.app_module.AuthService,
                self.app_module.ProxyService,
            )
        return results[0], send

    def test_all_pages_replace_the_catalog_once(self):
        first = page([{"id": "first-model"}], more=True, cursor="first-model")
        last = page([{"id": "claude-haiku-5-5", "max_input_tokens": 1_000_000}])
        result, send = self.refresh([first, last])
        assert result["status"] == "updated"
        assert {
            model.model_id
            for model in self.catalog.list_models()
            if model.provider == "anthropic"
        } == {"first-model", "claude-haiku-5-5"}
        assert send.call_count == 2
        assert send.call_args_list[0].kwargs["params"] == {"limit": 1000}
        assert send.call_args_list[1].kwargs["params"] == {
            "limit": 1000,
            "after_id": "first-model",
        }
        first.close.assert_called_once()
        last.close.assert_called_once()

    def test_later_page_failure_preserves_existing_catalog(self):
        result, send = self.refresh(
            [
                page([{"id": "first-model"}], more=True, cursor="first-model"),
                page([], status=503),
            ]
        )
        assert result["status"] == "failed" and send.call_count == 2
        assert self.catalog.has_model("anthropic", "existing-model")
        assert not self.catalog.has_model("anthropic", "first-model")

    def test_invalid_and_repeated_cursors_preserve_existing_catalog(self):
        for responses in (
            [page([{"id": "first-model"}], more=True)],
            [page([{"id": "first-model"}], more=True, cursor="other-model")],
            [
                page([{"id": "first-model"}], more=True, cursor="first-model"),
                page([{"id": "first-model"}], more=True, cursor="first-model"),
            ],
        ):
            result, _ = self.refresh(responses)
            assert result["status"] == "failed"
            assert self.catalog.has_model("anthropic", "existing-model")

    def test_page_and_model_limits_preserve_existing_catalog(self):
        with patch.object(anthropic_catalog, "MAX_CATALOG_PAGES", 1):
            result, send = self.refresh(
                [page([{"id": "first-model"}], more=True, cursor="first-model")]
            )
            assert result["status"] == "failed" and send.call_count == 1
        with patch("services.provider_catalog_service.MAX_MODELS_PER_PROVIDER", 1):
            result, _ = self.refresh(
                [page([{"id": "first-model"}, {"id": "second-model"}])]
            )
            assert result["status"] == "failed"
        assert self.catalog.has_model("anthropic", "existing-model")
