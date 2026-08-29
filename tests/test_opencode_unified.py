import io
import json
from unittest.mock import patch

import requests

from services.provider_catalog_service import ProviderCatalogService
from tests.unified_api_test_case import UnifiedApiTestCase


class OpenCodeUnifiedRouteTest(UnifiedApiTestCase):
    def test_v1_models_exposes_each_native_protocol(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        models = {
            model["id"]: model for model in response.get_json()["data"]
        }
        expected = {
            "opencode:glm-5.3-flash": (
                "/v1/chat/completions",
                "openai_chat_completions",
            ),
            "opencode:qwen3.8-flash": (
                "/v1/messages",
                "anthropic_messages",
            ),
            "opencode:gpt-5.6-luna": (
                "/v1/responses",
                "openai_responses",
            ),
        }
        for model_id, (endpoint, protocol) in expected.items():
            with self.subTest(model_id=model_id):
                self.assertEqual(models[model_id]["api_endpoint"], endpoint)
                self.assertEqual(models[model_id]["api_protocol"], protocol)

    def test_v1_models_exposes_current_zen_free_models(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        models = {
            model["id"]: model for model in response.get_json()["data"]
        }
        chat_models = {
            "big-pickle",
            "deepseek-v4-flash-free",
            "hy3-free",
            "laguna-s-2.1-free",
            "ling-3.0-flash-fin-free",
            "mimo-v2.5-free",
            "nemotron-3-ultra-free",
            "nemotron-3.5-lightning-free",
        }
        for model_id in chat_models:
            with self.subTest(model_id=model_id):
                model = models[f"opencode:{model_id}"]
                self.assertEqual(model["api_endpoint"], "/v1/chat/completions")
                self.assertEqual(model["api_protocol"], "openai_chat_completions")

        muse = models["opencode:muse-spark-1.2-contributor-free"]
        self.assertEqual(muse["api_endpoint"], "/v1/responses")
        self.assertEqual(muse["api_protocol"], "openai_responses")

    def test_v1_chat_completions_routes_go_model(self):
        upstream_response = self._chat_response("hello")

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.6",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["choices"][0]["message"]["content"],
            "hello",
        )
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "opencode")
        self.assertEqual(
            request_kwargs["url"],
            "https://opencode.ai/zen/go/v1/chat/completions",
        )
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["model"], "kimi-k2.6")
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer opencode-provider-key",
        )

    def test_v1_chat_completions_routes_other_go_model(self):
        upstream_response = self._chat_response("hello")

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:mimo-v2-pro",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        upstream_payload = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream_payload["model"], "mimo-v2-pro")

    def test_v1_chat_completions_routes_free_model_to_zen(self):
        upstream_response = self._chat_response("free model selected")

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:big-pickle",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://opencode.ai/zen/v1/chat/completions",
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer opencode-provider-key",
        )
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["model"], "big-pickle")

    def test_live_free_model_gets_zen_metadata_and_route(self):
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("future-trial-free",),
        )

        models_response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )
        self.assertEqual(models_response.status_code, 200)
        models = {
            model["id"]: model for model in models_response.get_json()["data"]
        }
        discovered = models["opencode:future-trial-free"]
        self.assertEqual(discovered["api_endpoint"], "/v1/chat/completions")
        self.assertEqual(discovered["api_protocol"], "openai_chat_completions")

        upstream_response = self._chat_response("future free model selected")
        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:future-trial-free",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            make_request.call_args.kwargs["url"],
            "https://opencode.ai/zen/v1/chat/completions",
        )

    def test_go_responses_model_uses_native_endpoint(self):
        self._assert_native_responses_route(
            model="gpt-5.6-luna",
            expected_url="https://opencode.ai/zen/go/v1/responses",
        )

    def test_free_responses_model_uses_zen_native_endpoint(self):
        self._assert_native_responses_route(
            model="muse-spark-1.2-contributor-free",
            expected_url="https://opencode.ai/zen/v1/responses",
        )

    def _assert_native_responses_route(self, *, model: str, expected_url: str):
        native_body = (
            b'{"id":"resp_opencode","object":"response",'
            b'"status":"completed","output":[]}'
        )
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(native_body)
        upstream_response.headers["Content-Type"] = "application/json"

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": f"opencode:{model}",
                    "input": "Say hi",
                    "stream": False,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["url"], expected_url)
        self.assertEqual(
            json.loads(request_kwargs["data"]),
            {"model": model, "input": "Say hi", "stream": False},
        )
