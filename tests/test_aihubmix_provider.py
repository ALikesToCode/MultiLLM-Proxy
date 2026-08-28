import io
import json
import os
import unittest
from unittest.mock import patch

import requests

from config import Config
from providers.aihubmix import (
    AIHUBMIX_BUILTIN_MODEL_IDS,
    AIHUBMIX_IMAGE_MODEL_IDS,
    AIHUBMIX_PRIMARY_BASE_URL,
    AIHUBMIX_SECONDARY_BASE_URL,
    build_aihubmix_image_request,
    is_valid_aihubmix_request,
    normalize_aihubmix_image_response,
    request_with_aihubmix_origin_fallback,
    trusted_aihubmix_origin,
)
from providers.registry import get_adapter
from proxy import PROVIDER_DETAILS
from services.auth_service import AuthService
from services.model_catalog_service import build_model_catalog
from tests.unified_api_test_case import UnifiedApiTestCase


def _response(payload, status=200, *, raw=True):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    response.raw = io.BytesIO(response._content) if raw else None
    return response


class AIHubMixProviderRegistrationTest(unittest.TestCase):
    def test_provider_uses_trusted_primary_and_secondary_origins(self):
        self.assertEqual(Config.API_BASE_URLS["aihubmix"], AIHUBMIX_PRIMARY_BASE_URL)
        self.assertEqual(
            Config.AIHUBMIX_BACKUP_BASE_URL,
            AIHUBMIX_SECONDARY_BASE_URL,
        )
        self.assertEqual(Config.API_TIMEOUTS["aihubmix"], (5, 600))

    def test_base_origin_rejects_untrusted_or_structured_urls(self):
        for candidate in (
            "http://aihubmix.com",
            "https://attacker.example",
            "https://user:pass@aihubmix.com",
            "https://aihubmix.com/other/path",
            "https://aihubmix.com?redirect=https://attacker.example",
        ):
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    trusted_aihubmix_origin(candidate, AIHUBMIX_PRIMARY_BASE_URL),
                    AIHUBMIX_PRIMARY_BASE_URL,
                )

        self.assertEqual(
            trusted_aihubmix_origin(
                "https://api.inferera.com/v1/",
                AIHUBMIX_PRIMARY_BASE_URL,
            ),
            AIHUBMIX_SECONDARY_BASE_URL,
        )

    def test_adapter_exposes_openai_chat_and_image_capabilities(self):
        adapter = get_adapter("aihubmix", Config.API_BASE_URLS)

        self.assertIsNotNone(adapter)
        self.assertEqual(
            adapter.chat_completions_url(),
            "https://aihubmix.com/v1/chat/completions",
        )
        capabilities = adapter.capabilities()
        self.assertTrue(capabilities.supports_chat)
        self.assertTrue(capabilities.supports_streaming)
        self.assertTrue(capabilities.supports_images)

    def test_key_is_loaded_from_the_dedicated_environment_name(self):
        with patch.object(AuthService, "_api_keys", {}), patch.dict(
            os.environ,
            {"AIHUBMIX_API_KEY": "aihubmix-test-key"},
            clear=False,
        ):
            AuthService._load_provider_api_keys()

            self.assertEqual(
                AuthService.get_api_key("aihubmix"),
                "aihubmix-test-key",
            )
            self.assertEqual(
                AuthService.provider_credential_env_names("aihubmix"),
                ("AIHUBMIX_API_KEY",),
            )

    def test_current_free_catalog_and_requested_image_models_are_built_in(self):
        expected = {
            "coding-glm-5.3-free",
            "gemini-3.7-flash-free",
            "gpt-5.5-free",
            "gpt-image-2-free",
            "gemini-3.1-flash-image-preview-free",
            "doubao-seedream-4-0",
        }

        self.assertTrue(expected.issubset(AIHUBMIX_BUILTIN_MODEL_IDS))
        self.assertEqual(
            AIHUBMIX_IMAGE_MODEL_IDS,
            {
                "doubao-seedream-4-0",
                "gemini-3.1-flash-image-preview-free",
                "gpt-image-2-free",
            },
        )

    def test_model_catalog_marks_only_known_aihubmix_image_models_as_images(self):
        models = {
            model["id"]: model
            for model in build_model_catalog(Config.API_BASE_URLS)
        }

        for model_id in AIHUBMIX_IMAGE_MODEL_IDS:
            with self.subTest(model_id=model_id):
                self.assertTrue(
                    models[f"aihubmix:{model_id}"]["capabilities"][
                        "supports_images"
                    ]
                )
        self.assertFalse(
            models["aihubmix:coding-glm-5.3-free"]["capabilities"][
                "supports_images"
            ]
        )

    def test_dashboard_metadata_lists_native_image_contracts(self):
        details = PROVIDER_DETAILS["aihubmix"]
        endpoint_urls = {endpoint["url"] for endpoint in details["endpoints"]}

        self.assertEqual(
            endpoint_urls,
            {
                "/v1/models",
                "/v1/chat/completions",
                "/v1/images/generations",
                "/v1/images/edits",
                "/v1/models/doubao/doubao-seedream-4-0/predictions",
            },
        )
        self.assertTrue(details["supported_features"]["images"])
        self.assertTrue(details["supported_features"]["free_models"])
        doubao = next(
            endpoint
            for endpoint in details["endpoints"]
            if endpoint["url"].endswith("doubao-seedream-4-0/predictions")
        )
        self.assertIn('\\"model\\": \\"doubao-seedream-4-0\\"', doubao["curl"])


class AIHubMixContractTest(unittest.TestCase):
    def test_raw_route_allowlist_is_method_specific(self):
        accepted = (
            ("v1/models", "GET"),
            ("v1/chat/completions", "POST"),
            ("v1/images/generations", "POST"),
            ("v1/images/edits", "POST"),
            ("v1/models/doubao/doubao-seedream-4-0/predictions", "POST"),
        )
        for path, method in accepted:
            with self.subTest(path=path, method=method):
                self.assertTrue(is_valid_aihubmix_request(path, method))

        for path, method in (
            ("v1/images/generations", "GET"),
            ("v1/files", "POST"),
            ("v1/../models", "GET"),
            ("v1/models?key=secret", "GET"),
        ):
            with self.subTest(path=path, method=method):
                self.assertFalse(is_valid_aihubmix_request(path, method))

    def test_gpt_image_uses_the_openai_images_contract(self):
        request = build_aihubmix_image_request(
            "gpt-image-2-free",
            {
                "model": "aihubmix:gpt-image-2-free",
                "prompt": "A green triangle",
                "size": "1024x1024",
                "quality": "low",
                "output_format": "png",
                "n": 1,
            },
        )

        self.assertEqual(request.path, "v1/images/generations")
        self.assertEqual(request.response_kind, "openai")
        self.assertEqual(
            request.payload,
            {
                "model": "gpt-image-2-free",
                "prompt": "A green triangle",
                "size": "1024x1024",
                "quality": "low",
                "output_format": "png",
                "n": 1,
            },
        )

    def test_gemini_image_translates_to_multimodal_chat(self):
        request = build_aihubmix_image_request(
            "gemini-3.1-flash-image-preview-free",
            {
                "model": "aihubmix:gemini-3.1-flash-image-preview-free",
                "prompt": "A paper fox",
                "temperature": 0.4,
                "n": 1,
            },
        )

        self.assertEqual(request.path, "v1/chat/completions")
        self.assertEqual(request.response_kind, "gemini")
        self.assertEqual(
            request.payload,
            {
                "model": "gemini-3.1-flash-image-preview-free",
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": "A paper fox"}],
                    }
                ],
                "modalities": ["text", "image"],
                "temperature": 0.4,
            },
        )

    def test_doubao_image_translates_to_prediction_input(self):
        request = build_aihubmix_image_request(
            "doubao-seedream-4-0",
            {
                "model": "aihubmix:doubao-seedream-4-0",
                "prompt": "A glass observatory",
                "size": "2K",
                "watermark": False,
                "n": 1,
            },
        )

        self.assertEqual(
            request.path,
            "v1/models/doubao/doubao-seedream-4-0/predictions",
        )
        self.assertEqual(request.response_kind, "prediction")
        self.assertEqual(
            request.payload,
            {
                "input": {
                    "model": "doubao-seedream-4-0",
                    "prompt": "A glass observatory",
                    "size": "2K",
                    "sequential_image_generation": "disabled",
                    "stream": False,
                    "response_format": "url",
                    "watermark": False,
                }
            },
        )

    def test_non_single_image_requests_are_rejected_for_translated_models(self):
        for model in (
            "gemini-3.1-flash-image-preview-free",
            "doubao-seedream-4-0",
        ):
            with self.subTest(model=model):
                with self.assertRaisesRegex(ValueError, "exactly one image"):
                    build_aihubmix_image_request(
                        model,
                        {"model": f"aihubmix:{model}", "prompt": "test", "n": 2},
                    )

    def test_gemini_response_normalizes_inline_image_data(self):
        normalized = normalize_aihubmix_image_response(
            "gemini",
            {
                "created": 1787719630,
                "choices": [
                    {
                        "message": {
                            "multi_mod_content": [
                                {"text": "Generated image"},
                                {
                                    "inline_data": {
                                        "data": "aW1hZ2U=",
                                        "mime_type": "image/png",
                                    }
                                },
                            ]
                        }
                    }
                ],
                "usage": {"total_tokens": 12},
            },
        )

        self.assertEqual(normalized["created"], 1787719630)
        self.assertEqual(normalized["data"], [{"b64_json": "aW1hZ2U="}])
        self.assertEqual(normalized["output_format"], "png")
        self.assertEqual(normalized["usage"], {"total_tokens": 12})

    def test_doubao_response_normalizes_output_urls(self):
        normalized = normalize_aihubmix_image_response(
            "prediction",
            {
                "output": {
                    "created": 1787719630,
                    "images": [
                        "https://images.example/one.png",
                        {"url": "https://images.example/two.png"},
                    ],
                }
            },
        )

        self.assertEqual(normalized["created"], 1787719630)
        self.assertEqual(
            normalized["data"],
            [
                {"url": "https://images.example/one.png"},
                {"url": "https://images.example/two.png"},
            ],
        )

    def test_origin_fallback_replays_get_and_idempotent_post_only(self):
        transport_failure = _response(
            {
                "error": {
                    "type": "upstream_transport_error",
                    "message": "AIHubMix upstream transport request failed",
                }
            },
            status=502,
            raw=False,
        )
        success = _response({"data": []})

        for method, headers, expected_calls in (
            ("GET", {}, 2),
            ("POST", {"Idempotency-Key": "image-123"}, 2),
            ("POST", {}, 1),
        ):
            calls = []

            def send(origin):
                calls.append(origin)
                return transport_failure if len(calls) == 1 else success

            with self.subTest(method=method, headers=headers):
                response = request_with_aihubmix_origin_fallback(
                    send,
                    primary_origin=AIHUBMIX_PRIMARY_BASE_URL,
                    secondary_origin=AIHUBMIX_SECONDARY_BASE_URL,
                    method=method,
                    request_headers=headers,
                )

                self.assertEqual(len(calls), expected_calls)
                self.assertIs(response, success if expected_calls == 2 else transport_failure)

    def test_real_upstream_502_is_not_treated_as_transport_failure(self):
        upstream_502 = _response(
            {"error": {"type": "provider_error"}},
            status=502,
            raw=True,
        )
        calls = []

        response = request_with_aihubmix_origin_fallback(
            lambda origin: calls.append(origin) or upstream_502,
            primary_origin=AIHUBMIX_PRIMARY_BASE_URL,
            secondary_origin=AIHUBMIX_SECONDARY_BASE_URL,
            method="GET",
            request_headers={},
        )

        self.assertIs(response, upstream_502)
        self.assertEqual(calls, [AIHUBMIX_PRIMARY_BASE_URL])


class AIHubMixUnifiedRouteTest(UnifiedApiTestCase):
    def test_unified_catalog_advertises_every_aihubmix_image_model(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        models = {
            model["id"]: model
            for model in response.get_json()["data"]
        }
        for model_id in AIHUBMIX_IMAGE_MODEL_IDS:
            with self.subTest(model_id=model_id):
                model = models[f"aihubmix:{model_id}"]
                self.assertEqual(model["provider"], "aihubmix")
                self.assertTrue(model["capabilities"]["supports_images"])

        self.assertFalse(
            models["aihubmix:coding-glm-5.3-free"]["capabilities"][
                "supports_images"
            ]
        )

    def test_unified_chat_uses_backup_after_replayable_transport_failure(self):
        transport_failure = _response(
            {
                "error": {
                    "type": "upstream_transport_error",
                    "message": "AIHubMix upstream transport request failed",
                }
            },
            status=502,
            raw=False,
        )
        success = _response(
            {
                "id": "chatcmpl-aihubmix",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ready"},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

        with patch(
            "app.ProxyService.make_request",
            side_effect=[transport_failure, success],
        ) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Idempotency-Key": "chat-123",
                },
                json={
                    "model": "aihubmix:coding-glm-5.3-free",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "ready")
        self.assertEqual(
            [call.kwargs["url"] for call in make_request.call_args_list],
            [
                "https://aihubmix.com/v1/chat/completions",
                "https://api.inferera.com/v1/chat/completions",
            ],
        )

    def test_unified_gpt_image_preserves_openai_response_and_free_model_id(self):
        native_body = {
            "created": 1787719630,
            "data": [{"b64_json": "aW1hZ2U="}],
            "usage": {"total_tokens": 212},
        }
        upstream_response = _response(native_body, status=200)

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/images/generations",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Idempotency-Key": "image-123",
                },
                json={
                    "model": "aihubmix:gpt-image-2-free",
                    "prompt": "A green triangle",
                    "size": "1024x1024",
                    "quality": "low",
                    "output_format": "png",
                    "n": 1,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), native_body)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "aihubmix")
        self.assertEqual(
            request_kwargs["url"],
            "https://aihubmix.com/v1/images/generations",
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer aihubmix-provider-key",
        )
        self.assertEqual(
            request_kwargs["headers"]["Idempotency-Key"],
            "image-123",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "gpt-image-2-free",
        )

    def test_unified_gemini_image_normalizes_chat_response(self):
        upstream_response = _response(
            {
                "created": 1787719630,
                "choices": [
                    {
                        "message": {
                            "multi_mod_content": [
                                {
                                    "inlineData": {
                                        "data": "aW1hZ2U=",
                                        "mimeType": "png",
                                    }
                                }
                            ]
                        }
                    }
                ],
            }
        )

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/images/generations",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "aihubmix:gemini-3.1-flash-image-preview-free",
                    "prompt": "A paper fox",
                    "n": 1,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["data"],
            [{"b64_json": "aW1hZ2U="}],
        )
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://aihubmix.com/v1/chat/completions",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"])["modalities"],
            ["text", "image"],
        )

    def test_unified_doubao_image_normalizes_prediction_response(self):
        upstream_response = _response(
            {
                "output": {
                    "created": 1787719630,
                    "images": ["https://images.example/seedream.png"],
                }
            }
        )

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/images/generations",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "aihubmix:doubao-seedream-4-0",
                    "prompt": "A glass observatory",
                    "size": "2K",
                    "watermark": False,
                    "n": 1,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["data"],
            [{"url": "https://images.example/seedream.png"}],
        )
        self.assertEqual(
            make_request.call_args.kwargs["url"],
            "https://aihubmix.com/v1/models/doubao/"
            "doubao-seedream-4-0/predictions",
        )

    def test_unified_translated_image_rejects_invalid_success_payload(self):
        upstream_response = _response({"choices": []})

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ), patch.object(upstream_response, "close") as close_response:
            response = self.client.post(
                "/v1/images/generations",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "aihubmix:gemini-3.1-flash-image-preview-free",
                    "prompt": "A paper fox",
                    "n": 1,
                },
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.get_json()["message"],
            "An unexpected error occurred.",
        )
        close_response.assert_called_once_with()

    def test_raw_image_edit_preserves_multipart_bytes(self):
        boundary = "----aihubmix-test-boundary"
        native_request = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="model"\r\n\r\n'
            "gpt-image-2-free\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="image"; filename="input.png"\r\n'
            "Content-Type: image/png\r\n\r\n"
        ).encode("utf-8") + b"\x89PNG\r\n\x1a\n\x00\xff" + (
            f"\r\n--{boundary}--\r\n"
        ).encode("utf-8")
        native_response = _response({"data": [{"b64_json": "aW1hZ2U="}]})

        with patch(
            "app.ProxyService.make_request",
            return_value=native_response,
        ) as make_request:
            response = self.client.post(
                "/aihubmix/v1/images/edits",
                headers={"Authorization": "Bearer admin-test-key"},
                data=native_request,
                content_type=f"multipart/form-data; boundary={boundary}",
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["data"], native_request)
        self.assertIn(
            "multipart/form-data; boundary=",
            request_kwargs["headers"]["Content-Type"],
        )
        self.assertTrue(request_kwargs["force_raw_passthrough"])

    def test_raw_provider_rejects_undocumented_paths(self):
        with patch("app.ProxyService.make_request") as make_request:
            response = self.client.post(
                "/aihubmix/v1/files",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"purpose": "assistants"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid AIHubMix path", response.get_json()["message"])
        make_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
