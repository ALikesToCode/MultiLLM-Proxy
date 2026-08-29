import json
import os
import unittest
from unittest.mock import patch

import requests

from config import Config
from providers.image_relays import (
    BUILTIN_IMAGE_RELAY_SPECS,
    clear_image_relay_caches,
    image_relay_api_key,
    image_relay_spec,
    image_relay_specs,
    is_valid_image_relay_request,
)
from proxy import PROVIDER_DETAILS
from services.auth_service import AuthService
from services.provider_catalog_service import PROVIDER_CATALOG_SPECS
from services.transport_policy import RAW_PASSTHROUGH_PROVIDERS
from tests.unified_api_test_case import UnifiedApiTestCase


class ImageRelayConfigurationTest(unittest.TestCase):
    def tearDown(self):
        clear_image_relay_caches()

    def test_built_in_relays_have_isolated_origins_models_and_credentials(self):
        expected = {
            "a6api": (
                "https://api.a6api.com",
                None,
                "gpt-image-2",
                "A6API_API_KEY",
                True,
            ),
            "aimlapi": (
                "https://api.aimlapi.com",
                None,
                "openai/gpt-image-2",
                "AIMLAPI_API_KEY",
                True,
            ),
            "ephone": (
                "https://api.ephone.ai",
                None,
                "gpt-image-2",
                "EPHONE_API_KEY",
                True,
            ),
            "gguu": (
                "https://gguuai.com",
                "https://api.aiaimax.com",
                "gpt-image-2",
                "GGUU_API_KEY",
                False,
            ),
            "latix": (
                "https://api.latix.ai",
                None,
                "gpt-image-2",
                "LATIX_API_KEY",
                True,
            ),
        }

        self.assertEqual(
            {spec.provider for spec in BUILTIN_IMAGE_RELAY_SPECS},
            set(expected),
        )
        for provider, (
            base_url,
            backup_base_url,
            model,
            credential_env,
            supports_chat,
        ) in expected.items():
            with self.subTest(provider=provider):
                spec = image_relay_spec(provider)
                self.assertIsNotNone(spec)
                self.assertEqual(spec.base_url, base_url)
                self.assertEqual(spec.backup_base_url, backup_base_url)
                self.assertIn(model, spec.models)
                self.assertEqual(spec.credential_env, credential_env)
                self.assertEqual(spec.supports_chat, supports_chat)
                self.assertEqual(Config.API_BASE_URLS[provider], base_url)
                self.assertIn(provider, RAW_PASSTHROUGH_PROVIDERS)
                self.assertIn(provider, PROVIDER_CATALOG_SPECS)
                self.assertIn(provider, PROVIDER_DETAILS)

    def test_custom_relay_accepts_only_public_https_origins_and_typed_flags(self):
        valid = json.dumps(
            {
                "myrelay": {
                    "display_name": "My Relay",
                    "base_url": "https://images.example.com",
                    "backup_base_url": "https://images-backup.example.com",
                    "credential_env": "MYRELAY_API_KEY",
                    "models": ["gpt-image-2", "gpt-image-2"],
                    "supports_chat": False,
                    "supports_edits": True,
                }
            }
        )
        with patch.dict(os.environ, {"IMAGE_RELAY_PROVIDERS_JSON": valid}):
            clear_image_relay_caches()
            spec = image_relay_spec("myrelay")
            self.assertEqual(spec.base_url, "https://images.example.com")
            self.assertEqual(
                spec.backup_base_url,
                "https://images-backup.example.com",
            )
            self.assertEqual(spec.models, ("gpt-image-2",))
            self.assertFalse(spec.supports_chat)

        invalid_origins = (
            "http://images.example.com",
            "https://user:pass@images.example.com",
            "https://images.example.com/v1",
            "https://127.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://images.example.com:invalid",
        )
        for origin in invalid_origins:
            with self.subTest(origin=origin), patch.dict(
                os.environ,
                {
                    "IMAGE_RELAY_PROVIDERS_JSON": json.dumps(
                        {
                            "myrelay": {
                                "base_url": origin,
                                "models": ["gpt-image-2"],
                            }
                        }
                    )
                },
            ):
                clear_image_relay_caches()
                with self.assertRaises(ValueError):
                    image_relay_specs()

        invalid_bool = json.dumps(
            {
                "myrelay": {
                    "base_url": "https://images.example.com",
                    "models": ["gpt-image-2"],
                    "supports_chat": "false",
                }
            }
        )
        with patch.dict(
            os.environ,
            {"IMAGE_RELAY_PROVIDERS_JSON": invalid_bool},
        ):
            clear_image_relay_caches()
            with self.assertRaisesRegex(ValueError, "must be a boolean"):
                image_relay_specs()

        invalid_backup = json.dumps(
            {
                "myrelay": {
                    "base_url": "https://images.example.com",
                    "backup_base_url": "http://images-backup.example.com",
                    "models": ["gpt-image-2"],
                }
            }
        )
        with patch.dict(
            os.environ,
            {"IMAGE_RELAY_PROVIDERS_JSON": invalid_backup},
        ):
            clear_image_relay_caches()
            with self.assertRaisesRegex(ValueError, "credential-free HTTPS origins"):
                image_relay_specs()

    def test_custom_relay_cannot_replace_existing_provider(self):
        serialized = json.dumps(
            {
                "openai": {
                    "base_url": "https://images.example.com",
                    "models": ["gpt-image-2"],
                }
            }
        )
        with patch.dict(
            os.environ,
            {"IMAGE_RELAY_PROVIDERS_JSON": serialized},
        ):
            clear_image_relay_caches()
            with self.assertRaisesRegex(ValueError, "cannot be overridden"):
                image_relay_specs()

    def test_secret_map_accepts_known_relays_only(self):
        with patch.dict(
            os.environ,
            {"IMAGE_RELAY_API_KEYS_JSON": '{"latix":"relay-secret"}'},
        ):
            clear_image_relay_caches()
            self.assertEqual(image_relay_api_key("latix"), "relay-secret")
            self.assertEqual(AuthService.get_api_key("latix"), "relay-secret")

        with patch.dict(
            os.environ,
            {"IMAGE_RELAY_API_KEYS_JSON": '{"unknown":"secret"}'},
        ):
            clear_image_relay_caches()
            with self.assertRaisesRegex(ValueError, "Unknown provider"):
                image_relay_api_key("unknown")

    def test_native_path_allowlist_is_method_specific(self):
        for path, method in (
            ("v1/models", "GET"),
            ("v1/images/generations", "POST"),
            ("v1/images/edits", "POST"),
            ("v1/chat/completions", "POST"),
            ("v1/responses", "POST"),
            ("v1/images/generations", "OPTIONS"),
        ):
            with self.subTest(path=path, method=method):
                self.assertTrue(is_valid_image_relay_request("latix", path, method))

        for path, method in (
            ("v1/images/generations", "GET"),
            ("v1/files", "POST"),
            ("v1/billing", "GET"),
            ("v1/models?key=secret", "GET"),
            ("v1/../models", "GET"),
        ):
            with self.subTest(path=path, method=method):
                self.assertFalse(is_valid_image_relay_request("latix", path, method))

        self.assertTrue(
            is_valid_image_relay_request("gguu", "v1/images/edits", "POST")
        )
        self.assertFalse(
            is_valid_image_relay_request("gguu", "v1/chat/completions", "POST")
        )


class ImageRelayRouteTest(UnifiedApiTestCase):
    @staticmethod
    def _image_response():
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"created":1,"data":[{"b64_json":"aW1hZ2U="}]}'
        response.headers["Content-Type"] = "application/json"
        return response

    @staticmethod
    def _models_response():
        response = requests.Response()
        response.status_code = 200
        response._content = (
            b'{"object":"list","data":[{"id":"gpt-image-2","object":"model"}]}'
        )
        response.headers["Content-Type"] = "application/json"
        return response

    @staticmethod
    def _transport_failure_response():
        response = requests.Response()
        response.status_code = 502
        response._content = json.dumps(
            {
                "error": {
                    "message": "Provider upstream transport request failed",
                    "type": "upstream_transport_error",
                    "code": 502,
                }
            }
        ).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
        return response

    def test_catalog_marks_only_declared_image_models(self):
        from services.model_catalog_service import build_model_catalog

        models = {
            model["id"]: model
            for model in build_model_catalog(self.app.config["API_BASE_URLS"])
        }

        for spec in BUILTIN_IMAGE_RELAY_SPECS:
            for provider_model in spec.models:
                with self.subTest(provider=spec.provider, model=provider_model):
                    self.assertTrue(
                        models[f"{spec.provider}:{provider_model}"]["capabilities"][
                            "supports_images"
                        ]
                    )
        self.assertTrue(
            models["together:openai/gpt-image-2"]["capabilities"][
                "supports_images"
            ]
        )
        self.assertFalse(
            models["openai:gpt-4.1"]["capabilities"]["supports_images"]
        )

    def test_unified_generation_accepts_every_builtin_relay(self):
        cases = (
            (
                "a6api",
                "gpt-image-2",
                "https://api.a6api.com/v1/images/generations",
                "a6api-provider-key",
            ),
            (
                "aimlapi",
                "openai/gpt-image-2",
                "https://api.aimlapi.com/v1/images/generations",
                "aimlapi-provider-key",
            ),
            (
                "ephone",
                "gpt-image-2",
                "https://api.ephone.ai/v1/images/generations",
                "ephone-provider-key",
            ),
            (
                "gguu",
                "gpt-image-2",
                "https://gguuai.com/v1/images/generations",
                "gguu-provider-key",
            ),
            (
                "latix",
                "gpt-image-2",
                "https://api.latix.ai/v1/images/generations",
                "latix-provider-key",
            ),
        )
        configured_keys = {
            image_relay_spec(provider).credential_env: key
            for provider, _model, _url, key in cases
        }

        with patch.dict(os.environ, configured_keys):
            for provider, provider_model, url, key in cases:
                with self.subTest(provider=provider), patch(
                    "app.ProxyService.make_request",
                    return_value=self._image_response(),
                ) as make_request:
                    response = self.client.post(
                        "/v1/images/generations",
                        headers={
                            "Authorization": "Bearer admin-test-key",
                            "Idempotency-Key": "image-idempotency-key",
                        },
                        json={
                            "model": f"{provider}:{provider_model}",
                            "prompt": "A lighthouse at dusk",
                            "size": "1024x1024",
                        },
                    )

                self.assertEqual(response.status_code, 200)
                request_kwargs = make_request.call_args.kwargs
                self.assertEqual(request_kwargs["api_provider"], provider)
                self.assertEqual(request_kwargs["url"], url)
                self.assertTrue(request_kwargs["force_raw_passthrough"])
                self.assertEqual(
                    request_kwargs["headers"]["Authorization"],
                    f"Bearer {key}",
                )
                self.assertEqual(
                    request_kwargs["headers"]["Idempotency-Key"],
                    "image-idempotency-key",
                )
                self.assertEqual(
                    json.loads(request_kwargs["data"])["model"],
                    provider_model,
                )

    def test_gguu_unified_generation_fails_over_only_when_replay_safe(self):
        headers = {"Authorization": "Bearer admin-test-key"}
        payload = {
            "model": "gguu:gpt-image-2",
            "prompt": "A glass observatory at sunrise",
            "quality": "high",
            "size": "3840x2160",
        }
        with patch.dict(os.environ, {"GGUU_API_KEY": "gguu-provider-key"}), patch(
            "app.ProxyService.make_request",
            side_effect=[self._transport_failure_response(), self._image_response()],
        ) as make_request:
            unsafe_response = self.client.post(
                "/v1/images/generations",
                headers=headers,
                json=payload,
            )

        self.assertEqual(unsafe_response.status_code, 502)
        self.assertEqual(make_request.call_count, 1)
        self.assertEqual(
            make_request.call_args.kwargs["url"],
            "https://gguuai.com/v1/images/generations",
        )

        with patch.dict(os.environ, {"GGUU_API_KEY": "gguu-provider-key"}), patch(
            "app.ProxyService.make_request",
            side_effect=[self._transport_failure_response(), self._image_response()],
        ) as make_request:
            safe_response = self.client.post(
                "/v1/images/generations",
                headers={**headers, "Idempotency-Key": "gguu-image-123"},
                json=payload,
            )

        self.assertEqual(safe_response.status_code, 200)
        self.assertEqual(
            [call.kwargs["url"] for call in make_request.call_args_list],
            [
                "https://gguuai.com/v1/images/generations",
                "https://api.aiaimax.com/v1/images/generations",
            ],
        )

    def test_gguu_native_edit_preserves_multipart_body_and_boundary(self):
        boundary = "----multillm-gguu-boundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="model"\r\n\r\n'
            "gpt-image-2\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        content_type = f"multipart/form-data; boundary={boundary}"

        with patch.dict(os.environ, {"GGUU_API_KEY": "gguu-provider-key"}), patch(
            "app.ProxyService.make_request",
            return_value=self._image_response(),
        ) as make_request:
            response = self.client.post(
                "/gguu/v1/images/edits",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Content-Type": content_type,
                },
                data=body,
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://gguuai.com/v1/images/edits",
        )
        self.assertEqual(request_kwargs["data"], body)
        self.assertEqual(request_kwargs["headers"]["Content-Type"], content_type)
        self.assertTrue(request_kwargs["force_raw_passthrough"])

    def test_gguu_native_model_catalog_uses_backup_after_transport_failure(self):
        with patch.dict(os.environ, {"GGUU_API_KEY": "gguu-provider-key"}), patch(
            "app.ProxyService.make_request",
            side_effect=[self._transport_failure_response(), self._models_response()],
        ) as make_request:
            response = self.client.get(
                "/gguu/v1/models",
                headers={"Authorization": "Bearer admin-test-key"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [call.kwargs["url"] for call in make_request.call_args_list],
            [
                "https://gguuai.com/v1/models",
                "https://api.aiaimax.com/v1/models",
            ],
        )
        self.assertEqual(response.json["data"][0]["id"], "gpt-image-2")

    def test_native_route_forwards_images_and_rejects_account_paths(self):
        with patch.dict(os.environ, {"AIMLAPI_API_KEY": "aimlapi-provider-key"}), patch(
            "app.ProxyService.make_request",
            return_value=self._image_response(),
        ) as make_request:
            response = self.client.post(
                "/aimlapi/v1/images/generations",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "openai/gpt-image-2",
                    "prompt": "A green triangle",
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "aimlapi")
        self.assertEqual(
            request_kwargs["url"],
            "https://api.aimlapi.com/v1/images/generations",
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer aimlapi-provider-key",
        )

        with patch("app.ProxyService.make_request") as blocked_request:
            blocked = self.client.get(
                "/aimlapi/v1/billing",
                headers={"Authorization": "Bearer admin-test-key"},
            )

        self.assertEqual(blocked.status_code, 400)
        blocked_request.assert_not_called()

    def test_together_gpt_image_uses_raw_unified_transport(self):
        with patch.dict(os.environ, {"TOGETHER_API_KEY": "together-provider-key"}), patch(
            "app.ProxyService.make_request",
            return_value=self._image_response(),
        ) as make_request:
            response = self.client.post(
                "/v1/images/generations",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "together:openai/gpt-image-2",
                    "prompt": "A paper fox",
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "together")
        self.assertEqual(
            request_kwargs["url"],
            "https://api.together.xyz/v1/images/generations",
        )
        self.assertTrue(request_kwargs["force_raw_passthrough"])
        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "openai/gpt-image-2",
        )


if __name__ == "__main__":
    unittest.main()
