import json
from unittest.mock import patch

import requests
from flask import Response

from services.free_quota_service import FreeQuotaService
from tests.unified_api_test_case import UnifiedApiTestCase


def catalog_row(
    provider, model, *, vision=None, pricing=None, outputs=None, status="available"
):
    metadata = {}
    if vision is not None:
        metadata["supports_vision"] = vision
    if pricing is not None:
        metadata["pricing"] = pricing
    if outputs is not None:
        metadata["output_modalities"] = outputs
    return {
        "id": f"{provider}:{model}",
        "provider": provider,
        "model": model,
        "status": status,
        "provider_metadata": metadata,
    }


class FreeRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            FREE_ROUTE_FREE_TIER_PROVIDERS="", FREE_ROUTE_PROVIDER_ORDER=""
        )
        self.rows = [
            catalog_row("opencode", "mimo-v2.5-free", vision=True),
            catalog_row("opencode", "hy3-free"),
            catalog_row("aihubmix", "gemma-4-31b-it-free", vision=True),
        ]
        self.catalog = patch(
            "services.free_model_policy.build_model_catalog",
            side_effect=lambda _: self.rows,
        )
        self.catalog.start()
        self.addCleanup(self.catalog.stop)
        self.keys = {
            "opencode": "test-opencode",
            "aihubmix": "test-aihubmix",
            "openrouter": "test-openrouter",
        }
        self.auth = patch.object(
            self.app_module.AuthService, "get_api_key", side_effect=self.keys.get
        )
        self.auth.start()
        self.addCleanup(self.auth.stop)
        self.headers = {
            "Authorization": "Bearer admin-test-key",
            "Origin": "https://example.test",
        }

    def post(self, payload=None, mode="text", **kwargs):
        return self.client.post(
            f"/v1/free/{mode}/chat/completions",
            headers=self.headers,
            json=payload or {"messages": [{"role": "user", "content": "Hello"}]},
            **kwargs,
        )

    def test_fixed_text_route_uses_free_zen_and_does_not_forward_client_overrides(self):
        self.headers.update({"X-Provider": "paid", "X-Billing-Mode": "standard"})
        with patch(
            "app.ProxyService.make_request",
            return_value=self._chat_response("free answer"),
        ) as send:
            response = self.post()
            self.assertEqual(
                response.get_json()["choices"][0]["message"]["content"], "free answer"
            )
        args = send.call_args.kwargs
        self.assertEqual(args["url"], "https://opencode.ai/zen/v1/chat/completions")
        self.assertTrue(json.loads(args["data"])["model"].endswith("-free"))
        self.assertEqual(json.loads(args["data"])["max_tokens"], 1024)
        self.assertTrue(args["force_raw_passthrough"])
        self.assertFalse(args["use_cache"])
        self.assertEqual(args["params"], {})
        self.assertNotIn("X-Provider", args["headers"])
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "free:text")
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "opencode")
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"], "https://example.test"
        )

    def test_429_cools_whole_provider_and_next_request_skips_it(self):
        limited = Response("quota", status=429, headers={"Retry-After": "120"})
        with patch(
            "app.ProxyService.make_request",
            side_effect=[limited, self._chat_response(), self._chat_response()],
        ) as send:
            first = self.post()
            second = self.post()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            [c.kwargs["api_provider"] for c in send.call_args_list],
            ["opencode", "aihubmix", "aihubmix"],
        )
        self.assertEqual(first.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertGreaterEqual(FreeQuotaService.remaining("provider:opencode"), 119)

    def test_success_at_zero_tokens_uses_reset_header_on_next_request(self):
        success = self._chat_response()
        success.headers.update(
            {"x-ratelimit-remaining-tokens": "0", "x-ratelimit-reset-tokens": "2m3.5s"}
        )
        with patch(
            "app.ProxyService.make_request",
            side_effect=[success, self._chat_response()],
        ) as send:
            self.post().get_data()
            response = self.post()
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "aihubmix")
        self.assertEqual(send.call_count, 2)
        self.assertGreater(FreeQuotaService.remaining("provider:opencode"), 120)

    def test_expired_provider_is_eligible_again(self):
        FreeQuotaService.block("provider:opencode", 5, now=1)
        with patch("app.ProxyService.make_request", return_value=self._chat_response()):
            response = self.post()
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "opencode")

    def test_exhaustion_returns_retry_after_without_paid_fallback(self):
        with patch(
            "app.ProxyService.make_request",
            side_effect=lambda **_: Response(status=429, headers={"Retry-After": "42"}),
        ) as send:
            response = self.post()
            again = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json()["error"]["code"], "free_pool_exhausted")
        self.assertGreaterEqual(int(response.headers["Retry-After"]), 40)
        self.assertEqual(send.call_count, 3)
        self.assertEqual(again.headers["X-MultiLLM-Auto-Attempts"], "0")

    def test_vision_preserves_image_payload_across_fallback(self):
        image = {
            "type": "image_url",
            "image_url": {"url": "data:image/png;base64,aGVsbG8=", "detail": "low"},
        }
        payload = {
            "model": "free:vision",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Read this screenshot"},
                        image,
                    ],
                }
            ],
        }
        with patch(
            "app.ProxyService.make_request",
            side_effect=[Response(status=429), self._chat_response()],
        ) as send:
            response = self.post(payload, mode="vision")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_count, 2)
        for call in send.call_args_list:
            self.assertEqual(
                json.loads(call.kwargs["data"])["messages"], payload["messages"]
            )

    def test_vision_unknown_is_excluded_and_openrouter_free_router_is_seeded(self):
        self.rows = [
            catalog_row("opencode", "hy3-free"),
            catalog_row("aihubmix", "unknown-free"),
            catalog_row("aihubmix", "image-free", vision=True, outputs=["image"]),
        ]
        with patch(
            "app.ProxyService.make_request", return_value=self._chat_response()
        ) as send:
            response = self.post(mode="vision")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"])["model"], "openrouter/free"
        )

    def test_paid_and_non_chat_candidates_are_excluded(self):
        self.rows = [
            catalog_row("aihubmix", "gpt-image-2-free"),
            catalog_row("opencode", "glm-5.3"),
            catalog_row("opencode", "muse-spark-1.2-contributor-free"),
            catalog_row("aihubmix", "was-free", pricing={"prompt": "0.001"}),
            catalog_row(
                "openrouter",
                "minimax/minimax-m3:free",
                pricing={"prompt": "0", "completion": "0"},
            ),
        ]
        with patch(
            "app.ProxyService.make_request", return_value=self._chat_response()
        ) as send:
            response = self.post()
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "openrouter")
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"])["model"], "openrouter/free"
        )

    def test_disabled_candidates_and_missing_credentials_are_skipped(self):
        self.rows = [catalog_row("opencode", "hy3-free", status="disabled")]
        self.keys.pop("openrouter")
        with patch("app.ProxyService.make_request") as send:
            self.assertEqual(self.post().status_code, 503)
        send.assert_not_called()

    def test_attempt_limit_bounds_missing_models(self):
        self.rows = [catalog_row("aihubmix", f"model-{i}-free") for i in range(12)]
        with patch(
            "app.ProxyService.make_request",
            side_effect=lambda **_: Response(status=404),
        ) as send:
            response = self.post()
        self.assertEqual(send.call_count, 8)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"]["code"], "free_attempt_limit")

    def test_free_path_has_one_local_rate_bucket_with_or_without_model(self):
        from route_helpers import provider_from_request_path

        for path in ("/v1/free/chat/completions", "/v1/free/text/chat/completions"):
            for payload in ({}, {"model": "free:text"}, {"model": "free:vision"}):
                self.assertEqual(provider_from_request_path(path, payload), "free")

    def test_groq_and_gemini_require_explicit_free_account_assertion(self):
        self.keys.update(groq="test-groq", gemini="test-gemini")
        self.rows = [catalog_row("groq", "qwen/qwen3.8-27b", vision=True)]
        with patch(
            "app.ProxyService.make_request", return_value=self._chat_response()
        ) as send:
            self.assertEqual(self.post().headers["X-MultiLLM-Provider"], "openrouter")
        self.app.config["FREE_ROUTE_FREE_TIER_PROVIDERS"] = "groq,gemini"
        with patch(
            "app.ProxyService.make_request",
            side_effect=[Response(status=429), self._chat_response()],
        ) as send:
            response = self.post(mode="vision")
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "gemini")
        self.assertEqual(
            [c.kwargs["url"] for c in send.call_args_list],
            [
                "https://api.groq.com/openai/v1/chat/completions",
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            ],
        )

    def test_invalid_input_never_dispatches(self):
        base = {"messages": [{"role": "user", "content": "Hello"}]}
        invalid = [
            {**base, key: value}
            for key, value in {
                "model": "openrouter:paid",
                "models": ["paid"],
                "provider": {"order": ["paid"]},
                "plugins": [{"id": "web"}],
                "extra_body": {"model": "paid"},
                "tools": [],
                "stream": "false",
                "max_tokens": 0,
            }.items()
        ]
        invalid += [
            {"messages": []},
            {"messages": [{"role": {}, "content": "Hello"}]},
            {"messages": [{"role": "user", "content": ""}]},
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {"url": "https://example.test/a.png"},
                            }
                        ],
                    }
                ]
            },
        ]
        with patch("app.ProxyService.make_request") as send:
            for payload in invalid:
                with self.subTest(payload=payload):
                    self.assertEqual(self.post(payload).status_code, 400)
            self.assertEqual(self.post(query_string={"model": "paid"}).status_code, 400)
        send.assert_not_called()

    def test_validation_errors_are_not_retried_but_transient_errors_are(self):
        for status in (400, 413, 422):
            with patch(
                "app.ProxyService.make_request", return_value=Response(status=status)
            ) as send:
                self.assertEqual(self.post().status_code, status)
                self.assertEqual(send.call_count, 1)
        with patch(
            "app.ProxyService.make_request",
            side_effect=[requests.ConnectionError("offline"), self._chat_response()],
        ) as send:
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual(send.call_count, 2)

    def test_invalid_200_response_does_not_count_as_completion(self):
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                Response("{}", content_type="application/json"),
                self._chat_response("real answer"),
            ],
        ) as send:
            response = self.post()
        self.assertEqual(
            response.get_json()["choices"][0]["message"]["content"], "real answer"
        )
        self.assertEqual(send.call_count, 2)

    def test_stream_failure_after_text_does_not_append_another_model(self):
        def chunks():
            yield 'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            raise requests.ConnectionError("private upstream detail")

        upstream = Response(chunks(), content_type="text/event-stream")
        with patch("app.ProxyService.make_request", return_value=upstream) as send:
            response = self.post(
                {"messages": [{"role": "user", "content": "Hello"}], "stream": True}
            )
            body = response.get_data(as_text=True)
        self.assertIn("partial", body)
        self.assertIn("free_stream_interrupted", body)
        self.assertNotIn("private upstream detail", body)
        self.assertNotIn("[DONE]", body)
        self.assertEqual(send.call_count, 1)

    def test_initial_stream_quota_error_falls_back_and_complete_stream_survives(self):
        failed = Response(
            'data: {"error":{"code":429}}\n\n', content_type="text/event-stream"
        )
        success_body = (
            'data: {"choices":[{"delta":{"content":"answer"}}]}\n\n'
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
            "data: [DONE]\n\n"
        )
        success = Response(success_body, content_type="text/event-stream")
        with patch(
            "app.ProxyService.make_request", side_effect=[failed, success]
        ) as send:
            response = self.post(
                {"messages": [{"role": "user", "content": "Hello"}], "stream": True}
            )
            body = response.get_data(as_text=True)
        self.assertEqual(body, success_body)
        self.assertEqual(send.call_count, 2)

    def test_models_auth_and_cors_and_no_configured_candidate(self):
        self.assertEqual(self.client.get("/v1/free/models").status_code, 401)
        preflight = self.client.options(
            "/v1/free/vision/chat/completions",
            headers={"Origin": "https://example.test"},
        )
        self.assertEqual(preflight.status_code, 204)
        models = self.client.get("/v1/free/models", headers=self.headers)
        self.assertEqual(
            {m["id"] for m in models.get_json()["data"]}, {"free:text", "free:vision"}
        )
        self.assertNotIn("test-opencode", models.get_data(as_text=True))
        self.keys.clear()
        with patch("app.ProxyService.make_request") as send:
            self.assertEqual(self.post().status_code, 503)
        send.assert_not_called()

    def test_universal_endpoint_uses_model_to_select_vision_pool(self):
        with patch(
            "app.ProxyService.make_request", return_value=self._chat_response()
        ) as send:
            response = self.client.post(
                "/v1/free/chat/completions",
                headers=self.headers,
                json={
                    "model": "free:vision",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"])["model"], "mimo-v2.5-free"
        )
