import json
from unittest.mock import patch

from flask import Response

from tests.test_free_routes import catalog_row
from tests.unified_api_test_case import UnifiedApiTestCase


class FreeAliasTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            FREE_ROUTE_FREE_TIER_PROVIDERS="",
            FREE_ROUTE_EXTRA_PROVIDERS="",
            FREE_ROUTE_PROVIDER_ORDER="opencode,openrouter",
        )
        catalog = patch(
            "services.free_model_policy.build_model_catalog",
            return_value=[catalog_row("opencode", "mimo-v2.5-free", vision=True)],
        )
        catalog.start()
        self.addCleanup(catalog.stop)
        auth = patch.object(
            self.app_module.AuthService,
            "get_api_key",
            side_effect={"opencode": "test-zen", "openrouter": "test-router"}.get,
        )
        auth.start()
        self.addCleanup(auth.stop)
        self.headers = {"Authorization": "Bearer admin-test-key"}

    def payload(self, model="free:text"):
        return {"model": model, "messages": [{"role": "user", "content": "Hello"}]}

    def post(self, payload):
        return self.client.post(
            "/v1/chat/completions", headers=self.headers, json=payload
        )

    def test_standard_models_advertise_both_aliases_with_vision_metadata(self):
        response = self.client.get("/v1/models", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        aliases = [m for m in response.json["data"] if m["id"].startswith("free:")]
        self.assertEqual(len(aliases), 2)
        self.assertEqual(
            {m["id"]: m["supports_vision"] for m in aliases},
            {"free:text": False, "free:vision": True},
        )
        detailed = self.client.get("/v1/free/models", headers=self.headers).json
        for alias, full in zip(aliases, detailed["data"]):
            self.assertEqual(alias, {k: full[k] for k in alias})

    def test_standard_text_alias_uses_free_router_and_quota_failover(self):
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                Response(status=429, headers={"Retry-After": "60"}),
                self._chat_response("free answer"),
            ],
        ) as send:
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["choices"][0]["message"]["content"], "free answer"
        )
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "free:text")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(
            [c.kwargs["api_provider"] for c in send.call_args_list],
            ["opencode", "openrouter"],
        )
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"])["model"], "openrouter/free"
        )

    def test_standard_vision_preserves_images_and_json_schema(self):
        payload = self.payload("free:vision")
        payload["messages"][0]["content"] = [
            {"type": "text", "text": "Read the color"},
            {
                "type": "image_url",
                "image_url": {"url": "data:image/png;base64,aGVsbG8="},
            },
        ]
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "color",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {"color": {"type": "string"}},
                    "required": ["color"],
                    "additionalProperties": False,
                },
            },
        }
        with patch(
            "app.ProxyService.make_request",
            return_value=self._chat_response('{"color":"red"}'),
        ) as send:
            response = self.post(payload)
        self.assertEqual(response.status_code, 200)
        upstream = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(upstream["messages"], payload["messages"])
        self.assertEqual(upstream["response_format"], payload["response_format"])
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "free:vision")

    def test_standard_alias_preserves_stream_completion(self):
        payload = {**self.payload(), "stream": True}
        data = (
            'data: {"choices":[{"delta":{"content":"hello"},"finish_reason":null}]}\n\n'
        )
        data += 'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        with patch(
            "app.ProxyService.make_request",
            return_value=Response(data, content_type="text/event-stream"),
        ):
            response = self.post(payload)
            body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('"hello"', body)
        self.assertIn("data: [DONE]", body)

    def test_standard_alias_rejects_paid_overrides_and_unknown_free_models(self):
        for payload in (
            {**self.payload(), "provider": {"order": ["paid"]}},
            self.payload("free:unknown"),
        ):
            with (
                self.subTest(payload=payload),
                patch("app.ProxyService.make_request") as send,
            ):
                self.assertEqual(self.post(payload).status_code, 400)
                send.assert_not_called()

    def test_standard_alias_rejects_query_parameters(self):
        with patch("app.ProxyService.make_request") as send:
            response = self.client.post(
                "/v1/chat/completions?provider=paid",
                headers=self.headers,
                json=self.payload(),
            )
        self.assertEqual(response.status_code, 400)
        send.assert_not_called()

    def test_standard_routes_still_require_authentication(self):
        with patch("app.ProxyService.make_request") as send:
            self.assertEqual(
                self.client.post(
                    "/v1/chat/completions", json=self.payload()
                ).status_code,
                401,
            )
            self.assertEqual(self.client.get("/v1/models").status_code, 401)
            send.assert_not_called()
