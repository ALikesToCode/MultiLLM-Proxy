import json
from unittest.mock import patch

import requests

from services.auto_route_service import AutoRouteService
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"gguu": "gguu-test-key", "latix": "latix-test-key", "opencode": "opencode-test-key"}


def upstream(status, body):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    return response


IMAGE = {"created": 1, "data": [{"b64_json": "aW1hZ2U="}]}


class AutoImageRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def generate(self, model, transport, **extra):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport) as make_request:
            response = self.client.post(
                "/v1/images/generations",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": model, "prompt": "A blue square", "size": "1024x1024", **extra},
            )
        return response, make_request

    def save(self, route_id, candidates):
        AutoRouteService.save_route(route_id, candidates, self.app.config["API_BASE_URLS"])

    def test_seeded_gpt_image_2_5_route_generates_through_gguu(self):
        response, make_request = self.generate("auto:gpt-image-2.5", [upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), IMAGE)
        forwarded = make_request.call_args.kwargs
        self.assertEqual(forwarded["url"], "https://gguuai.com/v1/images/generations")
        self.assertEqual(json.loads(forwarded["data"])["model"], "gpt-image-2.5")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "auto:gpt-image-2.5")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "gguu:gpt-image-2.5")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "1")

    def test_image_route_skips_unconfigured_and_chat_only_candidates_then_fails_over_after_refusal(self):
        self.save("auto:image-test", ["a6api:gpt-image-2", "opencode:glm-5.2", "gguu:gpt-image-2.5", "latix:gpt-image-2"])
        response, make_request = self.generate(
            "auto:image-test",
            [upstream(429, {"error": {"message": "rate limited"}}), upstream(200, IMAGE)],
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [call.kwargs["url"] for call in make_request.call_args_list],
            ["https://gguuai.com/v1/images/generations", "https://api.latix.ai/v1/images/generations"],
        )
        self.assertEqual(json.loads(make_request.call_args_list[1].kwargs["data"])["model"], "gpt-image-2")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "latix:gpt-image-2")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Priority"], "4")

    def test_image_route_never_repeats_a_paid_request_after_an_ambiguous_failure(self):
        self.save("auto:image-test", ["gguu:gpt-image-2.5", "latix:gpt-image-2"])
        response, make_request = self.generate(
            "auto:image-test", [upstream(500, {"error": {"message": "upstream failed"}})],
        )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(make_request.call_count, 1)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "1")

    def test_missing_or_unavailable_image_routes_are_reported(self):
        response, make_request = self.generate("auto:not-configured", [])
        self.assertEqual(response.status_code, 404)
        self.save("auto:chat-only", ["opencode:glm-5.2"])
        response, _ = self.generate("auto:chat-only", [])
        self.assertEqual(response.status_code, 503)
        self.assertEqual(make_request.call_count, 0)

    def test_models_list_advertises_route_capabilities(self):
        self.save("auto:image-test", ["gguu:gpt-image-2.5"])
        response = self.client.get("/v1/models", headers={"Authorization": "Bearer admin-test-key"})
        routes = {model["id"]: model for model in response.get_json()["data"] if model.get("owned_by") == "multillm-auto"}
        self.assertTrue(routes["auto:gpt-image-2.5"]["capabilities"]["supports_images"])
        self.assertFalse(routes["auto:gpt-image-2.5"]["capabilities"]["supports_chat"])
        self.assertTrue(routes["auto:glm-5.2"]["capabilities"]["supports_chat"])
        self.assertFalse(routes["auto:glm-5.2"]["capabilities"]["supports_images"])

    def test_responses_api_still_rejects_auto_routes_with_supported_endpoints(self):
        response = self.client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer admin-test-key"},
            json={"model": "auto:gpt-image-2.5", "input": "hi"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("/v1/images/generations", response.get_json()["message"])
