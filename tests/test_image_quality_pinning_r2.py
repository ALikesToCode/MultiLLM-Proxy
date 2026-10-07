"""Retries stay on the provider that actually generated the first image."""
import json
from unittest.mock import patch

from services.auto_route_service import AutoRouteService
from tests import test_image_quality as qa_tests
from tests.unified_api_test_case import UnifiedApiTestCase


class PinningRoundTwoTest(UnifiedApiTestCase):
    def test_retry_pins_second_provider_and_never_fails_over(self):
        keys = {name: "synthetic-provider" for name in ("gguu", "openai", "gguu-grok", "opencode")}
        AutoRouteService.save_route("auto:qa-pin", [qa_tests.MODEL, "openai:gpt-image-2", "gguu-grok:grok-imagine-image-2.0"], self.app.config["API_BASE_URLS"])
        for retry_status in (200, 503):
            calls = []
            def transport(**kwargs):
                payload = json.loads(kwargs["data"])
                provider = kwargs["api_provider"]
                calls.append((provider, payload))
                if provider == "opencode":
                    return qa_tests.upstream(qa_tests.completion(qa_tests.grade(3)))
                if provider == "gguu":
                    return qa_tests.upstream({"error": "synthetic pre-generation refusal"}, 400)
                assert provider == "openai"
                if "Avoid:" in payload["prompt"]:
                    return qa_tests.upstream({"data": [qa_tests.image(2)]}, retry_status)
                return qa_tests.upstream({"data": [qa_tests.image()]})
            with patch.object(self.app_module.AuthService, "get_api_key", side_effect=keys.get), \
                 patch.object(self.app_module.AuthService, "get_api_keys", side_effect=lambda provider: [keys[provider]] if provider in keys else []), \
                 patch.object(self.app_module.ProxyService, "make_request", side_effect=transport):
                result = self.client.post("/v1/images/generations", headers=qa_tests.ADMIN,
                    json={"model": "auto:qa-pin", "prompt": "square", "quality_check": {"judge_model": qa_tests.JUDGE}})
            assert result.status_code == 200
            generations = [(provider, body) for provider, body in calls if provider != "opencode"]
            assert [(provider, body["model"]) for provider, body in generations] == [
                ("gguu", "gpt-image-2.5-sunburst"), ("openai", "gpt-image-2"), ("openai", "gpt-image-2")]
            assert generations[-1][1]["prompt"] == "square\n\nAvoid: Correct the lettering"
            quality = result.get_json()["data"][0]["quality"]
            assert quality["attempts"] == 2
            if retry_status == 503:
                assert quality["stopped_reason"] == "generation_refused"
                assert "judge_error" not in quality
