import json
import os
import unittest
from unittest.mock import patch

from providers.nanogpt import (
    apply_nanogpt_speed_routing,
    apply_nanogpt_speed_suffix,
    nanogpt_model_has_speed_suffix,
    nanogpt_speed_routing,
    nanogpt_speed_routing_conflicts,
    nanogpt_subscription_only,
    nanogpt_text_base_url,
)

STANDARD_BASE_URL = "https://nano-gpt.com/api"
SUBSCRIPTION_BASE_URL = "https://nano-gpt.com/api/subscription"

from tests.unified_api_test_case import UnifiedApiTestCase


class NanoGPTSpeedRoutingTest(unittest.TestCase):
    def test_only_documented_suffixes_are_accepted(self):
        for suffix in ("fast", "throughput", "latency"):
            self.assertEqual(
                nanogpt_speed_routing({"NANOGPT_SPEED_ROUTING": suffix}),
                suffix,
            )
        self.assertEqual(nanogpt_speed_routing({}), "")
        self.assertEqual(
            nanogpt_speed_routing({"NANOGPT_SPEED_ROUTING": "turbo"}), ""
        )
        self.assertEqual(
            nanogpt_speed_routing({"NANOGPT_SPEED_ROUTING": " FAST "}), "fast"
        )

    def test_speed_routing_disables_subscription_only_guards(self):
        config = {
            "NANOGPT_BILLING_MODE": "subscription",
            "NANOGPT_SPEED_ROUTING": "fast",
        }
        self.assertFalse(nanogpt_subscription_only(config))
        self.assertTrue(
            nanogpt_subscription_only({"NANOGPT_BILLING_MODE": "subscription"})
        )

    def test_suffix_is_appended_once(self):
        self.assertEqual(
            apply_nanogpt_speed_suffix("moonshotai/kimi-k2.6", "fast"),
            "moonshotai/kimi-k2.6:fast",
        )
        self.assertEqual(
            apply_nanogpt_speed_suffix("moonshotai/kimi-k2.6:fast", "throughput"),
            "moonshotai/kimi-k2.6:fast",
        )
        self.assertEqual(
            apply_nanogpt_speed_suffix("zai-org/glm-5.2:thinking", "fast"),
            "zai-org/glm-5.2:thinking:fast",
        )
        self.assertEqual(apply_nanogpt_speed_suffix("", "fast"), "")
        self.assertEqual(
            apply_nanogpt_speed_suffix("moonshotai/kimi-k2.6", ""),
            "moonshotai/kimi-k2.6",
        )

    def test_existing_routing_suffix_is_detected(self):
        self.assertTrue(nanogpt_model_has_speed_suffix("kimi-k2.6:latency"))
        self.assertFalse(nanogpt_model_has_speed_suffix("kimi-k2.6:thinking"))
        self.assertFalse(nanogpt_model_has_speed_suffix("kimi-k2.6"))
        self.assertFalse(nanogpt_model_has_speed_suffix(None))

    def test_caller_provider_selection_wins(self):
        payload = {"model": "moonshotai/kimi-k2.6"}
        self.assertTrue(
            nanogpt_speed_routing_conflicts({**payload, "provider": "groq"})
        )
        self.assertTrue(
            nanogpt_speed_routing_conflicts(payload, {"X-Provider": "groq"})
        )
        self.assertTrue(
            nanogpt_speed_routing_conflicts(payload, {"x-use-byok": "true"})
        )
        self.assertFalse(
            nanogpt_speed_routing_conflicts(payload, {"Accept": "text/event-stream"})
        )
        self.assertFalse(nanogpt_speed_routing_conflicts(payload, {"X-Provider": " "}))

    def test_payload_routing_leaves_conflicting_requests_untouched(self):
        payload = {"model": "moonshotai/kimi-k2.6", "stream": True}

        routed = apply_nanogpt_speed_routing(payload, "fast", {})
        self.assertEqual(routed["model"], "moonshotai/kimi-k2.6:fast")
        self.assertTrue(routed["stream"])
        self.assertEqual(payload["model"], "moonshotai/kimi-k2.6")

        self.assertEqual(
            apply_nanogpt_speed_routing(payload, "", {})["model"],
            "moonshotai/kimi-k2.6",
        )
        self.assertEqual(
            apply_nanogpt_speed_routing(
                payload, "fast", {"X-Provider": "groq"}
            )["model"],
            "moonshotai/kimi-k2.6",
        )

    def test_speed_routing_forces_the_paygo_text_endpoint(self):
        self.assertEqual(
            nanogpt_text_base_url(
                STANDARD_BASE_URL, SUBSCRIPTION_BASE_URL, "subscription", ""
            ),
            SUBSCRIPTION_BASE_URL,
        )
        self.assertEqual(
            nanogpt_text_base_url(
                STANDARD_BASE_URL, SUBSCRIPTION_BASE_URL, "subscription", "fast"
            ),
            STANDARD_BASE_URL,
        )
        self.assertEqual(
            nanogpt_text_base_url(
                STANDARD_BASE_URL, SUBSCRIPTION_BASE_URL, "standard", ""
            ),
            STANDARD_BASE_URL,
        )


class NanoGPTSpeedRoutingRequestTest(UnifiedApiTestCase):
    """The configured suffix has to survive all the way onto the wire."""

    def _enable_speed_routing(self, suffix):
        self.app.config["NANOGPT_SPEED_ROUTING"] = suffix
        # API_BASE_URLS is a Config class attribute shared across app
        # instances, so replace the mapping rather than mutating it.
        self.app.config["API_BASE_URLS"] = {
            **self.app.config["API_BASE_URLS"],
            "nanogpt": nanogpt_text_base_url(
                self.app.config["NANOGPT_STANDARD_BASE_URL"],
                self.app.config["NANOGPT_SUBSCRIPTION_BASE_URL"],
                self.app.config["NANOGPT_BILLING_MODE"],
                suffix,
            ),
        }

    def _post_chat(self, headers=None, payload_extras=None):
        os.environ["NANOGPT_API_KEY"] = "nanogpt-provider-key"
        with patch(
            "app.ProxyService.make_request",
            return_value=self._chat_response("routed upstream"),
        ) as make_request, patch(
            "routes.unified.NanoGPTKeyPool.select_key",
            return_value="nanogpt-provider-key",
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    **(headers or {}),
                },
                json={
                    "model": "nanogpt:zai-org/glm-5.2:thinking",
                    "messages": [{"role": "user", "content": "Continue."}],
                    **(payload_extras or {}),
                },
            )
        self.assertEqual(response.status_code, 200)
        return make_request.call_args.kwargs

    def test_unified_chat_sends_the_suffixed_model_to_the_paygo_endpoint(self):
        self._enable_speed_routing("fast")

        request_kwargs = self._post_chat()

        self.assertEqual(
            request_kwargs["url"],
            "https://nano-gpt.com/api/v1/chat/completions",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "zai-org/glm-5.2:thinking:fast",
        )

    def test_unified_chat_keeps_the_plain_model_when_routing_is_off(self):
        request_kwargs = self._post_chat()

        self.assertEqual(
            request_kwargs["url"],
            "https://nano-gpt.com/api/subscription/v1/chat/completions",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "zai-org/glm-5.2:thinking",
        )

    def test_raw_nanogpt_chat_also_carries_the_suffix(self):
        self._enable_speed_routing("latency")
        os.environ["NANOGPT_API_KEY"] = "nanogpt-provider-key"

        with patch(
            "app.ProxyService.make_request",
            return_value=self._chat_response("routed upstream"),
        ) as make_request:
            response = self.client.post(
                "/nanogpt/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "moonshotai/kimi-k2.6",
                    "messages": [{"role": "user", "content": "Continue."}],
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "moonshotai/kimi-k2.6:latency",
        )

    def test_a_caller_pinned_provider_is_left_alone(self):
        self._enable_speed_routing("throughput")

        request_kwargs = self._post_chat(headers={"X-Provider": "paid-provider"})

        self.assertEqual(
            json.loads(request_kwargs["data"])["model"],
            "zai-org/glm-5.2:thinking",
        )


if __name__ == "__main__":
    unittest.main()
