import json
import os
import unittest
from itertools import product
from unittest.mock import patch

import requests

from providers.nanogpt import apply_nanogpt_speed_routing
from services.nanogpt_speed_breaker import NanoGPTSpeedBreaker
from services.provider_prompt_cache import apply_prompt_cache_policy
from tests.unified_api_test_case import UnifiedApiTestCase


MODEL = "zai-org/glm-5.2:thinking"
SUFFIXES = ("fast", "throughput", "latency")


class NanoGPTSpeedCachePolicyTest(unittest.TestCase):
    def test_speed_routing_removes_cache_selection_and_preserves_thinking(self):
        for suffix in SUFFIXES:
            for configured in (True, False):
                with self.subTest(suffix=suffix, configured=configured):
                    payload = {
                        "model": MODEL if configured else f"{MODEL}:{suffix}",
                        "caching": True,
                        "thinking": {"type": "enabled"},
                        "reasoning_effort": "max",
                        "stream": True,
                    }
                    routed = apply_nanogpt_speed_routing(
                        payload, suffix if configured else ""
                    )
                    self.assertEqual(routed["model"], f"{MODEL}:{suffix}")
                    self.assertNotIn("caching", routed)
                    self.assertEqual(routed["thinking"], payload["thinking"])
                    self.assertEqual(routed["reasoning_effort"], "max")
                    self.assertTrue(routed["stream"])
                    self.assertTrue(payload["caching"])

    def test_unrouted_requests_retain_cache_selection(self):
        payload = {"model": MODEL, "caching": True}
        for suffix, headers in (("", {}), ("fast", {"X-Provider": "example"})):
            with self.subTest(suffix=suffix, headers=headers):
                self.assertEqual(
                    apply_nanogpt_speed_routing(payload, suffix, headers), payload
                )

    def test_speed_routing_preserves_cache_opt_out_and_explicit_annotations(self):
        payload = {
            "model": MODEL,
            "caching": False,
            "prompt_caching": {"enabled": True},
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Continue.",
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                }
            ],
        }
        self.assertEqual(
            apply_nanogpt_speed_routing(payload, "fast"),
            {**payload, "model": f"{MODEL}:fast"},
        )

    def test_cache_policy_never_adds_or_keeps_conflicting_cache_selection(self):
        cases = product(
            SUFFIXES,
            ({}, {"caching": True}, {"caching": False}),
            ((True, 1), (False, 1), (True, 1024)),
        )
        for suffix, cache_fields, (enabled, minimum_tokens) in cases:
            with self.subTest(
                suffix=suffix,
                cache=cache_fields,
                enabled=enabled,
                minimum=minimum_tokens,
            ):
                payload = {
                    "model": f"{MODEL}:{suffix}",
                    "messages": [{"role": "user", "content": "Continue."}],
                    "thinking": {"type": "enabled"},
                    "reasoning_effort": "max",
                    **cache_fields,
                }
                decision = apply_prompt_cache_policy(
                    payload,
                    provider="nanogpt",
                    model=MODEL,
                    enabled=enabled,
                    minimum_tokens=minimum_tokens,
                )
                expected = {**payload}
                if expected.get("caching") is True:
                    expected.pop("caching")
                self.assertEqual(decision.payload, expected)
                self.assertEqual(decision.status, "skipped")
                self.assertEqual(decision.mode, "nanogpt-speed-routing")
                self.assertEqual(decision.request_headers, {})


class NanoGPTSpeedCacheRequestTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        NanoGPTSpeedBreaker.reset()
        self.addCleanup(NanoGPTSpeedBreaker.reset)
        os.environ["NANOGPT_API_KEY"] = "nanogpt-provider-key"
        self.app.config.update(
            NANOGPT_SPEED_ROUTING="fast",
            NANOGPT_BILLING_MODE="standard",
            PROMPT_CACHE_ENABLED=True,
            PROMPT_CACHE_MIN_TOKENS=1,
            GLM_AUTO_OPTIMIZE=False,
        )
        self.app.config["API_BASE_URLS"] = {
            **self.app.config["API_BASE_URLS"],
            "nanogpt": "https://nano-gpt.com/api",
        }

    def _send(self, path, *, suffix="fast", explicit_suffix=False, **extras):
        self.app.config["NANOGPT_SPEED_ROUTING"] = "" if explicit_suffix else suffix
        model = f"{MODEL}:{suffix}" if explicit_suffix else MODEL
        if not path.startswith("/nanogpt/"):
            model = f"nanogpt:{model}"
        input_fields = (
            {"input": "Continue the scene."}
            if path.endswith("/responses")
            else {"messages": [{"role": "user", "content": "Continue the scene."}]}
        )

        def reply(**kwargs):
            payload = json.loads(kwargs["data"])
            if payload.get("caching") is True:
                response = requests.Response()
                response.status_code = 400
                response._content = json.dumps(
                    {
                        "error": {
                            "message": "Invalid provider selection: :fast cannot be combined with caching=true."
                        }
                    }
                ).encode()
                response.headers["Content-Type"] = "application/json"
                return response
            return self._chat_response("The scene continues.")

        with (
            patch("app.ProxyService.make_request", side_effect=reply) as upstream,
            patch(
                "routes.unified.NanoGPTKeyPool.select_key",
                return_value="nanogpt-provider-key",
            ),
            patch(
                "routes.proxy.NanoGPTKeyPool.select_key",
                return_value="nanogpt-provider-key",
            ),
        ):
            response = self.client.post(
                path,
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": model,
                    "reasoning_effort": "max",
                    "thinking": {"type": "enabled"},
                    **input_fields,
                    **extras,
                },
            )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(upstream.call_count, 1)
        sent = json.loads(upstream.call_args.kwargs["data"])
        self.assertEqual(sent["model"], f"{MODEL}:{suffix}")
        self.assertNotIn("caching", sent)
        self.assertEqual(sent["thinking"], {"type": "enabled"})
        self.assertEqual(sent["reasoning_effort"], "max")
        return response

    def test_unified_chat_skips_automatic_cache_selection(self):
        for suffix in SUFFIXES:
            with self.subTest(suffix=suffix):
                response = self._send("/v1/chat/completions", suffix=suffix)
                self.assertEqual(response.headers["X-MultiLLM-Prompt-Cache"], "skipped")
                self.assertEqual(
                    response.headers["X-MultiLLM-Prompt-Cache-Mode"],
                    "nanogpt-speed-routing",
                )

    def test_unified_endpoints_remove_caller_cache_selection(self):
        for path in ("/v1/chat/completions", "/v1/responses"):
            for explicit_suffix in (True, False):
                with self.subTest(path=path, explicit_suffix=explicit_suffix):
                    self._send(path, explicit_suffix=explicit_suffix, caching=True)

    def test_raw_endpoints_remove_caller_cache_selection(self):
        for path in ("/nanogpt/v1/chat/completions", "/nanogpt/v1/responses"):
            for explicit_suffix in (True, False):
                with self.subTest(path=path, explicit_suffix=explicit_suffix):
                    self._send(path, explicit_suffix=explicit_suffix, caching=True)

    def test_raw_cache_normalization_does_not_retry_an_explicit_speed_selection(self):
        refusal = requests.Response()
        refusal.status_code = 403
        refusal._content = b'{"code":"provider_selected"}'
        refusal.headers["Content-Type"] = "application/json"
        with (
            patch("app.ProxyService.make_request", return_value=refusal) as upstream,
            patch(
                "routes.proxy.NanoGPTKeyPool.select_key",
                return_value="nanogpt-provider-key",
            ),
        ):
            response = self.client.post(
                "/nanogpt/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": f"{MODEL}:fast",
                    "caching": True,
                    "messages": [{"role": "user", "content": "Continue."}],
                },
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(upstream.call_count, 1)
        self.assertTrue(NanoGPTSpeedBreaker.allows_suffix())
        self.assertNotIn("caching", json.loads(upstream.call_args.kwargs["data"]))


if __name__ == "__main__":
    unittest.main()
