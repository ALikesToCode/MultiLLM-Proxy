import io
import json
from unittest.mock import patch

from tests.unified_api_test_case import UnifiedApiTestCase


class OpenCodeThinkingTest(UnifiedApiTestCase):
    def _request(self, path, options, *, stream=False, model="glm-5.3-flash"):
        payload = {
            "model": f"opencode:{model}" if path == "/v1/chat/completions" else model,
            "messages": [{"role": "user", "content": "What is six times seven?"}],
            "stream": stream,
            **options,
        }
        upstream = self._chat_response("The answer is 42.")
        if stream:
            upstream.headers["Content-Type"] = "text/event-stream"
            upstream._content = (
                'data: {"choices":[{"delta":{"reasoning_content":"Check the arithmetic."}}]}\n\n'
                'data: {"choices":[{"delta":{"content":"The answer is 42."},"finish_reason":"stop"}]}\n\n'
                'data: [DONE]\n\n'
            ).encode()
            upstream.raw = io.BytesIO(upstream._content)
        with patch("app.ProxyService.make_request", return_value=upstream) as send:
            response = self.client.post(
                path,
                headers={"Authorization": "Bearer admin-test-key"},
                json=payload,
            )
            output = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("The answer is 42.", output)
        send.assert_called_once()
        self.assertEqual(
            send.call_args.kwargs["url"],
            "https://opencode.ai/zen/go/v1/chat/completions",
        )
        return json.loads(send.call_args.kwargs["data"])

    def test_go_reasoning_defaults_and_overrides_without_unsupported_thinking(self):
        for path in (
            "/v1/chat/completions",
            "/opencode/v1/chat/completions",
            "/opencode/chat/completions",
        ):
            for stream in (False, True):
                for options, expected in (
                    ({}, "max"),
                    ({"reasoning_effort": "max"}, "max"),
                    ({"reasoning_effort": "high"}, "high"),
                    ({"reasoning_effort": "low"}, "low"),
                    ({"reasoning_effort": "xhigh"}, "max"),
                    ({"reasoning": {"effort": "low"}}, "low"),
                ):
                    with self.subTest(path=path, stream=stream, options=options):
                        sent = self._request(path, options, stream=stream)
                        self.assertEqual(sent.get("reasoning_effort"), expected)
                        self.assertNotIn("thinking", sent)
                        self.assertNotIn("reasoning", sent)

    def test_explicit_thinking_options_are_preserved(self):
        for thinking in ({"type": "enabled", "clear_thinking": False}, {"type": "disabled"}):
            with self.subTest(thinking=thinking):
                sent = self._request(
                    "/opencode/v1/chat/completions",
                    {"thinking": thinking, "reasoning_effort": "low"},
                )
                self.assertEqual(sent["thinking"], thinking)
                self.assertEqual(sent["reasoning_effort"], "low")

    def test_other_models_do_not_receive_glm_defaults(self):
        sent = self._request("/opencode/v1/chat/completions", {}, model="kimi-k3")
        self.assertNotIn("thinking", sent)
        self.assertNotIn("reasoning_effort", sent)

    def test_invalid_effort_remains_the_providers_responsibility(self):
        sent = self._request(
            "/opencode/v1/chat/completions", {"reasoning_effort": "turbo"}
        )
        self.assertEqual(sent["reasoning_effort"], "turbo")
        self.assertNotIn("thinking", sent)

    def test_invalid_native_models_are_left_for_upstream_validation(self):
        for model in (None, 42, {}, []):
            with self.subTest(model=model):
                sent = self._request("/opencode/v1/chat/completions", {}, model=model)
                self.assertEqual(sent["model"], model)
                self.assertNotIn("thinking", sent)
