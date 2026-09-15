import io
import json
from unittest.mock import patch

from tests.unified_api_test_case import UnifiedApiTestCase


class NanoGPTReasoningTest(UnifiedApiTestCase):
    def _request(self, path, options, *, stream=False):
        model = "z-ai/glm-5.3-flash"
        payload = {
            "model": f"nanogpt:{model}" if path == "/v1/chat/completions" else model,
            "messages": [{"role": "user", "content": "Which path fits the clue?"}],
            "stream": stream,
            **options,
        }
        reasoning = "Consider the clue and the possible routes. " * 500
        answer = "Take the north path."
        upstream = self._chat_response(answer)
        if stream:
            upstream.headers["Content-Type"] = "text/event-stream"
            upstream._content = (
                f'data: {json.dumps({"choices": [{"delta": {"reasoning": reasoning}}]})}\n\n'
                f'data: {json.dumps({"choices": [{"delta": {"content": answer}, "finish_reason": "stop"}]})}\n\n'
                "data: [DONE]\n\n"
            ).encode()
            upstream.raw = io.BytesIO(upstream._content)
        else:
            body = upstream.json()
            body["choices"][0]["message"]["reasoning"] = reasoning
            upstream._content = json.dumps(body).encode()
        with (
            patch.object(self.app_module.AuthService, "get_api_keys", return_value=["nano-test-key"]),
            patch.object(self.app_module.AuthService, "get_api_key", return_value="nano-test-key"),
            patch("routes.unified.NanoGPTKeyPool.select_key", return_value="nano-test-key"),
            patch("routes.proxy.NanoGPTKeyPool.select_key", return_value="nano-test-key"),
            patch("app.ProxyService.make_request", return_value=upstream) as send,
        ):
            response = self.client.post(path, headers={"Authorization": "Bearer admin-test-key"}, json=payload)
            output = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(answer, output)
        self.assertIn(reasoning, output)
        send.assert_called_once()
        self.assertEqual(send.call_args.kwargs["api_provider"], "nanogpt")
        return json.loads(send.call_args.kwargs["data"])

    def test_native_thinking_is_preserved_on_unified_and_raw_chat_routes(self):
        for path in (
            "/v1/chat/completions",
            "/nanogpt/v1/chat/completions",
            "/nanogpt/subscription/v1/chat/completions",
        ):
            for stream in (False, True):
                with self.subTest(path=path, stream=stream):
                    sent = self._request(path, {}, stream=stream)
                    for field in ("reasoning_effort", "reasoning", "thinking"):
                        self.assertNotIn(field, sent)

    def test_explicit_effort_still_reaches_nanogpt(self):
        for path in ("/v1/chat/completions", "/nanogpt/v1/chat/completions"):
            for effort in ("low", "high", "none", "xhigh", "max"):
                with self.subTest(path=path, effort=effort):
                    sent = self._request(path, {"reasoning_effort": effort})
                    expected = "max" if path == "/v1/chat/completions" and effort == "xhigh" else effort
                    self.assertEqual(sent["reasoning_effort"], expected)

    def test_nested_override_is_still_mapped_on_unified_chat(self):
        sent = self._request("/v1/chat/completions", {"reasoning": {"effort": "low"}})
        self.assertEqual(sent["reasoning_effort"], "low")

    def test_native_options_are_not_replaced_by_defaults(self):
        options = {"thinking": {"type": "enabled"}, "reasoning": {"exclude": False}}
        sent = self._request("/v1/chat/completions", options)
        self.assertNotIn("reasoning_effort", sent)
        for field, value in options.items():
            self.assertEqual(sent[field], value)
