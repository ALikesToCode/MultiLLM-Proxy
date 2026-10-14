"""Standalone moderation and native safety metadata, using synthetic inputs only."""

import json
from unittest.mock import patch

from flask import g

from services.openai_safety import principal_safety_identifier
from services.protocol_translation import CHAT, RESPONSES, TranslationError, translate_request
from tests.test_media_audio import upstream
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}
RESULT = {"id": "modr-test", "model": "omni-moderation-latest", "results": [
    {"flagged": False, "categories": {"sexual/minors": False}, "category_scores": {"sexual/minors": 0.001},
     "category_applied_input_types": {"sexual/minors": ["text"]}}]}


class ModerationRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        keys = {"openai": "openai-test-key", "navyai": "navyai-test-key", "nanogpt": "nano-test-key"}
        for name, value in {"get_api_key": lambda provider: keys.get(provider),
                            "get_api_keys": lambda provider: [keys[provider]] if provider in keys else []}.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, path, response, **kwargs):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=response) as transport:
            result = self.client.post(path, headers=kwargs.pop("headers", ADMIN), **kwargs)
        return result, transport

    def test_default_and_bare_model_preserve_all_result_fields(self):
        for model in (None, "omni-moderation-latest", "nanogpt:omni-moderation-latest"):
            body = {"input": ["A synthetic example.", "Another example."]}
            if model:
                body["model"] = model
            result, transport = self.post("/v1/moderations", [upstream(200, RESULT)], json=body)
            self.assertEqual(result.status_code, 200, result.get_data(as_text=True))
            self.assertEqual(result.get_json(), RESULT)
            sent = transport.call_args.kwargs
            self.assertEqual(json.loads(sent["data"])["input"], body["input"])
            self.assertTrue(sent["url"].endswith("/v1/moderations"))
            self.assertFalse(sent["use_cache"])
            self.assertTrue(sent["force_raw_passthrough"])
            if model is None:
                self.assertEqual(result.headers["X-MultiLLM-Auto-Route"], "auto:moderation")

    def test_refusal_fails_over_to_navy_but_timeout_does_not(self):
        result, transport = self.post("/v1/moderations", [upstream(429, {"error": "quota"}), upstream(200, RESULT)],
                                      json={"input": "Synthetic text."})
        self.assertEqual(result.status_code, 200)
        self.assertIn("api.navy/v1/moderations", transport.call_args.kwargs["url"])
        self.assertEqual(transport.call_count, 2)
        result, transport = self.post("/v1/moderations", [
            upstream(502, {"error": "timeout"}, multillm_transport_failure="timeout")],
            json={"input": "Synthetic text."})
        self.assertEqual(result.status_code, 502)
        self.assertEqual(transport.call_count, 1)

    def test_images_go_to_openai_and_navy_is_refused_locally(self):
        parts = [{"type": "text", "text": "A safe scene."},
                 {"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}}]
        result, transport = self.post("/v1/moderations", [upstream(200, RESULT)], json={"input": parts})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(json.loads(transport.call_args.kwargs["data"])["input"], parts)
        result, transport = self.post("/v1/moderations", [], json={"model": "navyai:omni-moderation-latest", "input": parts})
        self.assertEqual(result.status_code, 400)
        transport.assert_not_called()

    def test_invalid_input_never_reaches_a_provider(self):
        for value in ("", [], [1], ["text", {"type": "text", "text": "text"}],
                      [{"type": "audio", "audio": "value"}],
                      [{"type": "image_url", "image_url": {"url": "http://example.com/a.png"}}],
                      [{"type": "image_url", "image_url": {"url": "data:image/png;base64,==="}}]):
            with self.subTest(value=value):
                result, transport = self.post("/v1/moderations", [], json={"input": value})
                self.assertEqual(result.status_code, 400)
                transport.assert_not_called()

    def test_authentication_and_preflight(self):
        result, transport = self.post("/v1/moderations", [], headers={}, json={"input": "Safe."})
        self.assertEqual(result.status_code, 401)
        transport.assert_not_called()
        self.assertEqual(self.client.options("/v1/moderations").status_code, 204)

    def test_moderation_models_cannot_be_sent_to_chat(self):
        for model in ("openai:omni-moderation-latest", "auto:moderation"):
            result, transport = self.post("/v1/chat/completions", [], json={
                "model": model, "messages": [{"role": "user", "content": "Safe."}]})
            self.assertEqual(result.status_code, 400)
            transport.assert_not_called()

    def test_native_chat_and_responses_keep_inline_results_and_caller_identity(self):
        moderation = {"input": {"type": "moderation_result", "results": RESULT["results"]},
                      "output": {"type": "moderation_error", "error": {"code": "test_error"}}}
        for path, prompt in (("/v1/chat/completions", {"messages": [{"role": "user", "content": "Safe."}]}),
                             ("/v1/responses", {"input": "Safe."}),
                             ("/openai/v1/responses", {"input": "Safe."})):
            body = {"model": "gpt-test" if path.startswith("/openai") else "openai:gpt-test",
                    "moderation": {"model": "omni-moderation-latest"}, "safety_identifier": "caller-hash", **prompt}
            result, transport = self.post(path, [upstream(200, {"id": "test", "moderation": moderation})], json=body)
            self.assertEqual(result.status_code, 200, result.get_data(as_text=True))
            self.assertEqual(result.get_json()["moderation"], moderation)
            sent = json.loads(transport.call_args.kwargs["data"])
            self.assertEqual(sent["moderation"], body["moderation"])
            self.assertEqual(sent["safety_identifier"], "caller-hash")

    def test_native_streaming_keeps_moderation_event(self):
        event = b'data: {"moderation":{"output":{"type":"moderation_result","results":[]}}}\n\ndata: [DONE]\n\n'
        result, _ = self.post("/v1/chat/completions", [upstream(200, event, "text/event-stream")], json={
            "model": "openai:gpt-test", "messages": [{"role": "user", "content": "Safe."}], "stream": True,
            "moderation": {"model": "omni-moderation-latest"}})
        self.assertEqual(result.status_code, 200)
        self.assertIn(b'"moderation"', result.get_data())

    def test_unified_other_provider_inline_is_refused(self):
        result, transport = self.post("/v1/chat/completions", [], json={"model": "navyai:gpt-test",
            "messages": [{"role": "user", "content": "Safe."}], "moderation": {"model": "omni-moderation-latest"}})
        self.assertEqual(result.status_code, 400)
        transport.assert_not_called()

    def test_default_safety_identity_is_opaque_stable_and_principal_specific(self):
        with self.app.test_request_context():
            g.authenticated_user = {"id": 10, "username": "private@example.com"}
            first = principal_safety_identifier()
            self.assertRegex(first, r"^[0-9a-f]{64}$")
            self.assertEqual(first, principal_safety_identifier())
            g.authenticated_user["id"] = 11
            self.assertNotEqual(first, principal_safety_identifier())
        result, transport = self.post("/v1/chat/completions", [self._chat_response()], json={
            "model": "openai:gpt-test", "messages": [{"role": "user", "content": "Safe."}]})
        self.assertEqual(result.status_code, 200)
        self.assertRegex(json.loads(transport.call_args.kwargs["data"])["safety_identifier"], r"^[0-9a-f]{64}$")


def test_translation_preserves_identity_and_refuses_inline_moderation():
    payload = {"model": "gpt-test", "messages": [{"role": "user", "content": "Safe."}], "safety_identifier": "caller"}
    converted = translate_request(payload, CHAT, RESPONSES)
    assert converted["safety_identifier"] == "caller"
    assert translate_request(converted, RESPONSES, CHAT)["safety_identifier"] == "caller"
    try:
        translate_request({**payload, "moderation": {"model": "omni-moderation-latest"}}, CHAT, RESPONSES)
    except TranslationError as error:
        assert error.param == "moderation"
    else:
        raise AssertionError("Inline moderation must not disappear during translation")
