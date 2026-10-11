"""Direct Claude provider and Haiku 5.5 compatibility coverage."""

import io
import json
import os
from unittest.mock import patch

import pytest
import requests

from providers.anthropic import with_anthropic_headers
from providers.protocols import MESSAGES, chat_bridge_endpoint, native_endpoints
from services.protocol_translation.anthropic import chat_request_to_messages
from services.transport_policy import provider_circuit_mode
from tests.test_protocol_routes import ANTHROPIC_STREAM, ADMIN, sse_upstream
from tests.test_protocol_translation import parse_frames
from tests.unified_api_test_case import UnifiedApiTestCase

MODEL = "claude-haiku-5-5"
SELECTOR = f"anthropic:{MODEL}"
MESSAGE = {
    "id": "msg_haiku",
    "type": "message",
    "role": "assistant",
    "model": MODEL,
    "content": [
        {"type": "thinking", "thinking": "", "signature": "test-signature"},
        {"type": "text", "text": "Hello"},
    ],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 8, "output_tokens": 4},
}


def upstream(body, status=200):
    response = requests.Response()
    response.status_code = status
    response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
    response.raw = io.BytesIO(response._content)
    response.headers["Content-Type"] = "application/json"
    return response


@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max", "minimal"])
def test_haiku_effort_uses_adaptive_thinking_without_sampling(effort):
    body = chat_request_to_messages(
        {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Hello"}],
            "reasoning_effort": effort,
            "max_tokens": 100,
            "temperature": 0.7,
            "top_p": 1,
            "top_k": 40,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"schema": {"type": "object"}},
            },
        }
    )
    assert body["thinking"] == {"type": "adaptive"}
    assert body["output_config"] == {
        "effort": "low" if effort == "minimal" else effort,
        "format": {"type": "json_schema", "schema": {"type": "object"}},
    }
    assert not {"temperature", "top_p", "top_k"} & body.keys()


@pytest.mark.parametrize("thinking", [None, {"type": "disabled"}])
def test_haiku_sampling_is_removed_even_without_explicit_thinking(thinking):
    body = chat_request_to_messages(
        {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.2,
            "top_p": 0.8,
            "thinking": thinking,
        }
    )
    assert "temperature" not in body
    assert "top_p" not in body
    assert body.get("thinking") == thinking


def test_haiku_manual_budget_becomes_adaptive_and_none_disables_thinking():
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": "Hello"}],
        "thinking": {"type": "enabled", "budget_tokens": 8000, "display": "summarized"},
        "output_config": {"effort": "medium"},
    }
    body = chat_request_to_messages(payload)
    assert body["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert payload["thinking"]["budget_tokens"] == 8000
    body = chat_request_to_messages({**payload, "reasoning": {"effort": "none"}})
    assert body["thinking"] == {"type": "disabled"}
    assert body["output_config"]["effort"] == "low"


def test_older_claude_models_keep_manual_thinking_budget():
    body = chat_request_to_messages(
        {
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "Hello"}],
            "reasoning_effort": "medium",
            "max_tokens": 4096,
        }
    )
    assert body["thinking"] == {"type": "enabled", "budget_tokens": 4095}


def test_direct_anthropic_protocol_and_header_policy():
    assert native_endpoints("anthropic", MODEL) == frozenset({MESSAGES})
    assert chat_bridge_endpoint("anthropic", MODEL) == MESSAGES
    assert provider_circuit_mode("anthropic") == "bypassed"
    headers = with_anthropic_headers(
        {
            "authorization": "Bearer caller-key",
            "x-api-key": "caller-key",
            "anthropic-version": "custom-version",
        },
        "provider-key",
    )
    assert headers == {
        "X-Api-Key": "provider-key",
        "anthropic-version": "custom-version",
    }
    assert "X-Api-Key" not in with_anthropic_headers(headers, None)


class AnthropicProviderTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["ANTHROPIC_API_KEY"] = "anthropic-provider-key"

    def post(self, path, body, response=None, headers=None):
        with patch(
            "app.ProxyService.make_request",
            return_value=response if response is not None else upstream(MESSAGE),
        ) as send:
            result = self.client.post(path, json=body, headers=headers or ADMIN)
            result.get_data()
        return result, send

    def test_chat_uses_saved_key_and_adaptive_thinking(self):
        result, send = self.post(
            "/v1/chat/completions",
            {
                "model": SELECTOR,
                "messages": [
                    {"role": "system", "content": "Be concise"},
                    {"role": "user", "content": "Hello"},
                ],
                "reasoning_effort": "high",
                "temperature": 0.5,
                "top_p": 1,
                "max_completion_tokens": 4096,
            },
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.get_json()["choices"][0]["message"]["content"], "Hello")
        send.assert_called_once()
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(kwargs["headers"]["X-Api-Key"], "anthropic-provider-key")
        self.assertEqual(kwargs["headers"]["Anthropic-Version"], "2023-06-01")
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertEqual(kwargs["api_provider"], "anthropic")
        self.assertEqual(
            json.loads(kwargs["data"]),
            {
                "model": MODEL,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "Hello"}]}
                ],
                "system": "Be concise",
                "max_tokens": 4096,
                "thinking": {"type": "adaptive"},
                "output_config": {"effort": "high"},
            },
        )

    def test_chat_stream_is_translated(self):
        result, _ = self.post(
            "/v1/chat/completions",
            {
                "model": SELECTOR,
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": True,
            },
            response=sse_upstream(ANTHROPIC_STREAM),
        )
        self.assertEqual(result.status_code, 200)
        frames = parse_frames(result.get_data(as_text=True))
        self.assertTrue(
            any(
                isinstance(body, dict)
                and body.get("choices")
                and body["choices"][0]["delta"].get("content") == "Salut"
                for _, body, _ in frames
            )
        )
        self.assertEqual(frames[-1][1], "[DONE]")

    def test_dashboard_chat_uses_the_messages_bridge(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": os.environ.get("ADMIN_USERNAME", "admin"),
                "is_admin": True,
                "api_key_prefix": "mllm_admin-te",
                "scopes": ["admin", "chat"],
                "session_id": "test-session",
            }
        for model in (MODEL, SELECTOR):
            with self.subTest(model=model):
                result, send = self.post(
                    "/api/backends/chat-completions/generate",
                    {
                        "provider": "anthropic",
                        "model": model,
                        "messages": [{"role": "user", "content": "Hello"}],
                        "reasoning_effort": "medium",
                        "temperature": 0.7,
                    },
                )
                self.assertEqual(result.status_code, 200)
                self.assertEqual(
                    result.get_json()["choices"][0]["message"]["content"], "Hello"
                )
                kwargs = send.call_args.kwargs
                self.assertEqual(kwargs["url"], "https://api.anthropic.com/v1/messages")
                body = json.loads(kwargs["data"])
                self.assertEqual(body["model"], MODEL)
                self.assertEqual(body["thinking"], {"type": "adaptive"})
                self.assertNotIn("temperature", body)
                self.assertNotIn("provider", body)

    def test_responses_bridge_uses_anthropic_effort(self):
        result, send = self.post(
            "/v1/responses",
            {
                "model": SELECTOR,
                "input": "Hello",
                "reasoning": {"effort": "low"},
                "max_output_tokens": 4096,
            },
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.get_json()["object"], "response")
        body = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(body["model"], MODEL)
        self.assertEqual(body["output_config"]["effort"], "low")

    def test_chat_tool_calls_and_results_use_claude_blocks(self):
        tool = {
            "type": "function",
            "function": {"name": "lookup", "parameters": {"type": "object"}},
        }
        message = {
            **MESSAGE,
            "content": [
                {
                    "type": "tool_use",
                    "id": "tool_2",
                    "name": "lookup",
                    "input": {"query": "next"},
                }
            ],
            "stop_reason": "tool_use",
        }
        result, send = self.post(
            "/v1/chat/completions",
            {
                "model": SELECTOR,
                "tools": [tool],
                "messages": [
                    {"role": "user", "content": "Look it up"},
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "tool_1",
                                "type": "function",
                                "function": {"name": "lookup", "arguments": "{}"},
                            }
                        ],
                    },
                    {"role": "tool", "tool_call_id": "tool_1", "content": "Found"},
                ],
            },
            response=upstream(message),
        )
        self.assertEqual(result.status_code, 200)
        choice = result.get_json()["choices"][0]
        self.assertEqual(choice["finish_reason"], "tool_calls")
        self.assertEqual(
            choice["message"]["tool_calls"][0]["function"]["name"], "lookup"
        )
        body = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(body["tools"][0]["input_schema"], {"type": "object"})
        self.assertEqual(
            body["messages"][-1]["content"][0],
            {"type": "tool_result", "tool_use_id": "tool_1", "content": "Found"},
        )

    def test_unified_messages_preserve_signed_thinking_and_native_settings(self):
        history = [
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "", "signature": "test-signature"},
                    {"type": "text", "text": "Hello"},
                ],
            },
            {"role": "user", "content": "Continue"},
        ]
        result, send = self.post(
            "/v1/messages",
            {
                "model": SELECTOR,
                "max_tokens": 4096,
                "messages": history,
                "thinking": {"type": "adaptive", "display": "summarized"},
                "temperature": 1,
            },
            headers={"X-Api-Key": "admin-test-key", "Anthropic-Beta": "test-beta"},
        )
        self.assertEqual(result.status_code, 200)
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Anthropic-Beta"], "test-beta")
        body = json.loads(kwargs["data"])
        self.assertEqual(body["messages"], history)
        self.assertEqual(body["temperature"], 1)
        self.assertEqual(
            body["thinking"], {"type": "adaptive", "display": "summarized"}
        )
        self.assertEqual(result.get_json()["content"], MESSAGE["content"])

    def test_native_messages_preserve_request_and_response_bytes(self):
        request_body = b'{ "model": "claude-haiku-5-5", "max_tokens": 4096, "messages": [{"role":"user","content":"Hello"}], "temperature": 0.5 }'
        response_body = b'{ "type": "error", "error": {"type":"invalid_request_error","message":"Unsupported temperature"} }'
        with patch(
            "app.ProxyService.make_request", return_value=upstream(response_body, 400)
        ) as send:
            result = self.client.post(
                "/anthropic/v1/messages?key=admin-test-key&beta=true&beta=false",
                data=request_body,
                content_type="application/json",
                headers={
                    "X-Api-Key": "admin-test-key",
                    "Anthropic-Version": "2023-06-01",
                    "Anthropic-Beta": "test-beta",
                    "X-Stainless-Lang": "python",
                },
            )
            self.assertEqual(result.get_data(), response_body)
        self.assertEqual(result.status_code, 400)
        send.assert_called_once()
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs["data"], request_body)
        self.assertEqual(kwargs["params"], [("beta", "true"), ("beta", "false")])
        self.assertEqual(kwargs["headers"]["X-Api-Key"], "anthropic-provider-key")
        self.assertEqual(kwargs["headers"]["X-Stainless-Lang"], "python")

    def test_native_sse_and_token_counting(self):
        for path, response, expected in (
            (
                "/anthropic/v1/messages",
                sse_upstream(ANTHROPIC_STREAM),
                b"".join(ANTHROPIC_STREAM),
            ),
            (
                "/anthropic/v1/messages/count_tokens",
                upstream({"input_tokens": 8}),
                b'{"input_tokens": 8}',
            ),
        ):
            with self.subTest(path=path):
                result, send = self.post(
                    path,
                    {
                        "model": MODEL,
                        "messages": [{"role": "user", "content": "Hello"}],
                        "max_tokens": 4096,
                        "stream": path.endswith("messages"),
                    },
                    response=response,
                )
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.get_data(), expected)
                self.assertEqual(
                    send.call_args.kwargs["url"],
                    "https://api.anthropic.com" + path.removeprefix("/anthropic"),
                )

    def test_anthropic_catalog_reads_native_limits_and_capabilities(self):
        from services.provider_catalog_service import ProviderCatalogService

        models = ProviderCatalogService.extract_models(
            "anthropic",
            {
                "data": [
                    {
                        "id": MODEL,
                        "max_input_tokens": 1_000_000,
                        "max_tokens": 128_000,
                        "capabilities": {
                            "image_input": {"supported": True},
                            "thinking": {"supported": True},
                        },
                    }
                ]
            },
        )
        assert len(models) == 1
        assert models[0].context_window == 1_000_000
        assert models[0].max_output_tokens == 128_000
        assert models[0].metadata["supports_vision"] is True
        assert models[0].metadata["supports_reasoning"] is True

    def test_model_catalog_includes_haiku_without_refresh(self):
        from services.model_catalog_service import build_model_catalog

        model = next(
            item
            for item in build_model_catalog(self.app.config["API_BASE_URLS"])
            if item["id"] == SELECTOR
        )
        self.assertEqual(model["context_window"], 1_000_000)
        self.assertEqual(model["max_output_tokens"], 128_000)
        self.assertTrue(model["capabilities"]["supports_vision"])
        self.assertEqual(
            model["provider_metadata"]["api_protocol"], "anthropic_messages"
        )

    def test_model_discovery_uses_server_key(self):
        with patch(
            "app.ProxyService.make_request",
            return_value=upstream({"data": [{"id": MODEL}]}),
        ) as send:
            result = self.client.get("/anthropic/v1/models", headers=ADMIN)
            result.get_data()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(
            send.call_args.kwargs["url"], "https://api.anthropic.com/v1/models"
        )
        self.assertEqual(
            send.call_args.kwargs["headers"]["X-Api-Key"], "anthropic-provider-key"
        )

    def test_catalog_refresh_persists_anthropic_models(self):
        from services.provider_catalog_service import ProviderCatalogService

        payload = {
            "data": [
                {
                    "id": MODEL,
                    "max_input_tokens": 1_000_000,
                    "max_tokens": 128_000,
                    "capabilities": {
                        "image_input": {"supported": True},
                        "thinking": {"supported": True},
                    },
                }
            ]
        }
        with patch(
            "app.ProxyService.make_request", return_value=upstream(payload)
        ) as send:
            results = ProviderCatalogService.refresh_configured(
                {"anthropic": "https://api.anthropic.com"},
                self.app_module.AuthService,
                self.app_module.ProxyService,
            )
        self.assertEqual(results[0]["status"], "updated")
        self.assertTrue(ProviderCatalogService.has_model("anthropic", MODEL))
        self.assertEqual(
            send.call_args.kwargs["headers"]["X-Api-Key"], "anthropic-provider-key"
        )

    def test_missing_key_and_unauthenticated_requests_do_not_reach_upstream(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result, send = self.post(
            "/v1/chat/completions",
            {
                "model": SELECTOR,
                "messages": [{"role": "user", "content": "Hello"}],
            },
        )
        self.assertEqual(result.status_code, 503)
        send.assert_not_called()
        with patch("app.ProxyService.make_request") as send:
            result = self.client.post("/anthropic/v1/messages", json={"model": MODEL})
        self.assertEqual(result.status_code, 401)
        send.assert_not_called()

    def test_upstream_rate_limit_keeps_status_and_retry_after(self):
        response = upstream(
            {
                "type": "error",
                "error": {"type": "rate_limit_error", "message": "Slow down"},
            },
            429,
        )
        response.headers["Retry-After"] = "10"
        result, send = self.post(
            "/v1/chat/completions",
            {
                "model": SELECTOR,
                "messages": [{"role": "user", "content": "Hello"}],
            },
            response=response,
        )
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.headers["Retry-After"], "10")
        send.assert_called_once()
