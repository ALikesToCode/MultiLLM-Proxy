import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests

from services.rate_limit_service import LimitDecision
from tests.test_context_optimizer import image_prompt


class OptimizedChatRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "KIMI_CODE_API_KEY": "kimi-code-provider-key",
                "LINKAPI_KEY": "linkapi-provider-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(self.temp_dir.name, "limits.sqlite3"),
                "MODEL_REGISTRY_DB_PATH": os.path.join(self.temp_dir.name, "models.sqlite3"),
            }
        )

        for module_name in list(sys.modules):
            if module_name.startswith(("routes.", "providers.")):
                sys.modules.pop(module_name, None)
        for module_name in (
            "app",
            "route_helpers",
            "services.auth_service",
            "services.context_optimizer",
            "services.model_registry",
            "services.proxy_service",
            "services.rate_limit_service",
        ):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.app = self.app_module.create_app()
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _raw_response(
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(body)
        response._content = body
        response.headers["Content-Type"] = content_type
        response.headers.update(headers or {})
        return response

    @staticmethod
    def _allowed_decision(**metadata):
        return LimitDecision(allowed=True, metadata=metadata)

    def _rate_patches(self):
        return (
            patch(
                "routes.optimized.RateLimitService.reserve_request_slot",
                return_value=self._allowed_decision(reservation_id=41),
            ),
            patch(
                "routes.optimized.RateLimitService.finalize_request_slot",
                return_value=self._allowed_decision(reservation_id=41),
            ),
        )

    @staticmethod
    def _summary_request(*, summary_model: str, **options):
        optimization = {
            "mode": "summarize",
            "summary_model": summary_model,
            "trigger_input_tokens": 0,
            "target_input_tokens": 64,
            "keep_recent_turns": 1,
            **options,
        }
        return {
            "model": "kimi-code:k3",
            "messages": [
                {"role": "system", "content": "Keep this instruction."},
                {"role": "user", "content": "The user chose blue."},
                {"role": "assistant", "content": "Choice recorded."},
                {"role": "user", "content": "The deadline is Friday."},
                {"role": "assistant", "content": "Deadline recorded."},
                {"role": "user", "content": "What should happen next?"},
            ],
            "optimization": optimization,
        }

    def test_deterministic_route_strips_options_and_accounts_transformed_payload_once(self):
        older_prompt = image_prompt("the old image")
        newest_prompt = image_prompt("the newest image")
        native_body = b'{"id":"chatcmpl_k3","object":"chat.completion","choices":[]}'
        upstream_response = self._raw_response(
            native_body,
            headers={
                "X-Request-ID": "req_optimized_k3",
                "Set-Cookie": "upstream-secret=1",
                "Location": "https://api.kimi.com/account",
            },
        )

        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request"
        ) as enforce_request, reserve_patch as reserve_request, finalize_patch as finalize_request:
            response = self.client.post(
                "/optimize/v1/chat/completions?trace=one&trace=two&key=caller-secret",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "X-Api-Key": "caller-provider-secret",
                    "User-Agent": "KimiCLI/1.2.3",
                },
                json={
                    "model": "kimi-code:k3",
                    "messages": [
                        {"role": "system", "content": "Keep continuity."},
                        {"role": "user", "content": older_prompt},
                        {"role": "assistant", "content": "Done."},
                        {"role": "user", "content": newest_prompt},
                        {"role": "assistant", "content": "Done."},
                        {"role": "user", "content": "Give the final title."},
                    ],
                    "tools": [{"type": "function", "function": {"name": "lookup"}}],
                    "reasoning_effort": "max",
                    "prompt_cache_key": "scene-session-1",
                    "optimization": {
                        "trigger_input_tokens": 0,
                        "target_input_tokens": 100000,
                        "keep_recent_turns": 1,
                    },
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        self.assertEqual(response.headers["X-MultiLLM-Optimization"], "applied")
        self.assertEqual(response.headers["X-MultiLLM-Optimization-Mode"], "deterministic")
        self.assertEqual(response.headers["X-MultiLLM-Image-Prompts-Compacted"], "1")
        self.assertEqual(response.headers["X-Request-ID"], "req_optimized_k3")
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("Location", response.headers)
        enforce_request.assert_not_called()
        reserve_request.assert_called_once()
        finalize_request.assert_called_once()

        upstream_payload = json.loads(make_request.call_args.kwargs["data"])
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["method"], "POST")
        self.assertEqual(
            request_kwargs["url"],
            "https://api.kimi.com/coding/v1/chat/completions",
        )
        self.assertEqual(request_kwargs["params"], [("trace", "one"), ("trace", "two")])
        self.assertEqual(request_kwargs["api_provider"], "kimi-code")
        self.assertFalse(request_kwargs["use_cache"])
        upstream_headers = {
            name.lower(): value for name, value in request_kwargs["headers"].items()
        }
        self.assertEqual(
            upstream_headers["authorization"],
            "Bearer kimi-code-provider-key",
        )
        self.assertNotIn("x-api-key", upstream_headers)
        self.assertEqual(upstream_payload["model"], "k3")
        self.assertNotIn("optimization", upstream_payload)
        self.assertIn("Earlier image-generation prompt omitted", upstream_payload["messages"][1]["content"])
        self.assertEqual(upstream_payload["messages"][3]["content"], newest_prompt)
        self.assertEqual(upstream_payload["reasoning_effort"], "max")
        self.assertEqual(upstream_payload["prompt_cache_key"], "scene-session-1")
        self.assertEqual(upstream_payload["tools"], [{"type": "function", "function": {"name": "lookup"}}])

        rate_kwargs = finalize_request.call_args.kwargs
        self.assertEqual(rate_kwargs["provider"], "kimi-code")
        self.assertEqual(rate_kwargs["payload_json"]["model"], "kimi-code:k3")
        self.assertNotIn("optimization", rate_kwargs["payload_json"])
        self.assertEqual(json.loads(rate_kwargs["payload_bytes"]), rate_kwargs["payload_json"])

    def test_summary_mode_uses_one_explicit_summary_call_then_final_provider(self):
        summary_response = self._raw_response(
            json.dumps(
                {
                    "id": "chatcmpl_summary",
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(
                                    {
                                        "facts": ["The deadline is Friday."],
                                        "requirements": ["Use blue."],
                                        "decisions": [],
                                        "open_tasks": ["Choose the next action."],
                                        "visual_continuity": [],
                                    }
                                ),
                            }
                        }
                    ],
                }
            ).encode()
        )
        final_body = b'{"id":"chatcmpl_final","choices":[]}'
        final_response = self._raw_response(final_body)

        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            side_effect=[summary_response, final_response],
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=self._allowed_decision(),
        ) as enforce_request, reserve_patch as reserve_request, finalize_patch as finalize_request:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "kimi-code:k3",
                    "messages": [
                        {"role": "system", "content": "Keep this instruction."},
                        {"role": "user", "content": "The user chose blue."},
                        {"role": "assistant", "content": "Choice recorded."},
                        {"role": "user", "content": "The deadline is Friday."},
                        {"role": "assistant", "content": "Deadline recorded."},
                        {"role": "user", "content": "What should happen next?"},
                    ],
                    "optimization": {
                        "mode": "summarize",
                        "summary_model": "linkapi:summary-model",
                        "summary_max_tokens": 256,
                        "allow_cross_provider_summary": True,
                        "trigger_input_tokens": 0,
                        "target_input_tokens": 64,
                        "keep_recent_turns": 1,
                    },
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, final_body)
        self.assertEqual(response.headers["X-MultiLLM-Optimization-Mode"], "summarize")
        self.assertEqual(response.headers["X-MultiLLM-Messages-Summarized"], "4")
        self.assertEqual(response.headers["X-MultiLLM-Summary"], "applied")
        self.assertEqual(make_request.call_count, 2)
        self.assertEqual(enforce_request.call_count, 1)
        reserve_request.assert_called_once()
        finalize_request.assert_called_once()

        summary_call = make_request.call_args_list[0].kwargs
        summary_payload = json.loads(summary_call["data"])
        self.assertEqual(summary_call["api_provider"], "linkapi")
        self.assertEqual(summary_call["timeout_override"], (5, 45))
        self.assertEqual(summary_payload["model"], "summary-model")
        self.assertFalse(summary_payload["stream"])
        summary_source = summary_payload["messages"][1]["content"]
        self.assertIn("The user chose blue.", summary_source)
        self.assertIn("The deadline is Friday.", summary_source)
        self.assertNotIn("Keep this instruction.", summary_source)
        self.assertNotIn("What should happen next?", summary_source)

        final_payload = json.loads(make_request.call_args_list[1].kwargs["data"])
        self.assertEqual(final_payload["model"], "k3")
        self.assertEqual(final_payload["messages"][0]["content"], "Keep this instruction.")
        self.assertIn("untrusted historical conversation memory", final_payload["messages"][1]["content"])
        self.assertEqual(final_payload["messages"][-1]["content"], "What should happen next?")
        self.assertNotIn("optimization", final_payload)

    def test_invalid_options_fail_after_early_slot_but_before_upstream(self):
        reserve_patch, finalize_patch = self._rate_patches()
        with patch("app.ProxyService.make_request") as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request"
        ) as enforce_request, reserve_patch as reserve_request, finalize_patch as finalize_request:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "kimi-code:k3",
                    "messages": [{"role": "user", "content": "hello"}],
                    "optimization": {"mode": "unsafe-magic"},
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("optimization.mode", response.get_json()["message"])
        make_request.assert_not_called()
        enforce_request.assert_not_called()
        reserve_request.assert_called_once()
        finalize_request.assert_not_called()

    def test_cross_provider_summary_requires_explicit_data_transfer_opt_in(self):
        reserve_patch, finalize_patch = self._rate_patches()
        with patch("app.ProxyService.make_request") as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request"
        ) as enforce_request, reserve_patch, finalize_patch as finalize_request:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(summary_model="linkapi:summary-model"),
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("allow_cross_provider_summary", response.get_json()["message"])
        make_request.assert_not_called()
        enforce_request.assert_not_called()
        finalize_request.assert_not_called()

    def test_same_provider_summary_is_allowed_without_cross_provider_opt_in(self):
        summary_response = self._raw_response(
            json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "facts": ["The deadline is Friday."],
                                        "requirements": ["Use blue."],
                                        "decisions": [],
                                        "open_tasks": [],
                                        "visual_continuity": [],
                                    }
                                )
                            }
                        }
                    ]
                }
            ).encode()
        )
        final_response = self._raw_response(b'{"choices":[]}')
        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            side_effect=[summary_response, final_response],
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=self._allowed_decision(),
        ), reserve_patch, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(summary_model="kimi-code:k3"),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Summary"], "applied")
        self.assertEqual(make_request.call_count, 2)
        self.assertEqual(make_request.call_args_list[0].kwargs["api_provider"], "kimi-code")

    def test_failed_summary_closes_upstream_and_falls_back_without_retry(self):
        failed_summary = self._raw_response(b'{"error":"unavailable"}', status=503)
        final_response = self._raw_response(b'{"choices":[]}')
        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            side_effect=[failed_summary, final_response],
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=self._allowed_decision(),
        ) as enforce_request, reserve_patch, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(summary_model="kimi-code:k3"),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Summary"], "failed")
        self.assertEqual(make_request.call_count, 2)
        self.assertEqual(enforce_request.call_count, 1)
        self.assertTrue(failed_summary.raw.closed)
        final_payload = json.loads(make_request.call_args_list[1].kwargs["data"])
        self.assertEqual(final_payload["messages"][1]["content"], "The user chose blue.")

    def test_busy_summary_pool_falls_back_without_upstream_summary_call(self):
        final_response = self._raw_response(b'{"choices":[]}')
        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "routes.optimized.SUMMARY_SEMAPHORE"
        ) as summary_semaphore, patch(
            "app.ProxyService.make_request",
            return_value=final_response,
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=self._allowed_decision(),
        ), reserve_patch, finalize_patch:
            summary_semaphore.acquire.return_value = False
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(summary_model="kimi-code:k3"),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Summary"], "capacity-denied")
        self.assertEqual(make_request.call_count, 1)
        summary_semaphore.release.assert_not_called()

    def test_summary_budget_denial_falls_back_or_propagates_when_required(self):
        denied = LimitDecision(
            allowed=False,
            status_code=429,
            error="rate_limit_exceeded",
            message="Summary budget exhausted.",
            retry_after=60,
        )
        final_response = self._raw_response(b'{"choices":[]}')

        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            return_value=final_response,
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=denied,
        ), reserve_patch, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(summary_model="kimi-code:k3"),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Summary"], "budget-denied")
        self.assertEqual(make_request.call_count, 1)

        reserve_patch, finalize_patch = self._rate_patches()
        with patch("app.ProxyService.make_request") as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=denied,
        ), reserve_patch, finalize_patch as finalize_request:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(
                    summary_model="kimi-code:k3",
                    require_target=True,
                ),
            )

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")
        make_request.assert_not_called()
        finalize_request.assert_not_called()

    def test_successful_but_insufficient_required_summary_returns_422(self):
        summary_response = self._raw_response(
            json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "facts": ["x" * 500],
                                        "requirements": ["y" * 500],
                                        "decisions": [],
                                        "open_tasks": [],
                                        "visual_continuity": [],
                                    }
                                )
                            }
                        }
                    ]
                }
            ).encode()
        )
        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            return_value=summary_response,
        ) as make_request, patch(
            "routes.optimized.RateLimitService.enforce_request",
            return_value=self._allowed_decision(),
        ), reserve_patch, finalize_patch as finalize_request:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(
                    summary_model="kimi-code:k3",
                    require_target=True,
                ),
            )

        self.assertEqual(response.status_code, 422)
        self.assertIn("target", response.get_json()["message"])
        self.assertEqual(make_request.call_count, 1)
        finalize_request.assert_not_called()

    def test_target_credentials_are_validated_before_reservation_or_summary(self):
        reserve_patch, finalize_patch = self._rate_patches()
        with patch("app.AuthService.get_api_key", return_value=None), patch(
            "app.ProxyService.make_request"
        ) as make_request, reserve_patch as reserve_request, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json=self._summary_request(summary_model="kimi-code:k3"),
            )

        self.assertEqual(response.status_code, 503)
        make_request.assert_not_called()
        reserve_request.assert_not_called()

    def test_optimizer_body_limit_rejects_before_json_parse_or_reservation(self):
        os.environ["OPTIMIZER_MAX_REQUEST_BYTES"] = "1024"
        payload = json.dumps(
            {
                "model": "kimi-code:k3",
                "messages": [{"role": "user", "content": "x" * 2000}],
            }
        ).encode()
        reserve_patch, finalize_patch = self._rate_patches()
        with patch("app.ProxyService.make_request") as make_request, reserve_patch as reserve_request, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                data=payload,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 413)
        make_request.assert_not_called()
        reserve_request.assert_not_called()

    def test_ordinary_unified_route_never_compacts_history(self):
        older_prompt = image_prompt("the old image")
        newest_prompt = image_prompt("the newest image")
        upstream_response = self._raw_response(b'{"choices":[]}')
        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request, patch(
            "route_helpers.RateLimitService.enforce_request",
            return_value=self._allowed_decision(),
        ) as enforce_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "kimi-code:k3",
                    "messages": [
                        {"role": "user", "content": older_prompt},
                        {"role": "assistant", "content": "Done."},
                        {"role": "user", "content": newest_prompt},
                    ],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-MultiLLM-Optimization", response.headers)
        self.assertEqual(enforce_request.call_count, 1)
        upstream_payload = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream_payload["messages"][0]["content"], older_prompt)
        self.assertEqual(upstream_payload["messages"][2]["content"], newest_prompt)

    def test_non_raw_provider_filters_only_after_optimizer_options_are_removed(self):
        upstream_response = self._raw_response(b'{"choices":[]}')
        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.AuthService.get_api_key",
            return_value="openai-provider-key",
        ), patch(
            "app.ProxyService.filter_request_data",
            side_effect=lambda provider, body: body,
        ) as filter_request_data, patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ), reserve_patch, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "openai:gpt-4o",
                    "messages": [{"role": "user", "content": "hello"}],
                    "optimization": {
                        "trigger_input_tokens": 0,
                        "target_input_tokens": 100000,
                    },
                },
            )

        self.assertEqual(response.status_code, 200)
        filtered_payload = json.loads(filter_request_data.call_args.args[1])
        self.assertNotIn("optimization", filtered_payload)

    def test_streaming_response_bytes_remain_unchanged_with_metadata_headers(self):
        native_sse = (
            b'data: {"id":"chatcmpl_1","choices":[{"delta":{"content":"hi"}}]}\n\n'
            b"data: [DONE]\n\n"
        )
        upstream_response = self._raw_response(
            native_sse,
            content_type="text/event-stream",
        )

        reserve_patch, finalize_patch = self._rate_patches()
        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ), patch(
            "routes.optimized.RateLimitService.enforce_request"
        ), reserve_patch, finalize_patch:
            response = self.client.post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "kimi-code:k3",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                    "optimization": {
                        "trigger_input_tokens": 0,
                        "target_input_tokens": 100000,
                    },
                },
            )
            response_data = response.data

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data, native_sse)
        self.assertEqual(response.headers["X-MultiLLM-Optimization"], "skipped")


if __name__ == "__main__":
    unittest.main()
