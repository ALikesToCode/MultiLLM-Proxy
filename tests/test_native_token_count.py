"""Native Messages counts must remain authorized, bounded and explicit."""

import io
import json
import os
from unittest.mock import Mock, patch

import requests

from tests.unified_api_test_case import UnifiedApiTestCase


class NativeTokenCountTest(UnifiedApiTestCase):
    BODY = {"model": "opencode:minimax-m3", "messages": [{"role": "user", "content": "hello"}]}
    HEADERS = {"x-api-key": "admin-test-key", "anthropic-version": "2023-06-01"}

    def setUp(self):
        super().setUp()
        os.environ["NATIVE_TOKEN_COUNT_ENDPOINTS_JSON"] = json.dumps({"opencode": "/v1/messages/count_tokens"})
        self.session = Mock()
        self.session.post.return_value = self.upstream({"input_tokens": 123})
        self.session_patch = patch("services.proxy_service.ProxyService._get_provider_session", return_value=self.session)
        self.session_factory = self.session_patch.start()
        self.addCleanup(self.session_patch.stop)
        self.generation_patch = patch("services.proxy_service.ProxyService.make_request")
        self.generation = self.generation_patch.start()
        self.addCleanup(self.generation_patch.stop)

    @staticmethod
    def upstream(body=None, status=200, raw=None):
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(raw if raw is not None else json.dumps(body).encode())
        response.headers["Content-Type"] = "application/json"
        response.close = Mock(wraps=response.close)
        return response

    def post(self, mode=None, body=None, headers=None):
        headers = dict(self.HEADERS if headers is None else headers)
        if mode is not None:
            headers["X-MultiLLM-Token-Count-Mode"] = mode
        return self.client.post("/v1/messages/count_tokens", headers=headers, json=self.BODY if body is None else body)

    def assert_error(self, response, status):
        self.assertEqual(response.status_code, status, response.get_data(as_text=True))
        self.assertEqual(response.json["type"], "error")
        self.assertTrue(response.json["error"]["message"])
        self.assertNotIn("X-MultiLLM-Token-Count", response.headers)
        self.assertNotIn("X-MultiLLM-Token-Count-Fallback", response.headers)

    def test_default_and_explicit_estimate_are_unchanged(self):
        from routes.unified_messages import estimate_message_tokens

        malformed_config = "{not-json"
        os.environ["NATIVE_TOKEN_COUNT_ENDPOINTS_JSON"] = malformed_config
        body = {**self.BODY, "system": "x" * 400,
                "tools": [{"name": "f", "input_schema": {"type": "object"}}],
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "synthetic"}},
                ]}]}
        expected = estimate_message_tokens(body)
        for mode in (None, "estimate"):
            with self.subTest(mode=mode):
                response = self.post(mode, body)
                self.assertEqual(response.json, {"input_tokens": expected})
                self.assertEqual(response.headers["X-MultiLLM-Token-Count"], "estimate")
                self.assertNotIn("X-MultiLLM-Token-Count-Fallback", response.headers)
        self.session_factory.assert_not_called()
        self.generation.assert_not_called()

    def test_invalid_modes_are_rejected(self):
        for mode in ("", "Native", "foo", "auto,native"):
            with self.subTest(mode=mode):
                self.assert_error(self.post(mode), 400)
        self.session_factory.assert_not_called()

    def test_authentication_precedes_upstream_dispatch(self):
        for headers in ({}, {"x-api-key": "invalid"}):
            self.assert_error(self.post("native", headers=headers), 401)
        self.session_factory.assert_not_called()

    def test_original_model_is_authorized_before_credentials_or_dispatch(self):
        from services.auth_service import AuthService

        user = {"username": "restricted", "scopes": ["chat"], "allowed_models": ["minimax-m3"]}
        with (patch.object(AuthService, "verify_api_key", return_value=user),
              patch.object(AuthService, "get_api_key") as credentials):
            self.assert_error(self.post("native"), 403)
            credentials.assert_not_called()
        self.session_factory.assert_not_called()

    def test_estimate_mode_keeps_its_contract_for_restricted_keys(self):
        from services.auth_service import AuthService

        user = {"username": "restricted", "scopes": ["chat"], "allowed_models": ["minimax-m3"]}
        with patch.object(AuthService, "verify_api_key", return_value=user):
            response = self.post("estimate")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Token-Count"], "estimate")
        self.session_factory.assert_not_called()

    def test_native_success_preserves_count_fields_and_strips_model_prefix(self):
        body = {**self.BODY, "model": "opencode:vendor/model:variant", "system": [{"type": "text", "text": "rules"}],
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "describe"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "synthetic"}},
                ]}],
                "tools": [{"name": "f", "input_schema": {"type": "object"}}],
                "tool_choice": {"type": "auto"}, "thinking": {"type": "enabled", "budget_tokens": 100},
                "max_tokens": 999, "stream": True, "temperature": 0.5, "foreign_extra": "omit"}
        upstream = self.session.post.return_value
        response = self.post("native", body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"input_tokens": 123})
        self.assertEqual(response.headers["X-MultiLLM-Token-Count"], "provider")
        self.assertNotIn("X-MultiLLM-Token-Count-Fallback", response.headers)
        self.session_factory.assert_called_once_with("opencode", raw_passthrough=True)
        self.session.post.assert_called_once()
        kwargs = self.session.post.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://opencode.ai/v1/messages/count_tokens")
        self.assertEqual(kwargs["json"], {key: value for key, value in body.items()
                                        if key in {"messages", "system", "tools", "tool_choice", "thinking"}}
                         | {"model": "vendor/model:variant"})
        self.assertEqual(kwargs["timeout"], (5, 10))
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer opencode-provider-key")
        self.assertEqual(kwargs["headers"]["Anthropic-Version"], "2023-06-01")
        upstream.close.assert_called_once()
        self.generation.assert_not_called()

    def test_configured_auto_uses_native_count(self):
        response = self.post("auto")
        self.assertEqual(response.json, {"input_tokens": 123})
        self.assertEqual(response.headers["X-MultiLLM-Token-Count"], "provider")

    def test_header_builder_uses_configured_count_path(self):
        from services.proxy_service import ProxyService

        with (patch.dict(os.environ, {"NATIVE_TOKEN_COUNT_ENDPOINTS_JSON": json.dumps({"linkapi": "/v1/messages/count_tokens"})}),
              patch.object(ProxyService, "prepare_headers", wraps=ProxyService.prepare_headers) as prepare):
            response = self.post("native", {**self.BODY, "model": "linkapi:claude-model"})
        self.assertEqual(response.json, {"input_tokens": 123})
        self.assertEqual(prepare.call_args.kwargs["upstream_path"], "/v1/messages/count_tokens")
        self.assertEqual(self.session.post.call_args.kwargs["headers"]["X-Api-Key"], "linkapi-provider-key")

    def test_unsupported_modes_are_explicit(self):
        for model in ("auto:route", "minimax-m3", "unknown:model", "opencode:"):
            with self.subTest(model=model):
                body = {**self.BODY, "model": model}
                estimated = self.post("auto", body)
                self.assertEqual(estimated.status_code, 200)
                self.assertEqual(estimated.headers["X-MultiLLM-Token-Count"], "estimate")
                self.assertEqual(estimated.headers["X-MultiLLM-Token-Count-Fallback"], "unsupported")
                unsupported = self.post("native", body)
                self.assert_error(unsupported, 501)
                self.assertIn("unsupported native counting", unsupported.json["error"]["message"].lower())
        self.session_factory.assert_not_called()

    def test_unconfigured_endpoint_or_credentials_is_unsupported(self):
        from services.auth_service import AuthService

        for config in (None, "{}"):
            with patch.dict(os.environ):
                if config is None:
                    os.environ.pop("NATIVE_TOKEN_COUNT_ENDPOINTS_JSON", None)
                else:
                    os.environ["NATIVE_TOKEN_COUNT_ENDPOINTS_JSON"] = config
                self.assertEqual(self.post("auto").headers["X-MultiLLM-Token-Count-Fallback"], "unsupported")
                self.assert_error(self.post("native"), 501)
        with patch.object(AuthService, "get_api_key", return_value=None):
            self.assertEqual(self.post("auto").headers["X-MultiLLM-Token-Count-Fallback"], "unsupported")
            self.assert_error(self.post("native"), 501)
        self.session_factory.assert_not_called()

    def test_malformed_config_and_unregistered_provider_fail_safely(self):
        for config in ("not-json", "[]", "null", '{"unknown":"/v1/messages/count_tokens"}',
                       '{"opencode":7}', '{"auto":"/v1/messages/count_tokens"}'):
            with self.subTest(config=config), patch.dict(os.environ, NATIVE_TOKEN_COUNT_ENDPOINTS_JSON=config):
                for mode in ("auto", "native"):
                    self.assert_error(self.post(mode), 500)
        self.session_factory.assert_not_called()

    def test_invalid_endpoint_paths_fail_without_dispatch(self):
        for path in ("https://other.example/v1/messages/count_tokens", "//other.example/messages/count_tokens",
                     "v1/messages/count_tokens", "/v1/../messages/count_tokens", "/./messages/count_tokens",
                     "/v1/messages/count_tokens?x=1", "/v1/messages/count_tokens#fragment",
                     "/v1/messages", "/v1//messages/count_tokens", "/v1/%2e%2e/messages/count_tokens",
                     "/v1\\messages/count_tokens", "/v1/\n/messages/count_tokens"):
            with self.subTest(path=path), patch.dict(os.environ, NATIVE_TOKEN_COUNT_ENDPOINTS_JSON=json.dumps({"opencode": path})):
                self.assert_error(self.post("auto"), 500)
        self.session_factory.assert_not_called()

    def test_exact_origin_path_replaces_base_prefix(self):
        for base in ("https://trusted.example/v1", "https://trusted.example/api/coding/v1/", "https://trusted.example:8443/v1"):
            with self.subTest(base=base), patch.dict(os.environ, {"NATIVE_TOKEN_COUNT_ENDPOINTS_JSON": json.dumps({"opencode": "/api/coding/v1/messages/count_tokens"})}):
                self.app.config["API_BASE_URLS"] = {"opencode": base}
                self.session.post.return_value = self.upstream({"input_tokens": 0})
                self.assertEqual(self.post("native").json, {"input_tokens": 0})
                origin = base.split("/v1")[0] if "/api" not in base else "https://trusted.example"
                self.assertEqual(self.session.post.call_args.kwargs["url"], origin + "/api/coding/v1/messages/count_tokens")

    def test_invalid_trusted_origin_never_dispatches(self):
        for base in ("file:///v1", "https:///v1", "https://user:password@trusted.example/v1",
                     "https://trusted.example:99999/v1", "https://trusted.example\\other/v1",
                     "https://trusted.example/white space/v1"):
            with self.subTest(base=base):
                self.app.config["API_BASE_URLS"] = {"opencode": base}
                self.assert_error(self.post("native"), 500)
        self.session_factory.assert_not_called()

    def test_upstream_errors_never_fall_back(self):
        for mode in ("auto", "native"):
            for status in (400, 401, 403, 404, 429, 500, 502, 503, 504):
                with self.subTest(mode=mode, status=status):
                    upstream = self.upstream({"error": {"message": "provider rejected request"}}, status)
                    self.session.post.return_value = upstream
                    self.assert_error(self.post(mode), status)
                    upstream.close.assert_called_once()
        self.assertEqual(self.session.post.call_count, 18)
        self.generation.assert_not_called()

    def test_redirects_are_terminal_protocol_errors(self):
        upstream = self.upstream(status=307, raw=b"redirect")
        upstream.headers["Location"] = "https://other.example"
        self.session.post.return_value = upstream
        self.assert_error(self.post("auto"), 502)
        self.session.post.assert_called_once()
        upstream.close.assert_called_once()

    def test_timeout_and_transport_failures_do_not_retry(self):
        for mode in ("auto", "native"):
            for error, status in ((requests.Timeout("private detail"), 504), (requests.ConnectionError("private detail"), 502)):
                with self.subTest(mode=mode, error=type(error)):
                    self.session.post.reset_mock()
                    self.session.post.side_effect = error
                    response = self.post(mode)
                    self.assert_error(response, status)
                    self.assertNotIn("private detail", response.get_data(as_text=True))
                    self.session.post.assert_called_once()

    def test_invalid_counts_and_json_are_terminal_errors(self):
        for body in ({}, [], {"input_tokens": True}, {"input_tokens": "123"}, {"input_tokens": -1},
                     {"input_tokens": 1.5}, {"input_tokens": None}, {"input_tokens": float("inf")},
                     {"input_tokens": float("nan")}, {"input_tokens": 4, "extra": float("nan")}):
            with self.subTest(body=body):
                upstream = self.upstream(body)
                self.session.post.return_value = upstream
                self.assert_error(self.post("auto"), 502)
                upstream.close.assert_called_once()
        upstream = self.upstream(raw=b"not json")
        self.session.post.return_value = upstream
        self.assert_error(self.post("native"), 502)
        upstream.close.assert_called_once()

    def test_response_limit_and_read_timeout_close_once(self):
        for raw in (b" " * 65537, b'{"input_tokens":1,"padding":"' + b"x" * 65536 + b'"}'):
            upstream = self.upstream(raw=raw)
            self.session.post.return_value = upstream
            self.assert_error(self.post("native"), 502)
            upstream.close.assert_called_once()
        upstream = self.upstream({"input_tokens": 1})
        upstream.iter_content = Mock(side_effect=requests.Timeout("read timed out"))
        self.session.post.return_value = upstream
        self.assert_error(self.post("auto"), 504)
        upstream.close.assert_called_once()

    def test_wrapped_read_timeout_closes_once(self):
        from urllib3.exceptions import ReadTimeoutError

        upstream = self.upstream({"input_tokens": 1})
        upstream.iter_content = Mock(side_effect=requests.ConnectionError(ReadTimeoutError(None, None, "read timeout")))
        self.session.post.return_value = upstream
        self.assert_error(self.post("auto"), 504)
        self.session.post.assert_called_once()
        upstream.close.assert_called_once()

    def test_exact_response_bound_and_chunked_json(self):
        raw = b'{"input_tokens":42}'
        upstream = self.upstream(raw=raw + b" " * (65536 - len(raw)))
        self.session.post.return_value = upstream
        self.assertEqual(self.post("native").json, {"input_tokens": 42})
        upstream.close.assert_called_once()
        upstream = self.upstream()
        upstream.iter_content = Mock(return_value=iter([b'{"input_', b'tokens":', b"42}"]))
        self.session.post.return_value = upstream
        self.assertEqual(self.post("native").json, {"input_tokens": 42})
        upstream.close.assert_called_once()

    def test_configured_headers_ignore_caller_credentials(self):
        headers = {**self.HEADERS, "Authorization": "Bearer untrusted-caller-value", "anthropic-beta": "count-test",
                   "X-MultiLLM-Api-Key": "admin-test-key", "x-api-key": "untrusted-caller-value", "Cookie": "stream=true"}
        self.assertEqual(self.post("native", headers=headers).status_code, 200)
        forwarded = self.session.post.call_args.kwargs["headers"]
        self.assertEqual(forwarded["Authorization"], "Bearer opencode-provider-key")
        self.assertEqual(forwarded["Anthropic-Beta"], "count-test")
        self.assertNotIn("untrusted-caller-value", str(forwarded))
        self.assertNotIn("admin-test-key", str(forwarded))
