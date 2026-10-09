"""Registered Flask paths exercise the opt-in gateway lifecycle with fake I/O."""
import importlib
import json
import os
import time
from unittest.mock import Mock, patch

from flask import Response, g

from services import admission_leases, usage_ledger
from services.admission_leases import AdmissionError
from services.config_revision_sync import SyncSettings
from services.model_cooldown import ModelCooldownExhausted
from services.model_cooldown import model_cooldown
from services.credential_pool import CredentialPool
from tests.unified_api_test_case import UnifiedApiTestCase
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate, policy
from services.intelligence_store import IntelligenceStore

FLAGS = ("ADMISSION_ENABLED", "MODEL_COOLDOWN_ENABLED", "CONTENT_RETENTION_ENABLED",
         "RATE_LIMIT_HEADERS_ENABLED", "CONFIG_REVISION_SYNC_ENABLED",
         "PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "UPSTREAM_RETRY_AFTER_ADVICE_ENABLED")
AUTH = {"Authorization": "Bearer admin-test-key"}
BODY = {"model": "opencode:glm-5.2", "messages": [{"role": "user", "content": "hi"}], "temperature": 0}


class Wave3IntegrationTest(UnifiedApiTestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {name: "false" for name in FLAGS})
        self.env_patch.start()
        self.loader = patch("config.load_runtime_env", return_value=None)
        self.loader.start()
        super().setUp()
        self.rows = []
        model_cooldown.reset()
        CredentialPool.reset()
        self.recorder = patch("services.request_accounting.usage_ledger.LEDGER.record", side_effect=self.rows.append)
        self.recorder.start()
        importlib.import_module("routes.chat_cache").clear()

    def tearDown(self):
        self.recorder.stop()
        model_cooldown.reset()
        CredentialPool.reset()
        usage_ledger.LEDGER.reset()
        super().tearDown()
        self.loader.stop()
        self.env_patch.stop()

    def chat(self, *, headers=None, stream=False):
        return self.client.post("/v1/chat/completions", headers={**AUTH, **(headers or {})},
                                json={**BODY, **({"stream": True} if stream else {})})

    def lease_client(self, *, denied=False):
        os.environ.update(ADMISSION_ENABLED="true", ADMISSION_LIMITS_JSON='{"principal":1}')
        lease = Mock()
        client = Mock()
        client.acquire.side_effect = AdmissionError("admission_denied", 429, 7) if denied else None
        client.acquire.return_value = lease
        self.app.extensions["admission_client"] = client
        return client, lease

    def test_identity_vector(self):
        self.assertEqual(admission_leases.principal_hash(" admin "),
            "a5d35b6466ec3a0d0858b4eb73370c1703f8ccdb68c6586f9d41d1cd0075ddec")

    def test_admission_denial_precedes_dispatch(self):
        client, _ = self.lease_client(denied=True)
        with patch("app.ProxyService.make_request") as dispatch:
            response = self.chat()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "7")
        dispatch.assert_not_called()
        identity = client.acquire.call_args.args[0]
        self.assertEqual(identity.model_group, BODY["model"])
        self.assertEqual(identity.principal_hash, admission_leases.principal_hash("admin"))
        self.assertTrue(callable(client.acquire.call_args.kwargs["on_lost"]))

    def test_admission_releases_once_and_excludes_usage_reads(self):
        client, lease = self.lease_client()
        with patch("app.ProxyService.make_request", return_value=self._chat_response()):
            response = self.chat()
        self.assertEqual(response.status_code, 200)
        response.close()
        lease.release.assert_called_once()
        client.acquire.reset_mock()
        self.client.get("/v1/usage", headers=AUTH)
        client.acquire.assert_not_called()

    def test_raw_admission_uses_provider_model(self):
        client, lease = self.lease_client()
        with patch("app.ProxyService.make_request", return_value=self._chat_response()):
            response = self.client.post("/opencode/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "glm-5.2"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.acquire.call_args.args[0].model_group, "opencode:glm-5.2")
        response.close()
        lease.release.assert_called_once()

    def test_cooldown_error_keeps_retry_advice(self):
        os.environ["MODEL_COOLDOWN_ENABLED"] = "true"
        with patch.object(self.app_module.AuthService, "get_api_key", side_effect=ModelCooldownExhausted(9)):
            response = self.chat()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "9")

    def test_real_pool_scopes_throttle_and_uses_normalized_retry_advice(self):
        os.environ.update({name: "" for name in os.environ
                           if name.startswith("CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL_")})
        os.environ.update(MODEL_COOLDOWN_ENABLED="true", UPSTREAM_RETRY_AFTER_ADVICE_ENABLED="true",
                          CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL="synthetic-pro-key")
        self.app.config["PROVIDER_QUOTA_BUCKETS"] = {"ce-gpt-pro": "chat"}
        self.assertEqual(len(CredentialPool.keys("ce-gpt-pro")), 1)
        rejected = self._chat_response()
        rejected.status_code = 429
        rejected.headers["Retry-After"] = "9"
        with patch.object(self.app_module.ProxyService, "_make_base_request", return_value=rejected) as send, \
             patch.object(CredentialPool, "select", wraps=CredentialPool.select) as select, \
             patch("services.model_cooldown.time.monotonic", return_value=1000):
            first = self.client.post("/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "ce-gpt-pro:gpt-6.1-sol"})
            self.assertEqual(model_cooldown.entry_count, 1)
            second = self.client.post("/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "ce-gpt-pro:gpt-6.1-sol"})
            self.assertTrue(select.called)
            self.assertTrue(all(call.kwargs == {"model": "gpt-6.1-sol", "quota_bucket": "chat"}
                                for call in select.call_args_list), [call.kwargs for call in select.call_args_list])
        self.assertEqual(first.status_code, 429)
        self.assertEqual(second.status_code, 429)
        self.assertIn(int(second.headers["Retry-After"]), (8, 9))
        self.assertEqual(send.call_count, 1)
        self.assertEqual(second.get_json()["error"], "model_cooldown")

    def test_endpoint_permission_denial_does_not_cool_every_model(self):
        os.environ.update(MODEL_COOLDOWN_ENABLED="true",
                          CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL="synthetic-pro-key")
        denied = self._chat_response()
        denied.status_code = 403
        with patch.object(self.app_module.ProxyService, "_make_base_request",
                side_effect=[denied, self._chat_response()]) as send:
            self.client.post("/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "ce-gpt-pro:gpt-6.1-sol"})
            response = self.client.post("/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "ce-gpt-pro:gpt-6.1-sol"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_count, 2)

    def test_enabled_cooldown_keeps_raw_non_json_body_unchanged(self):
        os.environ.update(MODEL_COOLDOWN_ENABLED="true",
                          CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL="synthetic-pro-key")
        self.app.config["PROVIDER_QUOTA_BUCKETS"] = {"ce-gpt-pro": "audio"}
        body = b"--boundary\r\nopaque\xff\r\n--boundary--\r\n"
        with patch.object(self.app_module.ProxyService, "_make_base_request", return_value=self._chat_response()) as send:
            response = self.client.post("/ce-gpt-pro/v1/chat/completions", headers=AUTH,
                data=body, content_type="multipart/form-data; boundary=boundary")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_args.kwargs["data"], body)

    def test_admission_loss_cancels_upstream_and_releases_once(self):
        client, lease = self.lease_client()
        upstream = self._chat_response()
        upstream.headers["content-type"] = "text/event-stream"
        upstream.iter_content = lambda chunk_size: iter([b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n', b'data: [DONE]\n\n'])
        close = Mock()
        upstream.close = close
        with patch.object(self.app_module.ProxyService, "_make_base_request", return_value=upstream):
            response = self.client.post("/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "mimo:mimo-v2.5-pro", "stream": True})
            client.acquire.call_args.kwargs["on_lost"](AdmissionError())
            response.close()
            response.close()
        close.assert_called_once()
        lease.release.assert_called_once()
        self.assertEqual(self.rows[0]["status"], 499)
        self.assertIsNone(self.rows[0]["input_tokens"])

    def test_admission_uses_intelligence_deadline_without_resetting_it(self):
        client, _ = self.lease_client(denied=True)
        with patch("services.intelligence_store.IntelligenceStore.policy", return_value={"deadline_ms": 5000}):
            before = time.time() * 1000
            response = self.client.post("/v1/chat/completions",
                headers=AUTH, json={**BODY, "model": "auto:intelligence", "routing": {"deadline_ms": 1000}})
        self.assertEqual(response.status_code, 429)
        deadline = client.acquire.call_args.args[0].deadline_ms
        self.assertGreater(deadline, before)
        self.assertLessEqual(deadline, before + 1100)

    def test_retention_bypasses_real_cache(self):
        os.environ["CONTENT_RETENTION_ENABLED"] = "true"
        with patch("app.ProxyService.make_request", side_effect=lambda **kwargs: self._chat_response()) as dispatch:
            for _ in range(2):
                response = self.chat(headers={"X-MultiLLM-Cache": "on", "X-MultiLLM-Retention": "zero"})
                self.assertEqual(response.status_code, 200)
            self.assertEqual(dispatch.call_count, 2)

    def test_all_flags_retention_precedes_admission_and_no_cache_write(self):
        os.environ.update({name: "true" for name in FLAGS})
        client, _ = self.lease_client(denied=True)
        seen = []
        def acquire(identity, **kwargs):
            seen.append(g.multillm_retention_policy["mode"])
            raise AdmissionError("admission_denied", 429, 7)
        client.acquire.side_effect = acquire
        with patch("app.ProxyService.make_request") as dispatch:
            response = self.chat(headers={"X-MultiLLM-Cache": "on", "X-MultiLLM-Retention": "zero"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(seen, ["zero"])
        dispatch.assert_not_called()
        self.assertEqual(self.rows, [])

    def test_rate_headers_only_on_managed_paths(self):
        os.environ["RATE_LIMIT_HEADERS_ENABLED"] = "true"
        with patch("app.ProxyService.make_request", side_effect=lambda **kwargs: self._chat_response()):
            managed = self.chat()
            raw = self.client.post("/opencode/v1/chat/completions", headers=AUTH,
                                   json={**BODY, "model": "glm-5.2"})
        self.assertIn("X-MultiLLM-RateLimit-Limit", managed.headers)
        self.assertFalse(any(name.startswith("X-MultiLLM-RateLimit-") for name in raw.headers.keys()))

    def test_revision_guard_runs_before_authentication(self):
        sync = Mock(settings=SyncSettings(True, 30, 5))
        sync.security_ready.return_value = False
        extensions = importlib.import_module("services.gateway_extensions")
        with patch.object(extensions, "configure_sync", return_value=sync), \
             patch.object(extensions, "supported_settings", return_value=sync.settings):
            guarded = self.app_module.create_app().test_client()
        with patch.object(self.app_module.AuthService, "verify_api_key") as authenticate:
            response = guarded.post("/v1/chat/completions", headers=AUTH, json=BODY)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"]["code"], "config_security_stale")
        authenticate.assert_not_called()

    def test_prompt_cache_buckets_reach_sqlite_from_managed_chat(self):
        os.environ.update(PROMPT_CACHE_USAGE_BUCKETS_ENABLED="true", USAGE_LEDGER_BACKEND="sql", USAGE_LEDGER_ENABLED="true",
                          USAGE_DB_PATH=os.path.join(self.temp_dir.name, "usage.sqlite3"))
        response = self._chat_response()
        response._content = json.dumps({"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10,
                      "prompt_tokens_details": {"cached_tokens": 60}}}).encode()
        self.recorder.stop()
        try:
            with patch("app.ProxyService.make_request", return_value=response):
                self.assertEqual(self.chat().status_code, 200)
            self.assertTrue(usage_ledger.LEDGER.flush())
            store = usage_ledger.LEDGER.store()
        finally:
            self.recorder.start()
        recent = store.recent("2000", None, None, 10)
        self.assertEqual(recent[0]["ordinary_input_tokens"], 40)
        self.assertEqual(recent[0]["cache_read_input_tokens"], 60)

    def test_stream_cancellation_closes_hidden_upstream_and_records_unknown(self):
        class Upstream:
            status_code = 200
            headers = {"content-type": "text/event-stream"}
            raw = None
            closes = 0
            def iter_content(self, chunk_size):
                yield b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'
                yield b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\n'
                yield b'data: [DONE]\n\n'
            def close(self):
                self.closes += 1
        upstream = Upstream()
        with patch.object(self.app_module.ProxyService, "_make_base_request", return_value=upstream):
            response = self.client.post("/v1/chat/completions", headers=AUTH,
                json={**BODY, "model": "mimo:mimo-v2.5-pro", "stream": True})
            self.assertEqual(response.status_code, 200)
            response.close()
            response.close()
        self.assertEqual(upstream.closes, 1)
        self.assertEqual(self.rows[0]["status"], 499)
        self.assertIsNone(self.rows[0]["input_tokens"])
        self.assertIsNone(self.rows[0]["output_tokens"])
        self.assertIsNone(self.rows[0]["cost_usd"])

    def test_close_before_first_iteration_owns_hidden_upstream(self):
        upstream = Mock(status_code=200, headers={"content-type": "text/event-stream"})
        close = upstream.close
        with self.app.test_request_context("/v1/chat/completions", method="POST", headers=AUTH,
                json={**BODY, "model": "mimo:mimo-v2.5-pro", "stream": True}), \
             patch.object(self.app_module.ProxyService, "_make_base_request", return_value=upstream):
            response = self.app.full_dispatch_request()
            self.assertEqual(response.status_code, 200)
            response.close()
            response.close()
        close.assert_called_once()

    def test_rejected_response_cleanup_keeps_conclusive_accounting(self):
        from services.request_accounting import UsageContext
        from services.upstream_transport import close_retry_response
        upstream = Mock(status_code=429, headers={"content-type": "application/json"})
        close = upstream.close
        with self.app.test_request_context("/v1/chat/completions", method="POST", json=BODY):
            context = g.usage_context = UsageContext("chat", [BODY["model"]], "opencode", {}, 0, 0)
            close_retry_response(upstream)
            self.assertFalse(context.ambiguous)
        close.assert_called_once()

    def test_all_flags_off_matches_app_without_hooks_byte_for_byte(self):
        with patch.object(self.app_module, "register_gateway_extensions", return_value=None):
            baseline = self.app_module.create_app().test_client()
        stream = b'data: {"choices":[{"delta":{"content":"first"}}]}\n\ndata: [DONE]\n\n'
        def fake(**kwargs):
            if json.loads(kwargs["data"]).get("stream"):
                return Response(iter([stream]), mimetype="text/event-stream")
            return self._chat_response()
        for path, body in (("/v1/chat/completions", BODY),
                           ("/v1/chat/completions", {**BODY, "stream": True}),
                           ("/opencode/v1/chat/completions", {**BODY, "model": "glm-5.2"}),
                           ("/v1/usage", None)):
            replies = []
            recorded = []
            for client in (baseline, self.client):
                self.rows.clear()
                with patch("app.ProxyService.make_request", side_effect=fake), \
                     patch("time.perf_counter", return_value=100.0), \
                     patch("services.usage_ledger.utc_timestamp", return_value="2026-01-01T00:00:00.000Z"):
                    headers = {**AUTH, "X-Request-ID": "test-wave-three"}
                    response = client.get(path, headers=headers) if body is None else client.post(path, headers=headers, json=body)
                    replies.append((response.status_code, response.get_data(), list(response.headers)))
                    response.close()
                    recorded.append(list(self.rows))
            self.assertEqual(replies[0], replies[1], path)
            self.assertEqual(recorded[0], recorded[1], path)


class Wave3IntelligenceIntegrationTest(IntelligenceApiTestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {name: "false" for name in FLAGS})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.loader = patch("config.load_runtime_env", return_value=None)
        self.loader.start()
        self.addCleanup(self.loader.stop)
        super().setUp()
        model_cooldown.reset()
        CredentialPool.reset()
        self.addCleanup(model_cooldown.reset)
        self.addCleanup(CredentialPool.reset)

    def test_unlimited_group_does_not_install_an_admission_deadline(self):
        self.seed()
        with patch.dict(os.environ, ADMISSION_ENABLED="true",
                        ADMISSION_LIMITS_JSON='{"model_groups":{"opencode:other":1}}'):
            client = self.app.extensions["admission_client"] = Mock()
            with self.requests(return_value=upstream(completion())):
                response = self.post()
        self.assertEqual(response.status_code, 200)
        client.acquire.assert_not_called()

    def test_scoped_exhaustion_never_falls_back_and_preserves_streaming_429(self):
        IntelligenceStore.seed(policy(candidates=[candidate("ce-gpt-pro:gpt-6.1-sol"),
                                                  candidate("navyai:large", quality_tier=2)]))
        with patch.dict(os.environ, MODEL_COOLDOWN_ENABLED="true"):
            CredentialPool.record("ce-gpt-pro", "synthetic-provider-key", 429,
                                  model="gpt-6.1-sol", retry_after_seconds=9)
            with self.requests() as send:
                for stream in (False, True):
                    response = self.post(stream=stream)
                    self.assertEqual(response.status_code, 429)
                    self.assertEqual(response.get_json()["error"], "model_cooldown")
                    self.assertIn(int(response.headers["Retry-After"]), (8, 9))
                send.assert_not_called()
