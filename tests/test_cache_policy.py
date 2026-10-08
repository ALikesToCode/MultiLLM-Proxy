"""Policy-scoped exact caching through the registered Chat Completions route."""

import hashlib
import importlib
import json
import os
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch

from flask import g

from tests.test_chat_cache import BODY, CACHED, chat_cache, completion
from tests.unified_api_test_case import UnifiedApiTestCase


class CachePolicyRouteTest(UnifiedApiTestCase):
    def setUp(self):
        # Patch before application imports as well as the fixture's create_app call.
        self.env_loader = patch("env_loader.load_runtime_env")
        self.env_loader.start()
        self.addCleanup(self.env_loader.stop)
        self.runtime_loader = patch("config.load_runtime_env")
        self.runtime_loader.start()
        self.addCleanup(self.runtime_loader.stop)
        self.network = patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected network call"))
        self.network.start()
        self.addCleanup(self.network.stop)
        super().setUp()
        chat_cache().clear()
        self.app.config["TESTING"] = True
        os.environ["RESPONSE_CACHE_ENABLED"] = "true"
        os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "v1"
        self.retention = {"mode": "legacy", "revision": "legacy"}
        self.workflow = "chat-v1"

        @self.app.before_request
        def resolved_policy():
            g.multillm_retention_policy = self.retention
            g.multillm_workflow_version = self.workflow
            g.request_id = "req_policy_test"

    def tearDown(self):
        chat_cache().clear()
        super().tearDown()

    def _post(self, *, body=BODY, headers=CACHED, reply=None):
        with patch("app.ProxyService.make_request", return_value=reply if reply is not None else completion()) as upstream:
            response = self.client.post("/v1/chat/completions", headers=headers, json=body)
        return response, upstream

    def _assert_miss(self, **kwargs):
        response, upstream = self._post(**kwargs)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.headers.get("X-MultiLLM-Cache"), "miss")
        self.assertEqual(upstream.call_count, 1)
        return response

    def test_unchanged_policy_hits_and_canonical_body_order_does_not_matter(self):
        first = self._assert_miss()
        response, upstream = self._post(body=dict(reversed(list(BODY.items()))))
        self.assertEqual(response.headers["X-MultiLLM-Cache"], "hit")
        self.assertEqual(response.data, first.data)
        upstream.assert_not_called()

    def test_different_authenticated_principals_miss(self):
        self._assert_miss()
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            key = auth.create_user("policy-reader", is_admin=False, scopes=["chat"])["api_key"]
        self._assert_miss(headers={"Authorization": f"Bearer {key}", "X-MultiLLM-Cache": "on"})

    def test_model_permissions_change_invalidates_even_when_requested_model_remains_allowed(self):
        self._assert_miss()
        auth = self.app_module.AuthService
        original = auth.verify_api_key

        def restricted(*args, **kwargs):
            user = original(*args, **kwargs)
            return {**user, "allowed_models": [BODY["model"]]}

        with patch.object(auth, "verify_api_key", side_effect=restricted):
            self._assert_miss()

    def test_effective_secret_policy_changes_miss(self):
        self._assert_miss()
        mode = "block"
        with patch.dict(os.environ, {"SECRET_SCAN_DEFAULT": mode}):
            self._assert_miss()

    def test_retention_revision_and_workflow_version_changes_miss(self):
        self._assert_miss()
        self.retention = {"mode": "legacy", "revision": "reviewed"}
        self._assert_miss()
        self.workflow = "chat-v2"
        self._assert_miss()

    def test_direct_route_configuration_changes_miss(self):
        self._assert_miss()
        self.app.config["API_BASE_URLS"] = {**self.app.config["API_BASE_URLS"], "opencode": "https://provider.invalid/v2"}
        self._assert_miss()

    def test_auto_route_candidate_and_revision_changes_miss(self):
        from services.auto_route_service import AutoRoute, AutoRouteService

        body = {**BODY, "model": "auto:policy-test"}
        route = AutoRoute("auto:policy-test", [BODY["model"]], "first")
        with patch.object(AutoRouteService, "get_route", return_value=route):
            self._assert_miss(body=body)
            response, upstream = self._post(body=body)
            self.assertEqual(response.headers["X-MultiLLM-Cache"], "hit")
            upstream.assert_not_called()
        for route in (
            AutoRoute("auto:policy-test", [BODY["model"]], "second"),
            AutoRoute("auto:policy-test", [BODY["model"], "mimo:mimo-v2.5-pro"], "second"),
        ):
            with patch.object(AutoRouteService, "get_route", return_value=route):
                self._assert_miss(body=body)

    def test_new_revision_cannot_read_legacy_entries_and_does_not_purge_them(self):
        os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "legacy"
        legacy = self._assert_miss(reply=completion("legacy"))
        os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "v1"
        self._assert_miss(reply=completion("isolated"))
        os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "legacy"
        response, upstream = self._post()
        self.assertEqual(response.data, legacy.data)
        upstream.assert_not_called()
        self.assertEqual(chat_cache()._store.stats()["entries"], 2)

    def test_unknown_revision_bypasses_reads_and_writes_without_changing_upstream(self):
        self._assert_miss()
        os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "future"
        for _ in range(2):
            response, upstream = self._post()
            self.assertEqual(response.headers["X-MultiLLM-Cache"], "bypass")
            self.assertEqual(upstream.call_count, 1)
        self.assertEqual(chat_cache()._store.stats()["entries"], 1)
        self.assertEqual(json.loads(upstream.call_args.kwargs["data"])["messages"], BODY["messages"])

    def test_empty_revision_is_the_legacy_default(self):
        from services.cache_policy import LEGACY_REVISION, policy_revision

        for value in ("", "  "):
            os.environ["RESPONSE_CACHE_POLICY_REVISION"] = value
            self.assertEqual(policy_revision(), LEGACY_REVISION)

    def test_default_revision_preserves_legacy_identity_response_and_headers(self):
        os.environ.pop("RESPONSE_CACHE_POLICY_REVISION", None)
        with patch("services.cache_service.time.time", return_value=100):
            first = self._assert_miss(reply=completion("unchanged"))
            hit, upstream = self._post()
        canonical = json.dumps(BODY, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        principal = "admin\x00" + hashlib.sha256(b"admin-test-key").hexdigest()
        expected_key = hashlib.sha256("\x00".join((principal, "/v1/chat/completions", canonical)).encode()).hexdigest()
        self.assertIn(expected_key, chat_cache()._store._entries)
        self.assertEqual(hit.data, first.data)
        self.assertEqual(hit.headers["Age"], "0")
        self.assertEqual(hit.headers["X-MultiLLM-Cache"], "hit")
        self.assertEqual(hit.headers["X-MultiLLM-Route-Decision"], "cache-hit")
        upstream.assert_not_called()
        self.retention = {"mode": "legacy", "revision": "changed"}
        with patch("services.cache_service.time.time", return_value=101):
            response, upstream = self._post()
        self.assertEqual(response.headers["X-MultiLLM-Cache"], "hit")
        upstream.assert_not_called()

    def test_default_bypass_body_headers_and_upstream_payload_are_unchanged(self):
        for headers, body in (
            ({"Authorization": CACHED["Authorization"]}, BODY),
            ({**CACHED, "Cache-Control": "no-store"}, BODY),
            (CACHED, {**BODY, "temperature": 0.7}),
        ):
            with self.subTest(headers=headers, body=body):
                os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "legacy"
                with patch("route_helpers.time.perf_counter", return_value=100):
                    before, sent_before = self._post(body=body, headers=headers)
                os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "v1"
                with patch("route_helpers.time.perf_counter", return_value=100):
                    after, sent_after = self._post(body=body, headers=headers)
                self.assertEqual(after.data, before.data)
                self.assertEqual(dict(after.headers), dict(before.headers))
                self.assertEqual(sent_after.call_args.kwargs["data"], sent_before.call_args.kwargs["data"])

    def test_no_store_does_not_read_or_write_and_refresh_remains_supported(self):
        old = self._assert_miss(reply=completion("old"))
        response, upstream = self._post(headers={**CACHED, "Cache-Control": "no-store"}, reply=completion("private"))
        self.assertNotIn("X-MultiLLM-Cache", response.headers)
        self.assertEqual(upstream.call_count, 1)
        response, upstream = self._post()
        self.assertEqual(response.data, old.data)
        upstream.assert_not_called()
        fresh = self._assert_miss(headers={**CACHED, "X-MultiLLM-Cache": "refresh"}, reply=completion("fresh"))
        response, upstream = self._post()
        self.assertEqual(response.data, fresh.data)
        upstream.assert_not_called()

    def test_cache_disable_ttl_expiry_and_max_age_remain_effective(self):
        with patch("services.cache_service.time.time", return_value=100):
            self._assert_miss()
        with patch("services.cache_service.time.time", return_value=399):
            response, upstream = self._post()
            self.assertEqual(response.headers["X-MultiLLM-Cache"], "hit")
            upstream.assert_not_called()
            self._assert_miss(headers={**CACHED, "Cache-Control": "max-age=1"})
        with patch("services.cache_service.time.time", return_value=699):
            self._assert_miss()
        os.environ["RESPONSE_CACHE_ENABLED"] = "false"
        response, upstream = self._post()
        self.assertEqual(response.headers["X-MultiLLM-Cache"], "bypass")
        self.assertEqual(upstream.call_count, 1)

    def test_incomplete_and_error_responses_are_not_stored(self):
        for reply in (completion(status=500), completion(finish_reason="length")):
            chat_cache().clear()
            self._post(reply=reply)
            self._assert_miss()

    def test_unavailable_policy_bypasses_instead_of_reusing_an_entry(self):
        self._assert_miss()
        with patch("services.cache_policy.resolve_policy", return_value=None):
            response, upstream = self._post()
        self.assertEqual(response.headers["X-MultiLLM-Cache"], "bypass")
        self.assertEqual(upstream.call_count, 1)

    def test_policy_loading_failure_bypasses_without_suppressing_the_normal_response(self):
        self._assert_miss()
        with patch("services.cache_policy._resolved_route", side_effect=RuntimeError("Unavailable policy store")):
            response, upstream = self._post(reply=completion("fresh"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Cache"], "bypass")
        self.assertEqual(upstream.call_count, 1)
        self.assertEqual(chat_cache()._store.stats()["entries"], 1)

    def test_disabled_model_never_replays_a_previously_allowed_answer(self):
        self._assert_miss()
        from services.model_registry import ModelRegistry

        with patch.object(ModelRegistry, "get_model_status", return_value="disabled"):
            response, upstream = self._post()
        self.assertEqual(response.status_code, 400)
        upstream.assert_not_called()

    def test_unrecognized_or_nonstoring_retention_policy_bypasses(self):
        self._assert_miss()
        for mode in ("zero-content", "unknown"):
            self.retention = {"mode": mode, "revision": "new"}
            response, upstream = self._post()
            self.assertEqual(response.headers["X-MultiLLM-Cache"], "bypass")
            self.assertEqual(upstream.call_count, 1)

    def test_policy_change_during_generation_does_not_store_under_old_identity(self):
        def changed_policy(**kwargs):
            self.retention["revision"] = "changed-during-generation"
            return completion("in flight")

        with patch("app.ProxyService.make_request", side_effect=changed_policy) as upstream:
            response = self.client.post("/v1/chat/completions", headers=CACHED, json=BODY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(upstream.call_count, 1)
        self.assertEqual(chat_cache()._store.stats()["entries"], 0)
        self.retention["revision"] = "legacy"
        self._assert_miss()

    def test_revision_change_during_generation_does_not_write_a_stale_entry(self):
        def changed_revision(**kwargs):
            os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "future"
            return completion("in flight")

        with patch("app.ProxyService.make_request", side_effect=changed_revision):
            response = self.client.post("/v1/chat/completions", headers=CACHED, json=BODY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(chat_cache()._store.stats()["entries"], 0)

    def test_concurrent_misses_execute_independently_and_store_only_real_completions(self):
        barrier = threading.Barrier(2)

        def upstream_reply(**kwargs):
            barrier.wait(timeout=5)
            return completion("concurrent")

        def send():
            with self.app.test_client() as client:
                return client.post("/v1/chat/completions", headers=CACHED, json=BODY)

        with patch("app.ProxyService.make_request", side_effect=upstream_reply) as upstream:
            with ThreadPoolExecutor(max_workers=2) as pool:
                responses = list(pool.map(lambda _: send(), range(2)))
        self.assertEqual(upstream.call_count, 2)
        for response in responses:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["X-MultiLLM-Cache"], "miss")
            self.assertEqual(response.json["choices"][0]["message"]["content"], "concurrent")
        self.assertEqual(chat_cache()._store.stats()["entries"], 1)
        response, upstream = self._post()
        self.assertEqual(response.headers["X-MultiLLM-Cache"], "hit")
        upstream.assert_not_called()

    def test_unsupported_policy_revisions_do_not_change_raw_provider_traffic(self):
        with patch("route_helpers.time.perf_counter", return_value=100):
            with patch("app.ProxyService.make_request", return_value=completion()) as upstream:
                before = self.client.post("/opencode/v1/chat/completions", headers=CACHED, json=BODY)
                before_payload = upstream.call_args.kwargs["data"]
                os.environ["RESPONSE_CACHE_POLICY_REVISION"] = "future"
                after = self.client.post("/opencode/v1/chat/completions", headers=CACHED, json=BODY)
        self.assertEqual(before.status_code, 200)
        self.assertEqual(after.data, before.data)
        self.assertEqual(dict(after.headers), dict(before.headers))
        self.assertEqual(upstream.call_count, 2)
        self.assertEqual(upstream.call_args.kwargs["data"], before_payload)
        self.assertNotIn("X-MultiLLM-Cache", after.headers)


class CachePolicyDigestTest(unittest.TestCase):
    def test_policy_digest_is_canonical_and_every_policy_boundary_changes_identity(self):
        policy = importlib.import_module("services.cache_policy")
        snapshot = policy.CachePolicy(
            {"model": "opencode:glm-5.2", "options": {"a": 1, "b": 2}},
            ["opencode:*"], "redact", {"mode": "legacy", "revision": "first"}, "chat-v1",
        )
        digest = policy.policy_digest(snapshot)
        self.assertEqual(digest, policy.policy_digest(replace(snapshot, resolved_route={
            "options": {"b": 2, "a": 1}, "model": "opencode:glm-5.2",
        })))
        for field, value in (
            ("resolved_route", {"model": "mimo:mimo-v2.5-pro"}),
            ("model_permissions", ["*"]), ("secret_policy", "block"),
            ("retention_policy", {"mode": "legacy", "revision": "second"}),
            ("workflow_version", "chat-v2"),
        ):
            self.assertNotEqual(policy.policy_digest(replace(snapshot, **{field: value})), digest)
        self.assertEqual(len(digest), 64)

    def test_invalid_policy_values_do_not_produce_a_shared_digest(self):
        policy = importlib.import_module("services.cache_policy")
        snapshot = policy.CachePolicy({}, None, "redact", {"revision": float("nan")}, "chat-v1")
        with self.assertRaises(ValueError):
            policy.policy_digest(snapshot)
