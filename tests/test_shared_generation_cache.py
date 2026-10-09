"""Shared exact responses through authenticated Chat Completions and bounded storage."""
import base64
import importlib
import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

from tests.test_chat_cache import BODY, CACHED, chat_cache, completion
from tests.unified_api_test_case import UnifiedApiTestCase

MIGRATION = "0019_generation_cache.sql"


class SharedCacheRouteTest(UnifiedApiTestCase):
    def setUp(self):
        for target in ("env_loader.load_runtime_env", "config.load_runtime_env"):
            loader = patch(target)
            loader.start()
            self.addCleanup(loader.stop)
        network = patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected network"))
        network.start()
        self.addCleanup(network.stop)
        super().setUp()
        os.environ.update(GENERATION_CACHE_BACKEND="d1-r2", GENERATION_CACHE_SHARED_ENABLED="true",
                          RESPONSE_CACHE_ENABLED="true", RESPONSE_CACHE_POLICY_REVISION="legacy",
                          CONTENT_RETENTION_ENABLED="false", SECRET_SCAN_DEFAULT="off")
        module = importlib.import_module("services.shared_generation_cache")
        self.rows, self.calls = {}, []

        def transport(value):
            self.calls.append(value)
            key = (value["principal_hash"], value["cache_key"], value["policy_hash"], value["model"])
            if value["operation"] == "get":
                return {"version": 1, "entry": self.rows.get(key)}
            self.rows[key] = {"body": value["body"], "metadata": value["metadata"], "age": 0}
            return {"version": 1, "stored": True}

        self.transport = transport
        self.store_type = module.SharedGenerationCache
        self.app.extensions["shared_generation_cache"] = self.store_type(transport)
        chat_cache().clear()

    def tearDown(self):
        chat_cache().clear()
        super().tearDown()

    def post(self, body=BODY, headers=CACHED, reply=None):
        with patch.object(self.app_module.ProxyService, "make_request", return_value=reply if reply is not None else completion()) as upstream:
            response = self.client.post("/v1/chat/completions", headers=headers, json=body)
        return response, upstream.call_count

    def test_two_runtime_instances_share_an_exact_complete_response_and_account_cache(self):
        rows = []
        accounting = importlib.import_module("services.request_accounting")
        with patch.object(accounting.usage_ledger.LEDGER, "record", side_effect=rows.append):
            first, calls = self.post()
            self.assertEqual(calls, 1)
            self.app.extensions["shared_generation_cache"] = self.store_type(self.transport)
            chat_cache().clear()
            hit, calls = self.post(body=dict(reversed(list(BODY.items()))))
        self.assertEqual(calls, 0)
        self.assertEqual(hit.data, first.data)
        self.assertEqual(hit.headers["X-MultiLLM-Cache"], "hit")
        self.assertEqual(hit.headers["X-MultiLLM-Cache-Backend"], "d1-r2")
        self.assertEqual((rows[-1]["cost_usd"], rows[-1]["cost_basis"]), (0, "cache"))
        self.assertEqual(hit.headers["X-MultiLLM-Usage-Basis"], "cache-served")
        self.assertEqual(hit.headers["X-MultiLLM-Provider-Calls"], "0")

    def test_policy_model_principal_and_authentication_isolation(self):
        self.post()
        os.environ["SECRET_SCAN_DEFAULT"] = "block"
        self.assertEqual(self.post()[1], 1)
        self.assertEqual(self.post(body={**BODY, "model": "opencode:glm-5.3"})[1], 1)
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            key = auth.create_user("shared-reader", is_admin=False, scopes=["chat"])["api_key"]
        self.assertEqual(self.post(headers={**CACHED, "Authorization": f"Bearer {key}"})[1], 1)
        before = len(self.calls)
        response, calls = self.post(headers={**CACHED, "Authorization": "Bearer wrong"})
        self.assertEqual((response.status_code, calls, len(self.calls)), (401, 0, before))

    def test_retention_and_ineligible_requests_never_touch_storage(self):
        os.environ["CONTENT_RETENTION_ENABLED"] = "true"
        for body, headers in ((BODY, {**CACHED, "X-MultiLLM-Retention": "zero"}),
                              ({**BODY, "temperature": 1}, CACHED),
                              ({**BODY, "tools": [{"type": "function"}]}, CACHED),
                              (BODY, {**CACHED, "Cache-Control": "no-store"})):
            self.post(body=body, headers=headers)
        self.assertEqual(self.calls, [])

    def test_inherit_retention_can_cache_and_revision_invalidates(self):
        os.environ["CONTENT_RETENTION_ENABLED"] = "true"
        self.post()
        self.assertEqual(self.post()[1], 0)
        os.environ["CONTENT_RETENTION_POLICY_JSON"] = '{"routes":{"/other":"zero"}}'
        self.assertEqual(self.post()[1], 1)

    def test_errors_incomplete_and_oversized_results_are_not_stored(self):
        for bad in (completion(status=500), completion(finish_reason="length"),
                    completion(tool_calls=[{"id": "call"}]), completion("x" * (1024 * 1024))):
            self.rows.clear()
            self.post(reply=bad)
            self.assertEqual(self.post()[1], 1)

    def test_storage_outage_is_an_ordinary_dispatch_and_policy_changes_do_not_store(self):
        def broken(value):
            raise RuntimeError("private storage detail")
        self.app.extensions["shared_generation_cache"] = self.store_type(broken)
        self.assertEqual(self.post()[1], 1)
        self.assertEqual(self.post()[1], 1)
        self.app.extensions["shared_generation_cache"] = self.store_type(self.transport)
        original = self.app_module.ProxyService.make_request
        def dispatch(*args, **kwargs):
            os.environ["SECRET_SCAN_DEFAULT"] = "block"
            return completion()
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=dispatch):
            self.client.post("/v1/chat/completions", headers=CACHED, json=BODY)
        self.assertFalse(self.rows)
        self.assertIsNotNone(original)

    def test_policy_change_during_lookup_cannot_replay_old_response(self):
        self.post()
        def changed(value):
            entry = self.transport(value)
            if value["operation"] == "get":
                os.environ["SECRET_SCAN_DEFAULT"] = "block"
            return entry
        self.app.extensions["shared_generation_cache"] = self.store_type(changed)
        self.assertEqual(self.post()[1], 1)

    def test_default_empty_disabled_and_malformed_settings_preserve_memory_headers(self):
        for backend, enabled in (("memory", "true"), ("", ""), ("d1-r2", "false"), ("bad", "true"), ("d1-r2", "bad")):
            os.environ.update(GENERATION_CACHE_BACKEND=backend, GENERATION_CACHE_SHARED_ENABLED=enabled)
            chat_cache().clear()
            first, _ = self.post()
            hit, calls = self.post()
            self.assertEqual((hit.headers["X-MultiLLM-Cache"], calls), ("hit", 0))
            self.assertEqual(first.data, hit.data)
            self.assertNotIn("X-MultiLLM-Cache-Backend", hit.headers)
        self.assertFalse(self.calls)


def test_shared_adapter_validates_response_size_age_and_metadata():
    module = importlib.import_module("services.shared_generation_cache")
    body = json.dumps({"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}).encode()
    metadata = {"content_type": "application/json", "headers": {}, "provider": None, "model": None}
    identity = dict(principal_hash="a" * 64, policy_hash="b" * 64, model="fixture:model")
    result = {"version": 1, "entry": {"body": base64.b64encode(body).decode(), "metadata": metadata, "age": 2}}
    store = module.SharedGenerationCache(lambda value: result)
    assert store.get("c" * 64, **identity)[0] == body
    assert store.get("c" * 64, max_age=0, **identity) is None
    result["entry"]["metadata"]["headers"] = {"Set-Cookie": "private"}
    assert store.get("c" * 64, **identity) is None
    assert not store.put("c" * 64, b"x" * (1024 * 1024 + 1), metadata, **identity)


def test_additive_migration_rehearsal_preserves_old_rows():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE old_rows (id INTEGER)")
    db.execute("INSERT INTO old_rows VALUES (7)")
    sql = (Path(__file__).parents[1] / "intelligence-migrations" / MIGRATION).read_text()
    db.executescript(sql)
    db.executescript(sql)
    assert db.execute("SELECT id FROM old_rows").fetchone() == (7,)
    assert db.execute("SELECT COUNT(*) FROM generation_cache").fetchone() == (0,)
