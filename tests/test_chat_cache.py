"""Opt-in exact-match cache for deterministic, non-streaming chat completions."""

import importlib
import json
import os
from unittest.mock import patch

import requests

from services.cache_service import ResponseCache
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}
CACHED = {**ADMIN, "X-MultiLLM-Cache": "on"}
BODY = {"model": "opencode:glm-5.2", "messages": [{"role": "user", "content": "2+2?"}], "temperature": 0}


def completion(text="4", finish_reason="stop", status=200, **message):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps({
        "id": "chatcmpl-cache", "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text, **message},
                     "finish_reason": finish_reason}],
    }).encode()
    response.headers["Content-Type"] = "application/json"
    return response


def chat_cache():
    """The module the current app imported; every test app imports its own copy."""
    return importlib.import_module("routes.chat_cache")


class ChatCacheTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        chat_cache().clear()

    def tearDown(self):
        chat_cache().clear()
        super().tearDown()

    def _post(self, responses, body=BODY, headers=CACHED):
        with patch("app.ProxyService.make_request", side_effect=list(responses)) as make_request:
            response = self.client.post("/v1/chat/completions", headers=headers, json=body)
        return response, make_request.call_count

    def _second_key(self):
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            return auth.create_user("cache-reader", is_admin=False, scopes=["chat"])["api_key"]

    def test_a_repeated_deterministic_request_is_served_from_the_cache(self):
        first, first_calls = self._post([completion("4")])
        second, second_calls = self._post([completion("never used")])

        self.assertEqual((first.status_code, first.headers["X-MultiLLM-Cache"], first_calls), (200, "miss", 1))
        self.assertEqual((second.status_code, second.headers["X-MultiLLM-Cache"], second_calls), (200, "hit", 0))
        self.assertEqual(second.get_json(), first.get_json())
        self.assertEqual(second.headers["X-MultiLLM-Route-Decision"], "cache-hit")
        self.assertIn("Age", second.headers)

    def test_a_cache_hit_is_recorded_without_a_charge(self):
        rows = []
        with patch("services.request_accounting.usage_ledger.LEDGER.record", side_effect=rows.append):
            self._post([completion("4")])
            self._post([completion("never used")])
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]["cost_basis"], "cache")
        self.assertEqual((rows[1]["cost_usd"], rows[1]["cost_basis"]), (0.0, "cache"))

    def test_key_order_does_not_matter_but_any_body_change_does(self):
        self._post([completion("4")])
        reordered = {"temperature": 0, "messages": BODY["messages"], "model": BODY["model"]}
        self.assertEqual(self._post([completion()], body=reordered)[0].headers["X-MultiLLM-Cache"], "hit")
        changed = {**BODY, "max_tokens": 5}
        self.assertEqual(self._post([completion()], body=changed)[0].headers["X-MultiLLM-Cache"], "miss")

    def test_entries_are_never_shared_between_keys(self):
        other_key = self._second_key()
        self._post([completion("admin answer")])

        response, calls = self._post([completion("reader answer")],
                                     headers={"Authorization": f"Bearer {other_key}", "X-MultiLLM-Cache": "on"})

        self.assertEqual((response.headers["X-MultiLLM-Cache"], calls), ("miss", 1))
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "reader answer")

    def test_authentication_runs_before_a_hit_is_served(self):
        self._post([completion("4")])

        response, calls = self._post([], headers={"Authorization": "Bearer wrong-key", "X-MultiLLM-Cache": "on"})

        self.assertEqual((response.status_code, calls), (401, 0))
        self.assertNotIn("X-MultiLLM-Cache", response.headers)

    def test_caching_is_opt_in(self):
        self._post([completion()], headers=ADMIN)
        response, calls = self._post([completion()], headers=ADMIN)
        self.assertEqual(calls, 1)
        self.assertNotIn("X-MultiLLM-Cache", response.headers)

    def test_non_deterministic_streaming_or_tool_requests_bypass_the_cache(self):
        tool = {"type": "function", "function": {"name": "send_email", "parameters": {"type": "object"}}}
        for label, body in (
            ("sampled", {**BODY, "temperature": 0.7}),
            ("streaming", {**BODY, "stream": True}),
            ("several choices", {**BODY, "n": 2}),
            ("runnable tools", {**BODY, "tools": [tool]}),
            ("intelligence route", {**BODY, "model": "auto:intelligence"}),
        ):
            with self.subTest(label):
                self.assertFalse(chat_cache().request_is_cacheable(body))
        self.assertTrue(chat_cache().request_is_cacheable({**BODY, "tools": [tool], "tool_choice": "none"}))
        self.assertTrue(chat_cache().request_is_cacheable({**BODY, "temperature": 0.9, "seed": 7}))

        response, calls = self._post([completion(), completion()], body={**BODY, "temperature": 0.7})
        self.assertEqual((response.headers["X-MultiLLM-Cache"], calls), ("bypass", 1))

    def test_errors_and_incomplete_answers_are_never_stored(self):
        for label, bad in (
            ("server error", completion(status=500)),
            ("truncated", completion(finish_reason="length")),
            ("tool call", completion(finish_reason="tool_calls", tool_calls=[{"id": "call_1"}])),
        ):
            with self.subTest(label):
                chat_cache().clear()
                self._post([bad])
                response, calls = self._post([completion("fresh")])
                self.assertEqual((response.headers["X-MultiLLM-Cache"], calls), ("miss", 1))

    def test_cache_control_can_refuse_or_refresh_a_stored_answer(self):
        self._post([completion("old")])

        no_store, calls = self._post([completion("x")], headers={**CACHED, "Cache-Control": "no-store"})
        self.assertEqual((calls, no_store.headers.get("X-MultiLLM-Cache")), (1, None))

        refreshed, calls = self._post([completion("new")], headers={**CACHED, "Cache-Control": "no-cache"})
        self.assertEqual((calls, refreshed.headers["X-MultiLLM-Cache"]), (1, "miss"))
        hit, calls = self._post([completion("unused")])
        self.assertEqual(hit.get_json()["choices"][0]["message"]["content"], "new")

        too_old, calls = self._post([completion("newest")], headers={**CACHED, "Cache-Control": "max-age=0"})
        self.assertEqual((calls, too_old.headers["X-MultiLLM-Cache"]), (1, "miss"))

    def test_the_operator_can_disable_the_cache(self):
        os.environ["RESPONSE_CACHE_ENABLED"] = "false"
        self._post([completion()])
        response, calls = self._post([completion()])
        self.assertEqual((response.headers["X-MultiLLM-Cache"], calls), ("bypass", 1))


def test_the_store_is_bounded_by_entries_bytes_and_ttl():
    store = ResponseCache(max_entries=2, max_bytes=100)
    for index in range(3):
        store.put(f"k{index}", b"x" * 10, {}, ttl_seconds=60, now=0)
    assert store.get("k0", now=1) is None and store.get("k2", now=1) is not None
    assert store.stats() == {"entries": 2, "bytes": 20}
    assert not store.put("big", b"x" * 101, {}, ttl_seconds=60, now=0)
    store.put("fits", b"x" * 90, {}, ttl_seconds=60, now=0)
    assert store.stats()["bytes"] <= 100
    assert store.get("fits", now=59) is not None
    assert store.get("fits", now=60) is None, "expired entries are dropped"
