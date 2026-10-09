"""Scoped semantic lookup and authenticated Chat Completions contracts."""
import importlib
import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, Response, g

from tests.test_chat_cache import BODY, ADMIN, CACHED, chat_cache, completion
from tests.unified_api_test_case import UnifiedApiTestCase


def module():
    return importlib.import_module("services.semantic_generation_cache")


POLICY = {"routes": ["/v1/chat/completions"], "embedding_model": "openai:embed-test", "revision": "one"}
PRICES = json.dumps({"openai:embed-test": {"input": 0.1, "output": 0}})
ANSWER = json.dumps({"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]}).encode()


class Store:
    def __init__(self):
        self.rows = []
        self.ready_calls = 0
        self.missing = False
        self.broken = False

    def ready(self):
        self.ready_calls += 1
        if self.missing:
            raise module().SemanticCacheSchemaMissing()
        if self.broken:
            raise RuntimeError("storage error")

    def scan(self, identity, vector, guard):
        return [row for row in self.rows if row["identity"] == identity]

    def body(self, identity, row):
        return row["body"], row["metadata"], 0

    def put(self, identity, vector, guard, body, metadata):
        self.rows.append(dict(identity=identity, vector=vector, guard_hash=guard, body=body, metadata=metadata))
        return True


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SEMANTIC_CACHE_ENABLED", "true")
    monkeypatch.setenv("SEMANTIC_CACHE_POLICY_JSON", json.dumps(POLICY))
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", PRICES)
    return monkeypatch


def test_settings_defaults_empty_and_invalid_warn_once(caplog):
    m = module()
    m._warn_once.cache_clear()
    for config in ({}, {"SEMANTIC_CACHE_ENABLED": "", "SEMANTIC_CACHE_POLICY_JSON": ""}):
        assert not m.settings(config).enabled
    assert m.settings({"SEMANTIC_CACHE_ENABLED": "true"}).policy == {}
    for bad in ("broken", "[]", '{"allow_tools":true}', '{"allow_streams":true}'):
        assert not m.settings({"SEMANTIC_CACHE_ENABLED": "true", "SEMANTIC_CACHE_POLICY_JSON": bad}).enabled
        assert bad not in caplog.text
    assert len(caplog.records) == 1


@pytest.mark.parametrize("change", [{"stream": True}, {"n": 2}, {"tools": [{}], "tool_choice": "none"},
    {"functions": [{}]}, {"messages": [{"role": "tool", "content": "result"}, {"role": "user", "content": "question"}]},
    {"messages": [{"role": "user", "content": "latest weather today"}]},
    {"messages": [{"role": "user", "content": "x" * 4097}]}])
def test_ineligible_requests(env, change):
    assert not module().eligible({**BODY, **change})


@pytest.mark.parametrize("a,b", [("buy 12 shares", "buy 13 shares"), ("on 2026-10-09", "on 2026-10-10"),
    ("do it", "do not do it"), ('say "hello"', 'say "bye"'), ("use 'yes'", "use 'no'"),
    ("can go", "can't go"), ("no need", "need"), ("October 9", "November 9"),
    ("meet Monday", "meet Tuesday"), ("buy twelve shares", "buy thirteen shares")])
def test_protected_facts(a, b):
    assert module().guard_hash(a) != module().guard_hash(b)


def test_similarity_threshold_and_bad_vectors():
    m = module()
    assert m.cosine([1, 0], [0.99, 0.01]) >= 0.98
    assert m.cosine([1, 0], [0.9, 0.44]) < 0.98
    for vector in ([], [0, 0], [float("nan"), 1], [True, 1], [1]):
        assert m.cosine([1, 0], vector) == -1


def test_full_partition_except_last_user_content(env):
    m = module()
    payload = {**BODY, "messages": [{"role": "system", "content": "rules"}, {"role": "user", "content": "explain caching"}]}
    one = m.partition("owner", "/v1/chat/completions", payload, {"policy": "one"}, POLICY)
    paraphrase = {**payload, "messages": [payload["messages"][0], {"role": "user", "content": "describe caching"}]}
    assert one == m.partition("owner", "/v1/chat/completions", paraphrase, {"policy": "one"}, POLICY)
    for field, value in (("temperature", 0.1), ("top_p", 0.5), ("seed", 7), ("model", "openai:other"),
                         ("response_format", {"type": "json_object"}), ("stop", ["done"])):
        assert one != m.partition("owner", "/v1/chat/completions", {**payload, field: value}, {"policy": "one"}, POLICY)
    assert one != m.partition("foreign", "/v1/chat/completions", payload, {"policy": "one"}, POLICY)
    assert one != m.partition("owner", "/v1/chat/completions", payload, {"policy": "two"}, POLICY)


class SemanticRouteTests(UnifiedApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()
        os.environ.update(SEMANTIC_CACHE_ENABLED="true", SEMANTIC_CACHE_POLICY_JSON=json.dumps(POLICY),
                          MODEL_PRICING_USD_PER_MILLION=PRICES, GENERATION_CACHE_SHARED_ENABLED="false",
                          CONTENT_RETENTION_ENABLED="false", RESPONSE_CACHE_POLICY_REVISION="legacy")
        self.store = Store()
        self.embeddings = []
        self.app.extensions["semantic_generation_cache"] = self.store
        self.app.extensions["semantic_cache_embedding"] = lambda model, text: self.embeddings.append((model, text)) or [1, 0]
        chat_cache().clear()

    def post(self, text="explain caching", headers=ADMIN, **extra):
        payload = {**BODY, "messages": [{"role": "user", "content": text}], **extra}
        with patch.object(self.app_module.ProxyService, "make_request", return_value=completion("real answer")) as send:
            result = self.client.post("/v1/chat/completions", json=payload, headers=headers)
        return result, send.call_count

    def test_registered_hit_preserves_body_and_zero_generation_cost(self):
        accounting = importlib.import_module("services.request_accounting")
        rows = []
        with patch.object(accounting.usage_ledger.LEDGER, "record", side_effect=rows.append):
            first, _ = self.post()
            hit, calls = self.post("describe caching")
        assert calls == 0
        assert first.data == hit.data
        assert hit.headers["X-MultiLLM-Cache"] == "semantic-hit"
        assert hit.headers["X-MultiLLM-Usage-Basis"] == "cache-served"
        assert hit.headers["X-MultiLLM-Provider-Calls"] == "0"
        assert rows[-1]["cost_usd"] == 0 and rows[-1]["cost_basis"] == "cache"
        assert len(self.embeddings) == 2

    def test_schema_missing_fails_before_embedding_and_provider(self):
        self.store.missing = True
        response, calls = self.post()
        assert response.status_code == 503 and calls == 0
        assert response.get_json()["error"] == "semantic_cache_schema_missing"
        assert self.embeddings == []

    def test_outage_falls_through_once_and_no_synthetic_output(self):
        self.store.broken = True
        result, calls = self.post()
        assert calls == 1 and result.get_json()["choices"][0]["message"]["content"] == "real answer"
        assert self.embeddings == []

    def test_protected_mismatch_and_incomplete_never_hit(self):
        self.post("explain 12 caches")
        assert self.post("describe 13 caches")[1] == 1
        self.store.rows.clear()
        with patch.object(self.app_module.ProxyService, "make_request", return_value=completion(finish_reason="length")):
            self.client.post("/v1/chat/completions", json={**BODY, "messages": [{"role": "user", "content": "explain caching"}]}, headers=ADMIN)
        assert not self.store.rows

    def test_scope_price_retention_and_tools_skip_every_semantic_operation(self):
        cases = [("SEMANTIC_CACHE_POLICY_JSON", "{}", {}), ("SEMANTIC_CACHE_ENABLED", "false", {}),
                 ("MODEL_PRICING_USD_PER_MILLION", "{}", {}),
                 ("MODEL_PRICING_USD_PER_MILLION", json.dumps({"openai:embed-test": {"input": 100, "output": 0}}), {}),
                 ("CONTENT_RETENTION_ENABLED", "true", {"X-MultiLLM-Retention": "zero"})]
        for name, value, headers in cases:
            with patch.dict(os.environ, {name: value}):
                assert self.post(headers={**ADMIN, **headers})[1] == 1
        assert self.post(tools=[{}], tool_choice="none")[1] == 1
        assert self.store.ready_calls == 0 and self.embeddings == []

    def test_disabled_exact_cache_bytes_and_headers_unchanged(self):
        with patch.dict(os.environ, {"SEMANTIC_CACHE_ENABLED": ""}):
            first, _ = self.post(headers=CACHED)
            second, calls = self.post(headers=CACHED)
        assert second.data == first.data and calls == 0
        assert second.headers["X-MultiLLM-Cache"] == "hit" and self.embeddings == []

    def test_authentication_precedes_semantic_cache(self):
        response, calls = self.post(headers={"Authorization": "Bearer invalid"})
        assert response.status_code == 401 and calls == 0 and not self.store.ready_calls

    def test_embedding_is_separately_charged_with_provider_or_estimated_usage(self):
        accounting = importlib.import_module("services.request_accounting")
        rows = []
        with patch.object(accounting.usage_ledger.LEDGER, "record", side_effect=rows.append):
            self.post()
            self.app.extensions["semantic_cache_embedding"] = lambda *_: {"data": [{"embedding": [1, 0]}], "usage": {"prompt_tokens": 4}}
            self.post("describe caching")
        embeddings = [row for row in rows if row["kind"] == "embeddings"]
        assert [row["cost_basis"] for row in embeddings] == ["estimate", "usage"]
        assert [row["input_tokens"] for row in embeddings] == [1024, 4]
        assert embeddings[0]["cost_usd"] == pytest.approx(0.0001024)
        assert embeddings[1]["cost_usd"] == pytest.approx(0.0000004)

    def test_security_headers_partition_and_max_age_without_exact_opt_in(self):
        self.post(headers={**ADMIN, "OpenAI-Project": "one"})
        assert self.post("describe caching", headers={**ADMIN, "OpenAI-Project": "two"})[1] == 1
        with patch.object(self.store, "body", side_effect=lambda identity, row: (row["body"], row["metadata"], 10)):
            assert self.post("describe caching", headers={**ADMIN, "OpenAI-Project": "one", "Cache-Control": "max-age=1"})[1] == 1

    def test_budget_denial_and_embedding_failure_still_dispatch_once(self):
        accounting = importlib.import_module("services.request_accounting")
        from types import SimpleNamespace
        with self.app.test_request_context("/v1/chat/completions", method="POST"):
            g.authenticated_user = {"id": "owner"}
            with patch.object(accounting, "budgeted", return_value=True), patch.object(accounting.BudgetService, "check_and_reserve", return_value=SimpleNamespace(allowed=False)):
                assert module().embed_accounted("openai:embed-test", "hello", 0.0001) is None
        assert not self.embeddings
        self.app.extensions["semantic_cache_embedding"] = lambda *_: (_ for _ in ()).throw(RuntimeError("embedding failure"))
        rows = []
        with patch.object(accounting.usage_ledger.LEDGER, "record", side_effect=rows.append):
            assert self.post()[1] == 1
        assert rows[0]["kind"] == "embeddings" and rows[0]["status"] == 502 and rows[0]["cost_usd"] > 0


def test_migration_is_additive_and_repeatable():
    db = sqlite3.connect(":memory:")
    db.executescript("CREATE TABLE existing(id); INSERT INTO existing VALUES(7);")
    sql = (Path(__file__).parents[1] / "intelligence-migrations/0026_semantic_cache.sql").read_text()
    db.executescript(sql)
    db.executescript(sql)
    assert db.execute("SELECT id FROM existing").fetchone() == (7,)
    assert db.execute("SELECT COUNT(*) FROM semantic_generation_cache").fetchone() == (0,)


def test_private_adapter_enforces_complete_bounded_bodies_and_identity():
    import base64
    calls = []
    metadata = {"content_type": "application/json", "headers": {}, "provider": "openai", "model": "chat"}
    entry = {"body": base64.b64encode(ANSWER).decode(), "metadata": metadata, "age": 0}
    def transport(value):
        calls.append(value)
        return {"version": 1, "entry": entry}
    cache = module().SemanticGenerationCache(transport)
    identity = {"principal_hash": "a"*64, "partition_hash": "b"*64, "model_revision": "c"*64}
    assert cache.body(identity, {"entry_id": "d"*32}) == (ANSWER, metadata, 0)
    assert all(calls[-1][key] == value for key, value in identity.items())
    for change in ({"age": 300}, {"body": base64.b64encode(b'{"error":"no"}').decode()}, {"metadata": {}}):
        entry.update(body=base64.b64encode(ANSWER).decode(), metadata=metadata, age=0)
        entry.update(change)
        assert cache.body(identity, {"entry_id": "d"*32}) is None


def test_configured_embedding_preflight_and_transport_use_existing_interfaces():
    m = module()
    media = importlib.import_module("routes.media_audio")
    accounting = importlib.import_module("services.request_accounting")
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST"):
        g.authenticated_user = {"id": "owner"}
        with patch.object(media, "validate_media_candidate", side_effect=ValueError("unconfigured")), patch.object(accounting, "_record") as record:
            with pytest.raises(ValueError):
                m.embed_accounted("openai:embed-test", "hello", 0.0001)
            record.assert_not_called()
        response = Response(json.dumps({"data": [{"embedding": [1, 0]}], "usage": {"prompt_tokens": 4}}), content_type="application/json")
        with patch.object(media, "validate_media_candidate") as validate, patch.object(media, "dispatch_media_candidate", return_value=response) as dispatch, patch.object(accounting, "_record") as record:
            assert m.embed_accounted("openai:embed-test", "hello", 0.0001) == [1, 0]
        assert validate.call_count == dispatch.call_count == record.call_count == 1
