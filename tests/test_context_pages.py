"""Reversible paging uses synthetic content and injected storage only."""
import base64
import copy
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from flask import Flask

from services import context_pages as pages
from services.context_optimizer import optimize_chat_payload
from services.retention_policy import RetentionPolicy
from routes.context_pages import register_context_page_routes


class Store:
    def __init__(self):
        self.records = {}
        self.calls = 0

    def put(self, scope, bodies):
        self.calls += 1
        if sum(len(body) for body in bodies) + sum(len(row[2]) for row in self.records.values()) > pages.MAX_SESSION_BYTES:
            raise pages.ContextPageError("context_session_limit", 413)
        result = []
        for body in bodies:
            meta = {"page_id": "cp_" + str(len(self.records)).zfill(32) + "_" + "s" * 43,
                    "sha256": hashlib.sha256(body).hexdigest(), "expires_at": 4600,
                    "tool_schema": copy.deepcopy(pages.TOOL_SCHEMA)}
            self.records[meta["page_id"]] = (scope, meta, body)
            result.append(meta)
        return result

    def get(self, scope, page_id):
        self.calls += 1
        row = self.records.get(page_id)
        if row is None or row[0] != scope:
            raise pages.ContextPageError("context_page_not_found", 404)
        return {**row[1], "body_base64": base64.b64encode(row[2]).decode()}


def history():
    return [{"role": "system", "content": "Exact directive"},
            {"role": "user", "content": "old 雪\n" * 600},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "a", "type": "function", "function": {"name": "read", "arguments": "{}"}},
                {"id": "b", "type": "function", "function": {"name": "read", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "b", "content": "  bytes\n\t雪  "},
            {"role": "tool", "tool_call_id": "a", "content": "answer"},
            {"role": "assistant", "content": "Done"},
            {"role": "user", "content": "Current request"}]


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setenv("CONTEXT_PAGING_ENABLED", "true")
    store = Store()
    service = pages.ContextPageService(store, clock=lambda: 1000)
    scope = pages.PageScope("alice", "session", "rev-1")
    return service, store, scope


def page(setup, messages=None, **kw):
    service, _, scope = setup
    return service.page_payload({"model": "fixture", "messages": messages or history()}, scope=scope,
        capabilities=["multillm_context_retrieve"], target_input_tokens=500,
        retention_policy=RetentionPolicy(), managed=True, **kw)


def test_exact_tool_exchange_roundtrip_and_no_raw_blob(setup):
    service, store, scope = setup
    original = history()
    result = page(setup, original)
    assert result.payload["messages"][0] == original[0]
    assert result.payload["messages"][-1] == original[-1]
    assert "old 雪" not in json.dumps(result.payload, ensure_ascii=False)
    restored = service.retrieve(scope, result.pages[0]["page_id"], retention_policy=RetentionPolicy())
    assert restored["messages"] == original[1:-1]
    assert base64.b64decode(restored["body_base64"]) == pages.encode_group(original[1:-1])
    assert restored["sha256"] == hashlib.sha256(pages.encode_group(original[1:-1])).hexdigest()
    assert original == history() and store.calls == 2
    assert result.payload["tools"][-1] == pages.TOOL_SCHEMA


@pytest.mark.parametrize("flag", ["", "false", "invalid"])
def test_default_off_has_no_storage_or_mutation(setup, monkeypatch, flag):
    service, store, scope = setup
    monkeypatch.setenv("CONTEXT_PAGING_ENABLED", flag)
    payload = {"messages": history()}
    result = service.page_payload(payload, scope=scope, capabilities=["multillm_context_retrieve"],
        target_input_tokens=1, retention_policy=RetentionPolicy(), managed=True)
    assert result.payload is payload and not result.pages and store.calls == 0


@pytest.mark.parametrize("managed,capabilities,retention", [
    (False, ["multillm_context_retrieve"], RetentionPolicy()),
    (True, [], RetentionPolicy()),
    (True, ["multillm_context_retrieve"], RetentionPolicy("zero", True)),
])
def test_raw_capability_and_retention_bypass_before_storage(setup, managed, capabilities, retention):
    service, store, scope = setup
    payload = {"messages": history()}
    result = service.page_payload(payload, scope=scope, capabilities=capabilities,
        target_input_tokens=1, retention_policy=retention, managed=managed)
    assert result.payload is payload and store.calls == 0


@pytest.mark.parametrize("variant", ["foreign", "revision", "expired", "digest", "revoked", "zero"])
def test_retrieval_failures(setup, variant):
    service, store, scope = setup
    meta = page(setup).pages[0]
    if variant == "foreign":
        scope = pages.PageScope("bob", "session", "rev-1")
    if variant == "revision":
        scope = pages.PageScope("alice", "session", "rev-2")
    if variant == "expired":
        service.clock = lambda: 4600
    if variant == "digest":
        old_scope, old_meta, body = store.records[meta["page_id"]]
        store.records[meta["page_id"]] = old_scope, old_meta, body + b" "
    with pytest.raises(pages.ContextPageError) as error:
        service.retrieve(scope, meta["page_id"], retention_policy=RetentionPolicy("zero", variant == "zero"),
                         granted=variant != "revoked")
    assert error.value.status in {403, 404, 503}


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "legacy", "protected"])
def test_incomplete_and_protected_groups_never_page(setup, mutation):
    messages = history()
    if mutation == "missing":
        messages.pop(4)
    if mutation == "duplicate":
        messages[4]["tool_call_id"] = "b"
    if mutation == "legacy":
        messages[2]["function_call"] = {"name": "legacy", "arguments": "{}"}
    if mutation == "protected":
        messages.insert(3, {"role": "developer", "content": "Protect this exchange"})
    with pytest.raises(pages.ContextPageError, match="context_window_exceeded") as error:
        page(setup, messages)
    assert error.value.status == 413 and setup[1].calls == 0


def test_page_and_protected_window_limits_before_storage(setup):
    messages = history()
    messages[-1]["content"] = "protected" * 1000
    with pytest.raises(pages.ContextPageError, match="context_window_exceeded"):
        page(setup, messages)
    messages = history()
    messages[1]["content"] = "x" * pages.MAX_PAGE_BYTES
    with pytest.raises(pages.ContextPageError, match="context_page_limit"):
        page(setup, messages)
    assert setup[1].calls == 0


def test_enabled_missing_backend_503(setup):
    service, _, _ = setup
    service.store = None
    with pytest.raises(pages.ContextPageError) as error:
        page(setup)
    assert error.value.status == 503


def test_optimizer_uses_exact_paging_before_lossy_optimization(setup):
    service, _, scope = setup
    payload = {"messages": history(), "optimization": {"target_input_tokens": 500, "keep_recent_turns": 1}}
    result = optimize_chat_payload(payload, default_target_tokens=500, context_paging=pages.PagingRequest(
        service, scope, ["multillm_context_retrieve"], RetentionPolicy(), True))
    assert result.status == "paged" and result.pages
    assert not result.needs_summary and result.messages_summarized == 0


def test_registered_route_checks_current_authority_and_returns_exact_bytes(setup):
    service, _, scope = setup
    meta = page(setup).pages[0]
    app = Flask(__name__)
    authority = {"scope": scope, "granted": True, "retention_policy": RetentionPolicy()}
    register_context_page_routes(app, service=service, authorize=lambda: authority)
    client = app.test_client()
    response = client.get("/v1/context/pages/" + meta["page_id"])
    assert response.status_code == 200
    assert base64.b64decode(response.json["body_base64"]) == pages.encode_group(history()[1:-1])
    assert response.headers["Cache-Control"] == "private, no-store"
    authority["granted"] = False
    assert client.get("/v1/context/pages/" + meta["page_id"]).status_code == 403
    authority["granted"] = True
    authority["scope"] = pages.PageScope("bob", "session", "rev-1")
    assert client.get("/v1/context/pages/" + meta["page_id"]).status_code == 404
    service.store = None
    assert client.get("/v1/context/pages/" + meta["page_id"]).status_code == 503


def test_route_without_authority_fails_closed(setup):
    app = Flask(__name__)
    register_context_page_routes(app, service=setup[0])
    assert app.test_client().get("/v1/context/pages/cp_fixture").status_code == 503


def test_additive_migration_preserves_old_tables():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE older (value TEXT)")
    db.execute("INSERT INTO older VALUES ('retained')")
    sql = (Path(__file__).parents[1] / "intelligence-migrations/0024_context_pages.sql").read_text()
    db.executescript(sql)
    db.executescript(sql)
    assert db.execute("SELECT value FROM older").fetchone() == ("retained",)
    assert db.execute("SELECT COUNT(*) FROM context_pages").fetchone() == (0,)


def test_tool_retrieval_validates_arguments_and_current_grant(setup):
    service, _, scope = setup
    meta = page(setup).pages[0]
    assert service.retrieve_tool({"page_id": meta["page_id"]}, scope=scope,
        retention_policy=RetentionPolicy(), granted=True)["messages"] == history()[1:-1]
    for value in [None, {}, {"page_id": meta["page_id"], "principal": "alice"}]:
        with pytest.raises(pages.ContextPageError) as error:
            service.retrieve_tool(value, scope=scope, retention_policy=RetentionPolicy(), granted=True)
        assert error.value.status == 400


def test_session_limits_and_storage_failures_stop_optimization(setup):
    service, store, _ = setup
    body = pages.encode_group(history()[1:-1])
    store.records["older"] = (None, None, b"x" * (pages.MAX_SESSION_BYTES - len(body) + 1))
    with pytest.raises(pages.ContextPageError, match="context_session_limit") as error:
        page(setup)
    assert error.value.status == 413
    store.records.clear()
    def unavailable(*args):
        raise OSError("fixture outage")
    store.put = unavailable
    with pytest.raises(pages.ContextPageError) as error:
        page(setup)
    assert error.value.status == 503


def test_transport_preserves_private_error_status():
    class Missing(Exception):
        status = 404
        code = "context_page_not_found"
    def call(payload):
        raise Missing()
    store = pages.PrivatePageStore(call)
    with pytest.raises(pages.ContextPageError) as error:
        store.get(pages.PageScope("alice", "session", "rev"), "fixture")
    assert error.value.status == 404 and error.value.code == "context_page_not_found"


def test_registered_disabled_route_and_unpaged_fit(setup, monkeypatch):
    service, store, scope = setup
    payload = {"messages": [{"role": "user", "content": "small"}]}
    result = service.page_payload(payload, scope=scope, capabilities=["multillm_context_retrieve"],
        target_input_tokens=500, managed=True, retention_policy=RetentionPolicy())
    assert result.payload is payload and store.calls == 0
    monkeypatch.setenv("CONTEXT_PAGING_ENABLED", "false")
    app = Flask(__name__)
    register_context_page_routes(app)
    assert app.test_client().get("/v1/context/pages/fixture").status_code == 404


def test_protected_indices_preserve_entire_exchange(setup):
    with pytest.raises(pages.ContextPageError, match="context_window_exceeded"):
        page(setup, protected_indices=(4,))
    assert setup[1].calls == 0
