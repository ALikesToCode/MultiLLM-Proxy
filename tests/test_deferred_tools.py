"""Deferred discovery uses synthetic identities, grants, clocks and dispatch."""
import copy
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock

import pytest
from flask import Flask, g

from services import deferred_tools as deferred
from services import mcp_contract_drift as drift
from services.knowledge_client import KnowledgeError
from routes import gateway_mcp, knowledge_mcp

USER = {"id": "reader", "scopes": ["models", "chat", "knowledge:read"]}


def entry(name, scope="models", description="model search", schema=None):
    return {"scope": scope, "toolset": "core", "definition": {
        "name": name, "description": description, "inputSchema": schema or {
            "type": "object", "additionalProperties": False, "properties": {}}}}


def grant(name, scope="models", allowed=1, principal="*"):
    return {"principal_id": principal, "tool_name": name, "scopes": [scope], "allowed": allowed, "revision": 1}


@pytest.fixture
def fixture():
    rows = [grant("models_a"), grant("models_b")]
    revision = [1]
    clock = [100]
    store = Mock(side_effect=lambda principal: copy.deepcopy(rows))
    service = deferred.DeferredTools(store, revision=lambda: revision[0], clock=lambda: clock[0])
    return service, rows, revision, clock, store


def test_filter_before_ranking_and_full_authorized_list(fixture):
    service, rows, *_ = fixture
    entries = [entry("models_a"), entry("models_b"), entry("denied", description="secret exact match")]
    assert service.discover(entries, USER, {"query": "secret exact match"})["tools"] == []
    assert [t["name"] for t in service.list_tools(entries, USER)] == ["models_a", "models_b"]
    rows.append(grant("models_a", allowed=0, principal="reader"))
    assert [t["name"] for t in service.list_tools(entries, USER)] == ["models_b"]
    assert service.list_tools(entries, {"id": "reader", "scopes": []}) == []
    assert service.list_tools(entries, {"id": "reader", "scopes": ["admin"]}) == [entries[1]["definition"]]


def test_unadvertised_granted_call_and_runtime_validation(fixture):
    service, rows, *_ = fixture
    tool = entry("models_a")
    service.authorize_call(tool, USER, {})
    with pytest.raises(KnowledgeError, match="arguments") as caught:
        service.authorize_call(tool, USER, {"extra": True})
    assert caught.value.code == "invalid_arguments"
    rows.append(grant("models_a", allowed=0, principal="reader"))
    with pytest.raises(KnowledgeError) as caught:
        service.authorize_call(tool, USER, {})
    assert caught.value.code == "tool_not_granted" and caught.value.status == 403


def test_complete_schema_budget_and_pagination(fixture):
    service, rows, *_ = fixture
    entries = [entry(f"models_{i}", schema={"type": "object", "description": "é" * 1000}) for i in range(20)]
    rows[:] = [grant(e["definition"]["name"]) for e in entries]
    first = service.discover(entries, USER, {"query": "model", "limit": 16})
    assert len(first["tools"]) < 16
    assert len(json.dumps(first).encode()) <= 65536
    assert first["tools"][0]["inputSchema"] == entries[0]["definition"]["inputSchema"]
    seen = [t["name"] for t in first["tools"]]
    cursor = first["nextCursor"]
    while cursor:
        page = service.discover(entries, USER, {"query": "model", "limit": 16, "cursor": cursor})
        seen += [t["name"] for t in page["tools"]]
        cursor = page.get("nextCursor")
    assert len(seen) == len(set(seen)) == 20
    entries[0]["definition"]["inputSchema"]["description"] = "x" * 66000
    with pytest.raises(KnowledgeError) as caught:
        service.discover(entries[:1], USER, {"query": "model"})
    assert caught.value.code == "tool_schema_too_large"


@pytest.mark.parametrize("change", ["tamper", "expiry", "principal", "query", "limit", "revision", "grants", "digest"])
def test_cursor_bindings(fixture, change):
    service, rows, revision, clock, _ = fixture
    entries = [entry("models_a"), entry("models_b")]
    args = {"query": "model", "limit": 1}
    cursor = service.discover(entries, USER, args)["nextCursor"]
    user = USER
    if change == "tamper":
        cursor = ("A" if cursor[0] != "A" else "B") + cursor[1:]
    elif change == "expiry":
        clock[0] += 120
    elif change == "principal":
        user = {**USER, "id": "other"}
    elif change == "query":
        args["query"] = "search"
    elif change == "limit":
        args["limit"] = 2
    elif change == "revision":
        revision[0] += 1
    elif change == "grants":
        rows[0]["revision"] += 1
    else:
        entries[0]["definition"]["inputSchema"]["properties"]["new"] = {"type": "string"}
    with pytest.raises(KnowledgeError) as caught:
        service.discover(entries, user, {**args, "cursor": cursor})
    assert caught.value.code == "invalid_cursor"


@pytest.mark.parametrize("params", [{}, {"query": ""}, {"query": "x", "limit": 17}, {"query": "x", "limit": True},
                                    {"query": "x", "paid_embedding": True}, {"query": "x", "cursor": "x" * 4097}])
def test_input_bounds_before_storage(fixture, params):
    service, *_, store = fixture
    with pytest.raises(KnowledgeError):
        service.discover([], USER, params)
    store.assert_not_called()


@pytest.fixture
def gateway(monkeypatch, fixture):
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "false")
    app = Flask(__name__)
    app.config.update(TESTING=True)
    service, rows, *_ = fixture
    rows[:] = [grant("list_models"), grant("chat", "chat")]
    app.extensions["deferred_tools"] = service
    monkeypatch.setattr(gateway_mcp, "api_authenticate_only", lambda **kwargs: lambda fn: fn)
    gateway_mcp.register_gateway_mcp_routes(app, Mock(exempt=lambda fn: fn))
    @app.before_request
    def identity():
        g.authenticated_user = copy.deepcopy(USER)
    dispatch = Mock(return_value={"isError": False, "content": []})
    monkeypatch.setitem(gateway_mcp._HANDLERS, "list_models", dispatch)
    return app, rows, dispatch


def rpc(app, method, params=None):
    return app.test_client().post("/v1/mcp", json={"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}})


@pytest.mark.parametrize("flag", ["", "false", "0", "malformed"])
def test_registered_off_keeps_bytes_and_does_not_read_storage(gateway, monkeypatch, flag):
    app, _, dispatch = gateway
    expected = rpc(app, "tools/list")
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", flag)
    app.extensions["deferred_tools"] = Mock(side_effect=AssertionError("storage while off"))
    actual = rpc(app, "tools/list")
    assert actual.data == expected.data and list(actual.headers) == list(expected.headers)
    assert rpc(app, "multillm.tools.discover", {"query": "models"}).json["error"]["code"] == -32601
    assert rpc(app, "tools/call", {"name": "list_models", "arguments": {}}).json["result"]["isError"] is False
    dispatch.assert_called_once()


def test_registered_discovery_calls_recheck_and_schema(gateway, monkeypatch):
    app, rows, dispatch = gateway
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "true")
    assert [t["name"] for t in rpc(app, "tools/list").json["result"]["tools"]] == ["list_models", "chat"]
    discovery = rpc(app, "multillm.tools.discover", {"query": "model"}).json["result"]
    assert discovery["tools"] and discovery["_meta"]["contract_digest"] == drift.catalogue_digest(
        [t for t in gateway_mcp.tool_definitions() if t["name"] in {"list_models", "chat"}])
    assert rpc(app, "tools/call", {"name": "list_models"}).json["result"]["isError"] is False
    assert rpc(app, "tools/call", {"name": "list_models", "arguments": {"limit": 501}}).status_code == 400
    rows.append(grant("list_models", allowed=0, principal="reader"))
    assert rpc(app, "tools/call", {"name": "list_models"}).status_code == 403
    dispatch.assert_called_once()


def test_registered_missing_table_fails_closed(gateway, monkeypatch):
    app, _, dispatch = gateway
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "true")
    app.extensions["deferred_tools"] = deferred.DeferredTools(Mock(side_effect=sqlite3.OperationalError("no such table")))
    for method, params in [("tools/list", {}), ("multillm.tools.discover", {"query": "models"}),
                           ("tools/call", {"name": "list_models"})]:
        response = rpc(app, method, params)
        assert response.status_code == 503 and response.json["error"]["code"] == "tool_grants_unavailable"
    dispatch.assert_not_called()


def test_knowledge_hooks_preserve_digests_and_full_schema(fixture, monkeypatch):
    service, rows, *_ = fixture
    app = Flask(__name__)
    app.extensions["deferred_tools"] = service
    rows[:] = [grant("knowledge_context", "knowledge:read")]
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "true")
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    with app.app_context():
        result = knowledge_mcp.discovery_for_user(USER)
        assert [t["name"] for t in result["tools"]] == ["knowledge_context"]
        assert "contract_digest" in result["tools"][0]["_meta"]
        found = knowledge_mcp.deferred_discovery(USER, {"query": "technical"})
        assert found["tools"][0]["inputSchema"] == knowledge_mcp.QUERY_SCHEMA
        definition = found["tools"][0]
        knowledge_mcp.authorize_deferred_call(USER, definition["name"], {"query": "limits"})
        with pytest.raises(KnowledgeError):
            knowledge_mcp.authorize_deferred_call(USER, definition["name"], {"query": "limits", "unexpected": 1})


def test_revision_sync_uses_confirmed_model_grants_and_fails_stale(monkeypatch):
    from services import config_revision_sync as revisions
    app = Flask(__name__)
    monkeypatch.setenv("CONFIG_REVISION_SYNC_ENABLED", "true")
    sync = revisions.RevisionSync(revisions.SyncSettings(True), clock=lambda: 0)
    sync.register("model_grants", lambda revision: None, security=True)
    sync._domains["model_grants"].revision = 7
    sync._domains["model_grants"].checked = 0
    app.extensions["config_revision_sync"] = sync
    with app.app_context():
        assert deferred.grant_revision() == 7
        sync._domains["model_grants"].checked = None
        with pytest.raises(KnowledgeError):
            deferred.grant_revision()
    monkeypatch.setenv("CONFIG_REVISION_SYNC_ENABLED", "false")
    assert deferred.grant_revision() == deferred.grant_revision()


def test_additive_migration_preserves_old_rows_and_denies_new_tools():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE control_revisions(domain TEXT PRIMARY KEY, revision INTEGER, updated_at TEXT)")
    db.execute("INSERT INTO control_revisions VALUES('model_grants',7,'old')")
    sql = (Path(__file__).resolve().parents[1] / "intelligence-migrations/0018_tool_grants.sql").read_text()
    db.executescript(sql)
    db.execute("INSERT INTO tool_grants VALUES(?,?,?,?,?)", ("reader", "custom", json.dumps(["models"]), 0, 9))
    db.executescript(sql)
    assert db.execute("SELECT revision FROM control_revisions WHERE domain='model_grants'").fetchone() == (7,)
    assert db.execute("SELECT allowed, revision FROM tool_grants WHERE principal_id='reader'").fetchone() == (0, 9)
    seeded = {row[0] for row in db.execute("SELECT tool_name FROM tool_grants WHERE principal_id='*'")}
    expected = {tool["name"] for tool in gateway_mcp.TOOLS} | {e["definition"]["name"] for e in knowledge_mcp.catalogue()["tools"]}
    assert seeded == expected
    assert "future_tool" not in seeded
    db.close()


def test_concurrent_grant_change_refuses_discovery(fixture):
    service, rows, *_, store = fixture
    snapshots = [copy.deepcopy(rows), [grant("models_a", allowed=0), grant("models_b")]]
    store.side_effect = lambda principal: snapshots.pop(0)
    with pytest.raises(KnowledgeError) as caught:
        service.discover([entry("models_a"), entry("models_b")], USER, {"query": "model"})
    assert caught.value.code == "tool_grants_changed" and caught.value.status == 409


def test_cursor_chain_does_not_renew_ttl(fixture):
    service, rows, _, clock, _ = fixture
    rows.append(grant("models_c"))
    entries = [entry("models_a"), entry("models_b"), entry("models_c")]
    first = service.discover(entries, USER, {"query": "model", "limit": 1})
    clock[0] += 119
    second = service.discover(entries, USER, {"query": "model", "limit": 1, "cursor": first["nextCursor"]})
    clock[0] += 1
    with pytest.raises(KnowledgeError) as caught:
        service.discover(entries, USER, {"query": "model", "limit": 1, "cursor": second["nextCursor"]})
    assert caught.value.code == "invalid_cursor"


def test_registered_knowledge_off_bytes_and_on_grant_authority(monkeypatch, fixture):
    from routes import knowledge
    app = Flask(__name__)
    app.config.update(TESTING=True)
    service, rows, *_ = fixture
    app.extensions["deferred_tools"] = service
    monkeypatch.setattr(knowledge, "api_authenticate_only", lambda **kwargs: lambda fn: fn)
    knowledge.register_knowledge_routes(app, Mock(exempt=lambda fn: fn))
    @app.before_request
    def identity():
        g.authenticated_user = USER
    dispatch = Mock(return_value={"status": "ok"})
    monkeypatch.setattr(knowledge, "_dispatch", dispatch)
    def post(method, params=None):
        return app.test_client().post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "false")
    plain = post("tools/list")
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "")
    assert post("tools/list").data == plain.data
    assert post("multillm.tools.discover", {"query": "technical"}).json["error"]["code"] == -32601
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "true")
    rows[:] = [grant("knowledge_context", "knowledge:read")]
    assert [t["name"] for t in post("tools/list").json["result"]["tools"]] == ["knowledge_context"]
    response = post("tools/call", {"name": "knowledge_context", "arguments": {"query": "technical"}})
    assert response.status_code == 200 and response.json["result"]["isError"] is False
    dispatch.assert_called_once()
    dispatch.reset_mock()
    for arguments in ({}, {"query": 1}, {"query": "technical", "extra": True}, [], None):
        response = post("tools/call", {"name": "knowledge_context", "arguments": arguments})
        assert response.status_code == 400 and response.json["error"]["code"] == "invalid_arguments"
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    response = app.test_client().post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "knowledge_context", "arguments": {"query": "technical"}}},
        headers={"X-MultiLLM-MCP-Contract": "0" * 64})
    assert response.status_code == 409 and response.json["error"]["code"] == "mcp_contract_mismatch"
    rows[:] = []
    response = post("tools/call", {"name": "knowledge_context", "arguments": {"query": "technical"}})
    assert response.status_code == 403 and response.json["error"]["code"] == "tool_not_granted"
    rows[:] = [grant("knowledge_context", "knowledge:read"), grant("knowledge_search", "knowledge:read")]
    first = post("multillm.tools.discover", {"query": "technical", "limit": 1}).json["result"]
    second = post("multillm.tools.discover", {"query": "technical", "limit": 1, "cursor": first["nextCursor"]}).json["result"]
    assert len(first["tools"]) == len(second["tools"]) == 1
    assert first["tools"][0]["name"] != second["tools"][0]["name"]
    unknown = app.test_client().post("/mcp?toolsets=unknown", json={"jsonrpc": "2.0", "id": 1,
        "method": "multillm.tools.discover", "params": {"query": "technical"}})
    assert unknown.json["error"]["code"] == -32602
    app.extensions["deferred_tools"] = deferred.DeferredTools(Mock(side_effect=sqlite3.OperationalError("no such table")))
    for method, params in [("tools/list", {}), ("tools/call", {"name": "knowledge_context", "arguments": {"query": "technical"}})]:
        response = post(method, params)
        assert response.status_code == 503 and response.is_json
    dispatch.assert_not_called()


def test_registered_knowledge_disabled_calls_keep_bytes_and_error_order(monkeypatch):
    from routes import knowledge
    app = Flask(__name__)
    monkeypatch.setattr(knowledge, "api_authenticate_only", lambda **kwargs: lambda fn: fn)
    knowledge.register_knowledge_routes(app, Mock(exempt=lambda fn: fn))
    @app.before_request
    def identity():
        g.authenticated_user = USER
    monkeypatch.setattr(knowledge, "dispatch", Mock(return_value={"status": "ok"}))
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    authority = Mock(side_effect=AssertionError("disabled grants read"))
    app.extensions["deferred_tools"] = deferred.DeferredTools(authority)
    cases = [("knowledge_context", {"query": "technical"}, None, 200, None),
             ("knowledge_policy_update", {}, "0" * 64, 200, "insufficient_scope"),
             ("knowledge_context", [], "0" * 64, 409, "mcp_contract_mismatch"),
             ("knowledge_context", [], None, 200, -32602)]
    for name, arguments, pin, status, code in cases:
        def post():
            return app.test_client().post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}},
                headers={"X-MultiLLM-MCP-Contract": pin} if pin else {})
        monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "false")
        baseline = post()
        assert baseline.status_code == status
        if code == "insufficient_scope":
            assert json.loads(baseline.json["result"]["content"][0]["text"])["error"]["code"] == code
        elif code is not None:
            assert baseline.json["error"]["code"] == code
        for flag in ("", "0", "malformed"):
            monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", flag)
            response = post()
            assert (response.status_code, response.data, dict(response.headers)) == (baseline.status_code, baseline.data, dict(baseline.headers))
    authority.assert_not_called()
    baseline = None
    for flag in ("false", "", "0", "malformed"):
        monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", flag)
        response = app.test_client().post("/mcp?toolsets=unknown", json={"jsonrpc": "2.0", "id": 1,
            "method": "multillm.tools.discover", "params": {"query": "technical"}})
        assert response.json["error"]["code"] == -32601
        result = (response.status_code, response.data, dict(response.headers))
        baseline = result if baseline is None else baseline
        assert result == baseline


@pytest.mark.parametrize("status", [404, 503])
def test_private_grant_read_failures_are_json_503(monkeypatch, status):
    from routes import knowledge
    from services.intelligence_d1_store import PrivateIntelligenceError
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "true")
    monkeypatch.setattr(deferred.control_state_d1, "using_d1", lambda: True)
    monkeypatch.setattr(deferred.control_state_d1, "call", Mock(side_effect=PrivateIntelligenceError(status, "storage_unavailable")))
    app = Flask(__name__)
    app.extensions["deferred_tools"] = deferred.DeferredTools(deferred.D1GrantReader())
    monkeypatch.setattr(knowledge, "api_authenticate_only", lambda **kwargs: lambda fn: fn)
    knowledge.register_knowledge_routes(app, Mock(exempt=lambda fn: fn))
    @app.before_request
    def identity():
        g.authenticated_user = USER
    for method, params in [("tools/list", {}), ("multillm.tools.discover", {"query": "technical"}),
                           ("tools/call", {"name": "knowledge_context", "arguments": {"query": "technical"}})]:
        response = app.test_client().post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        assert response.status_code == 503 and response.json["error"]["code"] == "tool_grants_unavailable"


def test_knowledge_argument_preflight_preserves_contract_pin(fixture, monkeypatch):
    service, rows, *_ = fixture
    rows[:] = [grant("knowledge_context", "knowledge:read")]
    app = Flask(__name__)
    app.extensions["deferred_tools"] = service
    monkeypatch.setenv("DEFERRED_TOOLS_ENABLED", "true")
    tool = next(e["definition"] for e in knowledge_mcp.catalogue()["tools"] if e["definition"]["name"] == "knowledge_context")
    with app.app_context():
        knowledge_mcp.check_contract_pin("knowledge_context", drift.contract_digest(tool), enabled=True,
                                         user=USER, arguments={"query": "technical"})
        with pytest.raises(KnowledgeError) as caught:
            knowledge_mcp.check_contract_pin("knowledge_context", "0" * 64, enabled=True,
                                             user=USER, arguments={"query": "technical"})
        assert caught.value.code == "mcp_contract_mismatch"


def test_private_grant_reader_uses_existing_allowlisted_state_endpoint(monkeypatch):
    rows = [grant("list_models")]
    monkeypatch.setattr(deferred.control_state_d1, "using_d1", lambda: True)
    call = Mock(return_value={"version": 1, "grants": rows})
    monkeypatch.setattr(deferred.control_state_d1, "call", call)
    assert deferred.D1GrantReader()("reader") == rows
    call.assert_called_once_with("model_overrides", "tool_grants", principal="reader")
    call.return_value = {"version": 2, "grants": rows}
    with pytest.raises(KnowledgeError) as caught:
        deferred.D1GrantReader()("reader")
    assert caught.value.status == 503
