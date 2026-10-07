"""Knowledge boundary checks use persisted keys and a synthetic private service."""

import json
import re
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask
from flask_wtf.csrf import CSRFError, CSRFProtect

from error_handlers import APIError, init_error_handlers
from routes import knowledge, knowledge_management
from routes.csrf_errors import handle_csrf_error
from route_helpers import api_authenticate_only
from services import knowledge_client
from services.auth_service import AuthService
from services.user_provisioning import account_scopes


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.sqlite3"))
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-knowledge-admin")
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    monkeypatch.setattr(AuthService, "_storage_path", None)
    monkeypatch.setattr(AuthService, "_users", {})
    monkeypatch.setattr(AuthService, "_api_key_prefix_index", {})
    monkeypatch.setattr("route_helpers.AuthService", AuthService)
    monkeypatch.setattr("routes.core.AuthService", AuthService)
    AuthService.initialize()
    result = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / "templates"))
    result.config.update(SECRET_KEY="synthetic-session-secret", WTF_CSRF_ENABLED=False, TESTING=True)
    init_error_handlers(result)
    csrf = CSRFProtect(result)
    result.register_error_handler(CSRFError, handle_csrf_error)
    result.add_url_rule("/v1/chat/completions", "fixture_chat",
                        csrf.exempt(api_authenticate_only(required_scope="chat")(lambda: {})), methods=["POST"])
    for endpoint in ("status_page", "workbench", "manage_users", "usage_page", "proxy_documentation", "openrouter_dashboard", "logout", "login"):
        result.add_url_rule("/fixture/" + endpoint, endpoint, lambda: "fixture")
    knowledge.register_knowledge_routes(result, csrf)
    return result


@pytest.fixture
def keys(app):
    with app.test_request_context(), patch.object(AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
        return {name: AuthService.create_user(name, scopes=scopes)["api_key"] for name, scopes in {
            "reader": ["knowledge:read"], "manager": ["knowledge:manage"], "chat": ["chat", "models"],
        }.items()}


def bearer(key, **extra):
    return {"Authorization": "Bearer " + key, **extra}


def admin_session(client):
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user"] = {"username": "admin", "api_key_prefix": "mllm_syntheti", "is_admin": True}


def test_scoped_read_uses_persisted_principal_and_no_llm_quota(app, keys):
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value={"status": "insufficient_evidence"}) as remote, patch("route_helpers.RateLimitService.reserve_request_slot") as reserve:
        response = client.post("/v1/knowledge/context", json={"query": " Flask limits "},
                               headers=bearer(keys["reader"], **{"X-Knowledge-Principal": "admin"}))
    assert response.status_code == 200
    assert response.json == {"status": "insufficient_evidence"}
    assert response.headers["Cache-Control"] == "no-store"
    assert remote.call_args.args[1]["username"] == "reader"
    assert remote.call_args.args[2] == {"query": "Flask limits"}
    reserve.assert_not_called()
    assert client.post("/v1/knowledge/context", json={"query": "limits"}, headers=bearer(keys["chat"])).status_code == 403
    assert client.post("/v1/knowledge/context", json={"query": "limits"}).status_code == 401
    assert client.post("/v1/chat/completions", json={}, headers=bearer(keys["reader"])).status_code == 403


def test_scoped_manager_can_manage_but_reader_cannot(app, keys):
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value={"id": "source-1"}) as remote:
        denied = client.post("/v1/knowledge/sources", json={"url": "https://docs.example/", "product": "example"}, headers=bearer(keys["reader"]))
        accepted = client.patch("/v1/knowledge/sources/source-1", json={"expected_revision": 1, "pinned": True}, headers=bearer(keys["manager"]))
    assert denied.status_code == 403
    assert accepted.status_code == 200
    assert remote.call_args.args[2] == {"id": "source-1", "expected_revision": 1, "pinned": True}


def test_rotation_immediately_rejects_old_knowledge_key(app, keys):
    client = app.test_client()
    with app.test_request_context(), patch.object(AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
        new_key = AuthService.rotate_api_key("reader")["api_key"]
    with patch.object(knowledge, "dispatch", return_value={"status": "insufficient_evidence"}) as remote:
        assert client.post("/v1/knowledge/search", json={"query": "test"}, headers=bearer(keys["reader"])).status_code == 401
        assert client.post("/v1/knowledge/search", json={"query": "test"}, headers=bearer(new_key)).status_code == 200
    assert remote.call_count == 1


@pytest.mark.parametrize("payload", [{}, {"query": " "}, {"query": "x", "token_budget": True},
    {"query": "x", "token_budget": 16001}, {"query": "x", "mode": []}, {"query": "x", "freshness": {}},
    {"query": "x", "principal": {"id": "admin"}}])
def test_invalid_queries_never_dispatch(app, keys, payload):
    with patch.object(knowledge, "dispatch") as remote:
        response = app.test_client().post("/v1/knowledge/context", json=payload, headers=bearer(keys["reader"]))
    assert response.status_code == 400
    remote.assert_not_called()


def test_body_limits_and_artifact_identifier(app, keys):
    client = app.test_client()
    assert client.post("/v1/knowledge/context", data="x" * 65537, content_type="application/json", headers=bearer(keys["reader"])).status_code == 413
    with patch.object(knowledge, "dispatch", return_value={"text": "source"}) as remote:
        response = client.get("/v1/knowledge/artifacts/artifact-1", headers=bearer(keys["reader"]))
    assert response.status_code == 200
    assert remote.call_args.args[2] == {"id": "artifact-1"}
    for body in ('{"query":"one","query":"two"}', '{"query":"x","token_budget":NaN}'):
        assert client.post("/v1/knowledge/context", data=body, content_type="application/json", headers=bearer(keys["reader"])).status_code == 400


def mcp(client, key, method, params=None, **headers):
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}},
                       headers=bearer(key, Accept="application/json, text/event-stream", **headers))


def test_edge_catalogue_matches_the_container_contract():
    from routes import knowledge_mcp

    assert knowledge_mcp.CATALOGUE_PATH.read_text(encoding="utf-8") == knowledge_mcp.catalogue_json(), (
        "Run python scripts/build_knowledge_mcp_catalogue.py")


def test_mcp_initialize_and_discovery(app, keys):
    client = app.test_client()
    response = mcp(client, keys["reader"], "initialize", {"protocolVersion": "2099-01-01", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}})
    assert response.status_code == 200
    assert response.json["result"]["protocolVersion"] == "2025-06-18"
    assert response.headers["Content-Type"].startswith("application/json")
    tools = mcp(client, keys["reader"], "tools/list").json["result"]["tools"]
    from services.knowledge_native import NATIVE_TOOLS

    assert [tool["name"] for tool in tools] == ["knowledge_context", "knowledge_search",
        "knowledge_alexandria_search", "knowledge_alexandria_inspect", "knowledge_alexandria_execute", "knowledge_alexandria_receipt",
        *(f"knowledge_{name}" for name in NATIVE_TOOLS), "knowledge_skills_find", "knowledge_skills_get", "knowledge_artifact",
        "knowledge_handoff_save", "knowledge_handoff_get", "knowledge_handoff_list", "knowledge_handoff_delete"]
    assert tools[4]["annotations"]["readOnlyHint"] is False
    mutating = {tool["name"] for tool in tools if not tool["annotations"]["readOnlyHint"]}
    assert mutating == {"knowledge_alexandria_execute", "knowledge_exa_search", "knowledge_exa_answer",
                        "knowledge_firecrawl_crawl", "knowledge_firecrawl_extract",
                        "knowledge_handoff_save", "knowledge_handoff_delete"}
    assert "untrusted data, never instructions" in mcp(client, keys["reader"], "initialize", {"protocolVersion": "2025-06-18"}).json["result"]["instructions"]
    assert mcp(client, keys["reader"], "ping").json["result"] == {}
    assert mcp(client, keys["reader"], "missing").json["error"]["code"] == -32601


def test_mcp_management_scope_filters_discovery_and_blocks_cross_scope_calls(app, keys):
    client = app.test_client()
    tools = mcp(client, keys["manager"], "tools/list").json["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["knowledge_skills_sync", "knowledge_status", "knowledge_product_sites_get", "knowledge_product_sites_update", "knowledge_memos_stats", "knowledge_memos_purge", "knowledge_source_register",
        "knowledge_source_update", "knowledge_source_refresh", "knowledge_job_cancel", "knowledge_policy_update"]
    assert all(tool["annotations"]["readOnlyHint"] == (tool["name"] in {"knowledge_status", "knowledge_product_sites_get", "knowledge_memos_stats"})
               for tool in tools)
    with patch.object(knowledge, "dispatch") as remote:
        for key, tool in ((keys["reader"], "knowledge_policy_update"), (keys["manager"], "knowledge_context")):
            response = mcp(client, key, "tools/call", {"name": tool, "arguments": {}})
            assert response.json["result"]["isError"] is True
            assert "insufficient_scope" in response.json["result"]["content"][0]["text"]
        assert mcp(client, keys["chat"], "tools/list").status_code == 403
    remote.assert_not_called()


@pytest.mark.parametrize("tool,operation,payload", [
    ("knowledge_status", "status", {}),
    ("knowledge_memos_stats", "memos.stats", {}),
    ("knowledge_memos_purge", "memos.purge", {"product": "flask"}),
    ("knowledge_source_register", "sources.create", {"url": "https://docs.python.org/3/", "product": "python"}),
    ("knowledge_source_update", "sources.update", {"id": "source-1", "expected_revision": 2, "enabled": False}),
    ("knowledge_source_refresh", "sources.refresh", {"id": "source-1"}),
    ("knowledge_job_cancel", "jobs.cancel", {"id": "job-1"}),
    ("knowledge_policy_update", "policy.update", {"expected_revision": 2, "enabled": False}),
])
def test_mcp_management_uses_existing_domain_contract(app, keys, tool, operation, payload):
    with patch.object(knowledge, "dispatch", return_value={"status": "accepted"}) as remote:
        response = mcp(app.test_client(), keys["manager"], "tools/call", {"name": tool, "arguments": payload},
                       **{"MCP-Protocol-Version": "2025-06-18"})
    assert response.json["result"]["structuredContent"] == {"status": "accepted"}
    assert remote.call_args.args[0] == operation
    assert remote.call_args.args[1]["username"] == "manager"
    assert remote.call_args.args[2] == payload


def test_mcp_management_surfaces_revision_conflict_without_retry(app, keys):
    with patch.object(knowledge, "dispatch", side_effect=knowledge_client.KnowledgeError("revision_conflict", "Reload the policy.", 409)) as remote:
        response = mcp(app.test_client(), keys["manager"], "tools/call", {
            "name": "knowledge_policy_update", "arguments": {"expected_revision": 1},
        })
    assert response.json["result"]["isError"] is True
    assert "revision_conflict" in response.json["result"]["content"][0]["text"]
    assert remote.call_count == 1


def test_mcp_calls_share_domain_operation_and_surface_tool_failures(app, keys):
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value={"status": "insufficient_evidence"}) as remote:
        response = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_context", "arguments": {"query": "limits"}}, **{"MCP-Protocol-Version": "2025-06-18"})
    assert response.json["result"]["structuredContent"] == {"status": "insufficient_evidence"}
    assert remote.call_args.args[0] == "context"
    with patch.object(knowledge, "dispatch", return_value={"status": "ok"}):
        response = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_context", "arguments": {"query": "limits"}})
    assert response.json["result"]["structuredContent"] == {"status": "ok"}, "no version header is needed"
    with patch.object(knowledge, "dispatch", side_effect=knowledge_client.KnowledgeError("budget_exhausted", "Allowance exhausted.", 429)):
        response = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_search", "arguments": {"query": "limits"}})
    assert response.json["result"]["isError"] is True
    assert "budget_exhausted" in response.json["result"]["content"][0]["text"]


def test_mcp_evidence_answers_drop_bookkeeping_that_rest_clients_still_receive(app, keys):
    excerpt = {"artifact_id": "art-1", "source_id": "src-1", "text": "Limits apply.", "url": "https://docs.example/limits",
               "locator": "#limits", "content_hash": "abc", "expires_at": "2026-10-08T00:00:00Z", "source_review": "reviewed"}
    bundle = {"status": "ok", "query": "limits", "excerpts": [excerpt],
              "related_evidence": [{**excerpt, "artifact_id": "art-2", "url": "https://docs.example/v1/limits"}],
              "discoveries": [{"url": "https://docs.example/limits"}, {"url": "https://other.example"}],
              "token_count": 40, "token_counting_method": "estimate", "served_at": "2026-10-07T00:00:00Z",
              "path": "index", "elapsed_ms": 12, "gaps": [], "index_diagnostics": {"skipped": {"unpublished": 0}},
              "usage": [{"provider": "ai_search", "operation_id": "op-1", "bound_units": 1, "outcome": "ok"},
                        {"provider": "exa", "operation_id": "op-2", "bound_units": 2},
                        {"provider": "exa", "operation_id": "op-3", "bound_units": "x"}]}
    kept = {"artifact_id": "art-1", "text": "Limits apply.", "url": "https://docs.example/limits", "locator": "#limits",
            "source_review": "reviewed"}
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value=bundle):
        for name in ("knowledge_context", "knowledge_search"):
            result = mcp(client, keys["reader"], "tools/call", {"name": name, "arguments": {"query": "limits"}}).json["result"]
            assert result["structuredContent"] == {
                "status": "ok", "excerpts": [kept],
                "related_evidence": [{**kept, "artifact_id": "art-2", "url": "https://docs.example/v1/limits"}],
                "discoveries": [{"url": "https://other.example"}], "token_count": 40, "path": "index", "elapsed_ms": 12,
                "gaps": [], "index_diagnostics": {"skipped": {"unpublished": 0}}, "units": {"ai_search": 1, "exa": 2}}
            assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
        assert client.post("/v1/knowledge/context", json={"query": "limits"}, headers=bearer(keys["reader"])).json == bundle


def test_mcp_origin_protocol_media_and_notifications(app, keys):
    client = app.test_client()
    assert mcp(client, keys["reader"], "ping", Origin="https://evil.example").status_code == 403
    assert mcp(client, keys["reader"], "ping", Origin="http://localhost").status_code == 200
    assert mcp(client, keys["reader"], "ping", **{"MCP-Protocol-Version": "unknown"}).status_code == 400
    for accept, status in (("application/json", 200), ("*/*", 200), ("text/event-stream", 406)):
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers=bearer(keys["reader"], Accept=accept))
        assert response.status_code == status, accept
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers=bearer(keys["reader"])).status_code == 200
    # 2025-03-26 requires JSON-RPC batching, which the server does not accept, so it is not offered.
    assert mcp(client, keys["reader"], "initialize", {"protocolVersion": "2025-03-26"}).json["result"]["protocolVersion"] == "2025-06-18"
    assert mcp(client, keys["reader"], "ping", **{"MCP-Protocol-Version": "2025-03-26"}).status_code == 400
    reply = client.post("/mcp", json={"jsonrpc": "2.0", "id": "server-1", "result": {}}, headers=bearer(keys["reader"]))
    assert reply.status_code == 202 and not reply.data
    assert mcp(client, keys["reader"], "initialize", {"capabilities": {}}).json["error"]["code"] == -32602
    response = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=bearer(keys["reader"], Accept="application/json, text/event-stream"))
    assert response.status_code == 202 and not response.data
    for method in (client.get, client.delete):
        assert method("/mcp", headers=bearer(keys["reader"])).status_code == 405
    response = mcp(client, keys["reader"], "tools/call", {"name": [], "arguments": {}})
    assert response.json["error"]["code"] == -32602


def test_mcp_toolsets_narrow_discovery_and_keys_without_knowledge_learn_the_scope_they_need(app, keys):
    client = app.test_client()

    def listed(query):
        response = client.post("/mcp" + query, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=bearer(keys["reader"]))
        return response.json

    assert [tool["name"] for tool in listed("?toolsets=core")["result"]["tools"]] == [
        "knowledge_context", "knowledge_search", "knowledge_artifact"]
    names = [tool["name"] for tool in listed("?toolsets=core,firecrawl")["result"]["tools"]]
    assert "knowledge_firecrawl_scrape" in names and "knowledge_exa_search" not in names
    assert listed("?toolsets=everything")["error"]["code"] == -32602
    denied = mcp(client, keys["chat"], "tools/list")
    assert denied.status_code == 403
    assert "knowledge:read" in json.dumps(denied.json)


def test_status_reports_whether_the_knowledge_worker_serves_this_contract(app, keys):
    from routes import knowledge_mcp

    operations = sorted({entry["operation"] for entry in knowledge_mcp.catalogue()["tools"]})
    matching = {"enabled": True, "contract": {"native_tools_hash": knowledge_mcp.native_tools_hash(), "operations": operations}}
    with patch.object(knowledge, "_dispatch", return_value=matching):
        check = mcp(app.test_client(), keys["manager"], "tools/call", {"name": "knowledge_status", "arguments": {}}).json
    assert check["result"]["structuredContent"]["contract_check"]["matched"] is True
    stale = {"contract": {"native_tools_hash": "0" * 64, "operations": operations[1:]}}
    with patch.object(knowledge, "_dispatch", return_value=stale):
        check = mcp(app.test_client(), keys["manager"], "tools/call", {"name": "knowledge_status", "arguments": {}}).json
    result = check["result"]["structuredContent"]["contract_check"]
    assert result["matched"] is False and result["missing_operations"] == operations[:1]


def test_dashboard_session_gate_csrf_and_setup(app, monkeypatch, keys):
    client = app.test_client()
    assert client.get("/knowledge").status_code == 302
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user"] = {"username": "reader", "api_key_prefix": "mllm_" + keys["reader"][:8], "is_admin": True}
    assert client.get("/knowledge").status_code == 403
    admin_session(client)
    page = client.get("/knowledge")
    assert page.status_code == 200 and b"Find source evidence" in page.data
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "false")
    result = client.get("/admin/knowledge/status")
    assert result.json["ready"] is False
    assert result.json["providers"] == []
    assert client.post("/admin/knowledge/query", json={"query": "limits"}).json["error"]["code"] == "setup_needed"
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.put("/admin/knowledge/policy", json={}).status_code == 400
    assert client.post("/admin/knowledge/sources", json={}).status_code == 400
    assert client.post("/v1/knowledge/context", json={"query": "limits"}, headers=bearer(keys["reader"])).status_code == 503


def test_scope_choices_preserve_defaults_and_prevent_escalation(app, keys):
    assert account_scopes(False, None) == ("chat", "models")
    assert AuthService.verify_api_key(keys["reader"])["scopes"] == ["knowledge:read"]
    for scopes in ([], ["admin"], ["users"], ["knowledge:read", "knowledge:read"], "knowledge:read", [None]):
        with pytest.raises(APIError):
            account_scopes(False, scopes)
    with pytest.raises(APIError):
        account_scopes(True, ["knowledge:read"])


class FakeResponse:
    def __init__(self, body, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json"}
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
    def iter_content(self, _size):
        yield self.body
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return None


def test_private_transport_uses_one_fixed_submission(monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    with patch.object(knowledge_client.requests, "Session") as factory:
        session = factory.return_value.__enter__.return_value
        session.post.return_value = FakeResponse({"version": 1, "result": {"status": "ok"}})
        result = knowledge_client.dispatch("context", {"username": "reader", "scopes": ["knowledge:read", "chat"]}, {"query": "limits"})
    assert result == {"status": "ok"}
    assert session.post.call_count == 1
    assert session.post.call_args.args == ("http://knowledge.internal/v1/dispatch",)
    arguments = session.post.call_args.kwargs
    assert arguments["allow_redirects"] is False
    assert session.trust_env is False
    assert "Authorization" not in arguments["headers"]
    assert json.loads(arguments["data"])["principal"] == {"id": "reader", "scopes": ["knowledge:read"]}


@pytest.mark.parametrize("response", [
    FakeResponse({"version": True, "result": {}}), FakeResponse({"version": 1, "result": "wrong"}),
    FakeResponse({"version": 1, "result": {}}, 302), FakeResponse(b"x" * (knowledge_client.MAX_RESPONSE_BYTES + 1)),
    FakeResponse({"version": 1, "result": {}}, headers={"Content-Type": "text/html"}),
    FakeResponse({"version": 1, "result": {}}, headers={"Content-Type": "application/json", "Content-Length": "NaN"}),
    FakeResponse(b'{"version":1,"version":1,"result":{}}'),
])
def test_invalid_private_responses_fail_closed(response):
    with pytest.raises(knowledge_client.KnowledgeError):
        knowledge_client._decode(response, threading.Event(), time.monotonic() + 1)


def test_worst_case_reencoded_upstream_payload_fits_the_private_envelope():
    count = (knowledge_client.UPSTREAM_JSON_BYTES - 2) // 5
    upstream = "[" + ",".join(["1e20"] * count) + "]"
    assert len(upstream) <= knowledge_client.UPSTREAM_JSON_BYTES
    # The Worker's JSON.stringify writes 1e20 as 21 digits; mirror that re-encoding.
    receipt = {"status": "ok", "cost": {"credits": 15, "state": "confirmed"}, "data": [10 ** 20] * count}
    envelope = json.dumps({"version": 1, "result": receipt}, separators=(",", ":")).encode()
    assert len(envelope) > 4 * knowledge_client.UPSTREAM_JSON_BYTES
    result = knowledge_client._decode(FakeResponse(envelope), threading.Event(), time.monotonic() + 5)
    assert len(result["data"]) == count


def test_transport_preserves_structured_failure_and_unknown_timeout(monkeypatch):
    with pytest.raises(knowledge_client.KnowledgeError) as failure:
        knowledge_client._decode(FakeResponse({"version": 1, "error": {"code": "budget_exhausted", "message": "Cap reached."}}, 429), threading.Event(), time.monotonic() + 1)
    assert failure.value.code == "budget_exhausted" and failure.value.status == 429
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    monkeypatch.setattr(knowledge_client, "DEADLINE_SECONDS", 0.01)
    def slow_submission(_body, _stopped, _deadline, _results):
        try:
            time.sleep(0.03)
        finally:
            knowledge_client._SLOTS.release()
    monkeypatch.setattr(knowledge_client, "_submit", slow_submission)
    with pytest.raises(knowledge_client.KnowledgeError) as failure:
        knowledge_client.dispatch("context", {"username": "reader", "scopes": ["knowledge:read"]}, {"query": "test"})
    assert failure.value.code == "knowledge_timeout"
    assert "may still finish" in failure.value.message


@pytest.mark.parametrize("operation,payload", [
    ("search", {"query": "podcasts"}), ("inspect", {"quote_id": "quote-1"}),
    ("execute", {"quote_id": "quote-1", "request_id": "request-1", "options": {}, "reserve_credits": 15}),
    ("receipt", {"request_id": "request-1"}),
])
def test_alexandria_rest_and_mcp_share_scoped_contract(app, keys, operation, payload):
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value={"cost": {"credits": 15, "state": "confirmed"}}) as remote:
        response = client.post(f"/v1/knowledge/alexandria/{operation}", json=payload, headers=bearer(keys["reader"]))
        assert response.status_code == 200
        assert remote.call_args.args[0] == "alexandria." + operation
        assert remote.call_args.args[2] == payload
        tool = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_alexandria_" + operation, "arguments": payload},
                   **{"MCP-Protocol-Version": "2025-06-18"})
        assert tool.json["result"]["structuredContent"] == response.json
        assert client.post(f"/v1/knowledge/alexandria/{operation}", json=payload, headers=bearer(keys["chat"])).status_code == 403
        assert client.post(f"/v1/knowledge/alexandria/{operation}", json=payload).status_code == 401
    admin_session(client)
    app.config["WTF_CSRF_ENABLED"] = True
    with patch.object(knowledge, "dispatch") as remote:
        assert client.post(f"/admin/knowledge/alexandria/{operation}", json=payload).status_code == 400
        remote.assert_not_called()


@pytest.mark.parametrize("operation,payload", [
    ("search", {"query": "x", "sources": ["web"]}), ("search", {"query": "x", "limit": True}),
    ("search", {"query": "x\n"}), ("inspect", {"provider": "invented", "capability": "secret"}),
    ("receipt", {"request_id": "../other"}),
    ("execute", {"quote_id": "q", "request_id": "r", "options": [], "reserve_credits": 15}),
    ("execute", {"quote_id": "q", "request_id": "r", "options": {}, "reserve_credits": True}),
    ("execute", {"quote_id": "q", "request_id": "r", "options": {}, "reserve_credits": 15, "accept_variable_cost": "true"}),
])
def test_alexandria_invalid_inputs_never_reach_private_service(app, keys, operation, payload):
    with patch.object(knowledge, "dispatch") as remote:
        response = app.test_client().post(f"/v1/knowledge/alexandria/{operation}", json=payload, headers=bearer(keys["reader"]))
        assert response.status_code == 400
        remote.assert_not_called()


def test_alexandria_mcp_surfaces_unknown_cost_as_tool_error(app, keys):
    result = {"status": "unknown", "cost": {"credits": None, "state": "unknown"},
              "error": {"code": "provider_timeout", "message": "Cost unknown; check the receipt."}}
    with patch.object(knowledge, "dispatch", return_value=result):
        response = mcp(app.test_client(), keys["reader"], "tools/call", {"name": "knowledge_alexandria_receipt", "arguments": {"request_id": "r"}},
                       **{"MCP-Protocol-Version": "2025-06-18"})
    assert response.json["result"]["isError"] is True
    assert response.json["result"]["structuredContent"] == result


def test_alexandria_private_operation_is_allowlisted(monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    with patch.object(knowledge_client.requests, "Session") as factory:
        session = factory.return_value.__enter__.return_value
        session.post.return_value = FakeResponse({"version": 1, "result": {"tools": [], "cost": {"credits": 0, "state": "confirmed"}}})
        result = knowledge_client.dispatch("alexandria.search", {"username": "reader", "scopes": ["knowledge:read"]}, {"query": "podcasts"})
    assert result["cost"]["credits"] == 0
    assert json.loads(session.post.call_args.kwargs["data"])["operation"] == "alexandria.search"


def test_provider_tools_forward_native_arguments_over_mcp_and_rest(app, keys):
    client = app.test_client()
    arguments = {"query": "rust async", "type": "deep", "numResults": 20, "contents": {"highlights": True}}
    with patch.object(knowledge, "dispatch", return_value={"provider": "exa", "result": {"results": []}}) as remote:
        response = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_exa_search", "arguments": arguments},
                       **{"MCP-Protocol-Version": "2025-06-18"})
        assert response.json["result"]["structuredContent"]["provider"] == "exa"
        assert remote.call_args.args[0] == "native.exa_search"
        assert remote.call_args.args[2] == arguments
        rest = client.post("/v1/knowledge/native/firecrawl_map", json={"url": "https://docs.python.org/3/"},
                           headers=bearer(keys["reader"]))
        assert rest.status_code == 200
        assert remote.call_args.args[:3][0] == "native.firecrawl_map"
        assert client.post("/v1/knowledge/native/unknown_tool", json={}, headers=bearer(keys["reader"])).status_code == 404
        assert client.post("/v1/knowledge/native/exa_search", json={"query": "x"}, headers=bearer(keys["chat"])).status_code == 403
    assert remote.call_count == 2


def test_container_transport_accepts_every_provider_operation():
    from services.knowledge_native import NATIVE_OPERATIONS

    assert set(NATIVE_OPERATIONS) <= knowledge_client._OPERATIONS
    assert knowledge_client.DEADLINE_SECONDS >= 50


@pytest.mark.parametrize("method,operation,tool,payload", [
    ("get", "product_sites.get", "knowledge_product_sites_get", {}),
    ("patch", "product_sites.update", "knowledge_product_sites_update",
     {"pin": ["developer.mozilla.org", "github.com/mdn"], "block": ["overflow.co", "gitlab.com/unrelated"],
      "note": "Different product", "rebuild": True}),
])
def test_product_sites_rest_and_mcp_parity_with_scopes(app, keys, method, operation, tool, payload):
    client = app.test_client()
    product = "css overflow-clip-margin"
    path = "/v1/knowledge/product-sites/css%20overflow-clip-margin"
    call = getattr(client, method)
    options = {"json": payload} if method == "patch" else {}
    assert call(path, headers=bearer(keys["reader"]), **options).status_code == 403
    assert call(path, **options).status_code == 401
    result = {"product": product, "sites": {}, "blocked": {}, "revision": 0}
    with patch.object(knowledge, "dispatch", return_value=result) as remote:
        rest = call(path, headers=bearer(keys["manager"]), **options)
        assert remote.call_args.args[0] == operation
        assert remote.call_args.args[2] == {**payload, "product": product}
        rpc = mcp(client, keys["manager"], "tools/call", {"name": tool, "arguments": {**payload, "product": product}})
        assert rpc.json["result"]["structuredContent"] == rest.json == result
        assert remote.call_args.args[0] == operation
        assert remote.call_args.args[2] == {**payload, "product": product}


def test_product_sites_management_schema_accepts_only_hostnames_and_code_owners():
    tool = next(tool for tool in knowledge_management.TOOLS if tool["name"] == "knowledge_product_sites_update")
    properties = tool["inputSchema"]["properties"]
    for action in ("pin", "unpin", "block", "unblock"):
        schema = properties[action]["items"]
        assert schema["maxLength"] == 253
        for site in ("github.com/pallets", "raw.githubusercontent.com/pallets", "gitlab.com/team.docs",
                     "bitbucket.org/team_name", "first.readthedocs.io", "example.co.uk"):
            assert re.fullmatch(schema["pattern"], site)
        for site in ("github.com/Pallets", "github.com/pallets/repo", "example.org/page", "github.com/",
                     "github.com/%70allets", "github.com/" + "x" * 101):
            assert not re.fullmatch(schema["pattern"], site)


def test_product_sites_validation_errors_surface_without_retry(app, keys):
    client = app.test_client()
    with patch.object(knowledge, "dispatch") as remote:
        assert client.patch("/v1/knowledge/product-sites/codex", json={"product": "other"},
                            headers=bearer(keys["manager"])).status_code == 400
        remote.assert_not_called()
    with patch.object(knowledge, "dispatch", side_effect=knowledge_client.KnowledgeError(
            "invalid_request", "Use lowercase hostnames.", 400)) as remote:
        response = client.patch("/v1/knowledge/product-sites/codex", json={"pin": ["UPPER.dev"]},
                                headers=bearer(keys["manager"]))
        assert response.status_code == 400
        assert response.json["error"]["code"] == "invalid_request"
        rpc = mcp(client, keys["manager"], "tools/call", {
            "name": "knowledge_product_sites_update", "arguments": {"product": "codex", "pin": ["UPPER.dev"]},
        })
        assert rpc.json["result"]["isError"] is True
        assert "invalid_request" in rpc.json["result"]["content"][0]["text"]
        assert remote.call_count == 2


@pytest.mark.parametrize("method,path,body,operation,payload", [
    ("GET", "/v1/knowledge/memos", None, "memos.stats", {}),
    ("DELETE", "/v1/knowledge/memos", {"product": "flask"}, "memos.purge", {"product": "flask"}),
    ("DELETE", "/v1/knowledge/memos?all=true", None, "memos.purge", {"all": True}),
    ("DELETE", "/v1/knowledge/memos?product=", None, "memos.purge", {"product": ""}),
])
def test_memo_rest_mcp_parity_and_scope(app, keys, method, path, body, operation, payload):
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value={"accepted": True}) as remote:
        denied = client.open(path, method=method, json=body, headers=bearer(keys["reader"]))
        assert denied.status_code == 403
        remote.assert_not_called()
        response = client.open(path, method=method, json=body, headers=bearer(keys["manager"]))
        assert response.status_code == 200
        assert remote.call_args.args[0] == operation
        assert remote.call_args.args[2] == payload
        tool = "knowledge_memos_stats" if operation == "memos.stats" else "knowledge_memos_purge"
        result = mcp(client, keys["manager"], "tools/call", {"name": tool, "arguments": payload})
        assert result.json["result"]["structuredContent"] == response.json
        assert remote.call_args.args[0] == operation
        assert remote.call_args.args[2] == payload


@pytest.mark.parametrize("path,body", [
    ("/v1/knowledge/memos?all=1", None),
    ("/v1/knowledge/memos?all=true&all=false", None),
    ("/v1/knowledge/memos?other=flask", None),
    ("/v1/knowledge/memos?product=flask", {"all": True}),
])
def test_memo_rest_rejects_ambiguous_or_invalid_query(app, keys, path, body):
    with patch.object(knowledge, "dispatch") as remote:
        response = app.test_client().delete(path, json=body, headers=bearer(keys["manager"]))
        assert response.status_code == 400
        remote.assert_not_called()


def test_memo_metadata_survives_mcp_trim():
    memo = {"kind": "semantic", "similarity": 0.95, "matched_query": "limits", "age_seconds": 12}
    result = knowledge._agent_evidence({"excerpts": [], "usage": [], "served_at": "synthetic", "memo": memo})
    assert result["memo"] == memo
    assert "served_at" not in result

HANDOFF_ROUTES = json.loads((Path(__file__).parent / "fixtures/handoff_routes.json").read_text())

@pytest.mark.parametrize("case", HANDOFF_ROUTES)
def test_handoff_rest_parity(app, keys, case):
    client = app.test_client()
    with patch.object(knowledge, "dispatch", return_value={"trust": "operator"}) as remote:
        response = client.open(case["path"], method=case["method"], json=case["body"], headers=bearer(keys["reader"]))
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert remote.call_args.args[0] == case["operation"]
    assert remote.call_args.args[2] == case["payload"]
    assert client.open(case["path"], method=case["method"], json=case["body"], headers=bearer(keys["manager"])).status_code == 403


@pytest.mark.parametrize("arguments", [{"project": "synthetic/repo"}, {"id": "fixture-id"}, {"project": "Synthetic/Repo", "id": "fixture-id"}])
def test_handoff_mcp_toolset_and_markdown(app, keys, arguments):
    client = app.test_client()
    headers = bearer(keys["reader"], Accept="application/json")
    tools = client.post("/mcp?toolsets=handoff", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=headers).json["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["knowledge_handoff_save", "knowledge_handoff_get", "knowledge_handoff_list", "knowledge_handoff_delete"]
    shown = {"record": {"id": "fixture-id"}, "markdown": "# Fixture", "trust": "operator"}
    with patch.object(knowledge, "dispatch", return_value=shown) as remote:
        result = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "knowledge_handoff_get", "arguments": arguments}}, headers=headers).json["result"]
    assert remote.call_args.args[0] == "handoffs.get"
    assert remote.call_args.args[2] == arguments
    assert result["content"][0]["text"] == "# Fixture"
    assert result["structuredContent"] == shown


@pytest.mark.parametrize("path", ["/v1/knowledge/handoffs?limit=1&limit=2", "/v1/knowledge/handoffs?limit=1.5",
                                 "/v1/knowledge/handoffs/latest?unexpected=1", "/v1/knowledge/handoffs/fixture-id?project=p&project=q"])
def test_handoff_rejects_ambiguous_queries(app, keys, path):
    with patch.object(knowledge, "dispatch") as remote:
        response = app.test_client().get(path, headers=bearer(keys["reader"]))
    assert response.status_code == 400
    remote.assert_not_called()


@pytest.mark.parametrize("path", ["/mcp", "/v1/knowledge/handoffs"])
def test_handoff_flask_firewall_blocks_before_private_transport(app, keys, path):
    secret = "AK" + "IA" + "AB12CD34EF56GH78"
    payload = {"project": "synthetic/repo", "title": "Fixture", "sections": {"goal": secret}, "source": {"agent": "codex"}}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "knowledge_handoff_save", "arguments": payload}} if path == "/mcp" else payload
    with patch.object(knowledge_client, "_submit") as transport:
        response = app.test_client().post(path, json=body, headers=bearer(keys["reader"], Accept="application/json"))
    assert response.status_code == 422
    assert secret not in response.get_data(as_text=True)
    transport.assert_not_called()


def test_skills_rest_mcp_scope_toolset_and_list_parity(app, keys):
    client = app.test_client()
    result = [{"skill_id": "testing", "name": "Testing", "description": "Test guide", "score": 1,
               "why": ["test"], "files": ["SKILL.md"]}]
    with patch.object(knowledge, "dispatch", return_value=result) as remote:
        rest = client.get("/v1/knowledge/skills?query=test&mode=fast&limit=3&roots=agents,codex", headers=bearer(keys["reader"]))
        assert remote.call_args.args[0] == "skills.find"
        assert remote.call_args.args[2] == {"query": "test", "mode": "fast", "limit": 3, "roots": ["agents", "codex"]}
        rpc = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_skills_find", "arguments": {"query": "test", "mode": "fast"}})
        assert rest.json == json.loads(rpc.json["result"]["content"][0]["text"])
        assert "structuredContent" not in rpc.json["result"]
    with patch.object(knowledge, "dispatch", return_value={"text": "Guide", "trust": "operator"}) as remote:
        response = client.get("/v1/knowledge/skills/testing?path=references/guide.md", headers=bearer(keys["reader"]))
        assert response.json["trust"] == "operator"
        assert remote.call_args.args[2] == {"skill_id": "testing", "path": "references/guide.md"}
    assert client.post("/v1/knowledge/skills", json={"skills": []}, headers=bearer(keys["reader"])).status_code == 403
    with patch.object(knowledge, "dispatch", return_value={"results": []}) as remote:
        assert client.post("/v1/knowledge/skills", json={"skills": []}, headers=bearer(keys["manager"])).status_code == 200
        assert remote.call_args.args[0] == "skills.sync"
        large = {"skills": [{"files": [{"content": "x" * 100000}]}]}
        assert client.post("/v1/knowledge/skills", json=large, headers=bearer(keys["manager"])).status_code == 200
        assert mcp(client, keys["manager"], "tools/call", {"name": "knowledge_skills_sync", "arguments": large}).status_code == 200
    with patch.object(knowledge, "dispatch") as remote:
        assert client.get("/v1/knowledge/skills?query=test&query=again", headers=bearer(keys["reader"])).status_code == 400
        assert client.get("/v1/knowledge/skills?query=test&limit=bad", headers=bearer(keys["reader"])).status_code == 400
        remote.assert_not_called()
    listed = client.post("/mcp?toolsets=skills", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=bearer(keys["reader"]))
    assert [tool["name"] for tool in listed.json["result"]["tools"]] == ["knowledge_skills_find", "knowledge_skills_get"]


def test_skills_client_delegates_sync_scan_to_handler_and_retains_normal_scans(monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    user = {"username": "synthetic-operator", "scopes": ["knowledge:read", "knowledge:manage"]}
    token = "gh" + "p_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
    received = []
    def submit(body, stopped, deadline, results):
        received.append(json.loads(body))
        results.put(({"results": []}, None))
        knowledge_client._SLOTS.release()
    with patch.object(knowledge_client, "_submit", side_effect=submit), patch.object(knowledge_client, "protect_payload", side_effect=AssertionError("sync must use handler scanning")):
        assert knowledge_client.dispatch("skills.sync", user, {"skills": [{"content": token}]}) == {"results": []}
    assert received[0]["secret_scan_checked"] is True
    with patch.object(knowledge_client, "protect_payload", return_value={"query": "testing"}) as scan, patch.object(knowledge_client, "_submit", side_effect=submit):
        knowledge_client.dispatch("skills.find", user, {"query": "testing"})
        scan.assert_called_once()


def test_skills_sync_transport_limits(app, keys, monkeypatch):
    client = app.test_client()
    maximum = 8 * 1024 * 1024
    assert knowledge_client.SYNC_REQUEST_BYTES == maximum
    raw = json.dumps({"skills": []})
    with patch.object(knowledge, "dispatch", return_value={"results": []}) as remote:
        assert client.post("/v1/knowledge/skills", data=raw.ljust(maximum), content_type="application/json", headers=bearer(keys["manager"])).status_code == 200
        remote.reset_mock()
        assert client.post("/v1/knowledge/skills", data=raw.ljust(maximum + 1), content_type="application/json", headers=bearer(keys["manager"])).status_code == 413
        remote.assert_not_called()
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    user = {"username": "synthetic-operator", "scopes": ["knowledge:manage"]}
    received = []
    def submit(body, stopped, deadline, results):
        received.append(len(body))
        results.put(({"results": []}, None))
        knowledge_client._SLOTS.release()
    with patch.object(knowledge_client, "_submit", side_effect=submit):
        knowledge_client.dispatch("skills.sync", user, {"skills": [], "padding": ""})
        overhead = received.pop()
        assert knowledge_client.dispatch("skills.sync", user, {"skills": [], "padding": "x" * (maximum - overhead)}) == {"results": []}
        assert received == [maximum]
        with pytest.raises(knowledge_client.KnowledgeError) as error:
            knowledge_client.dispatch("skills.sync", user, {"skills": [], "padding": "x" * (maximum - overhead + 1)})
        assert error.value.status == 413
