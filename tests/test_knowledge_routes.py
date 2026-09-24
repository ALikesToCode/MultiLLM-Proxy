"""Knowledge boundary checks use persisted keys and a synthetic private service."""

import json
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask
from flask_wtf.csrf import CSRFError, CSRFProtect

from error_handlers import APIError, init_error_handlers
from routes import knowledge
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
    for endpoint in ("status_page", "workbench", "manage_users", "proxy_documentation", "openrouter_dashboard", "logout", "login"):
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


def test_mcp_initialize_and_discovery(app, keys):
    client = app.test_client()
    response = mcp(client, keys["reader"], "initialize", {"protocolVersion": "2099-01-01", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}})
    assert response.status_code == 200
    assert response.json["result"]["protocolVersion"] == "2025-06-18"
    assert response.headers["Content-Type"].startswith("application/json")
    tools = mcp(client, keys["reader"], "tools/list").json["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["knowledge_context", "knowledge_search",
        "knowledge_alexandria_search", "knowledge_alexandria_inspect", "knowledge_alexandria_execute", "knowledge_alexandria_receipt", "knowledge_artifact"]
    assert tools[4]["annotations"]["readOnlyHint"] is False
    assert mcp(client, keys["reader"], "ping").json["result"] == {}
    assert mcp(client, keys["reader"], "missing").json["error"]["code"] == -32601


def test_mcp_management_scope_filters_discovery_and_blocks_cross_scope_calls(app, keys):
    client = app.test_client()
    tools = mcp(client, keys["manager"], "tools/list").json["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["knowledge_status", "knowledge_source_register",
        "knowledge_source_update", "knowledge_source_refresh", "knowledge_job_cancel", "knowledge_policy_update"]
    assert tools[0]["annotations"]["readOnlyHint"] is True
    assert all(not tool["annotations"]["readOnlyHint"] for tool in tools[1:])
    with patch.object(knowledge, "dispatch") as remote:
        for key, tool in ((keys["reader"], "knowledge_policy_update"), (keys["manager"], "knowledge_context")):
            response = mcp(client, key, "tools/call", {"name": tool, "arguments": {}})
            assert response.json["result"]["isError"] is True
            assert "insufficient_scope" in response.json["result"]["content"][0]["text"]
        assert mcp(client, keys["chat"], "tools/list").status_code == 403
    remote.assert_not_called()


@pytest.mark.parametrize("tool,operation,payload", [
    ("knowledge_status", "status", {}),
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
    with patch.object(knowledge, "dispatch", side_effect=knowledge_client.KnowledgeError("budget_exhausted", "Allowance exhausted.", 429)):
        response = mcp(client, keys["reader"], "tools/call", {"name": "knowledge_search", "arguments": {"query": "limits"}})
    assert response.json["result"]["isError"] is True
    assert "budget_exhausted" in response.json["result"]["content"][0]["text"]


def test_mcp_origin_protocol_media_and_notifications(app, keys):
    client = app.test_client()
    assert mcp(client, keys["reader"], "ping", Origin="https://evil.example").status_code == 403
    assert mcp(client, keys["reader"], "ping", Origin="http://localhost").status_code == 200
    assert mcp(client, keys["reader"], "ping", **{"MCP-Protocol-Version": "unknown"}).status_code == 400
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers=bearer(keys["reader"], Accept="application/json")).status_code == 406
    response = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=bearer(keys["reader"], Accept="application/json, text/event-stream"))
    assert response.status_code == 202 and not response.data
    for method in (client.get, client.delete):
        assert method("/mcp", headers=bearer(keys["reader"])).status_code == 405
    response = mcp(client, keys["reader"], "tools/call", {"name": [], "arguments": {}})
    assert response.json["error"]["code"] == -32602


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
