"""Owned batch files, explicit admission and real managed execution boundaries."""
import io
import json

import pytest
from flask import Flask, g, jsonify, request
from flask_wtf.csrf import CSRFProtect

from error_handlers import init_error_handlers
from services import gateway_batches as batches
from routes.gateway_batches import register_gateway_batch_routes


def line(custom_id="one", **changes):
    return {"custom_id": custom_id, "method": "POST", "url": "/v1/chat/completions",
            "body": {"model": "openai:test", "messages": [{"role": "user", "content": "hello"}],
                     "max_tokens": 10}, **changes}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GATEWAY_BATCHES_ENABLED", "true")
    monkeypatch.setenv("BATCH_SPILLOVER_ENABLED", "false")
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "false")
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", '{"openai:test":{"input":1,"output":2}}')
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="synthetic-batch-secret")
    init_error_handlers(app)
    CSRFProtect(app)
    import route_helpers
    monkeypatch.setattr(route_helpers, "_authenticate_api_request", lambda: None)
    monkeypatch.setattr(route_helpers, "_authorize_api_scope", lambda _: None)
    monkeypatch.setattr(route_helpers, "_call_accounted", lambda target, args, kwargs: target(*args, **kwargs))
    @app.before_request
    def owner():
        g.authenticated_user = {"username": "alice", "scopes": ["chat"]}
    register_gateway_batch_routes(app)
    app.batch_calls = []
    def call(operation, **fields):
        app.batch_calls.append((operation, fields))
        if operation == "file_content":
            import base64
            return {"content": base64.b64encode((json.dumps(line()) + "\n").encode()).decode()}
        return {"data": [], "object": "list", "id": fields.get("id", "file_test"),
                "batch": {"id": "batch_test", "object": "batch", "status": "validating"}}
    monkeypatch.setattr(batches, "call", call)
    return app.test_client(), app


@pytest.mark.parametrize("value", ["", "false", "0", "invalid", "secret-value"])
def test_disabled_paths_do_not_touch_storage(client, monkeypatch, value):
    c, app = client
    monkeypatch.setenv("GATEWAY_BATCHES_ENABLED", value)
    for path in ("/v1/files", "/v1/files/file_test", "/v1/files/file_test/content", "/v1/batches"):
        assert c.get(path).status_code == 404
    assert not app.batch_calls


def test_upload_validates_before_storage(client):
    c, app = client
    response = c.post("/v1/files", data={"purpose": "batch", "file": (io.BytesIO((json.dumps(line()) + "\n").encode()), "input.jsonl")})
    assert response.status_code == 200
    assert app.batch_calls[0][0] == "file_create"
    response = c.post("/v1/files", data={"purpose": "batch", "file": (io.BytesIO((json.dumps(line()) + "\n{}\n").encode()), "input.jsonl")})
    assert response.status_code == 400
    assert response.json["error"]["line"] == 2
    assert len(app.batch_calls) == 1


@pytest.mark.parametrize("data,bad_line", [
    (b"not json\n", 1), (b"\xff", 1), (b"", 1),
    ((json.dumps(line()) + "\n" + json.dumps(line())).encode(), 2),
    (json.dumps(line(method="GET")).encode(), 1),
    (json.dumps(line(url="https://example.com")).encode(), 1),
    (json.dumps(line(body={"model": "x", "stream": True})).encode(), 1),
    (("\n".join(json.dumps(line(str(i))) for i in range(1001))).encode(), 1001),
])
def test_invalid_jsonl_reports_first_line(data, bad_line):
    with pytest.raises(batches.BatchError) as raised:
        batches.validate_jsonl(data)
    assert raised.value.status == 400
    assert raised.value.line == bad_line


def test_byte_limit():
    with pytest.raises(batches.BatchError) as raised:
        batches.validate_jsonl(b" " * (10 * 1024 * 1024 + 1))
    assert raised.value.status == 400


@pytest.mark.parametrize("budget", [None, "0", "-1", "NaN", "1e2", 1, "0.00000000001"])
def test_budget_requires_positive_bounded_decimal_string(budget):
    with pytest.raises(batches.BatchError):
        batches.budget_units(budget)


def test_creation_rejects_unknown_prices(client, monkeypatch):
    c, app = client
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", "{}")
    response = c.post("/v1/batches", json={"input_file_id": "file_test", "endpoint": "/v1/chat/completions",
        "completion_window": "24h", "metadata": {"multillm_budget_usd": "1"}})
    assert response.status_code == 400
    assert response.json["error"]["code"] == "unknown_price"
    assert not any(op == "batch_create" for op, _ in app.batch_calls)


def test_missing_table_has_clear_json_503(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(batches, "call", lambda *a, **kw: (_ for _ in ()).throw(batches.BatchError(503, "gateway_batches_unavailable", "Batch storage is unavailable; apply its D1 migration.")))
    response = c.get("/v1/batches")
    assert response.status_code == 503
    assert "migration" in response.json["error"]["message"]


def test_zero_retention_rejects_writes(client, monkeypatch):
    c, app = client
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", '{"default":"zero"}')
    for path in ("/v1/files", "/v1/batches"):
        response = c.post(path, json={})
        assert response.status_code == 400
        assert response.json["error"]["code"] == "retention_conflict"
    assert not app.batch_calls



def test_endpoint_zero_retention_rejects_upload_and_creation(client, monkeypatch):
    c, app = client
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", '{"routes":{"/v1/chat/completions":"zero"}}')
    uploaded = c.post("/v1/files", data={"purpose": "batch", "file": (io.BytesIO(json.dumps(line()).encode()), "input.jsonl")})
    assert uploaded.status_code == 400
    assert uploaded.json["error"]["code"] == "retention_conflict"
    assert not app.batch_calls
    created = c.post("/v1/batches", json={"input_file_id": "file_test", "endpoint": "/v1/chat/completions",
        "completion_window": "24h", "metadata": {"multillm_budget_usd": "1"}})
    assert created.status_code == 400
    assert created.json["error"]["code"] == "retention_conflict"
    assert not any(op == "batch_create" for op, _ in app.batch_calls)

def test_spillover_is_explicit_and_returns_real_batch(client, monkeypatch):
    c, app = client
    @app.post("/v1/chat/completions")
    def chat():
        from services.gateway_extensions import after_authentication
        refused = after_authentication()
        return refused if refused is not None else jsonify({"normal": True})
    app.extensions["csrf"].exempt(chat)
    headers = {"X-MultiLLM-Priority": "batch", "Prefer": "respond-async"}
    assert c.post("/v1/chat/completions", json=line()["body"], headers=headers).json == {"normal": True}
    monkeypatch.setenv("BATCH_SPILLOVER_ENABLED", "true")
    for partial in ({"Prefer": "respond-async"}, {"X-MultiLLM-Priority": "batch"}):
        assert c.post("/v1/chat/completions", json=line()["body"], headers=partial).status_code == 200
    monkeypatch.setenv("FLASK_SECRET_KEY", "synthetic-batch-signing")
    response = c.post("/v1/chat/completions", json={**line()["body"], "metadata": {"multillm_budget_usd": "1"}}, headers=headers)
    assert response.status_code == 202
    assert response.json["object"] == "batch"
    assert "choices" not in response.json
    assert any(op == "batch_create" for op, _ in app.batch_calls)



@pytest.mark.parametrize("body", [{"model": "x", "max_tokens": 0}, {"model": "x", "max_output_tokens": 262145},
                                 {"model": "x", "n": True}, {"model": "x", "n": 17}])
def test_token_and_completion_bounds(body):
    with pytest.raises(batches.BatchError) as raised:
        batches.validate_jsonl(json.dumps(line(body=body)).encode())
    assert raised.value.status == 400
    assert raised.value.line == 1


def test_upload_purpose_and_byte_bound_fail_before_storage(client):
    c, app = client
    for purpose, data in (("assistants", json.dumps(line()).encode()), ("batch", b" " * (batches.MAX_FILE_BYTES + 1))):
        response = c.post("/v1/files", data={"purpose": purpose, "file": (io.BytesIO(data), "input.jsonl")})
        assert response.status_code == 400
    assert not app.batch_calls


def test_estimate_reserves_all_completions_and_conservative_default(client):
    single = batches.estimate_item(line())
    assert batches.estimate_item(line(body={**line()["body"], "n": 2})) > single
    assert batches.estimate_item(line(body={"model": "openai:test", "messages": []})) > single


def test_private_transport_never_retries_or_follows_redirects(monkeypatch):
    import requests
    operations = []
    class Session:
        trust_env = True
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def mount(self, prefix, adapter):
            assert prefix == "http://" and adapter.max_retries.total == 0
        def post(self, url, **kwargs):
            assert self.trust_env is False
            assert kwargs["allow_redirects"] is False
            assert kwargs["timeout"] == (3, 30)
            operations.append(url)
            raise requests.exceptions.ConnectionError("synthetic failure")
    monkeypatch.setattr(batches.requests, "Session", Session)
    with pytest.raises(batches.BatchError) as raised:
        batches.call("file_list", owner="alice")
    assert raised.value.status == 503
    assert operations == [batches.ENDPOINT]

from tests.unified_api_test_case import UnifiedApiTestCase
from unittest.mock import patch
import importlib
import os


class RegisteredBatchTests(UnifiedApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()
        for name in ("CONTENT_RETENTION_ENABLED", "USAGE_RESERVATIONS_ENABLED", "MANAGED_IDEMPOTENCY_ENABLED",
                     "GENERATION_CACHE_SHARED_ENABLED", "USAGE_LEDGER_ENABLED", "PROMPT_CACHE_AFFINITY_ENABLED",
                     "BATCH_SPILLOVER_ENABLED"):
            os.environ[name] = "false"
        os.environ.update(GATEWAY_BATCHES_ENABLED="true", SESSION_TIER_MODE="off",
                          MODEL_PRICING_USD_PER_MILLION='{"mimo:mimo-v2.5":{"input":1,"output":2}}')
        self.routes = importlib.import_module("routes.gateway_batches")
        self.service = self.routes.batches
        self.routes.register_gateway_batch_routes(self.app)
        from services.budget_service import BudgetService
        BudgetService.reset()
        self.addCleanup(BudgetService.reset)
        self.user = importlib.import_module("services.auth_service").AuthService.verify_api_key("admin-test-key", "127.0.0.1")
        self.item = line(body={"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 10})
        self.item["estimate_units"] = self.service.estimate_item(self.item)
        self.batch = {"id": "batch_test", "client_ip": "127.0.0.1", "key_hash": "", "key_prefix": ""}

    def internal(self):
        from services.media_signing import issue_principal
        capability = issue_principal("gateway_batch", "batch_test", self.user["username"], 100)
        return self.client.post("/internal/gateway/batch-item", json={"batch_id": "batch_test", "idx": 0, "lease_token": "lease_test"},
                                headers={"Authorization": "BatchPrincipal " + capability})

    def test_registered_internal_dispatch_reuses_managed_accounting_and_deadline(self):
        accounting = importlib.import_module("services.request_accounting")
        seen = []
        def send(**kwargs):
            assert g.authenticated_user["username"] == self.user["username"]
            assert 0 < g.generation_deadline.remaining() <= 30
            assert g.gateway_cancellation is not None
            seen.append(json.loads(kwargs["data"]))
            reply = self._chat_response()
            body = json.loads(reply.content)
            body["usage"] = {"prompt_tokens": 4, "completion_tokens": 2}
            reply._content = json.dumps(body).encode()
            return reply
        with patch.object(self.service, "call", return_value={"item": self.item, "batch": self.batch}) as start, \
             patch.object(self.app_module.ProxyService, "make_request", side_effect=send), \
             patch.object(accounting, "mark_dispatched", wraps=accounting.mark_dispatched) as mark:
            response = self.internal()
        assert response.status_code == 200, response.json
        assert response.json["status_code"] == 200, response.json
        assert response.json["cost_units"] == 80000
        assert response.json["ambiguous"] is False
        assert len(seen) == mark.call_count == 1
        assert start.call_args.args == ("item_start",)
        assert seen[0]["model"] == "mimo-v2.5"

    def test_registered_item_runs_the_route_response_finalizers(self):
        finalized = []
        def record(response):
            finalized.append(request.path)
            return response
        self.app.after_request(record)
        def send(**kwargs):
            reply = self._chat_response()
            body = json.loads(reply.content)
            body["usage"] = {"prompt_tokens": 4, "completion_tokens": 2}
            reply._content = json.dumps(body).encode()
            return reply
        with patch.object(self.service, "call", return_value={"item": self.item, "batch": self.batch}), \
             patch.object(self.app_module.ProxyService, "make_request", side_effect=send):
            response = self.internal()
        assert response.json["status_code"] == 200, response.json
        assert finalized.count("/v1/chat/completions") == 1

    def test_registered_item_refuses_context_paging_before_provider(self):
        item = {**self.item, "body": {**self.item["body"], "capabilities": ["multillm_context_retrieve"]}}
        with patch.dict(os.environ, {"CONTEXT_PAGING_ENABLED": "true"}), \
             patch.object(self.service, "call", return_value={"item": item, "batch": self.batch}), \
             patch.object(self.app_module.ProxyService, "make_request") as send:
            response = self.internal()
        assert response.json["status_code"] == 400, response.json
        assert response.json["body"]["error"]["code"] == "context_paging_unsupported"
        assert response.json["ambiguous"] is False and response.json["cost_units"] == 0
        send.assert_not_called()

    def test_registered_execution_enforces_owner_permissions_before_provider(self):
        restricted = {**self.user, "allowed_models": ["openai:other"]}
        with patch.object(self.service, "call", return_value={"item": self.item, "batch": self.batch}), \
             patch.object(importlib.import_module("routes.media_batches"), "principal_user", return_value=restricted), \
             patch.object(self.app_module.ProxyService, "make_request", side_effect=AssertionError("provider called")) as send:
            response = self.internal()
        assert response.json["status_code"] == 403, response.json
        assert response.json["cost_units"] == 0
        assert send.call_count == 0

    def test_registered_default_traffic_and_explicit_spillover(self):
        headers = {"Authorization": "Bearer admin-test-key", "X-MultiLLM-Priority": "batch", "Prefer": "respond-async"}
        with patch.object(self.app_module.ProxyService, "make_request", return_value=self._chat_response()) as send:
            before = self.client.post("/v1/chat/completions", json=self.item["body"], headers=headers)
        assert before.data == self._chat_response().content
        assert send.call_count == 1
        os.environ["BATCH_SPILLOVER_ENABLED"] = "true"
        def storage(operation, **fields):
            if operation == "file_create":
                return {"file": {"id": "file_test"}}
            if operation == "file_content":
                import base64
                return {"content": base64.b64encode(json.dumps({k:v for k,v in self.item.items() if k != "estimate_units"}).encode()).decode()}
            return {"batch": {"id": fields["id"], "object": "batch", "status": "validating"}}
        with patch.object(self.service, "call", side_effect=storage), \
             patch.object(self.app_module.ProxyService, "make_request", side_effect=AssertionError("provider called")) as send:
            queued = self.client.post("/v1/chat/completions", json={**self.item["body"], "metadata": {"multillm_budget_usd": "1"}}, headers=headers)
        assert queued.status_code == 202, queued.json
        assert queued.json["object"] == "batch"
        assert queued.headers["Location"] == "/v1/batches/" + queued.json["id"]
        assert send.call_count == 0


    def test_registered_disabled_routes_return_404_even_without_authentication(self):
        os.environ["GATEWAY_BATCHES_ENABLED"] = "false"
        for path in ("/v1/files", "/v1/files/file_test", "/v1/files/file_test/content", "/v1/batches",
                     "/v1/batches/batch_test", "/v1/batches/batch_test/cancel", "/internal/gateway/batch-item"):
            assert self.client.get(path).status_code in {404, 405}
        assert self.client.post("/v1/batches", json={}).status_code == 404
        assert self.client.post("/internal/gateway/batch-item", json={}).status_code == 404

    def test_registered_expired_or_ip_restricted_owner_never_calls_provider(self):
        for restriction, status in (({"expires_at": "2000-01-01T00:00:00Z"}, 401), ({"allowed_ips": ["192.0.2.0/24"]}, 403)):
            with self.subTest(restriction=restriction), \
                 patch.object(self.service, "call", return_value={"item": self.item, "batch": self.batch}), \
                 patch.object(importlib.import_module("routes.media_batches"), "principal_user", return_value={**self.user, **restriction}), \
                 patch.object(self.app_module.ProxyService, "make_request", side_effect=AssertionError("provider called")) as send:
                response = self.internal()
            assert response.json["status_code"] == status, response.json
            assert response.json["cost_units"] == 0
            assert send.call_count == 0

    def test_registered_responses_item_uses_its_managed_translator(self):
        item = {**self.item, "url": "/v1/responses", "body": {"model": "mimo:mimo-v2.5", "input": "hello", "max_output_tokens": 10}}
        item["estimate_units"] = self.service.estimate_item(item)
        reply = self._chat_response()
        body = json.loads(reply.content)
        body["usage"] = {"prompt_tokens": 4, "completion_tokens": 2}
        reply._content = json.dumps(body).encode()
        with patch.object(self.service, "call", return_value={"item": item, "batch": self.batch}), \
             patch.object(self.app_module.ProxyService, "make_request", return_value=reply) as send:
            response = self.internal()
        assert response.json["status_code"] == 200, response.json
        assert response.json["body"]["object"] == "response"
        assert response.json["ambiguous"] is False
        assert response.json["cost_units"] == 80000
        assert send.call_count == 1


    def test_registered_owner_budget_is_checked_before_submission(self):
        limited = {**self.user, "daily_budget_usd": 0.00000001}
        with patch.object(self.service, "call", return_value={"item": self.item, "batch": self.batch}), \
             patch.object(importlib.import_module("routes.media_batches"), "principal_user", return_value=limited), \
             patch.object(self.app_module.ProxyService, "make_request", side_effect=AssertionError("provider called")) as send:
            response = self.internal()
        assert response.json["status_code"] == 429, response.json
        assert response.json["cost_units"] == 0
        assert send.call_count == 0

    def test_registered_lost_usage_retains_an_unknown_hold(self):
        with patch.object(self.service, "call", return_value={"item": self.item, "batch": self.batch}), \
             patch.object(self.app_module.ProxyService, "make_request", return_value=self._chat_response()) as send:
            response = self.internal()
        assert response.json["status_code"] == 200
        assert response.json["ambiguous"] is True
        assert response.json["cost_units"] is None
        assert send.call_count == 1
