"""Key controls, budgets and the usage ledger through the real application routes."""

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import requests

from services import telemetry_export, usage_ledger
from services.budget_service import BudgetService
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"username": "admin", "is_admin": True}
PRICING = {"opencode:*": {"input": 1000, "output": 1000}, "gguu:*": {"request": 0.04}}


def upstream(body, content_type="application/json", status=200):
    response = requests.Response()
    response.status_code = status
    response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
    response.headers["Content-Type"] = content_type
    return response


def completion(prompt_tokens=5, completion_tokens=7):
    return {"id": "chatcmpl-test", "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "prompt_tokens_details": {"cached_tokens": 0}}}


class UsageRoutesTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ.update({
            "USAGE_LEDGER_ENABLED": "true", "USAGE_LEDGER_BACKEND": "sql", "USAGE_LEDGER_FLUSH_SECONDS": "300",
            "USAGE_DB_PATH": os.path.join(self.temp_dir.name, "usage.sqlite3"),
            "MODEL_PRICING_USD_PER_MILLION": json.dumps(PRICING),
        })
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        self.auth = self.app_module.AuthService

    def tearDown(self):
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        telemetry_export.EXPORTER.reset()
        super().tearDown()

    def account(self, name="agent", scopes=("chat", "models"), **controls):
        with patch.object(self.auth, "get_current_user", return_value=ADMIN):
            key = self.auth.create_user(name, scopes=list(scopes))["api_key"]
            if controls:
                self.auth.set_key_controls(name, controls)
        return key

    def chat(self, key, model="opencode:glm-5.2", body=None, headers=None, **kwargs):
        with patch("app.ProxyService.make_request", return_value=body or upstream(completion())) as make_request:
            response = self.client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}", **(headers or {})},
                                        json={"model": model, "messages": [{"role": "user", "content": "hi"}],
                                              "max_tokens": 5}, buffered=True, **kwargs)
        return response, make_request

    def rows(self, principal=None):
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        return usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", principal, None, 50)

    def test_model_allowlist_is_enforced_before_dispatch_and_filters_models(self):
        key = self.account(allowed_models=["opencode:*", "free:*"])
        refused, make_request = self.chat(key, model="mimo:mimo-v2.5-pro")
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(refused.get_json()["error"], "model_not_allowed")
        make_request.assert_not_called()
        allowed, make_request = self.chat(key)
        self.assertEqual(allowed.status_code, 200)
        make_request.assert_called_once()

        listed = self.client.get("/v1/models", headers={"Authorization": f"Bearer {key}"}).get_json()["data"]
        self.assertTrue(listed)
        self.assertTrue(all(model["id"].startswith(("opencode:", "free:")) for model in listed))

        for path, body in (("/openai/v1/chat/completions", {"model": "gpt-4.1"}), ("/openai/v1/embeddings", {})):
            response = self.client.post(path, headers={"Authorization": f"Bearer {key}"}, json=body)
            self.assertEqual(response.status_code, 403, path)
            self.assertEqual(response.get_json()["error"], "model_not_allowed")
        batch = self.client.post("/v1/images/batch", headers={"Authorization": f"Bearer {key}"},
                                 json={"items": [{"prompt": "a"}, {"prompt": "b", "model": "free:text"}]})
        self.assertEqual(batch.status_code, 403, "the default auto:image route is not on the list")

    def test_expired_and_out_of_range_keys_are_refused(self):
        expired = self.account("old", expires_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat())
        response, _ = self.chat(expired)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "key_expired")
        self.assertEqual(self.client.get("/v1/models", headers={"Authorization": f"Bearer {expired}"}).status_code, 401)
        self.assertFalse(self.auth.authenticate_user("old", expired), "an expired key cannot sign in")

        ranged = self.account("office", allowed_ips=["203.0.113.0/24"])
        response, _ = self.chat(ranged)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "ip_not_allowed")
        response, _ = self.chat(ranged, environ_base={"REMOTE_ADDR": "203.0.113.9"})
        self.assertEqual(response.status_code, 200)
        spoofed, _ = self.chat(ranged, headers={"CF-Connecting-IP": "203.0.113.9"})
        self.assertEqual(spoofed.status_code, 403, "CF-Connecting-IP counts only behind the Worker")
        os.environ["MULTILLM_TRUST_PROXY_HEADERS"] = "true"
        behind_worker, _ = self.chat(ranged, headers={"CF-Connecting-IP": "203.0.113.9"})
        self.assertEqual(behind_worker.status_code, 200)

    def test_budgets_refuse_with_retry_after_and_settle_actual_cost(self):
        key = self.account(daily_budget_usd=0.025)
        first, _ = self.chat(key)
        self.assertEqual(first.status_code, 200)
        second, _ = self.chat(key)
        self.assertEqual(second.status_code, 200, "0.012 spent + 0.006 estimated fits 0.025")
        third, make_request = self.chat(key)
        self.assertEqual(third.status_code, 429)
        body = third.get_json()
        self.assertEqual(body["error"], "budget_exceeded")
        self.assertEqual(body["budget"]["period"], "daily")
        self.assertAlmostEqual(body["budget"]["spent_usd"], 0.024)
        self.assertGreater(int(third.headers["Retry-After"]), 0)
        make_request.assert_not_called()

        rows = self.rows("agent")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["cost_basis"] for row in rows}, {"usage"})
        self.assertEqual((rows[0]["input_tokens"], rows[0]["output_tokens"]), (5, 7))
        self.assertAlmostEqual(rows[0]["cost_usd"], 0.012)

        usage = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"}).get_json()
        self.assertEqual(usage["principal"], "agent")
        self.assertAlmostEqual(usage["budget"]["spent_today_usd"], 0.024)
        self.assertAlmostEqual(usage["budget"]["daily_remaining_usd"], 0.001)
        self.assertEqual(usage["daily"][0]["requests"], 2)
        self.assertEqual(usage["models"][0]["model"], "opencode:glm-5.2")
        self.assertIsNone(usage["controls"]["allowed_models"])

    def test_admins_are_exempt_unless_a_budget_is_set(self):
        response, _ = self.chat("admin-test-key")
        self.assertEqual(response.status_code, 200)
        with patch.object(self.auth, "get_current_user", return_value=ADMIN):
            self.auth.set_key_controls("admin", {"daily_budget_usd": 0})
        response, _ = self.chat("admin-test-key")
        self.assertEqual(response.status_code, 429)
        with patch.object(self.auth, "get_current_user", return_value=ADMIN):
            refused = self.client.put("/users/admin/controls", json={"allowed_ips": ["10.0.0.0/8"]})
        self.assertEqual(refused.status_code, 400, "the break-glass admin key cannot be limited to addresses")

    def test_ledger_rows_hold_request_metadata_without_prompts_or_keys(self):
        key = self.account()
        response, _ = self.chat(key, headers={"X-Request-ID": "req_ledger_1"})
        self.assertEqual(response.status_code, 200)
        self.client.get("/v1/models", headers={"Authorization": f"Bearer {key}"})
        [row] = self.rows()
        self.assertEqual(row["principal"], "agent")
        self.assertEqual(row["key_prefix"], f"mllm_{key[:8]}")
        self.assertEqual((row["kind"], row["endpoint"]), ("chat", "/v1/chat/completions"))
        self.assertEqual((row["requested_model"], row["selected_model"]), ("opencode:glm-5.2", "opencode:glm-5.2"))
        self.assertEqual((row["status"], row["request_id"]), (200, "req_ledger_1"))
        self.assertGreaterEqual(row["latency_ms"], 0)
        self.assertNotIn(key, json.dumps(row))
        self.assertNotIn("hi", json.dumps({name: value for name, value in row.items() if name != "at"}).replace("chat", ""))

    def test_streamed_responses_are_recorded_on_close_with_reported_usage(self):
        key = self.account()
        events = (b'data: {"choices":[{"delta":{"content":"o"}}]}\n\n'
                  b'data: {"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":3}}\n\ndata: [DONE]\n\n')
        with patch("app.ProxyService.make_request", return_value=upstream(events, "text/event-stream")):
            response = self.client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                                        json={"model": "opencode:glm-5.2", "stream": True,
                                              "messages": [{"role": "user", "content": "hi"}]})
            self.assertEqual(self.rows(), [], "nothing is recorded before the stream closes")
            self.assertIn(b"[DONE]", response.get_data())
            response.close()
        [row] = self.rows()
        self.assertEqual((row["input_tokens"], row["output_tokens"], row["cost_basis"]), (11, 3, "usage"))
        self.assertAlmostEqual(row["cost_usd"], 0.014)

    def test_failed_requests_are_recorded_without_cost(self):
        key = self.account()
        response, _ = self.chat(key, model="nosuch:model")
        self.assertEqual(response.status_code, 400)
        [failed] = self.rows()
        self.assertEqual((failed["status"], failed["requested_model"]), (400, "nosuch:model"))
        self.assertIsNone(failed["cost_usd"])
        self.assertIsNone(failed["cost_basis"])

    def test_dashboard_usage_views_and_key_controls_api(self):
        key = self.account()
        self.chat(key)
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        login = self.client.post("/login", data={"username": "admin", "api_key": "admin-test-key"})
        self.assertEqual(login.status_code, 302)
        page = self.client.get("/usage")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"usage-console", page.data)
        self.assertEqual(self.client.get("/users").status_code, 200)

        overview = self.client.get("/usage/data?days=7").get_json()
        self.assertIsNone(overview["principal"])
        self.assertEqual(overview["principals"][0]["principal"], "agent")
        self.assertEqual(overview["ledger"]["backend"], "sql")
        updated = self.client.put("/users/agent/controls", json={
            "daily_budget_usd": 2, "allowed_models": ["auto:*"], "expires_at": "2099-01-01T00:00:00Z"})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["user"]["allowed_models"], ["auto:*"])
        access = self.client.get("/users").get_data(as_text=True)
        self.assertIn("$2.00 a day · 1 model pattern · expires 2099-01-01", access)
        self.assertIn('data-controls-user="agent"', access)
        self.assertIn('"allowed_models": ["auto:*"]', access)
        detail = self.client.get("/usage/data?principal=agent&days=30").get_json()
        self.assertEqual(detail["budget"]["daily_budget_usd"], 2.0)
        self.assertEqual(detail["controls"]["expires_at"], "2099-01-01T00:00:00+00:00")
        self.assertEqual(detail["daily"][0]["requests"], 1)
        invalid = self.client.put("/users/agent/controls", json={"allowed_ips": ["nope"]})
        self.assertEqual(invalid.status_code, 400)
        self.assertIn("allowed_ips", invalid.get_json()["message"])
        self.assertEqual(self.client.put("/users/nobody/controls", json={}).status_code, 404)

        rotated = self.client.post("/users/agent/rotate-key").get_json()
        self.assertEqual(self.auth.verify_api_key(rotated["api_key"])["daily_budget_usd"], 2.0,
                         "rotating a key keeps its limits")

    def test_operators_see_only_their_own_usage(self):
        key = self.account("reader", scopes=("chat", "models"))
        self.account("other")
        self.chat(key)
        self.client.post("/login", data={"username": "reader", "api_key": key})
        data = self.client.get("/usage/data?principal=other").get_json()
        self.assertEqual(data["principal"], "reader")
        self.assertNotIn("principals", data)
        self.assertNotIn("ledger", data)
        self.assertEqual(self.client.put("/users/other/controls", json={}).status_code, 403)
        self.assertEqual(self.client.get("/v1/usage", headers={"Authorization": "Bearer nope"}).status_code, 401)

    def test_knowledge_only_keys_cannot_read_usage(self):
        key = self.account("librarian", scopes=("knowledge:read",))
        response = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"})
        self.assertEqual(response.status_code, 403)

    def test_request_spans_and_metrics_export_over_otlp_json(self):
        received = []

        class Collector(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, dict(self.headers),
                                 json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Collector)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = f"http://127.0.0.1:{server.server_port}/"
            os.environ["OTEL_EXPORTER_OTLP_HEADERS"] = "x-collector-token=synthetic%20token"
            key = self.account()
            with patch.object(telemetry_export.EXPORTER, "_run", lambda: None):
                response, _ = self.chat(key, headers={
                    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(telemetry_export.EXPORTER.export_once(), 1)
        finally:
            server.shutdown()
        paths = {path: (headers, body) for path, headers, body in received}
        self.assertEqual(set(paths), {"/v1/traces", "/v1/metrics"})
        headers, traces = paths["/v1/traces"]
        self.assertEqual(headers["x-collector-token"], "synthetic token")
        [span] = traces["resourceSpans"][0]["scopeSpans"][0]["spans"]
        self.assertEqual(span["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(span["parentSpanId"], "00f067aa0ba902b7")
        attributes = {item["key"]: item["value"] for item in span["attributes"]}
        self.assertEqual(attributes["gen_ai.response.model"], {"stringValue": "opencode:glm-5.2"})
        self.assertEqual(attributes["gen_ai.usage.input_tokens"], {"intValue": "5"})
        self.assertEqual(attributes["enduser.id"], {"stringValue": "agent"})
        exported = json.dumps(received)
        self.assertNotIn(key, exported)
        self.assertNotIn(key[:8], exported)
        self.assertNotIn('"hi"', exported)
        metrics = paths["/v1/metrics"][1]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        requests_metric = next(metric for metric in metrics if metric["name"] == "multillm.requests")
        self.assertEqual(requests_metric["sum"]["dataPoints"][0]["asInt"], "1")
        self.assertEqual(requests_metric["sum"]["aggregationTemporality"], 1)
