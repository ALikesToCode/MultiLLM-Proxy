import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from services.intelligence_store import IntelligenceStore
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate, policy


class IntelligenceTransportTests(IntelligenceApiTestCase):
    def test_real_http_provider_rejection_falls_back_with_intact_body(self):
        self.seed()
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append(body)
                status = 429 if body["model"] == "small" else 200
                raw = json.dumps(
                    {"error": "unavailable"} if status == 429 else completion()
                ).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with patch.dict(
                self.app.config["API_BASE_URLS"], {"openai": base, "navyai": base}
            ):
                response = self.post(routing={"task": "research"})
            assert response.status_code == 200
            assert [item["model"] for item in received] == ["small", "large"]
            assert response.json["model"] == "navyai:large"
            assert all("routing" not in item for item in received)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_subscription_path_cannot_be_upgraded_by_global_speed_or_caller_headers(
        self,
    ):
        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate("nanogpt:z-ai/glm-5.3-flash", billing="subscription")
                ]
            )
        )
        NanoGPTUnifiedKeyPool.reset()
        self.app.config["NANOGPT_SPEED_ROUTING"] = "fast"
        self.app.config["NANOGPT_SUBSCRIPTION_BASE_URL"] = (
            "https://subscription.invalid"
        )
        self.headers.update(
            {"X-Billing-Mode": "paygo", "X-Provider": "paid", "X-Payment": "untrusted"}
        )
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post(reasoning_effort="high")
        assert response.status_code == 200
        assert (
            send.call_args.kwargs["url"]
            == "https://subscription.invalid/v1/chat/completions"
        )
        body = json.loads(send.call_args.kwargs["data"])
        assert (
            body["model"] == "z-ai/glm-5.3-flash" and body["reasoning_effort"] == "high"
        )
        assert not {"x-billing-mode", "x-provider", "x-payment"} & {
            name.lower() for name in send.call_args.kwargs["headers"]
        }

    def test_known_key_cooldowns_are_reused_without_claiming_or_running_a_probe(self):
        NanoGPTUnifiedKeyPool.reset()
        NanoGPTUnifiedKeyPool.record_result("synthetic-a", 429)
        assert (
            NanoGPTUnifiedKeyPool.select_available_key(["synthetic-a", "synthetic-b"])
            == "synthetic-b"
        )
        assert NanoGPTUnifiedKeyPool._active_key is None
        NanoGPTUnifiedKeyPool.reset()

    def test_errors_and_logs_never_include_provider_exception_text(self):
        self.seed()
        with self.assertLogs(level="INFO") as logs:
            with self.requests(
                side_effect=RuntimeError("credential-canary-private-value")
            ):
                response = self.post()
        assert response.status_code == 502
        assert "credential-canary-private-value" not in "\n".join(logs.output)
        assert b"credential-canary-private-value" not in response.data
