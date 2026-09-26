"""The MultiLLM MCP server at /v1/mcp: protocol, scopes and every tool, with mocked upstreams."""

import base64
import json
from unittest.mock import patch

import requests

from routes import gateway_mcp
from tests.test_media_generation import IMAGE, KEYS as MEDIA_KEYS, upstream
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = "admin-test-key"
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).decode()
ACCEPT = "application/json, text/event-stream"
KEYS = {**MEDIA_KEYS, "opencode": "opencode-test-key"}


class GatewayMcpTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        AuthService = self.app_module.AuthService
        with self.app.test_request_context(), patch.object(
            AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}
        ):
            self.keys = {
                name: AuthService.create_user(name, scopes=scopes)["api_key"]
                for name, scopes in {
                    "chatter": ["chat"], "browser": ["models"], "reader": ["knowledge:read"],
                }.items()
            }
        self.keys["admin"] = ADMIN

    def rpc(self, method, params=None, *, key=ADMIN, identifier=7, headers=None, path="/v1/mcp"):
        message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if identifier is not None:
            message["id"] = identifier
        return self.client.post(path, json=message, headers={
            "Authorization": f"Bearer {key}", "Accept": ACCEPT, **(headers or {})})

    def call(self, name, arguments=None, **kwargs):
        response = self.rpc("tools/call", {"name": name, "arguments": arguments or {}}, **kwargs)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()["result"]

    # Protocol

    def test_initialize_negotiates_the_knowledge_protocol_versions(self):
        for offered, expected in (("2099-01-01", "2025-06-18"), ("2025-06-18", "2025-06-18")):
            response = self.rpc("initialize", {"protocolVersion": offered, "capabilities": {},
                                               "clientInfo": {"name": "fixture", "version": "1"}})
            self.assertEqual(response.status_code, 200)
            result = response.get_json()["result"]
            self.assertEqual(result["protocolVersion"], expected)
            self.assertEqual(result["capabilities"], {"tools": {}})
            self.assertEqual(result["serverInfo"]["name"], "multillm")
            self.assertIn("never retried", result["instructions"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(self.rpc("initialize", {}).get_json()["error"]["code"], -32602)
        self.assertEqual(self.rpc("ping").get_json()["result"], {})

    def test_tools_are_listed_with_schemas_annotations_and_scope_filtering(self):
        tools = {tool["name"]: tool for tool in self.rpc("tools/list").get_json()["result"]["tools"]}
        self.assertEqual(set(tools), {"list_models", "chat", "generate_image", "generate_images_batch",
                                      "create_video", "get_video", "media_providers"})
        for tool in tools.values():
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertIs(tool["inputSchema"]["additionalProperties"], False)
            self.assertNotIn("scope", tool)
            self.assertIn("openWorldHint", tool["annotations"])
        for paid in ("chat", "generate_image", "generate_images_batch", "create_video"):
            self.assertIs(tools[paid]["annotations"]["readOnlyHint"], False)
            self.assertIn("PAID", tools[paid]["description"])
        for free in ("list_models", "get_video", "media_providers"):
            self.assertIs(tools[free]["annotations"]["readOnlyHint"], True)
        names = lambda key: {tool["name"] for tool in self.rpc("tools/list", key=self.keys[key]).get_json()["result"]["tools"]}  # noqa: E731
        self.assertEqual(names("browser"), {"list_models"})
        self.assertEqual(names("chatter"), set(tools) - {"list_models"})

    def test_scope_errors(self):
        denied = self.call("list_models", key=self.keys["chatter"])
        self.assertIs(denied["isError"], True)
        self.assertEqual(denied["structuredContent"]["error"]["code"], "insufficient_scope")
        with patch("app.ProxyService.make_request") as send:
            denied = self.call("chat", {"prompt": "hi"}, key=self.keys["browser"])
        self.assertEqual(denied["structuredContent"]["error"]["code"], "insufficient_scope")
        send.assert_not_called()
        response = self.rpc("tools/list", key=self.keys["reader"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("chat", response.get_json()["message"])
        self.assertEqual(self.client.post("/v1/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code, 401)

    def test_notifications_and_client_replies_are_accepted_without_a_body(self):
        response = self.rpc("notifications/initialized", identifier=None)
        self.assertEqual((response.status_code, response.data), (202, b""))
        reply = self.client.post("/v1/mcp", json={"jsonrpc": "2.0", "id": "server-1", "result": {}},
                                 headers={"Authorization": f"Bearer {ADMIN}"})
        self.assertEqual(reply.status_code, 202)
        self.assertEqual(self.rpc("tools/list", identifier=None).status_code, 400)

    def test_malformed_json_rpc_is_rejected(self):
        headers = {"Authorization": f"Bearer {ADMIN}", "Content-Type": "application/json"}
        cases = [
            ("{not json", 400, -32700),
            ('{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}', 400, -32700),
            ('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":NaN}}', 400, -32700),
            ("[]", 400, -32600),
            ('{"jsonrpc":"1.0","id":1,"method":"ping"}', 400, -32600),
            ('{"jsonrpc":"2.0","id":{},"method":"ping"}', 400, -32600),
            ('{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}', 400, -32600),
            ('{"jsonrpc":"2.0","id":1,"method":"resources/list"}', 200, -32601),
            ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"}}', 200, -32602),
            ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chat","arguments":[]}}', 200, -32602),
        ]
        for body, status, code in cases:
            with self.subTest(body=body):
                response = self.client.post("/v1/mcp", data=body, headers=headers)
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.get_json()["error"]["code"], code)
        oversized = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"x": "a" * (1024 * 1024)}})
        self.assertEqual(self.client.post("/v1/mcp", data=oversized, headers=headers).status_code, 413)
        self.assertEqual(self.client.post("/v1/mcp", data="x", headers={**headers, "Content-Type": "text/plain"}).status_code, 415)

    def test_transport_rules(self):
        for method in (self.client.get, self.client.delete):
            self.assertEqual(method("/v1/mcp", headers={"Authorization": f"Bearer {ADMIN}"}).status_code, 405)
        self.assertEqual(self.rpc("ping", headers={"MCP-Protocol-Version": "1999-01-01"}).status_code, 400)
        self.assertEqual(self.rpc("ping", headers={"MCP-Protocol-Version": "2025-06-18"}).status_code, 200)
        self.assertEqual(self.rpc("ping", headers={"Accept": "text/html"}).status_code, 406)
        self.assertEqual(self.rpc("ping", headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.rpc("ping", headers={"Origin": "http://localhost"}).status_code, 200)
        # The Knowledge MCP keeps /mcp.
        self.assertEqual(self.app.url_map.bind("localhost").match("/mcp", method="POST")[0], "knowledge_mcp")

    def test_invalid_arguments_are_tool_errors_that_never_dispatch(self):
        with patch("app.ProxyService.make_request") as send:
            for name, arguments in (
                ("chat", {"prompt": "hi", "plugins": [{"id": "web"}]}),
                ("chat", {"prompt": "hi", "messages": [{"role": "user", "content": "hi"}]}),
                ("chat", {}),
                ("chat", {"prompt": "hi", "max_tokens": 0}),
                ("generate_image", {"prompt": "x", "n": 5}),
                ("generate_images_batch", {"items": []}),
                ("create_video", {"prompt": "x", "seconds": 60}),
                ("get_video", {"id": "../../v1/models"}),
                ("list_models", {"limit": 0}),
            ):
                with self.subTest(name=name, arguments=arguments):
                    result = self.call(name, arguments)
                    self.assertIs(result["isError"], True)
                    self.assertEqual(result["structuredContent"]["error"]["code"], "invalid_arguments")
        send.assert_not_called()

    # Tools

    def test_list_models_filters_and_bounds_the_catalog(self):
        free = self.call("list_models", {"free": True})["structuredContent"]
        self.assertEqual({entry["id"] for entry in free["data"]}, {"free:text", "free:vision"})
        self.assertTrue(all(entry["free"] and entry["chat"] for entry in free["data"]))
        chat = self.call("list_models", {"kind": "chat", "provider": "opencode", "limit": 2})["structuredContent"]
        self.assertEqual(chat["returned"], 2)
        self.assertTrue(chat["truncated"])
        self.assertTrue(all(entry["provider"] == "opencode" and entry["chat"] for entry in chat["data"]))
        images = self.call("list_models", {"kind": "images", "search": "GPT-IMAGE"})["structuredContent"]
        self.assertTrue(images["data"])
        self.assertTrue(all("gpt-image" in entry["id"] for entry in images["data"]))
        result = self.call("list_models", {"free": True})
        self.assertEqual(json.loads(result["content"][-1]["text"]), result["structuredContent"])
        self.assertIs(self.call("list_models", key=self.keys["browser"])["isError"], False)

    def test_chat_makes_one_request_with_the_callers_key_and_rules(self):
        with patch("app.ProxyService.make_request", return_value=self._chat_response("Bonjour")) as send:
            result = self.call("chat", {"model": "opencode:glm-5.2", "prompt": "Say hello in French.",
                                        "system": "Be brief.", "temperature": 0.2}, key=self.keys["chatter"])
        self.assertIs(result["isError"], False)
        structured = result["structuredContent"]
        self.assertEqual(structured["content"], "Bonjour")
        self.assertEqual(structured["finish_reason"], "stop")
        self.assertEqual(structured["gateway"]["status"], 200)
        self.assertEqual(structured["gateway"]["provider"], "opencode")
        self.assertEqual(send.call_count, 1)
        sent = json.loads(send.call_args.kwargs["data"])
        self.assertEqual([message["role"] for message in sent["messages"]], ["system", "user"])
        self.assertEqual(sent["max_tokens"], gateway_mcp.DEFAULT_MAX_TOKENS)
        self.assertNotIn("stream", sent)

    def test_chat_defaults_to_the_free_text_pool(self):
        with patch("services.free_model_policy.build_model_catalog", return_value=[]), \
                patch("app.ProxyService.make_request") as send:
            result = self.call("chat", {"prompt": "hi"})
        self.assertIs(result["isError"], True)
        error = result["structuredContent"]["error"]
        self.assertEqual((error["status"], error["code"]), (503, "free_models_unavailable"))
        self.assertIs(result["structuredContent"]["retried"], False)
        send.assert_not_called()

    def test_upstream_failures_are_reported_once_with_a_billing_note(self):
        failure = requests.Response()
        failure.status_code = 502
        failure._content = b'{"error": {"message": "upstream exploded", "type": "server_error"}}'
        failure.headers["Content-Type"] = "application/json"
        with patch("app.ProxyService.make_request", return_value=failure) as send:
            result = self.call("chat", {"model": "opencode:glm-5.2", "prompt": "hi"})
        self.assertEqual(send.call_count, 1)
        self.assertIs(result["isError"], True)
        structured = result["structuredContent"]
        self.assertEqual(structured["error"]["status"], 502)
        self.assertIn("billed", structured["billing_note"])

    def test_generate_image_returns_urls_and_capped_inline_images(self):
        with patch.object(self.app_module.ProxyService, "make_request",
                          side_effect=[upstream(200, IMAGE)]) as send:
            result = self.call("generate_image", {"prompt": "A red fox", "model": "gguu:gpt-image-2"})
        self.assertIs(result["isError"], False)
        self.assertEqual(result["structuredContent"]["images"], [{"url": "https://images.example/one.png"}])
        self.assertEqual(json.loads(send.call_args.kwargs["data"])["response_format"], "url")
        big = "A" * (gateway_mcp.MAX_INLINE_IMAGE_BYTES + 4)
        inline = {"created": 1, "data": [{"b64_json": PNG}, {"b64_json": big}, {"b64_json": "!!notbase64!!"}]}
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=[upstream(200, inline)]):
            result = self.call("generate_image", {"prompt": "A red fox", "model": "gguu:gpt-image-2",
                                                  "response_format": "b64_json", "n": 3})
        images = result["structuredContent"]["images"]
        self.assertEqual(result["content"][0], {"type": "image", "data": PNG, "mimeType": "image/png"})
        self.assertEqual([image.get("inline") for image in images], [True, False, False])
        self.assertNotIn(big, json.dumps(result["structuredContent"]))
        self.assertEqual(len(result["content"]), 2)

    def test_generate_images_batch_reports_each_item(self):
        def transport(**kwargs):
            # Batch items run in parallel, so answer by prompt rather than by call order.
            if json.loads(kwargs["data"])["prompt"] == "Lake":
                return upstream(200, IMAGE)
            return upstream(200, {"created": 1, "data": [{"b64_json": PNG}]})

        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport):
            result = self.call("generate_images_batch", {
                "defaults": {"model": "gguu:gpt-image-2"},
                "items": [{"id": "hero", "prompt": "Lake"}, {"id": "icon", "prompt": "Icon"}]})
        structured = result["structuredContent"]
        self.assertEqual(structured["summary"]["succeeded"], 2)
        by_id = {item["id"]: item for item in structured["data"]}
        self.assertEqual(by_id["hero"]["images"], [{"url": "https://images.example/one.png"}])
        self.assertIs(by_id["icon"]["images"][0]["inline"], True)
        self.assertEqual(result["content"][0]["type"], "image")

    def test_video_tools_create_poll_and_link_the_content_without_bytes(self):
        calls = []

        def provider(method, url, **kwargs):
            calls.append(url)
            if url.endswith("/v1/videos/generations"):
                return upstream(200, {"request_id": "req-1"})
            if url.endswith("/v1/videos/req-1"):
                return upstream(200, {"status": "done", "video": {"url": "https://vidgen.x.ai/v.mp4"}})
            raise AssertionError(url)

        with patch("services.video_generation.requests.request", side_effect=provider):
            created = self.call("create_video", {"prompt": "An eagle", "model": "xai:grok-imagine-video-1.5"})
            job = created["structuredContent"]
            self.assertEqual(job["status"], "queued")
            self.assertIn("get_video", job["next"])
            done = self.call("get_video", {"id": job["id"]})["structuredContent"]
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["content_path"], f"/v1/videos/{job['id']}/content")
        self.assertTrue(done["content_url"].endswith(done["content_path"]))
        self.assertEqual(len(calls), 2)
        other = self.call("get_video", {"id": job["id"]}, key=self.keys["chatter"])
        self.assertEqual(other["structuredContent"]["error"]["status"], 404)

    def test_media_providers_is_free_and_read_only(self):
        with patch("app.ProxyService.make_request") as send:
            result = self.call("media_providers")
        routes = {route["id"] for route in result["structuredContent"]["routes"]}
        self.assertIn("auto:image", routes)
        send.assert_not_called()

    def test_each_tool_call_reserves_the_rest_routes_rate_budget_once(self):
        from route_helpers import RateLimitService

        with patch.object(RateLimitService, "enforce_request", wraps=RateLimitService.enforce_request) as enforce, \
                patch("app.ProxyService.make_request", return_value=self._chat_response("ok")):
            self.rpc("tools/list")
            self.assertEqual(enforce.call_count, 0)
            self.call("chat", {"model": "opencode:glm-5.2", "prompt": "x"})
        self.assertEqual(enforce.call_count, 1)
        self.assertEqual(enforce.call_args.kwargs["provider"], "opencode")
        self.assertEqual(json.loads(enforce.call_args.kwargs["payload_bytes"])["model"], "opencode:glm-5.2")

    def test_inner_requests_do_not_leak_state_into_the_mcp_response(self):
        with patch("app.ProxyService.make_request", return_value=self._chat_response("ok")):
            response = self.rpc("tools/call", {"name": "chat", "arguments": {"model": "opencode:glm-5.2", "prompt": "x"}},
                                headers={"X-Request-ID": "mcp-outer-1"})
        self.assertEqual(response.headers["X-Request-ID"], "mcp-outer-1")
        self.assertNotIn("X-MultiLLM-Model", response.headers)
