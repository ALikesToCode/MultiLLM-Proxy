import assert from "node:assert/strict";
import test from "node:test";

import { isApiRequestPath } from "../worker/api-paths.mjs";
import { isKnowledgeEdgePath } from "../worker/knowledge-edge.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const worker = (await loadWorkerModule()).default;
const ADMIN_KEY = "synthetic-gateway-mcp-admin";
const body = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

function environment(fetch) {
  return {
    ADMIN_API_KEY: ADMIN_KEY,
    MULTILLM_PROXY_CONTAINER: { getByName: () => ({ fetch }) },
    // A bound Knowledge service must still leave /v1/mcp to the Container.
    KNOWLEDGE_SERVICE: { fetch() { throw new Error("The Knowledge service must not see /v1/mcp"); } },
  };
}

test("the gateway MCP path is an API path outside the Knowledge edge", () => {
  assert.equal(isApiRequestPath("/v1/mcp"), true);
  assert.equal(isKnowledgeEdgePath("/v1/mcp"), false);
  assert.equal(isKnowledgeEdgePath("/mcp"), true);
});

test("gateway MCP requests reach the container unchanged, even with an edge-verifiable key", async () => {
  let calls = 0;
  const response = await worker.fetch(new Request("https://proxy.example/v1/mcp", {
    method: "POST",
    headers: { Authorization: `Bearer ${ADMIN_KEY}`, "Content-Type": "application/json",
      Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18" },
    body: JSON.stringify(body),
  }), environment(async (request) => {
    calls += 1;
    assert.equal(new URL(request.url).pathname, "/v1/mcp");
    assert.equal(request.headers.get("authorization"), `Bearer ${ADMIN_KEY}`);
    assert.equal(request.headers.get("mcp-protocol-version"), "2025-06-18");
    assert.equal(request.headers.get("x-multillm-external-origin"), "https://proxy.example");
    assert.deepEqual(await request.json(), body);
    return Response.json({ jsonrpc: "2.0", id: 1, result: { tools: [] } }, { headers: { "Cache-Control": "no-store" } });
  }));
  assert.equal(calls, 1);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { jsonrpc: "2.0", id: 1, result: { tools: [] } });
});

test("gateway MCP notifications keep their empty 202 reply", async () => {
  const response = await worker.fetch(new Request("https://proxy.example/v1/mcp", {
    method: "POST",
    headers: { Authorization: `Bearer ${ADMIN_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  }), environment(async () => new Response(null, { status: 202 })));
  assert.equal(response.status, 202);
  assert.equal(await response.text(), "");
});

test("gateway MCP preflight is answered at the edge without starting a container", async () => {
  const response = await worker.fetch(new Request("https://proxy.example/v1/mcp", {
    method: "OPTIONS",
    headers: { Origin: "https://proxy.example", "Access-Control-Request-Headers": "authorization,content-type" },
  }), environment(() => { throw new Error("Unexpected container call"); }));
  assert.equal(response.status, 204);
});
