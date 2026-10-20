import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { handleKnowledgeEdgeRequest } from "../worker/knowledge-edge.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
const TOKEN = "AK" + "IA" + "AB12CD34EF56GH78";
for (const path of ["/v1/knowledge/context", "/mcp"]) for (const mode of ["observe", "redact", "block", "off"]) test(`Knowledge ${path} forces block except ${mode}`, async () => {
  const bodies = [];
  const env = { ADMIN_API_KEY: "synthetic-admin", SECRET_SCAN_DEFAULT: mode, KNOWLEDGE_SERVICE: { async fetch(_url, init) {
    bodies.push(JSON.parse(init.body)); return Response.json({ version: 1, result: { status: "ok" } });
  } } };
  const payload = path === "/mcp" ? { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "knowledge_context", arguments: { query: TOKEN } } } : { query: TOKEN };
  const response = await handleKnowledgeEdgeRequest(new Request("https://gateway.invalid" + path, { method: "POST", headers: { authorization: "Bearer synthetic-admin", "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(payload) }), env);
  assert.equal(response.status, mode === "off" ? 200 : 422);
  assert.equal(bodies.length, mode === "off" ? 1 : 0);
  if (bodies.length) { assert.equal(bodies[0].payload.query, TOKEN); assert.equal(bodies[0].secret_scan_mode, "off"); assert.equal(bodies[0].secret_scan_checked, true); }
  assert.ok(!(await response.text()).includes(TOKEN));
});
test("private Knowledge ingress blocks before authority and provider dispatch", async () => {
  let calls = 0;
  const events = [];
  const env = { INTELLIGENCE_DB: { prepare() { return { bind(...args) { events.push(args); return { run: async () => ({}) }; } }; } } };
  await assert.rejects(() => dispatchKnowledge(env, { version: 1, operation: "context", principal: { id: "synthetic-reader", scopes: ["knowledge:read"] }, payload: { query: TOKEN } }, { authority: { call() { calls++; assert.fail("must not dispatch"); } } }), error => error.code === "secret_detected" && error.status === 422 && !error.message.includes(TOKEN));
  assert.equal(calls, 0);
  assert.equal(events.length, 1); assert.ok(!JSON.stringify(events).includes(TOKEN));
  assert.equal(JSON.parse(events[0][5]).action, "blocked");
});
test("Knowledge audit binding reuses the gateway database", () => {
  const config = JSON.parse(readFileSync(new URL("../wrangler.knowledge.jsonc", import.meta.url), "utf8"));
  const gateway = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
  const binding = config.d1_databases.find(item => item.binding === "INTELLIGENCE_DB");
  assert.equal(binding.database_name, "multillm-intelligence");
  assert.equal(binding.database_id, /"database_id":\s*"([^"]+)"/.exec(gateway)[1]);
});
