import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { generateIntegrationCredential, hashIntegrationKey } from "../scripts/intelligence_operator.mjs";
import { handleKnowledgeEdgeRequest, isKnowledgeEdgePath } from "../worker/knowledge-edge.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const ORIGIN = "https://gateway.example";
const ADMIN_KEY = "synthetic-edge-admin-key";
const catalogue = JSON.parse(await readFile(new URL("../worker/knowledge-mcp-catalogue.json", import.meta.url), "utf8"));
const [reader, manager, chatOnly] = await Promise.all([1, 2, 3].map(() => generateIntegrationCredential()));

function database(records, calls = { lookups: 0 }, accounts = []) {
  return {
    calls,
    accounts,
    prepare(sql) {
      if (sql.includes("control_users")) {
        return { bind(prefix) {
          return { async all() {
            calls.accounts = (calls.accounts ?? 0) + 1;
            return { results: accounts.filter(row => row.api_key_prefix === prefix && row.revoked_at === null) };
          } };
        } };
      }
      return { bind(prefix) {
        return { async first() {
          calls.lookups += 1;
          if (calls.fail) throw new Error("private storage detail");
          const record = records.get(prefix);
          return record ? { id: record.id, scopes: JSON.stringify(record.scopes), version: 1, created_at: "2026-09-24T00:00:00Z",
            revoked_at: record.revokedAt ?? null, key_prefix: prefix, key_hash: record.keyHash } : null;
        } };
      } };
    },
  };
}

function environment({ result = { status: "ok" }, status = 200, overrides = {} } = {}) {
  const dispatched = [];
  const records = new Map([
    [reader.keyPrefix, { id: "integration:agents", scopes: ["knowledge:read"], keyHash: reader.keyHash }],
    [manager.keyPrefix, { id: "integration:operator", scopes: ["knowledge:read", "knowledge:manage", "chat"], keyHash: manager.keyHash }],
    [chatOnly.keyPrefix, { id: "integration:omni", scopes: ["chat", "models"], keyHash: chatOnly.keyHash }],
  ]);
  const env = {
    ADMIN_API_KEY: ADMIN_KEY,
    ADMIN_USERNAME: " operator ",
    INTELLIGENCE_DB: database(records),
    KNOWLEDGE_SERVICE: {
      async fetch(url, init) {
        assert.equal(url, "http://knowledge.internal/v1/dispatch");
        dispatched.push(JSON.parse(init.body));
        return Response.json(status < 400 ? { version: 1, result } : { version: 1, error: result }, { status });
      },
    },
    ...overrides,
  };
  return { env, dispatched, records };
}

function mcpRequest(key, method, params, headers = {}) {
  return new Request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json",
      accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, ...(params === undefined ? {} : { params }) }),
  });
}

async function call(env, request) {
  const response = await handleKnowledgeEdgeRequest(request, env);
  assert.ok(response, "the edge should answer this request");
  return response;
}

test("edge covers only the Knowledge MCP and REST namespaces", () => {
  for (const path of ["/mcp", "/v1/knowledge/context", "/v1/knowledge/sources/a/refresh"]) assert.equal(isKnowledgeEdgePath(path), true);
  for (const path of ["/mcpx", "/v1/chat/completions", "/knowledge", "/admin/knowledge/status"]) assert.equal(isKnowledgeEdgePath(path), false);
});

test("durable read keys discover and call only read tools through the private service", async () => {
  const { env, dispatched } = environment({ result: { status: "ok", excerpts: [] } });
  const init = await (await call(env, mcpRequest(reader.key, "initialize", { protocolVersion: "2099-01-01" }))).json();
  assert.deepEqual(init.result.serverInfo, catalogue.serverInfo);
  assert.equal(init.result.protocolVersion, "2025-06-18");
  assert.equal(init.result.instructions, catalogue.instructions);
  const tools = (await (await call(env, mcpRequest(reader.key, "tools/list"))).json()).result.tools;
  assert.deepEqual(tools, catalogue.tools.filter(entry => entry.scope === "knowledge:read").map(entry => entry.definition));
  const response = await call(env, mcpRequest(reader.key, "tools/call",
    { name: "knowledge_context", arguments: { query: "limits", product: "flask" } }, { "mcp-protocol-version": "2025-06-18" }));
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.deepEqual(body.result.structuredContent, { status: "ok", excerpts: [] });
  assert.equal(body.result.isError, false);
  assert.deepEqual(dispatched, [{ version: 1, operation: "context",
    principal: { id: "integration:agents", scopes: ["knowledge:read"] }, payload: { query: "limits", product: "flask" } }]);
  const denied = await (await call(env, mcpRequest(reader.key, "tools/call", { name: "knowledge_policy_update", arguments: {} }))).json();
  assert.equal(denied.result.isError, true);
  assert.match(denied.result.content[0].text, /insufficient_scope/);
  assert.equal(dispatched.length, 1);
});

test("admin and manager principals see every tool with only Knowledge scopes forwarded", async () => {
  const { env, dispatched } = environment();
  for (const [key, id, expected] of [[ADMIN_KEY, "operator", ["knowledge:read", "knowledge:manage"]],
    [manager.key, "integration:operator", ["knowledge:read", "knowledge:manage"]]]) {
    const tools = (await (await call(env, mcpRequest(key, "tools/list"))).json()).result.tools;
    assert.equal(tools.length, catalogue.tools.length);
    await call(env, mcpRequest(key, "tools/call", { name: "knowledge_status" }));
    assert.deepEqual(dispatched.at(-1), { version: 1, operation: "status", principal: { id, scopes: expected }, payload: {} });
  }
});

test("rotation, revocation and unknown durable keys are rejected on every request", async () => {
  const { env, records } = environment();
  const forged = reader.keyPrefix + "x".repeat(reader.key.length - reader.keyPrefix.length);
  const unknown = "mllm_intelligence_" + "z".repeat(48);
  for (const key of [forged, unknown, "mllm_intelligence_short"]) {
    const response = await call(env, mcpRequest(key, "ping"));
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, "Invalid API key");
  }
  assert.equal((await call(env, mcpRequest(reader.key, "ping"))).status, 200);
  const lookups = env.INTELLIGENCE_DB.calls.lookups;
  records.get(reader.keyPrefix).revokedAt = "2026-09-24T01:00:00Z";
  assert.equal((await call(env, mcpRequest(reader.key, "ping"))).status, 401);
  assert.equal(env.INTELLIGENCE_DB.calls.lookups, lookups + 1);
  const chat = await call(env, mcpRequest(chatOnly.key, "tools/list"));
  assert.equal(chat.status, 403);
  assert.equal((await chat.json()).error, "insufficient_scope");
});

test("keys the edge cannot verify, storage faults and malformed records use the Container", async () => {
  const { env, records } = environment();
  const sqlAccounts = { ...env, AUTH_STORAGE_BACKEND: "sql" };
  assert.equal(await handleKnowledgeEdgeRequest(mcpRequest("legacy-dashboard-key-0000000000000", "ping"), sqlAccounts), null);
  assert.equal((await handleKnowledgeEdgeRequest(mcpRequest("unknown-dashboard-key-000000000000", "ping"), env)).status, 401,
    "with accounts in D1 the edge rejects unknown keys itself");
  assert.equal(await handleKnowledgeEdgeRequest(new Request(`${ORIGIN}/mcp`, { method: "POST" }), env), null);
  assert.equal(await handleKnowledgeEdgeRequest(mcpRequest(reader.key, "ping"), { ...env, KNOWLEDGE_SERVICE: undefined }), null);
  assert.equal(await handleKnowledgeEdgeRequest(new Request(`${ORIGIN}/v1/knowledge/unknown`, {
    method: "POST", headers: { authorization: `Bearer ${ADMIN_KEY}` } }), env), null);
  records.get(reader.keyPrefix).scopes = ["admin"];
  assert.equal(await handleKnowledgeEdgeRequest(mcpRequest(reader.key, "ping"), env), null);
  env.INTELLIGENCE_DB.calls.fail = true;
  assert.equal(await handleKnowledgeEdgeRequest(mcpRequest(manager.key, "ping"), env), null);
});

test("MCP transport rules match the Container route and accept JSON-only clients", async () => {
  const { env } = environment();
  const status = async (request) => (await call(env, request)).status;
  assert.equal(await status(mcpRequest(ADMIN_KEY, "ping", undefined, { origin: "https://evil.example" })), 403);
  assert.equal(await status(mcpRequest(ADMIN_KEY, "ping", undefined, { origin: ORIGIN })), 200);
  assert.equal(await status(mcpRequest(ADMIN_KEY, "ping", undefined, { accept: "application/json" })), 200);
  assert.equal(await status(mcpRequest(ADMIN_KEY, "ping", undefined, { accept: "text/event-stream" })), 406);
  assert.equal(await status(mcpRequest(ADMIN_KEY, "ping", undefined, { "mcp-protocol-version": "unknown" })), 400);
  for (const method of ["GET", "DELETE"]) {
    const response = await call(env, new Request(`${ORIGIN}/mcp`, { method, headers: { authorization: `Bearer ${ADMIN_KEY}` } }));
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "POST");
  }
  const notification = await call(env, new Request(`${ORIGIN}/mcp`, { method: "POST",
    headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) }));
  assert.equal(notification.status, 202);
  const malformed = await call(env, new Request(`${ORIGIN}/mcp`, { method: "POST",
    headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/json" }, body: "{" }));
  assert.equal((await malformed.json()).error.code, -32700);
  assert.equal((await (await call(env, mcpRequest(ADMIN_KEY, "tools/call", { name: [], arguments: {} }))).json()).error.code, -32602);
  assert.equal((await (await call(env, mcpRequest(ADMIN_KEY, "missing"))).json()).error.code, -32601);
});

test("service failures become tool errors without inventing a result", async () => {
  const { env } = environment({ status: 429, result: { code: "allowance_exhausted", message: "Allowance exhausted." } });
  const body = await (await call(env, mcpRequest(reader.key, "tools/call", { name: "knowledge_search", arguments: { query: "x" } }))).json();
  assert.equal(body.result.isError, true);
  assert.deepEqual(JSON.parse(body.result.content[0].text), { error: { code: "allowance_exhausted", message: "Allowance exhausted." } });
  const broken = environment({ overrides: { KNOWLEDGE_SERVICE: { fetch: async () => new Response("not json") } } }).env;
  const failure = await (await call(broken, mcpRequest(reader.key, "tools/call", { name: "knowledge_search", arguments: { query: "x" } }))).json();
  assert.match(failure.result.content[0].text, /knowledge_unavailable/);
});

test("REST routes enforce scopes, identifiers and body placement before dispatch", async () => {
  const { env, dispatched } = environment({ result: { job: { id: "job-1" } } });
  const rest = (key, method, path, body) => new Request(`${ORIGIN}/v1/knowledge/${path}`, { method,
    headers: { "x-multillm-api-key": key, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  assert.equal((await call(env, rest(reader.key, "POST", "context", { query: "limits" }))).status, 200);
  assert.equal((await call(env, rest(reader.key, "POST", "alexandria/search", { query: "companies" }))).status, 200);
  assert.equal((await call(env, rest(reader.key, "GET", "artifacts/art-1"))).status, 200);
  const forbidden = await call(env, rest(reader.key, "GET", "status"));
  assert.equal(forbidden.status, 403);
  assert.equal((await forbidden.json()).message, "The authenticated key requires the knowledge:manage scope");
  assert.equal((await call(env, rest(manager.key, "POST", "sources/src-1/refresh"))).status, 200);
  assert.equal((await call(env, rest(manager.key, "PATCH", "sources/src-1", { id: "other", enabled: false }))).status, 400);
  assert.equal((await (await call(env, rest(manager.key, "POST", "jobs/bad%20id/cancel"))).json()).error.code, "invalid_identifier");
  const unsupported = await call(env, new Request(`${ORIGIN}/v1/knowledge/search`, { method: "POST",
    headers: { authorization: `Bearer ${reader.key}`, "content-type": "text/plain" }, body: "query" }));
  assert.equal(unsupported.status, 415);
  assert.deepEqual(dispatched.map(item => [item.operation, item.payload]), [
    ["context", { query: "limits" }], ["alexandria.search", { query: "companies" }],
    ["artifact", { id: "art-1" }], ["sources.refresh", { id: "src-1" }],
  ]);
});

test("the Worker answers verified Knowledge keys without waking the Container", async () => {
  const worker = (await loadWorkerModule()).default;
  const forwarded = [];
  const { env } = environment();
  env.MULTILLM_PROXY_CONTAINER = { getByName: () => ({ fetch: async (request) => {
    forwarded.push(await request.text());
    return Response.json({ error: "Invalid API key" }, { status: 401 });
  } }) };
  const verified = await worker.fetch(mcpRequest(reader.key, "ping"), env);
  assert.equal(verified.status, 200);
  assert.equal(forwarded.length, 0);
  const unknown = await worker.fetch(mcpRequest("unknown-dashboard-key-000000000000", "ping"), env);
  assert.equal(unknown.status, 401);
  assert.equal(forwarded.length, 0, "D1 accounts let the edge reject unknown keys without the Container");
  const legacy = await worker.fetch(mcpRequest("legacy-dashboard-key-0000000000000", "ping"), { ...env, AUTH_STORAGE_BACKEND: "sql" });
  assert.equal(legacy.status, 401);
  assert.deepEqual(forwarded.map(body => JSON.parse(body).method), ["ping"]);
});

test("dashboard accounts stored in D1 are verified at the edge with their Knowledge scopes", async () => {
  const account = async (username, scopes, changes = {}) => {
    const key = "Dash" + username.padEnd(28, "k").slice(0, 28);
    return { key, row: { username, api_key_hash: await hashIntegrationKey(key, "saltsaltsalt1234"), api_key_prefix: `mllm_${key.slice(0, 8)}`,
      scopes, is_admin: 0, created_at: "2026-09-24T00:00:00+00:00", last_login: null, last_used_at: null, last_used_ip: null,
      created_by: "admin", rotated_at: null, revoked_at: null, ...changes } };
  };
  const reader = await account("reader", "knowledge:read");
  const chat = await account("chatter", "chat,models");
  const admin = await account("owner", "admin,chat,metrics,models,users", { is_admin: 1 });
  const revoked = await account("revoked", "knowledge:read", { revoked_at: "2026-09-24T01:00:00+00:00" });
  const legacy = await account("legacy", "knowledge:read", { api_key_hash: "pbkdf2:sha256:600000$salt$" + "b".repeat(64) });
  const { env, dispatched } = environment();
  env.INTELLIGENCE_DB = database(new Map(), { lookups: 0 }, [reader.row, chat.row, admin.row, revoked.row, legacy.row]);
  const tools = (await (await call(env, mcpRequest(reader.key, "tools/list"))).json()).result.tools;
  assert.equal(tools.length, catalogue.tools.filter(entry => entry.scope === "knowledge:read").length);
  await call(env, mcpRequest(admin.key, "tools/call", { name: "knowledge_status" }));
  assert.deepEqual(dispatched.at(-1).principal, { id: "owner", scopes: ["knowledge:read", "knowledge:manage"] });
  assert.equal((await call(env, mcpRequest(chat.key, "ping"))).status, 403);
  for (const key of [revoked.key, reader.key.slice(0, -1) + "x"]) assert.equal((await call(env, mcpRequest(key, "ping"))).status, 401);
  assert.equal(await handleKnowledgeEdgeRequest(mcpRequest(legacy.key, "ping"), env), null, "unverifiable hashes use the Container");
  const external = { ...env, CONTROL_PLANE_DATABASE_URL: "postgresql://control" };
  assert.equal(await handleKnowledgeEdgeRequest(mcpRequest(reader.key, "ping"), external), null, "PostgreSQL accounts stay in the Container");
});
