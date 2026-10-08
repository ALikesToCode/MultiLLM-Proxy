import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { handleUsageLedgerRequest, recordNativeUsage } from "../worker/usage-ledger-d1.mjs";
import { BUCKET_FIELDS } from "../worker/usage-buckets-d1.mjs";
import { handleKnowledgeEdgeRequest } from "../worker/knowledge-edge.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
import { HandoffStore } from "../worker/knowledge/handoff-store.mjs";
import { fixture, request as knowledgeQuery } from "./knowledge_fixture.mjs";
import { makeRoleplayEnv, completionResponse, roleplayRequest, withGlobalFetch, scopePublicRoleplaySessionId } from "./helpers/roleplay_fixture.mjs";
import { handleRoleplayEdgeRequest } from "../worker/roleplay/edge.mjs";

const clock = Date.parse("2026-10-09T00:00:00Z");
const enabled = { CONTENT_RETENTION_ENABLED: "true" };
const base = { at: new Date(clock).toISOString(), principal: "reader", key_prefix: null, kind: "chat",
  endpoint: "/v1/chat/completions", requested_model: "openai:fixture", selected_model: "openai:fixture",
  status: 200, latency_ms: 300, input_tokens: 100, output_tokens: 10, cost_usd: 0.001, cost_basis: "usage", request_id: null };
const buckets = { ordinary_input_tokens: 40, cache_read_input_tokens: 60, cache_write_input_tokens: 0,
  ordinary_input_cost_microusd: 80, cache_read_input_cost_microusd: 30, cache_write_input_cost_microusd: 0,
  output_cost_microusd: 80, bucket_basis: "measured", bucket_source: "openai" };
const turn = { model: "roleplay:auto", session_id: "transport-session", stream: false,
  messages: [{ role: "user", content: "private scene" }], memory: { mode: "auto" } };
const forged = { "X-MultiLLM-Retention-Key-ID": "forged", "X-MultiLLM-Retention-Key-Hash": "forged",
  "X-MultiLLM-Retention-Route": "/forged" };
const handoff = { project: "fixture/repo", title: "Continue fixture", sections: { state: "private state" }, source: { agent: "other" } };
const hash = value => createHash("sha256").update(value).digest("hex");

// Execute the real statements locally; batch rollback and JSON extraction match D1's SQLite contract.
async function ledger(t, migrated = true) {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  const migration = await readFile(new URL("../intelligence-migrations/0007_usage_ledger.sql", import.meta.url), "utf8");
  sqlite.exec(migration.slice(migration.indexOf("CREATE TABLE IF NOT EXISTS usage_events")));
  const extend = async () => sqlite.exec(await readFile(new URL("../intelligence-migrations/0016_usage_buckets.sql", import.meta.url), "utf8"));
  if (migrated) await extend();
  const statements = [];
  const db = { prepare(sql) {
    statements.push(sql);
    return { bind(...values) { return { run() { return { meta: { changes: Number(sqlite.prepare(sql).run(...values).changes) } }; },
      async all() { return { results: sqlite.prepare(sql).all(...values).map(row => ({ ...row })) }; } }; } };
  }, async batch(batch) {
    sqlite.exec("BEGIN");
    try { const results = batch.map(statement => statement.run()); sqlite.exec("COMMIT"); return results; }
    catch (error) { sqlite.exec("ROLLBACK"); throw error; }
  } };
  const call = (body, flags = {}) => handleUsageLedgerRequest(new Request("http://intelligence.internal/v1/usage", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
  }), { INTELLIGENCE_DB: db, ...flags });
  return { sqlite, db, statements, call, extend };
}
const recent = { operation: "recent", since: base.at, principal: null, before: null, limit: 10 };
const record = (rows = [base], batch = "a".repeat(32)) => ({ operation: "record", batch, rows });

test("flags off keeps ledger response bytes, columns and statements unchanged", async t => {
  const f = await ledger(t, false);
  const response = await f.call(record());
  assert.equal(await response.text(), '{"version":1,"recorded":1,"duplicate":false}');
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(await (await f.call(recent)).text(), JSON.stringify({ version: 1, rows: [{ id: 1, ...base }] }));
  assert.ok(f.statements.every(sql => !sql.includes("cache_read_input_tokens")));
  assert.equal((await f.call(record([{ ...base, ...buckets }]))).status, 400);
});

test("bucket ledger writes and reads exact extended columns with one rollup on retry", async t => {
  const f = await ledger(t);
  const flags = { PROMPT_CACHE_USAGE_BUCKETS_ENABLED: "true" };
  assert.equal(await (await f.call(record([{ ...base, ...buckets }]), flags)).text(), '{"version":1,"recorded":1,"duplicate":false}');
  const rows = (await (await f.call(recent, flags)).json()).rows;
  assert.deepEqual(rows, [{ id: 1, ...base, ...buckets }]);
  assert.deepEqual(Object.keys(rows[0]).sort(), ["id", ...Object.keys(base), ...BUCKET_FIELDS].sort());
  assert.equal(await (await f.call(record([{ ...base, ...buckets }]), flags)).text(), '{"version":1,"recorded":0,"duplicate":true}');
  assert.equal(f.sqlite.prepare("SELECT requests FROM usage_daily").get().requests, 1);
});

test("missing bucket migration rolls back extended batch, saves base and never duplicates retry", async t => {
  const f = await ledger(t, false);
  const flags = { PROMPT_CACHE_USAGE_BUCKETS_ENABLED: "true" };
  for (let i = 0; i < 2; i++) {
    const response = await f.call(record([{ ...base, ...buckets }]), flags);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal((await response.json()).error.code, "usage_buckets_unavailable");
  }
  await f.extend();
  assert.equal((await (await f.call(record([{ ...base, ...buckets }]), flags)).json()).duplicate, true);
  assert.equal(f.sqlite.prepare("SELECT COUNT(*) AS n FROM usage_events").get().n, 1);
  assert.equal(f.sqlite.prepare("SELECT requests FROM usage_daily").get().requests, 1);
  assert.equal((await (await f.call(recent, flags)).json()).rows[0].cache_read_input_tokens, null);
});

test("enabled ledger validates envelope and bucket values before SQL and native usage stays base only", async t => {
  const f = await ledger(t, false), flags = { PROMPT_CACHE_USAGE_BUCKETS_ENABLED: "true" };
  for (const body of [{ ...record(), batch: "bad" }, { ...record(), unexpected: true },
    record([{ ...base, ...buckets, cache_read_input_tokens: -1 }]), record([{ ...base, unexpected: true }])]) {
    assert.equal((await f.call(body, flags)).status, 400);
  }
  assert.equal(f.statements.length, 0);
  const native = await recordNativeUsage({ INTELLIGENCE_DB: f.db, ...flags }, { provider: "openai", model: "fixture",
    principal: "reader", endpoint: base.endpoint, status: 200, duration_ms: 300,
    input_tokens: 100, output_tokens: 10, cost_usd: 0.001, cost_basis: "usage", requestId: "b".repeat(32) });
  assert.equal(native.recorded, 1);
  assert.ok(f.statements.every(sql => !sql.includes("cache_read_input_tokens")));
});

function roleplayCapture(flags = {}) {
  const captured = [];
  const env = { ADMIN_API_KEY: "admin-roleplay-key", ROLEPLAY_API_KEY: "janitor-roleplay-key", ...flags,
    ROLEPLAY_SESSION: { getByName: () => ({ async fetch(request) {
      captured.push({ url: request.url, headers: Object.fromEntries(request.headers), body: await request.text() });
      return new Response("fixture bytes", { headers: { "content-type": "application/json" } });
    } }) } };
  return { env, captured };
}

test("flags off ignores retention and forged identity without changing internal roleplay bytes", async () => {
  const f = roleplayCapture();
  const first = await handleRoleplayEdgeRequest(roleplayRequest(turn), f.env);
  const second = await handleRoleplayEdgeRequest(roleplayRequest(turn, { ...forged, "X-MultiLLM-Retention": "zero" }), f.env);
  assert.deepEqual(f.captured[0], f.captured[1]);
  assert.equal(await first.text(), await second.text());
  assert.deepEqual([...first.headers], [...second.headers]);
});

test("enabled roleplay turn overwrites internal identity with verified admin and public path", async () => {
  const f = roleplayCapture({ ...enabled, ADMIN_USERNAME: " owner " });
  await handleRoleplayEdgeRequest(roleplayRequest(turn, { ...forged, "X-MultiLLM-Retention": "zero" }, "/roleplay/v1/chat/completions"), f.env);
  const headers = f.captured[0].headers;
  assert.equal(headers["x-multillm-retention"], "zero");
  assert.equal(headers["x-multillm-retention-key-id"], "owner");
  assert.equal(headers["x-multillm-retention-key-hash"], hash("admin-roleplay-key"));
  assert.equal(headers["x-multillm-retention-route"], "/roleplay/v1/chat/completions");
  const rejected = await handleRoleplayEdgeRequest(roleplayRequest(turn, { Authorization: "Bearer invalid", ...forged }), f.env);
  assert.equal(rejected.status, 401);
  assert.equal(f.captured.length, 1);
});

test("roleplay-only credential uses its verified identity and public zero header creates local state", async () => {
  const f = roleplayCapture(enabled);
  await handleRoleplayEdgeRequest(roleplayRequest(turn, { Authorization: "Bearer janitor-roleplay-key" }), f.env);
  assert.equal(f.captured[0].headers["x-multillm-retention-key-id"], "roleplay");
  assert.equal(f.captured[0].headers["x-multillm-retention-key-hash"], hash("janitor-roleplay-key"));
  const runtime = makeRoleplayEnv(enabled);
  const response = await withGlobalFetch(async () => completionResponse("fixture", "private reply"),
    () => handleRoleplayEdgeRequest(roleplayRequest(turn, { ...forged, "X-MultiLLM-Retention": "zero" }), runtime.env));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-MultiLLM-Retention"), "zero");
  await response.text();
  await runtime.waitForBackgroundWork();
  const entry = [...runtime.storageBySession.values()][0];
  assert.equal(entry.instance.stateRepository.loaded, false);
  assert.equal(entry.storage.operations.setAlarm, 0);
  assert.doesNotMatch(JSON.stringify([...entry.storage.values]), /private scene|private reply/);
});

test("operator memory and recovery transport use admin identity even when session scope is roleplay", async () => {
  const f = roleplayCapture({ ...enabled, ADMIN_USERNAME: "owner" });
  for (const operation of ["memory", "recovery"]) {
    const path = `/v1/roleplay/control/${operation}`;
    await handleRoleplayEdgeRequest(roleplayRequest({ action: "inspect" }, { ...forged, "X-MultiLLM-Retention": "zero" }, `${path}?session_id=transport-session`), f.env);
    const captured = f.captured.at(-1);
    assert.equal(captured.headers["x-multillm-retention"], "zero");
    assert.equal(captured.headers["x-multillm-retention-key-id"], "owner");
    assert.equal(captured.headers["x-multillm-retention-key-hash"], hash("admin-roleplay-key"));
    assert.equal(captured.headers["x-multillm-retention-route"], path);
  }
});

function knowledgeRequest(path, payload, headers = {}) {
  return new Request(`https://proxy.example${path}`, { method: "POST", body: JSON.stringify(payload),
    headers: { Authorization: "Bearer knowledge-fixture", "content-type": "application/json", ...headers } });
}
function knowledgeCapture(flags = {}) {
  const captured = [];
  return { captured, env: { ADMIN_API_KEY: "knowledge-fixture", ADMIN_USERNAME: "owner", ...flags,
    KNOWLEDGE_SERVICE: { async fetch(_url, init) {
      captured.push(init.body);
      return Response.json({ version: 1, result: { status: "fixture" } });
    } } } };
}

test("flags off keeps Knowledge retrieval and handoff service bodies and response bytes identical", async () => {
  const f = knowledgeCapture();
  for (const [path, payload, operation] of [["/v1/knowledge/context", { query: "fixture" }, "context"],
    ["/v1/knowledge/handoffs", handoff, "handoffs.save"]]) {
    const first = await handleKnowledgeEdgeRequest(knowledgeRequest(path, payload), f.env);
    const second = await handleKnowledgeEdgeRequest(knowledgeRequest(path, payload, { ...forged, "X-MultiLLM-Retention": "zero" }), f.env);
    assert.equal(f.captured.at(-1), f.captured.at(-2));
    assert.equal(f.captured.at(-1), JSON.stringify({ version: 1, operation,
      principal: { id: "owner", scopes: ["knowledge:read", "knowledge:manage"] }, payload, secret_scan_mode: "block", secret_scan_checked: true }));
    assert.equal(await first.text(), await second.text());
    assert.deepEqual([...first.headers], [...second.headers]);
  }
});

test("Knowledge edge resolves zero from verified key and public path, ignoring forged selectors", async () => {
  for (const selector of [{ keys: { owner: "zero" } }, { keys: { [hash("knowledge-fixture")]: "zero" } },
    { routes: { "/v1/knowledge/context": "zero" } }]) {
    const f = knowledgeCapture({ ...enabled, CONTENT_RETENTION_POLICY_JSON: JSON.stringify(selector) });
    await handleKnowledgeEdgeRequest(knowledgeRequest("/v1/knowledge/context", { query: "fixture" }, { ...forged, "X-MultiLLM-Retention": "inherit" }), f.env);
    assert.deepEqual(JSON.parse(f.captured[0]).retention_policy, { mode: "zero", enabled: true });
  }
  const f = knowledgeCapture({ ...enabled, CONTENT_RETENTION_POLICY_JSON: '{"keys":{"forged":"zero"},"routes":{"/forged":"zero"}}' });
  await handleKnowledgeEdgeRequest(knowledgeRequest("/v1/knowledge/context", { query: "fixture" }, forged), f.env);
  assert.deepEqual(JSON.parse(f.captured[0]).retention_policy, { mode: "inherit", enabled: true });
});

test("zero handoff REST and MCP saves refuse before service dispatch", async () => {
  const f = knowledgeCapture(enabled);
  const response = await handleKnowledgeEdgeRequest(knowledgeRequest("/v1/knowledge/handoffs", handoff, { "X-MultiLLM-Retention": "zero" }), f.env);
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error.code, "retention_forbidden");
  const rpc = await handleKnowledgeEdgeRequest(knowledgeRequest("/mcp", { jsonrpc: "2.0", id: 1,
    method: "tools/call", params: { name: "knowledge_handoff_save", arguments: handoff } }, { "X-MultiLLM-Retention": "zero" }), f.env);
  assert.match(await rpc.text(), /retention_forbidden/);
  assert.equal(f.captured.length, 0);
});

test("trusted zero retrieval bypasses global cache, memo lookup, embeddings and queued writes", async () => {
  const f = await fixture();
  await f.published();
  const original = globalThis.caches;
  globalThis.caches = { default: { match() { assert.fail("global cache read"); }, put() { assert.fail("global cache write"); } } };
  try {
    const result = await dispatchKnowledge({ ...f.env, ...enabled }, { version: 1, operation: "context",
      principal: { id: "owner", scopes: ["knowledge:read"] }, payload: knowledgeQuery({ version: "3.1.3" }),
      retention_policy: { mode: "zero", enabled: true } }, { authority: f.authority, corpus: f.corpus, retrieve: f.retrieve,
      cache: null, memos: { call() { assert.fail("memo storage"); } }, embed() { assert.fail("embedding"); }, waitUntil() { assert.fail("background memo"); } });
    assert.equal(result.status, "ok");
    assert.equal(result.excerpts.length, 1);
    assert.ok(result.usage.length > 0);
  } finally { if (original === undefined) delete globalThis.caches; else globalThis.caches = original; }
});

test("trusted zero handoff rejects before parse or storage; inherited policy reaches store with injected clock", async t => {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  t.mock.method(Date, "now", () => clock);
  const storage = { sql: { exec: (sql, ...args) => sqlite.prepare(sql).all(...args) }, transactionSync(fn) { return fn(); } };
  const store = new HandoffStore(storage);
  const calls = [];
  const env = { ...enabled, KNOWLEDGE_HANDOFFS: { idFromName: id => id, get: () => ({ async fetch(_url, init) {
    const body = JSON.parse(init.body); calls.push(body);
    return Response.json({ version: 1, result: store.call(body.operation, body.payload, Date.now(), body.retention_policy) });
  } }) } };
  const envelope = { version: 1, operation: "handoffs.save", principal: { id: "owner", scopes: ["knowledge:read"] }, payload: handoff };
  await assert.rejects(dispatchKnowledge(env, { ...envelope, payload: null, retention_policy: { mode: "zero", enabled: true } }), { code: "retention_forbidden", status: 409 });
  assert.equal(calls.length, 0);
  const saved = await dispatchKnowledge(env, { ...envelope, retention_policy: { mode: "inherit", enabled: true } });
  assert.equal(store.call("get", { id: saved.id }, clock).record.created_at, new Date(clock).toISOString());
  assert.deepEqual(calls[0].retention_policy, { mode: "inherit", enabled: true });
});

test("handoff Durable Object wrapper passes the trusted snapshot and clock to the store", async t => {
  const url = new URL("../worker/knowledge/index.mjs", import.meta.url);
  const source = (await readFile(url, "utf8"))
    .replace('import { DurableObject, WorkflowEntrypoint } from "cloudflare:workers";', "class DurableObject {}\nclass WorkflowEntrypoint {}")
    .replace(/from "(\.\.?\/[^\"]+)";/g, (_match, path) => `from "${new URL(path, url).href}";`);
  const { KnowledgeHandoffs } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  t.mock.method(Date, "now", () => clock);
  let writes = 0;
  const storage = { sql: { exec: (sql, ...args) => sqlite.prepare(sql).all(...args) },
    transactionSync(fn) { writes++; return fn(); } };
  const object = new KnowledgeHandoffs({ storage }, enabled);
  const call = body => object.fetch(new Request("http://handoffs.internal/dispatch", { method: "POST",
    headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
  const blocked = await call({ operation: "save", payload: null, retention_policy: { mode: "zero", enabled: true } });
  assert.equal(blocked.status, 409);
  assert.equal((await blocked.json()).error.code, "retention_forbidden");
  assert.equal(writes, 0);
  for (const policy of [null, "zero", { mode: "invalid", enabled: true }, { mode: "zero", enabled: "true" }]) {
    assert.equal((await call({ operation: "save", payload: handoff, retention_policy: policy })).status, 400);
  }
  const saved = (await (await call({ operation: "save", payload: handoff, retention_policy: { mode: "inherit", enabled: true } })).json()).result;
  assert.equal(object.handoffs.call("get", { id: saved.id }, clock).record.created_at, new Date(clock).toISOString());
  assert.equal(writes, 1);
});

test("captured edge policy survives service configuration changes and forbids caller-selected payload identity", async () => {
  const f = await fixture();
  await f.published();
  const edgeEnv = { ...enabled, ADMIN_API_KEY: "knowledge-fixture", ADMIN_USERNAME: "owner",
    CONTENT_RETENTION_POLICY_JSON: '{"routes":{"/v1/knowledge/context":"zero"}}',
    KNOWLEDGE_SERVICE: { async fetch(_url, init) {
      const envelope = JSON.parse(init.body);
      const result = await dispatchKnowledge(f.env, envelope, { authority: f.authority, corpus: f.corpus, retrieve: f.retrieve,
        cache: { match() { assert.fail("cache read"); }, put() { assert.fail("cache write"); } },
        memos: { call() { assert.fail("memo call"); } } });
      return Response.json({ version: 1, result });
    } } };
  const response = await handleKnowledgeEdgeRequest(knowledgeRequest("/v1/knowledge/context", knowledgeQuery({ version: "3.1.3" }), forged), edgeEnv);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, "ok");
  const capture = knowledgeCapture(enabled);
  await handleKnowledgeEdgeRequest(knowledgeRequest("/v1/knowledge/context", {
    query: "fixture", retention_policy: { mode: "zero", enabled: true }, principal: { id: "forged" },
  }), capture.env);
  assert.deepEqual(JSON.parse(capture.captured[0]).retention_policy, { mode: "inherit", enabled: true });
});

test("public key and route zero prevent durable roleplay recovery and memory reads", async () => {
  for (const [operation, selector] of [["memory", "routes"], ["recovery", "routes"], ["memory", "keys"], ["recovery", "keys"]]) {
    const path = `/v1/roleplay/control/${operation}`;
    const f = makeRoleplayEnv({ ...enabled, CONTENT_RETENTION_POLICY_JSON: JSON.stringify({ [selector]: { [selector === "keys" ? "admin" : path]: "zero" } }) });
    const id = await scopePublicRoleplaySessionId("transport-session", f.env.ROLEPLAY_API_KEY);
    f.env.ROLEPLAY_SESSION.getByName(id);
    const entry = f.storageBySession.get(id);
    await entry.instance.traces.ready;
    entry.storage.resetOperations();
    const response = await handleRoleplayEdgeRequest(roleplayRequest({ action: "inspect" }, {
      ...forged, "X-MultiLLM-Retention": "inherit",
    }, `${path}?session_id=transport-session`), f.env);
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error.code, operation === "recovery" ? "recovery_unavailable" : "retention_forbidden");
    assert.equal(entry.storage.operations.get, 0);
    assert.equal(entry.storage.operations.put, 0);
  }
});
