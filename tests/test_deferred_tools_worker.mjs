import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { DeferredTools, deferredEnabled, readGrantSnapshot, handleDeferredMcp } from "../worker/knowledge/deferred-tools.mjs";
import { catalogueDigest } from "../worker/knowledge/contract-drift.mjs";
import { rankToolDefinitions } from "../worker/knowledge/skills-index.mjs";
import * as deferred from "../worker/knowledge/deferred-tools.mjs";
import { handleKnowledgeEdgeRequest } from "../worker/knowledge-edge.mjs";
import { handleControlStateRequest } from "../worker/control-state-d1.mjs";
import { generateIntegrationCredential } from "../scripts/intelligence_operator.mjs";

const catalogue = JSON.parse(readFileSync(new URL("../worker/knowledge-mcp-catalogue.json", import.meta.url), "utf8"));

const principal = { id: "reader", scopes: ["knowledge:read"] };
const entry = (name, description = "technical model search", schema = { type: "object", additionalProperties: false, properties: {} }) =>
  ({ scope: "knowledge:read", toolset: "core", definition: { name, description, inputSchema: schema } });
const grant = (name, allowed = 1, id = "*") =>
  ({ principal_id: id, tool_name: name, scopes: ["knowledge:read"], allowed, revision: 1 });
function fixture() {
  const rows = [grant("models_a"), grant("models_b")], revision = [1], clock = [100];
  let reads = 0;
  const service = new DeferredTools(async () => { reads++; return structuredClone(rows); }, { revision: () => revision[0], clock: () => clock[0] });
  return { service, rows, revision, clock, reads: () => reads };
}

test("permission filter precedes lexical ranking; exact principal denial overrides public grants", async () => {
  const f = fixture(), entries = [entry("models_a"), entry("models_b"), entry("denied", "secret exact match")];
  assert.deepEqual((await f.service.discover(entries, principal, { query: "secret exact match" })).tools, []);
  f.rows.push(grant("models_a", 0, "reader"));
  assert.deepEqual((await f.service.listTools(entries, principal)).map(t => t.name), ["models_b"]);
  assert.deepEqual(await f.service.listTools(entries, { ...principal, scopes: [] }), []);
  assert.deepEqual(rankToolDefinitions(entries.slice(0, 2).map(e => e.definition), "model").map(t => t.name), ["models_a", "models_b"]);
});

test("granted unadvertised calls recheck grants and invoke full validator before dispatch", async () => {
  const f = fixture(), tool = entry("models_a");
  let validated = 0;
  const validate = (schema, args) => { validated++; assert.deepEqual(schema, tool.definition.inputSchema); return Object.keys(args).length === 0; };
  await f.service.authorizeCall(tool, principal, {}, validate);
  await assert.rejects(f.service.authorizeCall(tool, principal, { extra: true }, validate), { code: "invalid_arguments" });
  await assert.rejects(f.service.authorizeCall(tool, principal, {}, undefined), { code: "tool_validation_unavailable", status: 503 });
  f.rows.push(grant("models_a", 0, "reader"));
  await assert.rejects(f.service.authorizeCall(tool, principal, {}, validate), { code: "tool_not_granted", status: 403 });
  assert.equal(validated, 2);
});

test("complete schema byte budget paginates without modifying validation contracts", async () => {
  const f = fixture(), entries = Array.from({ length: 20 }, (_, i) => entry(`models_${i}`, "model", { type: "object", description: "é".repeat(4000) }));
  f.rows.splice(0, 2, ...entries.map(e => grant(e.definition.name)));
  const first = await f.service.discover(entries, principal, { query: "model", limit: 16 });
  assert.ok(first.tools.length < 16);
  assert.ok(Buffer.byteLength(JSON.stringify(first)) <= 65536);
  const seen = first.tools.map(t => t.name);
  assert.deepEqual(first.tools[0].inputSchema, entries[0].definition.inputSchema);
  let cursor = first.nextCursor;
  while (cursor) {
    const page = await f.service.discover(entries, principal, { query: "model", limit: 16, cursor });
    seen.push(...page.tools.map(t => t.name)); cursor = page.nextCursor;
  }
  assert.equal(new Set(seen).size, 20);
  entries[0].definition.inputSchema.description = "x".repeat(66000);
  await assert.rejects(f.service.discover(entries.slice(0, 1), principal, { query: "model" }), { code: "tool_schema_too_large" });
});

for (const change of ["tamper", "expiry", "principal", "query", "limit", "revision", "grants", "digest"]) {
  test(`signed cursor rejects changed ${change}`, async () => {
    const f = fixture(), entries = [entry("models_a"), entry("models_b")], args = { query: "model", limit: 1 };
    let cursor = (await f.service.discover(entries, principal, args)).nextCursor, user = principal;
    if (change === "tamper") cursor = (cursor[0] === "A" ? "B" : "A") + cursor.slice(1);
    else if (change === "expiry") f.clock[0] += 120;
    else if (change === "principal") user = { ...principal, id: "other" };
    else if (change === "query") args.query = "search";
    else if (change === "limit") args.limit = 2;
    else if (change === "revision") f.revision[0]++;
    else if (change === "grants") f.rows[0].revision++;
    else entries[0].definition.inputSchema.properties.new = { type: "string" };
    await assert.rejects(f.service.discover(entries, user, { ...args, cursor }), { code: "invalid_cursor" });
  });
}

test("bad inputs reject before storage and disabled adapter has no side effects", async () => {
  const f = fixture();
  for (const params of [{}, { query: "" }, { query: "x", limit: 17 }, { query: "x", limit: true }, { query: "x", mode: "embedding" }]) {
    await assert.rejects(f.service.discover([], principal, params), { code: "invalid_request" });
  }
  let warnings = 0;
  for (const flag of [undefined, "", "false", "0", "malformed"]) {
    assert.equal(deferredEnabled(flag, () => warnings++), false);
    assert.equal(await handleDeferredMcp({ method: "tools/list", id: 1 }, { DEFERRED_TOOLS_ENABLED: flag }, principal, [], { service: f.service }), null);
  }
  assert.equal(f.reads(), 0);
  assert.equal(warnings, 1);
});

test("HTTP adapter supplies real errors, grant-filtered list and existing contract digests", async () => {
  const f = fixture(), entries = [entry("models_a"), entry("models_b")];
  const env = { DEFERRED_TOOLS_ENABLED: "true", MCP_CONTRACT_DIGESTS_ENABLED: "true" };
  const response = await handleDeferredMcp({ method: "tools/list", id: 7 }, env, principal, entries, { service: f.service });
  assert.equal(response.status, 200);
  const result = (await response.json()).result;
  assert.equal(result._meta.contract_digest, await catalogueDigest(entries.map(e => e.definition)));
  assert.ok(result.tools.every(t => t._meta.contract_digest));
  const missing = new DeferredTools(async () => { throw new Error("no such table"); });
  const failed = await handleDeferredMcp({ method: "multillm.tools.discover", id: 7, params: { query: "model" } }, env, principal, entries, { service: missing });
  assert.equal(failed.status, 503); assert.equal((await failed.json()).error.code, "tool_grants_unavailable");
});

test("D1 snapshot uses model_grants revision and additive migration retains old rows", async t => {
  const db = new DatabaseSync(":memory:"); t.after(() => db.close());
  db.exec("CREATE TABLE control_revisions(domain TEXT PRIMARY KEY, revision INTEGER, updated_at TEXT); INSERT INTO control_revisions VALUES('model_grants',7,'old')");
  const sql = readFileSync(new URL("../intelligence-migrations/0018_tool_grants.sql", import.meta.url), "utf8");
  db.exec(sql); db.prepare("INSERT INTO tool_grants VALUES(?,?,?,?,?)").run("reader", "models_a", '["knowledge:read"]', 0, 9); db.exec(sql);
  const binding = { prepare: query => ({ bind: (...args) => ({ all: async () => ({ success: true, results: db.prepare(query).all(...args) }) }) }) };
  const snapshot = await readGrantSnapshot({ INTELLIGENCE_DB: binding, CONFIG_REVISION_SYNC_ENABLED: "true" }, principal.id);
  assert.equal(snapshot.revision, 7);
  assert.ok(snapshot.grants.some(g => g.tool_name === "models_a" && g.allowed === 0));
  assert.equal(db.prepare("SELECT revision FROM control_revisions WHERE domain='model_grants'").get().revision, 7);
  assert.equal(db.prepare("SELECT count(*) AS n FROM tool_grants WHERE tool_name='future_tool'").get().n, 0);
  db.exec("DROP TABLE tool_grants");
  await assert.rejects(readGrantSnapshot({ INTELLIGENCE_DB: binding }, principal.id), { code: "tool_grants_unavailable", status: 503 });
});


test("grant changes during discovery refuse the response", async () => {
  const rows = [grant("models_a"), grant("models_b")]; let reads = 0;
  const service = new DeferredTools(async () => reads++ === 0 ? rows : [grant("models_a", 0), grant("models_b")]);
  await assert.rejects(service.discover([entry("models_a"), entry("models_b")], principal, { query: "model" }), { code: "tool_grants_changed", status: 409 });
});

test("bounded validator recognizes every catalogue schema and rejects unsupported keywords in unused branches", () => {
  for (const entry of catalogue.tools) assert.equal(typeof deferred.validateToolArguments(entry.definition.inputSchema, {}), "boolean", entry.definition.name);
  for (const schema of [{ format: "uri" }, { anyOf: [{ type: "object" }, { unsupported: true }] }, { properties: { unused: { format: "uri" } } }]) {
    assert.throws(() => deferred.validateToolArguments(schema, {}), { code: "tool_validation_unavailable", status: 503 });
  }
  let nested = { type: "object" };
  for (let i = 0; i < 40; i++) nested = { properties: { child: nested } };
  assert.throws(() => deferred.validateToolArguments(nested, {}), { code: "tool_validation_unavailable", status: 503 });
  assert.throws(() => deferred.validateToolArguments({ uniqueItems: true }, Array.from({ length: 11000 }, (_, i) => i)), { code: "tool_validation_unavailable", status: 503 });
});

test("validator enforces the complete supported keyword subset without leaking values", () => {
  const cases = [
    [{ type: "object" }, [], false], [{ type: "integer" }, 1.5, false], [{ type: ["string", "null"] }, null, true],
    [{ required: ["q"] }, {}, false], [{ properties: { q: { type: "string" } } }, { q: 1 }, false],
    [{ additionalProperties: false, properties: { q: {} } }, { extra: 1 }, false],
    [{ additionalProperties: { type: "integer" } }, { extra: "x" }, false],
    [{ minLength: 2 }, "x", false], [{ maxLength: 1 }, "xy", false], [{ maxLength: 1 }, "😀", true],
    [{ pattern: "^[a-z]+$" }, "1", false], [{ enum: ["a"] }, "b", false],
    [{ enum: [{ a: 1, b: 2 }] }, { b: 2, a: 1 }, true],
    [{ minimum: 2 }, 1, false], [{ maximum: 1 }, 2, false],
    [{ items: { type: "integer" } }, ["x"], false], [{ minItems: 2 }, [1], false], [{ maxItems: 1 }, [1, 2], false],
    [{ uniqueItems: true }, [{ a: 1, b: 2 }, { b: 2, a: 1 }], false],
    [{ anyOf: [{ type: "string" }, { type: "number" }] }, false, false],
    [{ oneOf: [{ type: "number" }, { type: "integer" }] }, 1, false],
    [{ oneOf: [{ type: "string" }, { type: "integer" }] }, 1, true],
    [{ default: "x", description: "annotation" }, {}, true],
  ];
  for (const [schema, value, expected] of cases) assert.equal(deferred.validateToolArguments(schema, value), expected, JSON.stringify(schema));
  for (const schema of [{ type: "unknown" }, { pattern: "[" }, { minimum: "x" }, { items: [] }]) {
    assert.throws(() => deferred.validateToolArguments(schema, "private-value"), error => error.status === 503 && !error.message.includes("private-value"));
  }
});

test("dispatcher defaults to complete runtime validation and fails closed for unsupported schemas", async () => {
  const f = fixture(), env = { DEFERRED_TOOLS_ENABLED: "true" }, tool = entry("models_a");
  const body = { id: 1, method: "tools/call", params: { name: "models_a", arguments: {} } };
  assert.equal(await handleDeferredMcp(body, env, principal, [tool], { service: f.service }), null);
  const invalid = await handleDeferredMcp({ ...body, params: { ...body.params, arguments: { extra: "private-value" } } }, env, principal, [tool], { service: f.service });
  assert.equal(invalid.status, 400); assert.ok(!(await invalid.text()).includes("private-value"));
  tool.definition.inputSchema.format = "unknown";
  const unsupported = await handleDeferredMcp(body, env, principal, [tool], { service: f.service });
  assert.equal(unsupported.status, 503); assert.equal((await unsupported.json()).error.code, "tool_validation_unavailable");
});

function edgeFixture() {
  const dispatched = [], rows = [grant("knowledge_context"), grant("knowledge_search")];
  const env = { ADMIN_API_KEY: "synthetic-deferred-key", ADMIN_USERNAME: "reader", MCP_CONTRACT_DIGESTS_ENABLED: "true",
    INTELLIGENCE_DB: { prepare(sql) {
      assert.match(sql, /FROM tool_grants/);
      return { bind: id => ({ all: async () => ({ success: true, results: rows.filter(row => ["*", id].includes(row.principal_id))
        .map(({ scopes, ...row }) => ({ ...row, scopes_json: JSON.stringify(scopes) })) }) }) };
    } }, KNOWLEDGE_SERVICE: { async fetch(url, init) {
      dispatched.push(JSON.parse(init.body)); return Response.json({ version: 1, result: { status: "ok" } });
    } } };
  const post = (method, params = {}, { pin, toolsets, key = env.ADMIN_API_KEY } = {}) => handleKnowledgeEdgeRequest(new Request(
    `https://gateway.example/mcp${toolsets === undefined ? "" : `?toolsets=${toolsets}`}`, { method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(pin ? { "X-MultiLLM-MCP-Contract": pin } : {}) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params }) }), env);
  return { env, rows, dispatched, post };
}

test("edge handleMcp keeps disabled bytes and error order without grant reads", async () => {
  const f = edgeFixture();
  f.env.INTELLIGENCE_DB.prepare = () => { throw new Error("disabled grants read"); };
  for (const [method, params, options] of [["tools/call", { name: "knowledge_context", arguments: { query: "technical" } }, {}],
    ["tools/call", { name: "knowledge_context", arguments: [] }, {}],
    ["tools/call", { name: "knowledge_context", arguments: [] }, { pin: "0".repeat(64) }],
    ["multillm.tools.discover", { query: "technical" }, { toolsets: "unknown" }], ["tools/list", {}, {}]]) {
    f.env.DEFERRED_TOOLS_ENABLED = "false";
    const baseline = await f.post(method, params, options), bytes = await baseline.text();
    for (const flag of [undefined, "", "0", "bad"]) {
      f.env.DEFERRED_TOOLS_ENABLED = flag;
      const response = await f.post(method, params, options);
      assert.equal(response.status, baseline.status); assert.equal(await response.text(), bytes);
      assert.deepEqual([...response.headers], [...baseline.headers]);
    }
  }
});

test("edge handleMcp checks grants and arguments before dispatch and pages filtered discovery", async () => {
  const f = edgeFixture(); f.env.DEFERRED_TOOLS_ENABLED = "true";
  const denied = await f.post("tools/call", { name: "knowledge_exa_search", arguments: { query: "technical" } });
  assert.equal(denied.status, 403); assert.equal((await denied.json()).error.code, "tool_not_granted");
  for (const args of [{}, { query: 1 }, { query: "technical", extra: true }, null, []]) {
    const invalid = await f.post("tools/call", { name: "knowledge_context", arguments: args });
    assert.equal(invalid.status, 400); assert.equal((await invalid.json()).error.code, "invalid_arguments");
  }
  assert.equal(f.dispatched.length, 0);
  assert.equal((await f.post("tools/call", { name: "knowledge_context", arguments: { query: "technical" } })).status, 200);
  assert.equal(f.dispatched.length, 1);
  const pinned = await f.post("tools/call", { name: "knowledge_context", arguments: { query: "technical" } }, { pin: "0".repeat(64) });
  assert.equal(pinned.status, 409); assert.equal(f.dispatched.length, 1);
  const list = (await (await f.post("tools/list", {}, { toolsets: "core" })).json()).result;
  assert.deepEqual(list.tools.map(tool => tool.name), ["knowledge_context", "knowledge_search"]);
  assert.ok(list.tools.every(tool => tool._meta.contract_digest));
  const first = (await (await f.post("multillm.tools.discover", { query: "technical", limit: 1 })).json()).result;
  const second = (await (await f.post("multillm.tools.discover", { query: "technical", limit: 1, cursor: first.nextCursor })).json()).result;
  assert.notEqual(first.tools[0].name, second.tools[0].name);
  for (const method of ["tools/list", "multillm.tools.discover", "tools/call"]) {
    const response = await f.post(method, { query: "technical" }, { toolsets: "unknown" });
    assert.equal((await response.json()).error.code, -32602);
  }
  f.env.INTELLIGENCE_DB.prepare = () => { throw new Error("no such table"); };
  for (const method of ["tools/list", "multillm.tools.discover", "tools/call"]) {
    const response = await f.post(method, method === "tools/call" ? { name: "knowledge_context", arguments: { query: "technical" } } : { query: "technical" });
    assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "tool_grants_unavailable");
  }
});

test("disabled edge scope denial keeps bytes and precedes contract pins and argument checks", async () => {
  const f = edgeFixture(), credential = await generateIntegrationCredential();
  f.env.AUTH_STORAGE_BACKEND = "d1";
  f.env.INTELLIGENCE_DB.prepare = sql => {
    assert.ok(!sql.includes("tool_grants"));
    return { bind: () => ({ first: async () => ({ id: "integration:reader", scopes: '["knowledge:read"]', version: 1,
      created_at: "2026-09-24T00:00:00Z", revoked_at: null, key_prefix: credential.keyPrefix, key_hash: credential.keyHash }) }) };
  };
  let bytes;
  for (const flag of [undefined, "false", "", "bad"]) {
    f.env.DEFERRED_TOOLS_ENABLED = flag;
    const response = await f.post("tools/call", { name: "knowledge_policy_update", arguments: [] }, { pin: "0".repeat(64), key: credential.key });
    assert.equal(response.status, 200);
    const text = await response.text(), body = JSON.parse(text);
    assert.equal(JSON.parse(body.result.content[0].text).error.code, "insufficient_scope");
    bytes ??= text; assert.equal(text, bytes);
  }
  assert.equal(f.dispatched.length, 0);
});

test("private model-state tool_grants read is gated, bounded and fails closed", async () => {
  const f = edgeFixture();
  f.rows.push(grant("knowledge_context", 0, "reader"), grant("knowledge_context", 1, "other"));
  const queries = [], prepare = f.env.INTELLIGENCE_DB.prepare;
  f.env.INTELLIGENCE_DB.prepare = sql => { queries.push(sql); return prepare(sql); };
  const call = (principal = "reader", extra = {}) => handleControlStateRequest(new Request("http://intelligence.internal/v1/state/models", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ version: 1, operation: "tool_grants", principal, ...extra }) }), f.env);
  assert.equal((await call()).status, 503); assert.equal(queries.length, 0);
  f.env.DEFERRED_TOOLS_ENABLED = "true";
  assert.deepEqual(await (await call()).json(), { version: 1, grants: f.rows.slice(0, 3) });
  assert.match(queries[0], /LIMIT 4097/);
  for (const [id, extra] of [["*", {}], ["", {}], ["reader", { extra: true }]]) assert.equal((await call(id, extra)).status, 400);
  f.rows.splice(0, f.rows.length, ...Array.from({ length: 4097 }, (_, i) => grant(`tool_${i}`)));
  assert.equal((await call()).status, 503);
  f.env.INTELLIGENCE_DB.prepare = () => { throw new Error("no such table"); };
  const missing = await call(); assert.equal(missing.status, 503);
  assert.equal((await missing.json()).error.code, "tool_grants_unavailable");
});

test("revocation during async schema validation refuses execution", async () => {
  const f = fixture();
  await assert.rejects(f.service.authorizeCall(entry("models_a"), principal, {}, async () => {
    f.rows.push(grant("models_a", 0, "reader")); return true;
  }), { code: "tool_not_granted", status: 403 });
});

test("cursor page chains retain the initial expiry", async () => {
  const f = fixture(), entries = [entry("models_a"), entry("models_b"), entry("models_c")];
  f.rows.push(grant("models_c"));
  const first = await f.service.discover(entries, principal, { query: "model", limit: 1 });
  f.clock[0] += 119;
  const second = await f.service.discover(entries, principal, { query: "model", limit: 1, cursor: first.nextCursor });
  f.clock[0]++;
  await assert.rejects(f.service.discover(entries, principal, { query: "model", limit: 1, cursor: second.nextCursor }), { code: "invalid_cursor" });
});

test("HTTP call preflight permits an unadvertised grant and returns real permission errors", async () => {
  const f = fixture(), entries = [entry("models_a")], env = { DEFERRED_TOOLS_ENABLED: "true" };
  const body = { method: "tools/call", id: 1, params: { name: "models_a", arguments: {} } };
  assert.equal(await handleDeferredMcp(body, env, principal, entries, { service: f.service, validate: () => true }), null);
  f.rows.push(grant("models_a", 0, "reader"));
  const denied = await handleDeferredMcp(body, env, principal, entries, { service: f.service, validate: () => true });
  assert.equal(denied.status, 403); assert.equal((await denied.json()).error.code, "tool_not_granted");
});

test("loading the module makes no random values, which Workers forbid in global scope", async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis.crypto, "randomUUID");
  globalThis.crypto.randomUUID = () => { throw new Error("randomUUID called while loading the module"); };
  try {
    await import(`../worker/knowledge/deferred-tools.mjs?global-scope=${Date.now()}`);
  } finally {
    if (original) Object.defineProperty(globalThis.crypto, "randomUUID", original);
    else delete globalThis.crypto.randomUUID;
  }
});
