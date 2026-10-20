import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { scryptSync } from "node:crypto";
import { handleKnowledgeEdgeRequest } from "../worker/knowledge-edge.mjs";
import { handleRealtimeRequest } from "../worker/realtime.mjs";
import { activeUsersByPrefix, USER_FIELDS } from "../worker/control-users-d1.mjs";
import { handleTenantRequest, organisationsEnabled, resolveAccountTenant, tenantNamespace } from "../worker/tenants-d1.mjs";
import { handleManagedStateRequest } from "../worker/managed-state-dispatch.mjs";
import { nativeGenerationFetch } from "../worker/gateway-extensions.mjs";

test("disabled tenant domain and resolver touch no storage", async () => {
  const db = { prepare() { throw Error("No storage"); } };
  for (const flag of ["", "false", "invalid-private-value"]) {
    const env = { ORGANISATIONS_ENABLED: flag, INTELLIGENCE_DB: db };
    assert.equal(organisationsEnabled(env, () => {}), false);
    assert.equal(tenantNamespace(await resolveAccountTenant(db, "alice", env)), "");
    const response = await handleManagedStateRequest(new Request("http://intelligence.internal/v1/managed-state/tenants", { method: "POST", body: "broken" }), env);
    assert.equal(response.status, 404);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
});

test("tenant domain is private, bounded and fails closed on missing schema", async () => {
  const env = { ORGANISATIONS_ENABLED: "true", INTELLIGENCE_DB: { prepare() { throw Error("no such table: sensitive"); } } };
  const send = (url, body) => handleTenantRequest(new Request(url, { method: "POST", headers: { "content-type": "application/json" }, body }), env);
  assert.equal((await send("https://public.example/v1/managed-state/tenants", "{}")).status, 404);
  assert.equal((await send("http://intelligence.internal/v1/managed-state/tenants", "x".repeat(9000))).status, 400);
  const response = await send("http://intelligence.internal/v1/managed-state/tenants", JSON.stringify({ version: 1, operation: "resolve", principal: "alice" }));
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, "tenant_storage_unavailable");
});

test("native generation rejects unavailable tenant authority before provider or hooks", async () => {
  let calls = 0;
  const result = await nativeGenerationFetch(new Request("https://gateway.example/v1/chat/completions", { method: "POST", body: JSON.stringify({ org_id: "spoofed" }), headers: { "X-Org": "spoofed" } }),
    { ORGANISATIONS_ENABLED: "true" }, {}, { authenticated: true, principal: { id: "alice" }, provider: "openai" }, () => { calls++; return new Response("provider"); });
  assert.equal(result.status, 503);
  assert.equal(calls, 0);
});

function database() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(readFileSync(new URL("../intelligence-migrations/0033_tenant_hierarchy.sql", import.meta.url), "utf8"));
  sqlite.exec("CREATE TABLE control_users (username TEXT PRIMARY KEY)");
  sqlite.exec("INSERT INTO control_users VALUES ('alice'),('bob'),('operator')");
  const db = {
    prepare(sql) {
      let values = [];
      return { bind(...params) { values = params; return this; },
        async all() { return { results: sqlite.prepare(sql).all(...values) }; },
        async first() { return sqlite.prepare(sql).get(...values) ?? null; },
        async run() { return { meta: { changes: Number(sqlite.prepare(sql).run(...values).changes) } }; } };
    },
    async batch(statements) {
      sqlite.exec("BEGIN IMMEDIATE");
      try { const results = []; for (const statement of statements) results.push(await statement.run()); sqlite.exec("COMMIT"); return results; }
      catch (error) { sqlite.exec("ROLLBACK"); throw error; }
    },
  };
  const env = { ORGANISATIONS_ENABLED: "true", INTELLIGENCE_DB: db };
  const call = async (operation, values = {}) => {
    const response = await handleManagedStateRequest(new Request("http://intelligence.internal/v1/managed-state/tenants", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation, ...values }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { sqlite, db, env, call, close() { sqlite.close(); } };
}
async function hierarchy(f) {
  const org = (await f.call("org_create", { actor: "operator", data: { name: "Example" } })).body.result;
  const team = (await f.call("team_create", { actor: "operator", org_id: org.id, data: { name: "Support" } })).body.result;
  return { org, team };
}
async function member(f, org, team, data = {}) {
  return f.call("member_set", { actor: "operator", org_id: org.id, principal: "alice", revision: 0,
    data: { role: "member", team_id: team?.id ?? null, status: "active", ...data } });
}

test("D1 hierarchy has explicit bindings, matching namespaces and content-free audits", async () => {
  const f = database();
  try {
    const { org, team } = await hierarchy(f);
    assert.equal((await member(f, org, team)).status, 200);
    assert.equal(tenantNamespace(await resolveAccountTenant(f.db, "alice", f.env)), "");
    assert.deepEqual((await f.call("workspaces", { principal: "bob" })).body.result.memberships, []);
    const selected = await f.call("binding_set", { actor: "alice", principal: "alice", revision: 0, data: { org_id: org.id, team_id: team.id } });
    assert.equal(selected.status, 200);
    const context = await resolveAccountTenant(f.db, "alice", f.env);
    assert.equal(tenantNamespace(context), `org:${org.id}/team:${team.id}`);
    assert.equal(context.grants_revision, 4);
    const copied = await f.call("binding_set", { actor: "alice", principal: "bob", revision: 0, data: { org_id: org.id, team_id: team.id } });
    assert.equal(copied.status, 403);
    const audit = f.sqlite.prepare("SELECT * FROM tenant_audit").all();
    assert.equal(audit.length, 4);
    assert.equal(JSON.stringify(audit).includes("Support"), false);
    assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM tenant_bindings").get().n, 1);
  } finally { f.close(); }
});

test("D1 atomic membership plus binding and stale updates retain both old rows", async () => {
  const f = database();
  try {
    const { org, team } = await hierarchy(f);
    assert.equal((await member(f, org, team, { bind: true, binding_revision: 0 })).status, 200);
    const result = await f.call("member_set", { actor: "operator", org_id: org.id, principal: "alice", revision: 1,
      data: { role: "billing", bind: true, binding_revision: 0 } });
    assert.equal(result.status, 412);
    assert.equal(f.sqlite.prepare("SELECT role FROM tenant_memberships").get().role, "member");
    assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM tenant_audit").get().n, 4);
    const missing = await f.call("org_update", { actor: "operator", org_id: org.id, data: { name: "Other" } });
    assert.equal(missing.status, 428);
    assert.equal((await f.call("org_update", { actor: "operator", org_id: org.id, revision: 0, data: { name: "Other" } })).status, 412);
  } finally { f.close(); }
});

test("D1 revision changes are fresh and foreign, revoked and missing workspaces are refused", async () => {
  const f = database();
  try {
    const { org, team } = await hierarchy(f), foreign = await hierarchy(f);
    assert.equal((await member(f, org, foreign.team)).status, 404);
    await member(f, org, team, { bind: true, binding_revision: 0 });
    const before = await resolveAccountTenant(f.db, "alice", f.env);
    await f.call("member_set", { actor: "operator", org_id: org.id, principal: "alice", revision: 1, data: { role: "billing" } });
    assert.ok((await resolveAccountTenant(f.db, "alice", f.env)).grants_revision > before.grants_revision);
    await f.call("team_update", { actor: "operator", org_id: org.id, team_id: team.id, revision: 1, data: { status: "deactivated" } });
    await assert.rejects(resolveAccountTenant(f.db, "alice", f.env), error => error.code === "workspace_forbidden" && error.status === 403);
    f.sqlite.prepare("UPDATE tenant_bindings SET team_id='absent'").run();
    await assert.rejects(resolveAccountTenant(f.db, "alice", f.env), error => error.code === "workspace_not_found" && error.status === 404);
    assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM tenant_teams").get().n, 2);
  } finally { f.close(); }
});

test("D1 caps include deactivated rows and remain inside conditional writes", async () => {
  const f = database();
  try {
    const { org } = await hierarchy(f);
    for (let i = 0; i < 99; i++) f.sqlite.prepare("INSERT INTO tenant_teams VALUES (?,?,?,'deactivated',1)").run(`team_${i}`, org.id, "Example");
    assert.equal((await f.call("team_create", { actor: "operator", org_id: org.id, data: { name: "Extra" } })).body.error.code, "tenant_limit_reached");
    for (let i = 0; i < 1000; i++) f.sqlite.prepare("INSERT INTO tenant_memberships VALUES (?,?,NULL,'member','deactivated',1)").run(org.id, `user_${i}`);
    const capped = await member(f, org, null);
    assert.equal(capped.status, 409);
    assert.equal(capped.body.error.code, "tenant_limit_reached");
  } finally { f.close(); }
});

test("D1 CAS blocks a lost update and audit failure rolls the mutation back", async () => {
  const f = database();
  try {
    const { org } = await hierarchy(f);
    // Interleave a competing write after the read but before the guarded atomic batch.
    const original = f.db.batch;
    f.db.batch = async statements => {
      f.sqlite.prepare("UPDATE tenant_organisations SET revision=revision+1 WHERE id=?").run(org.id);
      return original(statements);
    };
    const conflict = await f.call("org_update", { actor: "operator", org_id: org.id, revision: 1, data: { name: "confidential-change" } });
    assert.equal(conflict.status, 412);
    assert.equal(f.sqlite.prepare("SELECT name FROM tenant_organisations").get().name, "Example");
    f.db.batch = original;
    f.sqlite.exec("CREATE TRIGGER reject_audit BEFORE INSERT ON tenant_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END");
    const failed = await f.call("org_update", { actor: "operator", org_id: org.id, revision: 2, data: { name: "confidential-change" } });
    assert.equal(failed.status, 503);
    assert.equal(f.sqlite.prepare("SELECT revision FROM tenant_organisations").get().revision, 2);
    assert.equal(f.sqlite.prepare("SELECT name FROM tenant_organisations").get().name, "Example");
  } finally { f.close(); }
});

test("native requests ignore headers and body scope and resolve before dispatch", async () => {
  const f = database();
  try {
    const { org, team } = await hierarchy(f);
    await member(f, org, team, { bind: true, binding_revision: 0 });
    const contexts = [];
    const request = () => new Request("https://gateway.example/v1/chat/completions", { method: "POST", headers: { "X-Org": "foreign", "X-Team": "foreign", "X-MultiLLM-Workspace": "foreign" },
      body: JSON.stringify({ model: "test", org_id: "foreign", team_id: "foreign" }) });
    const authority = { authenticated: true, principal: { id: "alice" }, provider: "openai" };
    const result = await nativeGenerationFetch(request(), f.env, {}, authority, async (req, env, resolved) => {
      contexts.push(resolved.tenantContext); return new Response("unchanged");
    });
    assert.equal(await result.text(), "unchanged");
    assert.equal(contexts[0].org_id, org.id);
    assert.equal(contexts[0].team_id, team.id);
    await f.call("org_update", { actor: "operator", org_id: org.id, revision: 1, data: { status: "deactivated" } });
    const rejected = await nativeGenerationFetch(request(), f.env, {}, authority, () => { throw Error("No provider"); });
    assert.equal(rejected.status, 403);
    assert.equal((await rejected.json()).error.code, "workspace_forbidden");
  } finally { f.close(); }
});

test("prefix lookup leaves tenant resolution to the verified principal", async () => {
  const row = { username: "alice" };
  const db = { prepare(sql) {
    assert.ok(sql.includes("api_key_prefix=?"));
    return { bind() { return this; }, async all() { return { results: [row] }; } };
  } };
  assert.deepEqual(await activeUsersByPrefix(db, "fixture", { ORGANISATIONS_ENABLED: "true" }), [row]);
  assert.equal(Object.hasOwn(row, "tenant_context"), false);
});

const accountKey = "shared01-synthetic-matching";
const otherKey = "shared01-synthetic-other";
const integrationKey = "mllm_intelligence_" + "s".repeat(32);
const hash = key => `scrypt:32768:8:1$syntheticsalt$${scryptSync(key, "syntheticsalt", 64,
  { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex")}`;
const accountRow = (username, key) => ({ ...Object.fromEntries(USER_FIELDS.map(name => [name, null])),
  username, api_key_hash: hash(key), api_key_prefix: `mllm_${key.slice(0, 8)}`,
  scopes: "knowledge:read,chat,audio", is_admin: 0, created_at: "2026-10-09T00:00:00Z" });
const rows = [accountRow("alice", otherKey), accountRow("bob", accountKey)];
const integrationRow = { id: "integration:synthetic", scopes: JSON.stringify(["knowledge:read", "chat", "audio"]),
  version: 1, created_at: "2026-10-09T00:00:00Z", revoked_at: null,
  key_prefix: integrationKey.slice(0, "mllm_intelligence_".length + 16), key_hash: hash(integrationKey) };
function authFixture() {
  const f = database(), calls = { tenants: [], writes: 0, dispatches: 0 };
  const db = { prepare(sql) {
    if (sql.includes("tenant_")) {
      calls.tenants.push(sql);
      const stmt = f.db.prepare(sql), bind = stmt.bind;
      stmt.bind = (...values) => { if (sql.includes("WHERE b.principal=?")) calls.principal = values[0]; return bind.apply(stmt, values); };
      return stmt;
    }
    return { bind() { return this; }, async all() { return { results: sql.includes("control_users") ? rows : [] }; },
      async first() { return sql.includes("intelligence_credentials") ? integrationRow : null; },
      async run() { calls.writes++; return { meta: { changes: 1 } }; } };
  } };
  const env = { ...f.env, INTELLIGENCE_DB: db, AUTH_STORAGE_BACKEND: "d1", ADMIN_API_KEY: "synthetic-bootstrap",
    ADMIN_USERNAME: "operator", JWT_SECRET: "synthetic-signing", REALTIME_ENABLED: "true",
    REALTIME_PROVIDERS_JSON: '{"openai:realtime-test":{"url":"wss://approved.example/realtime"}}',
    KNOWLEDGE_SERVICE: { async fetch() { calls.dispatches++; return Response.json({ version: 1, result: { status: "ok" } }); } } };
  return { ...f, env, calls };
}
const knowledgeRequest = (key, mcp = false) => new Request(mcp ? "https://gateway.example/mcp" : "https://gateway.example/v1/knowledge/artifacts/synthetic",
  { method: mcp ? "POST" : "GET", headers: { authorization: `Bearer ${key}`, "content-type": "application/json", "X-Org": "spoofed" },
    ...(mcp ? { body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }) } : {}) });
const realtimeRequest = key => new Request("https://gateway.example/v1/realtime/client_secrets", {
  method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json", "X-Team": "spoofed" },
  body: JSON.stringify({ model: "openai:realtime-test" }) });
const authRoutes = [
  ["knowledge", (f, key) => handleKnowledgeEdgeRequest(knowledgeRequest(key), f.env)],
  ["realtime", (f, key) => handleRealtimeRequest(realtimeRequest(key), f.env)],
];
for (const [route, send] of authRoutes) {
  test(`${route} resolves only the matching account despite a forbidden prefix candidate`, async () => {
    const f = authFixture();
    try {
      const { org } = await hierarchy(f);
      await member(f, org, null, { bind: true, binding_revision: 0 });
      await f.call("org_update", { actor: "operator", org_id: org.id, revision: 1, data: { status: "deactivated" } });
      assert.equal((await send(f, accountKey)).status, 200);
      assert.equal(f.calls.principal, "bob");
    } finally { f.close(); }
  });
  for (const kind of ["account", "bootstrap", "integration"]) {
    test(`${route} classifies workspace failures for verified ${kind} credentials`, async () => {
      const f = authFixture(), key = kind === "account" ? otherKey : kind === "bootstrap" ? f.env.ADMIN_API_KEY : integrationKey;
      const principal = kind === "account" ? "alice" : kind === "bootstrap" ? "operator" : integrationRow.id;
      try {
        const { org } = await hierarchy(f);
        await f.call("member_set", { actor: "operator", org_id: org.id, principal: "alice", revision: 0,
          data: { role: "member", bind: true, binding_revision: 0 } });
        f.sqlite.prepare("UPDATE tenant_memberships SET principal=?").run(principal);
        f.sqlite.prepare("UPDATE tenant_bindings SET principal=?").run(principal);
        await f.call("org_update", { actor: "operator", org_id: org.id, revision: 1, data: { status: "deactivated" } });
        for (const [status, code, mutate] of [
          [403, "workspace_forbidden", () => {}],
          [404, "workspace_not_found", () => f.sqlite.prepare("UPDATE tenant_bindings SET org_id='absent'").run()],
          [503, "tenant_storage_unavailable", () => f.sqlite.exec("DROP TABLE tenant_bindings")],
        ]) {
          mutate(); const response = await send(f, key);
          assert.equal(response.status, status); assert.equal((await response.json()).error.code, code);
          assert.equal(response.headers.get("cache-control"), "no-store");
          assert.equal(f.calls.writes, 0); assert.equal(f.calls.dispatches, 0);
        }
      } finally { f.close(); }
    });
  }
  test(`${route} with organisations off never queries tenants or changes responses`, async () => {
    const f = authFixture();
    try {
      for (const flag of [undefined, "", "false", "malformed"]) {
        f.env.ORGANISATIONS_ENABLED = flag;
        for (const key of [accountKey, f.env.ADMIN_API_KEY, integrationKey]) assert.equal((await send(f, key)).status, 200);
      }
      assert.deepEqual(f.calls.tenants, []);
    } finally { f.close(); }
  });
  test(`${route} invalid keys never resolve a tenant`, async () => {
    const f = authFixture();
    try {
      assert.equal((await send(f, "shared01-wrong-key")).status, 401);
      assert.deepEqual(f.calls.tenants, []); assert.equal(f.calls.writes, 0);
    } finally { f.close(); }
  });
}

test("Knowledge MCP preserves its JSON-RPC error envelope for forbidden workspaces", async () => {
  const f = authFixture();
  try {
    const { org } = await hierarchy(f);
    await member(f, org, null, { bind: true, binding_revision: 0 });
    await f.call("org_update", { actor: "operator", org_id: org.id, revision: 1, data: { status: "deactivated" } });
    const response = await handleKnowledgeEdgeRequest(knowledgeRequest(otherKey, true), f.env);
    assert.equal(response.status, 403);
    const body = await response.json();
    assert.equal(body.jsonrpc, "2.0"); assert.equal(body.error.code, -32000);
    assert.equal(body.error.message, "workspace_forbidden"); assert.equal(f.calls.dispatches, 0);
  } finally { f.close(); }
});

test("D1 rechecks team cap inside the write when another team wins the last slot", async () => {
  const f = database();
  try {
    const { org } = await hierarchy(f);
    for (let i = 0; i < 98; i++) f.sqlite.prepare("INSERT INTO tenant_teams VALUES (?,?,?,'active',1)").run(`team_${i}`, org.id, "Example");
    const original = f.db.batch;
    f.db.batch = async statements => {
      f.sqlite.prepare("INSERT INTO tenant_teams VALUES (?,?,?,'active',1)").run("last_slot", org.id, "Other");
      return original(statements);
    };
    const response = await f.call("team_create", { actor: "operator", org_id: org.id, data: { name: "Extra" } });
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, "tenant_limit_reached");
    assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM tenant_teams").get().n, 100);
    assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM tenant_audit").get().n, 2);
  } finally { f.close(); }
});

test("D1 malformed fields and unlisted operations never produce state changes", async () => {
  const f = database();
  try {
    const { org } = await hierarchy(f);
    for (const data of [{ name: null }, { name: "Example", id: "caller-chosen" }, { name: "Example", status: null }, { name: "Example", parent_id: org.id }]) {
      assert.equal((await f.call("org_create", { actor: "operator", data })).status, 400);
    }
    for (const data of [{ role: null }, { role: ["admin"] }, { status: null }, { status: ["active"] }]) {
      assert.equal((await member(f, org, null, data)).status, 400);
    }
    assert.equal((await f.call("unknown", { statement: "DROP TABLE tenant_organisations" })).status, 400);
    assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM tenant_memberships").get().n, 0);
  } finally { f.close(); }
});
