import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleControlUsersRequest, keyControlsPermit } from "../worker/control-users-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { authStorageBackend, collectContainerEnv } from "../worker/container-env.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";

const hash = "scrypt:32768:8:1$salt123456789012$" + "a".repeat(128);
const user = (username, changes = {}) => ({
  username, api_key_hash: hash, api_key_prefix: "mllm_abcdefgh", scopes: "knowledge:read", is_admin: 0,
  created_at: "2026-09-24T00:00:00+00:00", last_login: null, last_used_at: null, last_used_ip: null,
  created_by: "admin", rotated_at: null, revoked_at: null, daily_budget_usd: null, monthly_budget_usd: null,
  allowed_models: null, allowed_ips: null, expires_at: null, ...changes,
});

async function database(options) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, options);
  const call = async body => {
    const response = await handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), { INTELLIGENCE_DB: db });
    return { status: response.status, body: await response.json() };
  };
  return { mf, db, call };
}

test("accounts persist, page, match active prefixes and record usage in D1", async () => {
  const { mf, call } = await database();
  try {
    for (const name of ["carol", "alice", "bob"]) assert.equal((await call({ operation: "upsert", user: user(name) })).status, 200);
    await call({ operation: "upsert", user: user("bob", { scopes: "chat,models", revoked_at: "2026-09-24T01:00:00+00:00" }) });
    assert.equal((await call({ operation: "get", username: "bob" })).body.user.scopes, "chat,models");
    assert.equal((await call({ operation: "get", username: "nobody" })).body.user, null);
    const page = (await call({ operation: "list", after: null, limit: 2 })).body.users.map(item => item.username);
    assert.deepEqual(page, ["alice", "bob"]);
    assert.deepEqual((await call({ operation: "list", after: "bob", limit: 2 })).body.users.map(item => item.username), ["carol"]);
    const active = (await call({ operation: "by_prefix", prefix: "mllm_abcdefgh" })).body.users;
    assert.deepEqual(active.map(item => item.username), ["alice", "carol"], "revoked accounts never authenticate");
    assert.deepEqual(Object.keys(active[0]).sort(), Object.keys(user("x")).sort());
    assert.equal((await call({ operation: "touch", username: "alice", last_used_at: "2026-09-24T02:00:00+00:00", last_used_ip: "203.0.113.9" })).body.updated, true);
    assert.equal((await call({ operation: "get", username: "alice" })).body.user.last_used_ip, "203.0.113.9");
    assert.equal((await call({ operation: "delete", username: "carol" })).body.deleted, true);
    assert.equal((await call({ operation: "delete", username: "carol" })).body.deleted, false);
  } finally { await mf.dispose(); }
});

test("account records and operations are validated before any statement runs", async () => {
  const { mf, call } = await database();
  try {
    for (const body of [
      { operation: "upsert", user: user("alice", { is_admin: 2 }) },
      { operation: "upsert", user: user("alice", { is_admin: true }) },
      { operation: "upsert", user: { ...user("alice"), extra: 1 } },
      { operation: "upsert", user: user("ali\nce") },
      { operation: "upsert", user: user("alice", { scopes: "chat; DROP TABLE control_users" }) },
      { operation: "upsert", user: user("alice", { api_key_hash: "" }) },
      { operation: "list", after: null, limit: 201 },
      { operation: "get", username: ["alice"] },
      { operation: "sql", statement: "SELECT * FROM control_users" },
    ]) assert.equal((await call(body)).status, 400, JSON.stringify(body).slice(0, 80));
    assert.deepEqual((await call({ operation: "list", after: null, limit: 10 })).body.users, []);
  } finally { await mf.dispose(); }
});

test("the users RPC is private, bounded and never reveals storage errors", async () => {
  const env = { INTELLIGENCE_DB: { prepare() { throw new Error("private database detail"); } } };
  const request = (url, body = "{}", headers = { "content-type": "application/json" }) =>
    new Request(url, { method: "POST", headers, body });
  for (const url of ["https://intelligence.internal/v1/users", "http://other.internal/v1/users", "http://intelligence.internal/v1/users?x=1"]) {
    assert.equal((await handleControlUsersRequest(request(url), env)).status, 404);
  }
  assert.equal((await handleControlUsersRequest(request("http://intelligence.internal/v1/users", "{}", {}), env)).status, 400);
  assert.equal((await handleControlUsersRequest(request("http://intelligence.internal/v1/users", "x".repeat(9000)), env)).status, 400);
  assert.equal((await handleControlUsersRequest(request("http://intelligence.internal/v1/users", "{}"), {})).status, 503);
  const failed = await handleControlUsersRequest(request("http://intelligence.internal/v1/users",
    JSON.stringify({ version: 1, operation: "get", username: "alice" })), env);
  assert.equal(failed.status, 503);
  assert.equal((await failed.text()).includes("private database detail"), false);
  const routed = await handleIntelligenceOutbound(request("http://intelligence.internal/v1/users",
    JSON.stringify({ version: 1, operation: "get", username: "alice" })), env);
  assert.equal(routed.status, 503, "the outbound router reaches the users domain");
});

test("accounts use D1 only when explicitly configured, never merely because the binding exists", () => {
  assert.equal(authStorageBackend({ INTELLIGENCE_DB: {} }), "sql");
  assert.equal(authStorageBackend({}), "sql");
  assert.equal(authStorageBackend({ INTELLIGENCE_DB: {}, AUTH_STORAGE_BACKEND: "d1" }), "d1");
  assert.equal(authStorageBackend({ INTELLIGENCE_DB: {}, AUTH_STORAGE_BACKEND: " sql " }), "sql");
  assert.equal(collectContainerEnv({ INTELLIGENCE_DB: {} }).AUTH_STORAGE_BACKEND, "sql");
  assert.equal(collectContainerEnv({ INTELLIGENCE_DB: {}, AUTH_STORAGE_BACKEND: "d1" }).AUTH_STORAGE_BACKEND, "d1");
});

test("the Worker refuses durable admin accounts it did not configure and audits every account write", async () => {
  const { mf, db, call } = await database();
  const env = { INTELLIGENCE_DB: db, ADMIN_USERNAME: "owner", ADMIN_USERNAMES: "deputy, auditor" };
  const send = async body => {
    const response = await handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  try {
    for (const planted of [user("mallory", { is_admin: 1 }), user("mallory", { scopes: "chat,admin" })]) {
      const refused = await send({ operation: "upsert", user: planted });
      assert.deepEqual([refused.status, refused.body.error.code], [403, "admin_not_allowed"]);
    }
    assert.equal((await send({ operation: "get", username: "mallory" })).body.user, null);
    for (const name of ["owner", "deputy", "auditor"]) {
      assert.equal((await send({ operation: "upsert", user: user(name, { is_admin: 1, scopes: "admin,chat" }) })).status, 200);
    }
    assert.equal((await send({ operation: "upsert", user: user("mallory") })).status, 200, "ordinary accounts are unaffected");
    await send({ operation: "touch", username: "mallory", last_used_at: "2026-09-25T00:00:00+00:00", last_used_ip: null });
    await send({ operation: "delete", username: "mallory" });
    await send({ operation: "delete", username: "mallory" });
    const { results } = await db.prepare("SELECT operation, outcome, username, is_admin FROM control_user_audit ORDER BY id").all();
    assert.deepEqual(results.map(row => [row.operation, row.outcome, row.username, row.is_admin]), [
      ["upsert", "refused", "mallory", 1], ["upsert", "refused", "mallory", 0],
      ["upsert", "stored", "owner", 1], ["upsert", "stored", "deputy", 1], ["upsert", "stored", "auditor", 1],
      ["upsert", "stored", "mallory", 0], ["delete", "deleted", "mallory", null], ["delete", "missing", "mallory", null],
    ], "usage updates are not account changes");
    await db.prepare("DROP TABLE control_user_audit").run();
    assert.equal((await send({ operation: "upsert", user: user("erin") })).status, 503, "an unaudited write is refused");
    assert.equal((await send({ operation: "get", username: "erin" })).body.user, null);
  } finally { await mf.dispose(); }
});

test("a transient D1 error on an account read is retried once", async () => {
  const { mf, db, call } = await database();
  try {
    await call({ operation: "upsert", user: user("alice") });
    let failures = 1;
    const flaky = { prepare: (sql) => {
      const statement = db.prepare(sql);
      return { bind: (...values) => {
        const bound = statement.bind(...values);
        return { first: async () => { if (failures-- > 0) throw new Error("D1_ERROR: Network connection lost"); return bound.first(); },
          all: () => bound.all(), run: () => bound.run() };
      } };
    } };
    const response = await handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: 1, operation: "get", username: "alice" }) }), { INTELLIGENCE_DB: flaky });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).user.username, "alice");
  } finally { await mf.dispose(); }
});

test("per-key budgets, allowlists, expiry and address ranges persist and are validated", async () => {
  const { mf, call } = await database();
  try {
    const limited = user("limited", { daily_budget_usd: 5, monthly_budget_usd: 50.5, allowed_models: "auto:*,free:*,openai:gpt-4.1",
      allowed_ips: "203.0.113.0/24,2001:db8::/32", expires_at: "2026-12-31T00:00:00+00:00" });
    assert.equal((await call({ operation: "upsert", user: limited })).status, 200);
    assert.deepEqual((await call({ operation: "get", username: "limited" })).body.user, limited);
    assert.equal((await call({ operation: "by_prefix", prefix: "mllm_abcdefgh" })).body.users[0].allowed_models,
      "auto:*,free:*,openai:gpt-4.1");
    for (const changes of [{ daily_budget_usd: -1 }, { daily_budget_usd: "5" }, { monthly_budget_usd: 2e9 },
      { allowed_models: "openai:gpt 4" }, { allowed_models: "" }, { allowed_ips: "10.0.0.1" }, { allowed_ips: "10.0.0.0/8;x" },
      { expires_at: "soon" }]) {
      assert.equal((await call({ operation: "upsert", user: user("limited", changes) })).status, 400, JSON.stringify(changes));
    }
    const { daily_budget_usd: _, ...missing } = user("x");
    assert.equal((await call({ operation: "upsert", user: missing })).status, 400, "every column is required");
  } finally { await mf.dispose(); }
});

test("accounts keep working when code is deployed before the key-control migration", async () => {
  const { mf, call } = await database({ skip: ["0007_usage_ledger.sql"] });
  try {
    assert.equal((await call({ operation: "upsert", user: user("alice") })).status, 200);
    assert.deepEqual((await call({ operation: "get", username: "alice" })).body.user, user("alice"));
    assert.deepEqual((await call({ operation: "by_prefix", prefix: "mllm_abcdefgh" })).body.users, [user("alice")]);
    assert.deepEqual((await call({ operation: "list", after: null, limit: 5 })).body.users, [user("alice")]);
    const refused = await call({ operation: "upsert", user: user("alice", { daily_budget_usd: 1 }) });
    assert.equal(refused.status, 503, "controls cannot be stored before the migration");
    assert.equal((await call({ operation: "get", username: "alice" })).body.user.daily_budget_usd, null);
  } finally { await mf.dispose(); }
});

test("the edge applies key expiry and address ranges the same way as the Container", () => {
  const now = Date.parse("2026-09-26T12:00:00Z");
  const account = changes => ({ expires_at: null, allowed_ips: null, ...changes });
  assert.equal(keyControlsPermit(account(), null, now), true);
  assert.equal(keyControlsPermit(account({ expires_at: "2026-09-26T12:00:00+00:00" }), null, now), false);
  assert.equal(keyControlsPermit(account({ expires_at: "2026-09-26T12:00:01Z" }), null, now), true);
  const ranged = account({ allowed_ips: "203.0.113.0/24,2001:db8::/32,198.51.100.7/32" });
  for (const [address, allowed] of [["203.0.113.9", true], ["203.0.114.1", false], ["::ffff:203.0.113.5", true],
    ["2001:db8::1", true], ["2001:db9::1", false], ["198.51.100.7", true], ["198.51.100.8", false], [null, false], ["x", false]]) {
    assert.equal(keyControlsPermit(ranged, address, now), allowed, String(address));
  }
});
