import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleControlUsersRequest } from "../worker/control-users-d1.mjs";
import { authStorageBackend, collectContainerEnv } from "../worker/container-env.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";

const hash = "scrypt:32768:8:1$salt123456789012$" + "a".repeat(128);
const user = (username, changes = {}) => ({
  username, api_key_hash: hash, api_key_prefix: "mllm_abcdefgh", scopes: "knowledge:read", is_admin: 0,
  created_at: "2026-09-24T00:00:00+00:00", last_login: null, last_used_at: null, last_used_ip: null,
  created_by: "admin", rotated_at: null, revoked_at: null, ...changes,
});

async function database() {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  const migration = await readFile(new URL("../intelligence-migrations/0003_control_users.sql", import.meta.url), "utf8");
  for (const statement of migration.split(";").filter(item => item.trim())) await db.prepare(statement).run();
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

test("accounts use D1 unless an external control plane or explicit backend is configured", () => {
  assert.equal(authStorageBackend({ INTELLIGENCE_DB: {} }), "d1");
  assert.equal(authStorageBackend({}), "sql");
  assert.equal(authStorageBackend({ INTELLIGENCE_DB: {}, CONTROL_PLANE_DATABASE_URL: "postgresql://db" }), "sql");
  assert.equal(authStorageBackend({ INTELLIGENCE_DB: {}, AUTH_STORAGE_BACKEND: "sql" }), "sql");
  assert.equal(collectContainerEnv({ INTELLIGENCE_DB: {} }).AUTH_STORAGE_BACKEND, "d1");
  assert.equal(collectContainerEnv({}).AUTH_STORAGE_BACKEND, "sql");
});
