import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleControlUsersRequest } from "../worker/control-users-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

const hash = "scrypt:32768:8:1$salt123456789012$" + "a".repeat(128);
const user = (username, changes = {}) => ({
  username, api_key_hash: hash, api_key_prefix: "mllm_abcdefgh", scopes: "chat,models", is_admin: 0,
  created_at: "2026-09-26T00:00:00+00:00", last_login: null, last_used_at: null, last_used_ip: null,
  created_by: "admin", rotated_at: null, revoked_at: null, ...changes,
});
const event = (action, outcome, actor, target, detail) => ({ operation: "audit_record", action, outcome, actor, target, detail });
const list = (changes = {}) => ({ operation: "audit_list", actor: null, target: null, action: null,
  before_account: null, before_event: null, limit: 100, ...changes });

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}",
    d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  const env = { INTELLIGENCE_DB: db, ADMIN_USERNAME: "owner" };
  const call = async body => {
    const response = await handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

// Rows are ordered by their millisecond timestamps; keep consecutive writes apart.
const tick = () => new Promise(resolve => setTimeout(resolve, 3));

async function seed(call) {
  // Account writes are audited by the Worker; events are recorded by the Container.
  assert.equal((await call(event("sign_in", "succeeded", "owner", null, "method=access email=owner@example.com"))).status, 200);
  await tick();
  assert.equal((await call({ operation: "upsert", user: user("alice") })).status, 200);
  await tick();
  assert.equal((await call(event("setting_change", "succeeded", "owner", "alice", "setting=account.create status=200"))).status, 200);
  await tick();
  assert.equal((await call({ operation: "upsert", user: user("mallory", { is_admin: 1 }) })).status, 403);
  await tick();
  assert.equal((await call(event("sign_in", "refused", "bob@example.com", null, "method=access reason=email_not_allowed"))).status, 200);
  await tick();
  assert.equal((await call({ operation: "delete", username: "alice" })).status, 200);
  await tick();
  assert.equal((await call(event("sign_out", "succeeded", "owner", null, "method=access"))).status, 200);
  await tick();
}

const key = entry => `${entry.source}:${entry.id}`;

test("the audit log merges account writes and security events newest first", async t => {
  const { call } = await database(t);
  await seed(call);
  const { status, body } = await call(list());
  assert.equal(status, 200);
  assert.equal(body.next, null);
  assert.deepEqual(body.entries.map(entry => [entry.source, entry.action, entry.outcome, entry.actor, entry.target]), [
    ["event", "sign_out", "succeeded", "owner", null],
    ["account", "delete", "deleted", null, "alice"],
    ["event", "sign_in", "refused", "bob@example.com", null],
    ["account", "upsert", "refused", null, "mallory"],
    ["event", "setting_change", "succeeded", "owner", "alice"],
    ["account", "upsert", "stored", null, "alice"],
    ["event", "sign_in", "succeeded", "owner", null],
  ]);
  const refused = body.entries.find(entry => entry.target === "mallory");
  assert.deepEqual([refused.is_admin, refused.scopes, refused.api_key_prefix], [1, "chat,models", "mllm_abcdefgh"]);
  assert.deepEqual(Object.keys(body.entries[0]).sort(), ["action", "actor", "api_key_prefix", "at", "detail", "id", "is_admin",
    "outcome", "revoked_at", "scopes", "source", "target"]);
  for (const [left, right] of body.entries.slice(1).map((entry, index) => [body.entries[index], entry])) {
    assert.ok(left.at >= right.at, "entries are ordered by time");
  }
});

test("pages are bounded, cover every entry once and keep each table's cursor", async t => {
  const { call } = await database(t);
  await seed(call);
  await seed(call);
  const everything = (await call(list())).body.entries.map(key);
  assert.equal(everything.length, 14);
  const seen = [];
  let cursor = { account: null, event: null };
  for (let page = 0; page < 10; page += 1) {
    const { body } = await call(list({ limit: 3, before_account: cursor.account, before_event: cursor.event }));
    assert.ok(body.entries.length <= 3);
    seen.push(...body.entries.map(key));
    if (!body.next) break;
    cursor = body.next;
  }
  assert.deepEqual(seen, everything, "pagination neither skips nor repeats entries");
});

test("filters select an actor, a target or an action", async t => {
  const { call } = await database(t);
  await seed(call);
  const entries = async changes => (await call(list(changes))).body.entries.map(entry => [entry.source, entry.action, entry.target]);
  assert.deepEqual(await entries({ actor: "owner" }), [["event", "sign_out", null], ["event", "setting_change", "alice"],
    ["event", "sign_in", null]], "account rows have no actor");
  assert.deepEqual(await entries({ target: "alice" }), [["account", "delete", "alice"], ["event", "setting_change", "alice"],
    ["account", "upsert", "alice"]]);
  assert.deepEqual(await entries({ action: "upsert" }), [["account", "upsert", "mallory"], ["account", "upsert", "alice"]]);
  assert.deepEqual(await entries({ action: "sign_in", actor: "bob@example.com" }), [["event", "sign_in", null]]);
  assert.deepEqual(await entries({ target: "x' OR '1'='1" }), [], "filter values are bound, never interpolated");
  const exhausted = await call(list({ before_account: 0, before_event: 0 }));
  assert.deepEqual([exhausted.body.entries, exhausted.body.next], [[], null]);
});

test("audit requests are validated and the handler offers no way to change history", async t => {
  const { db, call } = await database(t);
  for (const body of [
    event("delete_everything", "succeeded", "owner", null, null),
    event("sign_in", "maybe", "owner", null, null),
    event("sign_in", "succeeded", "own\ner", null, null),
    event("sign_in", "succeeded", "owner", null, "x".repeat(513)),
    { ...event("sign_in", "succeeded", "owner", null, null), at: "1999-01-01T00:00:00Z" },
    list({ limit: 101 }), list({ limit: 0 }), list({ before_event: -1 }), list({ before_account: 1.5 }),
    list({ action: "drop" }), list({ actor: ["owner"] }), { ...list(), sql: "DELETE FROM control_audit_events" },
    { operation: "audit_delete", id: 1 }, { operation: "audit_update", id: 1, outcome: "succeeded" },
  ]) assert.equal((await call(body)).status, 400, JSON.stringify(body).slice(0, 80));
  assert.deepEqual((await call(list())).body.entries, []);
  await assert.rejects(db.prepare("INSERT INTO control_audit_events (at, action, outcome) VALUES ('x', 'purge', 'succeeded')").run(),
    "the schema itself refuses unknown actions");
});

test("an unavailable audit table fails closed without revealing storage details", async () => {
  const env = { INTELLIGENCE_DB: { prepare() { throw new Error("private database detail"); } } };
  for (const body of [list(), event("sign_out", "succeeded", "owner", null, null)]) {
    const response = await handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    assert.equal(response.status, 503);
    assert.equal((await response.text()).includes("private database detail"), false);
  }
});
