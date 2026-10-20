import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleScimStateRequest } from "../worker/scim-d1.mjs";
import { USER_FIELDS } from "../worker/control-users-d1.mjs";
import { RevisionConsumer } from "../worker/config-revision.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const schema = name => readFileSync(new URL(`../intelligence-migrations/${name}`, import.meta.url), "utf8");
const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
const groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
const id = n => String(n).padStart(32, "0");
function resource(n = 1, changes = {}, kind = "Users") {
  return { schemas: [kind === "Users" ? userSchema : groupSchema], id: id(n), externalId: `subject-${n}`,
    ...(kind === "Users" ? { userName: `user-${n}`, active: true } : { displayName: `team-${n}`, members: [] }),
    meta: { resourceType: kind === "Users" ? "User" : "Group", version: 'W/"1"',
      created: "2026-10-09T00:00:00Z", lastModified: "2026-10-09T00:00:00Z", location: `/scim/v2/${kind}/${id(n)}` }, ...changes };
}
function account(n = 1, changes = {}) {
  return { ...Object.fromEntries(USER_FIELDS.map(key => [key, null])), username: `user-${n}`,
    api_key_hash: "synthetic-hash", api_key_prefix: "mllm_synthetic", is_admin: 0,
    scopes: "chat,models", created_at: "2026-10-09T00:00:00Z", ...changes };
}
function database(t, migrated = true) {
  const sql = new DatabaseSync(":memory:");
  t.after(() => sql.close());
  for (const file of ["0003_control_users.sql", "0007_usage_ledger.sql", "0011_secret_firewall.sql", "0013_shadow_eval.sql", "0017_control_revisions.sql"])
    sql.exec(schema(file));
  sql.exec("CREATE TABLE retained_usage (username TEXT, amount INTEGER); INSERT INTO retained_usage VALUES ('user-1', 7)");
  sql.exec("CREATE TABLE fake_teams (org TEXT, id TEXT, name TEXT, active INTEGER, PRIMARY KEY(org,id))");
  sql.exec("CREATE TABLE fake_principals (org TEXT, username TEXT UNIQUE)");
  if (migrated) sql.exec(schema("0036_scim_provisioning.sql"));
  const db = { prepare(query) {
    let args = [];
    const statement = { bind(...values) { args = values; return statement; },
      first() { return sql.prepare(query).get(...args) ?? null; },
      all() { const p = sql.prepare(query); return p.columns().length ? { results: p.all(...args), meta: { changes: 0 } }
        : { results: [], meta: { changes: Number(p.run(...args).changes) } }; } };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const result = statements.map(s => s.all()); sql.exec("COMMIT"); return result; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const env = { SCIM_ENABLED: "true", CONFIG_REVISION_SYNC_ENABLED: "true", INTELLIGENCE_DB: db };
  const collaborators = { principalStatements: ({ org_id, resource: row }) => [
    db.prepare("INSERT INTO fake_principals VALUES (?,?)").bind(org_id, row.userName)],
  teamStatements: ({ org_id, resource: row, deactivated }) => [
    db.prepare("INSERT INTO fake_teams VALUES (?,?,?,?) ON CONFLICT(org,id) DO UPDATE SET name=excluded.name,active=excluded.active")
      .bind(org_id, row.id, row.displayName, Number(!deactivated))] };
  const send = async (body, extras = {}) => {
    const response = await handleScimStateRequest(new Request("http://intelligence.internal/v1/managed-state/scim", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, org_id: "org:a", ...body }),
    }), env, { ...collaborators, ...extras });
    return { status: response.status, ...await response.json() };
  };
  const put = (row, expected = 0, accountRow = null, kind = "Users", extras) => send({ operation: "put", kind,
    resource: row, expected, account: accountRow, token_digest: "a".repeat(64), deactivate: false }, extras);
  return { sql, db, env, send, put };
}

test("atomic account, identity, externalId replay, scoped uniqueness and retained usage", async t => {
  const { sql, send, put } = database(t);
  assert.equal((await put(resource(), 0, account())).status, 200);
  const duplicate = await put(resource(2, { externalId: "subject-1" }), 0, account(2));
  assert.equal(duplicate.resource.id, id(1));
  assert.equal(duplicate.created, false);
  assert.equal((await put(resource(2, { userName: "user-1" }), 0, account(2, { username: "user-1" }))).status, 409);
  assert.equal((await send({ operation: "get", kind: "Users", id: id(1), org_id: "org:b" })).resource, null);
  assert.equal(sql.prepare("SELECT count(*) n FROM control_users").get().n, 1);
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_audit").get().n, 1);
  assert.equal(sql.prepare("SELECT org FROM fake_principals").get().org, "org:a");
  assert.equal(sql.prepare("SELECT amount FROM retained_usage").get().amount, 7);
  for (const changes of [{ is_admin: 1 }, { scopes: "chat,admin" }])
    assert.equal((await put(resource(3), 0, account(3, changes))).status, 400);
});

test("CAS concurrent updates roll back account, audit, membership and revision changes", async t => {
  const { sql, put } = database(t);
  await put(resource(), 0, account());
  const next = resource(1, { active: false, meta: { ...resource().meta, version: 'W/"2"' } });
  const outcomes = await Promise.all([put(next, 1, account(1, { revoked_at: "2026-10-09T01:00:00Z", api_key_prefix: "mllm_changed", api_key_hash: "synthetic-changed-hash" })),
    put(next, 1, account(1, { revoked_at: "2026-10-09T01:00:00Z", api_key_prefix: "mllm_other", api_key_hash: "synthetic-other-hash" }))]);
  assert.deepEqual(outcomes.map(r => r.status).sort(), [200, 412]);
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_audit").get().n, 2);
  assert.equal(sql.prepare("SELECT revision FROM control_revisions WHERE domain='key_controls'").get().revision, 2);
  assert.equal(sql.prepare("SELECT api_key_prefix FROM control_users").get().api_key_prefix, "mllm_changed");
});

test("deactivation revision invalidates runtime within security TTL", async t => {
  const { db, env, put, sql } = database(t);
  let now = 0, refreshed = [];
  const consumer = new RevisionConsumer(env, { clock: () => now, jitter: () => 1,
    refreshers: Object.fromEntries(["model_overrides", "key_controls", "model_grants"].map(name => [name, () => {
      refreshed.push(name); return sql.prepare("SELECT revoked_at FROM control_users").get(); }])) });
  await put(resource(), 0, account());
  await consumer.tick();
  assert.equal(consumer.requireFreshSecurity(), null);
  const next = resource(1, { active: false, meta: { ...resource().meta, version: 'W/"2"' } });
  await put(next, 1, account(1, { revoked_at: "2026-10-09T01:00:00Z", api_key_prefix: "mllm_changed", api_key_hash: "synthetic-changed-hash" }));
  refreshed = []; now = 5;
  await consumer.tick();
  assert.ok(refreshed.includes("key_controls") && refreshed.includes("model_grants"));
  assert.equal(consumer.requireFreshSecurity(), null);
  db.prepare = () => { throw new Error("synthetic outage"); };
  now = 10.01; await consumer.tick();
  assert.equal(consumer.requireFreshSecurity().status, 503);
});

test("teams and membership stay tenant bound; collaborator failure rolls back", async t => {
  const { sql, put, send } = database(t);
  await put(resource(), 0, account());
  const group = resource(10, { members: [{ value: id(1) }] }, "Groups");
  assert.equal((await put(group, 0, null, "Groups")).status, 200);
  assert.equal(sql.prepare("SELECT name FROM fake_teams").get().name, "team-10");
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_group_members").get().n, 1);
  const foreign = resource(11, { members: [{ value: id(999) }] }, "Groups");
  assert.equal((await put(foreign, 0, null, "Groups")).status, 400);
  const failed = await put(resource(12, {}, "Groups"), 0, null, "Groups", { teamStatements: () => {
    throw new Error("private details"); } });
  assert.equal(failed.status, 503);
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_resources WHERE kind='Groups'").get().n, 1);
  assert.equal((await put(resource(13, {}, "Groups"), 0, null, "Groups", { teamStatements: undefined })).status, 503);
  const deactivated = { ...group, members: [], meta: { ...group.meta, version: 'W/"2"' } };
  assert.equal((await send({ operation: "put", kind: "Groups", resource: deactivated, expected: 1,
    account: null, token_digest: null, deactivate: true })).status, 200);
  assert.equal(sql.prepare("SELECT deactivated FROM scim_resources WHERE kind='Groups'").get().deactivated, 1);
  assert.equal(sql.prepare("SELECT active FROM fake_teams").get().active, 0);
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_group_members").get().n, 0);
  const outcomes = await Promise.all([put({ ...group, displayName: "winning", meta: { ...group.meta, version: 'W/"3"' } }, 2, null, "Groups"),
    put({ ...group, displayName: "losing", meta: { ...group.meta, version: 'W/"3"' } }, 2, null, "Groups")]);
  assert.deepEqual(outcomes.map(result => result.status).sort(), [200, 412]);
  assert.equal(sql.prepare("SELECT name FROM fake_teams").get().name, "winning");
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_group_members").get().n, 1);
});

test("missing schema, disabled flag, private target and invalid bodies fail before changes", async t => {
  const { sql, env, put } = database(t, false);
  assert.equal((await put(resource(), 0, account())).status, 503);
  assert.equal(sql.prepare("SELECT count(*) n FROM control_users").get().n, 0);
  const req = (url = "http://intelligence.internal/v1/managed-state/scim", body = "{}") => new Request(url, {
    method: "POST", headers: { "content-type": "application/json" }, body });
  for (const flag of [undefined, "", "false", "invalid-private"])
    assert.equal((await handleScimStateRequest(req(), { SCIM_ENABLED: flag, INTELLIGENCE_DB: {
      prepare() { assert.fail("off touched storage"); } } })).status, 404);
  assert.equal((await handleScimStateRequest(req("https://external.test/v1/managed-state/scim"), env)).status, 404);
  assert.equal((await handleScimStateRequest(req(undefined, "invalid"), env)).status, 400);
  assert.equal((await handleScimStateRequest(req(undefined, "a".repeat(140000)), env)).status, 400);
});

test("migration is additive and repeats without destroying existing rows; list count is capped", async t => {
  const { sql, send, put } = database(t);
  await put(resource(), 0, account());
  sql.exec(schema("0036_scim_provisioning.sql"));
  const listed = await send({ operation: "list", kind: "Users", attribute: "userName", value: "user-1", start: 1, count: 100 });
  assert.equal(listed.total, 1);
  assert.equal(listed.resources.length, 1);
  assert.equal((await send({ operation: "list", kind: "Users", attribute: "roles", value: "admin", start: 1, count: 100 })).status, 400);
  assert.equal((await send({ operation: "list", kind: "Users", attribute: null, value: null, start: 1, count: 101 })).status, 400);
});

test("mutations require atomic principal authority and fail closed on transaction errors", async t => {
  const { sql, put, env, send } = database(t);
  assert.equal((await put(resource(), 0, account(), "Users", { principalStatements: undefined })).status, 503);
  assert.equal(sql.prepare("SELECT count(*) n FROM control_users").get().n, 0);
  assert.equal((await put(resource(), 0, account(), "Users", { principalStatements: () => [
    env.INTELLIGENCE_DB.prepare("INSERT INTO nonexistent_authority VALUES (1)")] })).status, 503);
  assert.equal(sql.prepare("SELECT count(*) n FROM scim_resources").get().n, 0);
  assert.equal(sql.prepare("SELECT count(*) n FROM control_revisions").get().n, 0);
  env.CONFIG_REVISION_SYNC_ENABLED = "false";
  assert.equal((await send({ operation: "probe" })).status, 400);
  const response = await handleScimStateRequest(new Request("http://intelligence.internal/v1/managed-state/scim", {
    method: "POST", headers: { "content-type": "application/json" }, body: '{"version":1,"operation":"probe"}',
  }), env);
  assert.equal(response.status, 503);
});

test("missing owned columns and security revision schema precede account mutations", async t => {
  const { sql, put } = database(t, false);
  sql.exec("CREATE TABLE scim_resources (org_id TEXT); INSERT INTO scim_resources VALUES ('retained')");
  sql.exec(schema("0036_scim_provisioning.sql").split("CREATE UNIQUE INDEX", 1)[0]);
  assert.equal((await put(resource(), 0, account())).status, 503);
  assert.equal(sql.prepare("SELECT org_id FROM scim_resources").get().org_id, "retained");
  assert.equal(sql.prepare("SELECT count(*) n FROM control_users").get().n, 0);
  const second = database(t);
  second.sql.exec("DROP TABLE control_revisions");
  assert.equal((await second.put(resource(), 0, account())).status, 503);
  assert.equal(second.sql.prepare("SELECT count(*) n FROM control_users").get().n, 0);
});

test("public SCIM routes forward body, bearer and If-Match unchanged to Container", async () => {
  const { default: worker } = await loadWorkerModule();
  const captured = [];
  const env = { MULTILLM_PROXY_CONTAINER: { getByName() { return { async fetch(request) {
    captured.push({ path: new URL(request.url).pathname, body: await request.text(), headers: request.headers });
    return new Response("{}", { headers: { "content-type": "application/scim+json" } });
  } }; } } };
  const body = '{"Operations":[{"op":"replace","path":"active","value":false}]}';
  const response = await worker.fetch(new Request("https://gateway.test/scim/v2/Users/test", { method: "PATCH", body,
    headers: { "Authorization": "Bearer synthetic-scim-token", "Content-Type": "application/scim+json", "If-Match": 'W/"1"' } }), env);
  assert.equal(response.status, 200);
  assert.equal(captured.length, 1);
  assert.equal(captured[0].path, "/scim/v2/Users/test");
  assert.equal(captured[0].body, body);
  assert.equal(captured[0].headers.get("Authorization"), "Bearer synthetic-scim-token");
  assert.equal(captured[0].headers.get("If-Match"), 'W/"1"');
});
