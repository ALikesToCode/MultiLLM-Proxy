import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { handleRevisionedAutoRoutes, commitRevision, revisionSyncSettings, RevisionConsumer } from "../worker/config-revision.mjs";
import { handleAutoRoutesRequest } from "../worker/auto-routes-d1.mjs";
import { boundedBody } from "../worker/control-users-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { account, database, usersCall } from "./support/config_revision_fixtures.mjs";

const putModel = { operation: "put", model_id: "openai:test", status: "disabled", updated_at: "2026-10-09T00:00:00Z" };

test("disabled and malformed flags make no revision statements", async t => {
  const { db, call } = await database(t, true);
  for (const flag of [undefined, "", "false", "invalid"]) {
    const env = { INTELLIGENCE_DB: db, CONFIG_REVISION_SYNC_ENABLED: flag };
    assert.equal((await call("models", { operation: "revisions", domains: ["model_overrides"] }, env)).status, 404);
    assert.deepEqual((await call("models", putModel, env)).body, { version: 1, stored: true });
  }
  assert.equal(revisionSyncSettings({ CONFIG_REVISION_SYNC_ENABLED: "true", CONFIG_SYNC_TTL_SECONDS: "NaN" }).enabled, false);
  assert.equal(revisionSyncSettings({ CONFIG_REVISION_SYNC_ENABLED: "true", CONFIG_SYNC_TTL_SECONDS: "" }).ttl, 30);
});

test("missing migration fails closed before existing data changes", async t => {
  const { call, revisions, db } = await database(t, true);
  assert.equal((await revisions(["model_overrides"])).status, 503);
  assert.equal((await call("models", putModel)).status, 503);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_model_overrides").first()).n, 0);
  assert.equal((await call("routes", { operation: "put", route_id: "auto:test", candidates: ["openai:test"], updated_at: putModel.updated_at })).status, 503);
});

test("registered model writes atomically advance revision without altering response", async t => {
  const { call, revisions, db } = await database(t);
  assert.equal((await revisions(["model_overrides"])).body.revisions.model_overrides, 0);
  await Promise.all([call("models", putModel), call("models", { ...putModel, model_id: "openai:other" })]);
  assert.equal((await revisions(["model_overrides"])).body.revisions.model_overrides, 2);
  const metadata = await db.prepare("SELECT * FROM control_revisions").all();
  assert.equal(metadata.results[0].domain, "model_overrides");
  assert.equal(Object.hasOwn(metadata.results[0], "model_id"), false);
});

test("CAS admits one concurrent writer and preserves rejected configuration", async t => {
  const { db } = await database(t);
  const write = model => commitRevision(db, "model_overrides", [db.prepare("INSERT INTO control_model_overrides VALUES (?, 'disabled', 'time')").bind(model)], 0);
  const results = await Promise.all([write("openai:a"), write("openai:b")]);
  assert.deepEqual(results.sort(), [false, true]);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_model_overrides").first()).n, 1);
  assert.equal((await db.prepare("SELECT revision FROM control_revisions WHERE domain='model_overrides'").first()).revision, 1);
});

test("failed write rolls back revision and cannot leak error details", async t => {
  const { db } = await database(t);
  await assert.rejects(commitRevision(db, "model_overrides", [db.prepare("INSERT INTO missing_table VALUES ('private detail')")]));
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_revisions").first()).n, 0);
});

test("account mutations can increment key and grant domains in the same transaction", async t => {
  const { db, revisions } = await database(t);
  assert.equal(await commitRevision(db, ["key_controls", "model_grants"], [db.prepare("INSERT INTO control_model_overrides VALUES ('openai:account', 'disabled', 'time')")]), true);
  assert.deepEqual((await revisions(["key_controls", "model_grants"])).body.revisions, { key_controls: 1, model_grants: 1 });
  await assert.rejects(commitRevision(db, ["key_controls", "model_grants"], [db.prepare("INSERT INTO missing_table VALUES ('failure')")]));
  assert.deepEqual((await revisions(["key_controls", "model_grants"])).body.revisions, { key_controls: 1, model_grants: 1 });
});

test("auto routes bridge W13 and snapshot apply advances exactly once", async t => {
  const { env, call, revisions, db } = await database(t);
  assert.equal((await call("routes", { operation: "put", route_id: "auto:test", candidates: ["openai:old"], updated_at: putModel.updated_at })).status, 200);
  assert.equal((await revisions(["auto_routes"])).body.revisions.auto_routes, 1);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_revisions WHERE domain='auto_routes'").first()).n, 0);
  env.CONFIG_SNAPSHOTS_ENABLED = "true";
  const created = await call("routes", { operation: "snapshot_create", domain: "auto_routes", base_revision: 1,
    configuration: { routes: [{ route_id: "auto:test", candidates: ["openai:new"] }] }, actor: "a".repeat(64) });
  assert.equal(created.status, 200);
  const apply = () => call("routes", { operation: "snapshot_apply", id: created.body.snapshot.id, current_revision: 1,
    confirm: true, actor: "a".repeat(64) });
  const attempts = await Promise.all([apply(), apply()]);
  assert.deepEqual(attempts.map(item => item.status).sort(), [200, 409]);
  assert.equal((await revisions(["auto_routes"])).body.revisions.auto_routes, 2);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM config_snapshot_applications").first()).n, 1);
});

test("sync does not enable public snapshot operations", async t => {
  const { call } = await database(t);
  assert.equal((await call("routes", { operation: "snapshot_list" })).status, 404);
});

test("catalog writes and revision commit in one transaction; W11 remains reachable", async t => {
  const { call, revisions, env } = await database(t);
  assert.equal((await call("catalog", { operation: "put", provider: "openai", updated_at: putModel.updated_at, data: "YWJj" })).status, 200);
  assert.equal((await revisions(["provider_catalog"])).body.revisions.provider_catalog, 1);
  assert.equal((await call("prompt-templates", { operation: "list", principal: "a".repeat(64), after: null },
    { ...env, PROMPT_TEMPLATES_ENABLED: "true" })).status, 200);
});

test("native consumers load only newer revisions and fail closed after security TTL", async () => {
  let now = 100, revision = 0, offline = false;
  const loads = [];
  const consumer = new RevisionConsumer({ CONFIG_REVISION_SYNC_ENABLED: "true" }, {
    clock: () => now, jitter: () => 0,
    read: async domains => {
      if (offline) throw new Error("offline");
      return Object.fromEntries(domains.map(domain => [domain, revision]));
    },
    refreshers: Object.fromEntries(["auto_routes", "provider_catalog", "key_controls", "model_grants", "model_overrides"].map(
      domain => [domain, async value => loads.push([domain, value])])),
  });
  assert.equal(consumer.requireFreshSecurity().status, 503);
  await consumer.tick();
  assert.equal(consumer.requireFreshSecurity(), null);
  assert.equal(loads.length, 5);
  now += 5;
  await consumer.tick();
  assert.equal(loads.length, 5);
  revision = 1; now += 30;
  await consumer.tick();
  assert.equal(loads.length, 10);
  offline = true; now += 31;
  await consumer.tick();
  assert.equal(consumer.requireFreshSecurity().status, 503);
  assert.equal(consumer.status().domains.auto_routes.stale, true);
  assert.equal(JSON.stringify(consumer.status()).includes("offline"), false);
});

test("native disabled mode is inert and missing collaborators cannot certify keys", async () => {
  const inert = new RevisionConsumer({}, { read: () => assert.fail("No storage") });
  await inert.tick();
  assert.equal(inert.requireFreshSecurity(), null);
  const missing = new RevisionConsumer({ CONFIG_REVISION_SYNC_ENABLED: "true" }, {
    read: async domains => Object.fromEntries(domains.map(domain => [domain, 0])),
  });
  await missing.tick();
  assert.equal(missing.requireFreshSecurity().status, 503);
});

test("native polling is single flight and concurrent writes never renew security", async () => {
  let now = 100, calls = 0, revision = 0;
  const consumer = new RevisionConsumer({ CONFIG_REVISION_SYNC_ENABLED: "true" }, {
    clock: () => now, jitter: () => 1,
    read: async domains => { calls++; return Object.fromEntries(domains.map(domain => [domain, revision])); },
    refreshers: { model_overrides: async () => { revision++; } },
  });
  await Promise.all(Array.from({ length: 100 }, () => consumer.tick()));
  assert.equal(calls, 3);  // security read+confirmation, ordinary read
  assert.equal(consumer.status().domains.model_overrides.revision, null);
  assert.equal(consumer.requireFreshSecurity().status, 503);
  now += 1;
  await consumer.tick();
  assert.equal(calls, 3);
});

test("native rollback cannot hide an observed revision whose load failed", async () => {
  let now = 100, revision = 0, failure = false;
  const consumer = new RevisionConsumer({ CONFIG_REVISION_SYNC_ENABLED: "true" }, {
    clock: () => now,
    read: async domains => Object.fromEntries(domains.map(domain => [domain, revision])),
    refreshers: Object.fromEntries(["model_overrides", "key_controls", "model_grants"].map(domain => [domain, async () => {
      if (failure) throw new Error("offline");
    }])),
  });
  await consumer.tick();
  assert.equal(consumer.requireFreshSecurity(), null);
  failure = true; revision = 1; now += 5;
  await consumer.tick();
  assert.equal(consumer.requireFreshSecurity().status, 503);
  revision = 0; now += 5;
  await consumer.tick();
  assert.equal(consumer.requireFreshSecurity().status, 503);
});

test("revision request validation excludes contents, arbitrary domains and extra fields", async t => {
  const { call } = await database(t);
  for (const domains of [[], ["unknown"], ["model_overrides", "model_overrides"], ["model_overrides; DROP TABLE users"]]) {
    assert.equal((await call("models", { operation: "revisions", domains })).status, 400);
  }
  assert.equal((await call("models", { operation: "revisions", domains: ["model_overrides"], content: "private" })).status, 400);
});


test("real account writes advance both security domains; touches and refused writes do not", async t => {
  const { db, env, revisions } = await database(t);
  const current = async () => (await revisions(["key_controls", "model_grants"])).body.revisions;
  assert.deepEqual((await usersCall(env, { operation: "upsert", user: account() })).body, { version: 1, stored: true });
  assert.deepEqual(await current(), { key_controls: 1, model_grants: 1 });
  for (const changes of [{ revoked_at: putModel.updated_at }, { scopes: "models" }, { allowed_models: "openai:new" },
    { daily_budget_usd: 2, monthly_budget_usd: 3, expires_at: "2099-01-01T00:00:00Z" },
    { api_key_hash: "rotated-hash", api_key_prefix: "rotated", rotated_at: putModel.updated_at },
    { allowed_ips: "192.0.2.0/24" }]) {
    const before = await current();
    assert.equal((await usersCall(env, { operation: "upsert", user: account(changes) })).status, 200);
    assert.deepEqual(await current(), { key_controls: before.key_controls + 1, model_grants: before.model_grants + 1 });
  }
  const before = await current();
  assert.equal((await usersCall(env, { operation: "touch", username: "alice", last_used_at: putModel.updated_at, last_used_ip: null })).status, 200);
  assert.equal((await usersCall(env, { operation: "upsert", user: account({ is_admin: 1 }) })).status, 403);
  assert.deepEqual(await current(), before);
  assert.deepEqual((await usersCall(env, { operation: "delete", username: "alice" })).body, { version: 1, deleted: true });
  assert.deepEqual(await current(), { key_controls: before.key_controls + 1, model_grants: before.model_grants + 1 });
  const audit = (await db.prepare("SELECT outcome FROM control_user_audit WHERE operation='delete'").all()).results;
  assert.deepEqual(audit, [{ outcome: "deleted" }]);
  assert.deepEqual((await usersCall(env, { operation: "delete", username: "alice" })).body, { version: 1, deleted: false });
  assert.deepEqual((await db.prepare("SELECT outcome FROM control_user_audit WHERE operation='delete' ORDER BY id").all()).results,
    [{ outcome: "deleted" }, { outcome: "missing" }]);
});

test("enabled missing revision table refuses account mutations and disabled writers stay unchanged", async t => {
  const { db, env } = await database(t, true);
  assert.equal((await usersCall(env, { operation: "upsert", user: account() })).status, 503);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_users").first()).n, 0);
  const disabled = { ...env, CONFIG_REVISION_SYNC_ENABLED: "false" };
  assert.deepEqual((await usersCall(disabled, { operation: "upsert", user: account() })).body, { version: 1, stored: true });
  assert.equal((await usersCall(env, { operation: "delete", username: "alice" })).status, 503);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_users").first()).n, 1);
  assert.deepEqual((await usersCall(disabled, { operation: "delete", username: "alice" })).body, { version: 1, deleted: true });
});

test("enabled account transaction failure rolls back both revisions and the account", async t => {
  const { db, env, revisions } = await database(t);
  // An injected audit failure aborts the same batch as the account and both counters.
  const failing = { ...env, INTELLIGENCE_DB: { prepare: sql => db.prepare(sql.includes("INSERT INTO control_user_audit")
    ? "INSERT INTO missing_audit_table VALUES (?, ?, ?, ?, ?, ?, ?, ?)" : sql), batch: statements => db.batch(statements) } };
  assert.equal((await usersCall(failing, { operation: "upsert", user: account() })).status, 503);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM control_users").first()).n, 0);
  assert.deepEqual((await revisions(["key_controls", "model_grants"])).body.revisions, { key_controls: 0, model_grants: 0 });
});


test("enabled security listing never silently substitutes missing account controls", async t => {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true,
    script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, { skip: ["0013_shadow_eval.sql"] });
  const env = { INTELLIGENCE_DB: db, CONFIG_REVISION_SYNC_ENABLED: "true" };
  assert.equal((await usersCall(env, { operation: "list", after: null, limit: 200 })).status, 503);
  assert.deepEqual((await usersCall({ ...env, CONFIG_REVISION_SYNC_ENABLED: "false" },
    { operation: "list", after: null, limit: 200 })).body, { version: 1, users: [] });
});
