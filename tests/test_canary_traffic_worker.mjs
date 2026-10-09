import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { assignCohort, canaryEnabled, normalizeCanary, prepareCanary,
  handleCanaryRouteOperation, authenticatedPrincipal, sessionIdentifier, CANARY_HEADER } from "../worker/canary-assignment.mjs";

globalThis.crypto ??= webcrypto;
const candidates = ["openai:baseline", "openai:candidate", "openai:other"];
const key = "synthetic-canary-key";
const config = (changes = {}) => ({ enabled: true, mode: "live", weights: { baseline: 0, candidate: 100 },
  salt_revision: "r1", approved_candidates: [candidates[1]], ...changes });

test("shared Python vector, stable assignment and parallel requests", async () => {
  const policy = normalizeCanary(config({ weights: { baseline: 50, candidate: 50 } }), candidates);
  const input = { principal: "tenant:user", session: "session-42", routeId: "auto:experiment", key };
  assert.deepEqual(new Set(await Promise.all(Array.from({ length: 64 }, () => assignCohort(policy, input)))), new Set(["baseline"]));
  assert.equal(await assignCohort(policy, { ...input, session: null }), "baseline");
  assert.equal(await assignCohort(policy, { ...input, principal: null }), "baseline");
  assert.equal(await assignCohort(policy, { ...input, key: null }), "baseline");
});

test("weights and salt revisions change only reviewed cohorts", async () => {
  const first = normalizeCanary(config({ weights: { baseline: 50, candidate: 50 } }), candidates);
  const second = normalizeCanary(config({ weights: { baseline: 50, candidate: 50 }, salt_revision: "r2" }), candidates);
  const pairs = await Promise.all(Array.from({ length: 100 }, async (_, i) => {
    const input = { principal: "tenant:user", session: `s${i}`, routeId: "auto:experiment", key };
    return [await assignCohort(first, input), await assignCohort(second, input)];
  }));
  assert.deepEqual(new Set(pairs.flat()), new Set(["baseline", "candidate"]));
  assert.ok(pairs.some(([a, b]) => a !== b));
});

test("verified principal and session lookup match Container framing", () => {
  assert.equal(authenticatedPrincipal({ tenant_id: "tenant", id: "user" }), '["tenant","user"]');
  assert.equal(authenticatedPrincipal({ username: "user" }), '[null,"user"]');
  assert.equal(authenticatedPrincipal({}), null);
  assert.equal(sessionIdentifier(new Headers({ "X-OpenCode-Session": "header", "Session-Id": "second" }),
    { session_id: "body" }, { session_id: "signed" }), "header");
  assert.equal(sessionIdentifier(new Headers(), { metadata: { conversation_id: "metadata" } }), "metadata");
  assert.equal(sessionIdentifier(new Headers(), {}, { session_id: "signed" }), "signed");
  assert.equal(sessionIdentifier(new Headers()), null);
});

test("observation failures stay observational", async () => {
  const warnings = [];
  const assignment = await prepareCanary({ id: "auto:experiment", candidates, canary: config() }, {
    env: { CANARY_TRAFFIC_ENABLED: "true", JWT_SECRET: key }, principal: "verified", session: "s",
    observe: async () => { throw new Error("private telemetry detail"); }, warn: text => warnings.push(text) });
  assert.equal(assignment.candidates[0], candidates[1]);
  assert.equal(warnings.length, 1);
  assert.ok(!warnings.join().includes("private telemetry detail"));
});

test("defaults and invalid flags leave inputs identical and warn without values", async () => {
  const warnings = [];
  for (const flag of [undefined, "", "false", "off", "malformed-worker-value"]) {
    const env = { CANARY_TRAFFIC_ENABLED: flag, JWT_SECRET: key };
    const route = { id: "auto:experiment", candidates, canary: config() };
    assert.equal(await prepareCanary(route, { env, principal: "verified", session: "s", warn: text => warnings.push(text) }), null);
    canaryEnabled(env, text => warnings.push(text));
    assert.equal(route.candidates, candidates);
  }
  assert.equal(warnings.length, 1);
  assert.ok(!warnings.join().includes("malformed-worker-value"));
  assert.equal(await prepareCanary({ id: "auto:old", candidates }, { env: { CANARY_TRAFFIC_ENABLED: "true" } }), null);
});

test("malformed configurations refuse saves", () => {
  for (const change of [{ enabled: "true" }, { mode: "adaptive" }, { weights: { baseline: -1, candidate: 101 } },
    { weights: { baseline: true, candidate: 99 } }, { weights: { baseline: 40, candidate: 40 } },
    { approved_candidates: ["openai:outside"] }, { approved_candidates: [] },
    { approved_candidates: [candidates[1], candidates[1]] }, { salt_revision: "" }, { extra: true }]) {
    assert.throws(() => normalizeCanary(config(change), candidates));
  }
  for (const value of [null, [], "canary", 0]) assert.throws(() => normalizeCanary(value, candidates));
});

test("live proposal, shadow zero dispatch, content-free observation and policy wins", async () => {
  for (const mode of ["live", "shadow"]) {
    const events = [];
    const assignment = await prepareCanary({ id: "auto:experiment", candidates, canary: config({ mode }) }, {
      env: { CANARY_TRAFFIC_ENABLED: "true", JWT_SECRET: key }, principal: "verified", session: "private-session",
      observe: event => events.push(event) });
    assert.deepEqual(assignment.proposedOrder, [candidates[1], candidates[0], candidates[2]]);
    assert.deepEqual(assignment.candidates, mode === "live" ? assignment.proposedOrder : candidates);
    const eligible = assignment.candidates.filter(model => model !== candidates[1]);
    assert.equal(eligible[0], candidates[0]);
    const response = new Response("provider body");
    assignment.decorate(response);
    assert.equal(response.headers.get(CANARY_HEADER), `candidate; mode=${mode}`);
    assert.equal(events.length, 1);
    assert.ok(!JSON.stringify(events).includes("private-session"));
    assert.ok(!JSON.stringify(events).includes("verified"));
  }
});

test("baseline assignment proposes the unchanged route", async () => {
  const assignment = await prepareCanary({ id: "auto:experiment", candidates,
    canary: config({ mode: "shadow", weights: { baseline: 100, candidate: 0 } }) }, {
    env: { CANARY_TRAFFIC_ENABLED: "true", JWT_SECRET: key }, principal: "verified", session: "s" });
  assert.equal(assignment.cohort, "baseline");
  assert.equal(assignment.proposedOrder, candidates);
  assert.equal(assignment.candidates, candidates);
});

function database() {
  const sql = new DatabaseSync(":memory:");
  sql.exec("CREATE TABLE auto_routes (route_id TEXT PRIMARY KEY, candidates TEXT NOT NULL, updated_at TEXT NOT NULL)");
  sql.exec("CREATE TABLE config_snapshot_revisions (domain TEXT PRIMARY KEY, revision INTEGER NOT NULL)");
  const migration = readFileSync(new URL("../intelligence-migrations/0025_canary_traffic.sql", import.meta.url), "utf8");
  sql.exec(migration); sql.exec(migration);
  const db = { prepare(query) {
    const statement = sql.prepare(query);
    let args = [];
    return { bind(...values) { args = values; return this; },
      async all() { return { results: statement.all(...args) }; },
      async first() { return statement.get(...args) ?? null; },
      async run() { const result = statement.run(...args); return { success: true, meta: { changes: Number(result.changes) } }; } };
  }, async batch(statements) {
    sql.exec("BEGIN");
    try { const results = []; for (const statement of statements) results.push(await statement.run()); sql.exec("COMMIT"); return results; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  return { db, sql };
}
const write = (changes = {}) => ({ version: 1, operation: "canary_put", route_id: "auto:experiment", candidates,
  updated_at: "2026-10-09T00:00:00Z", canary: config(), current_revision: null, ...changes });

test("atomic route/config persistence, revision conflict and stale config baseline", async t => {
  const { db, sql } = database(); t.after(() => sql.close());
  const env = { CONFIG_REVISION_SYNC_ENABLED: "true" };
  assert.equal((await handleCanaryRouteOperation(db, write({ current_revision: 0 }), env)).status, 200);
  assert.equal((await handleCanaryRouteOperation(db, write({ current_revision: 0, canary: config({ mode: "shadow" }) }), env)).status, 409);
  const result = await (await handleCanaryRouteOperation(db, { version: 1, operation: "canary_list" }, env)).json();
  assert.equal(result.routes[0].canary.mode, "live");
  assert.equal(sql.prepare("SELECT revision FROM config_snapshot_revisions").get().revision, 1);
  sql.prepare("UPDATE auto_routes SET updated_at='new-review'").run();
  assert.deepEqual((await (await handleCanaryRouteOperation(db, { version: 1, operation: "canary_list" }, env)).json()).routes, []);
});

test("invalid settings, missing schema and failed transaction cannot partially save", async t => {
  const { db, sql } = database(); t.after(() => sql.close());
  assert.equal((await handleCanaryRouteOperation(db, write({ canary: config({ mode: "adaptive" }) }), {})).status, 400);
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM auto_routes").get().n, 0);
  const warnings = [];
  const broken = { prepare() { throw new Error("private database text"); } };
  const response = await handleCanaryRouteOperation(broken, write(), {}, text => warnings.push(text));
  assert.equal(response.status, 503);
  assert.ok(!(await response.text()).includes("private"));
  assert.equal(warnings.length, 1);
  assert.equal((await handleCanaryRouteOperation(db, write(), { CONFIG_SNAPSHOTS_ENABLED: "true" })).status, 409);
  assert.equal(await handleCanaryRouteOperation(db, { version: 1, operation: "list" }, {}), null);
});

test("a policy write failure rolls back route, policy and revision together", async t => {
  const { db, sql } = database(); t.after(() => sql.close());
  const env = { CONFIG_REVISION_SYNC_ENABLED: "true" };
  assert.equal((await handleCanaryRouteOperation(db, write({ current_revision: 0 }), env)).status, 200);
  sql.exec("CREATE TRIGGER reject_policy BEFORE INSERT ON canary_traffic BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END");
  const response = await handleCanaryRouteOperation(db, write({ current_revision: 1, updated_at: "2026-10-09T01:00:00Z",
    candidates: [...candidates].reverse(), canary: config({ mode: "shadow" }) }), env);
  assert.equal(response.status, 503);
  assert.equal(sql.prepare("SELECT revision FROM config_snapshot_revisions").get().revision, 1);
  assert.equal(sql.prepare("SELECT updated_at FROM auto_routes").get().updated_at, "2026-10-09T00:00:00Z");
  assert.equal(JSON.parse(sql.prepare("SELECT configuration FROM canary_traffic").get().configuration).mode, "live");
});
