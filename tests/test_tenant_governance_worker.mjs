import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { TenantContext } from "../worker/enterprise-contract.mjs";
import { handleTenantGovernanceRequest, intersectGrants, createGovernanceLifecycle } from "../worker/tenant-governance-d1.mjs";

const NOW = Date.UTC(2026, 9, 9);
const context = { principal_id: "alice", org_id: "org1", team_id: "team1", grants_revision: 0 };
const migration = readFileSync(new URL("../intelligence-migrations/0034_tenant_governance.sql", import.meta.url), "utf8");
function database(t, schema = true) {
  const sql = new DatabaseSync(":memory:");
  t.after(() => sql.close());
  if (schema) sql.exec(migration);
  const db = { prepare(query) {
    let values = [];
    const statement = { bind(...args) { values = args; return statement; },
      all() {
        const prepared = sql.prepare(query);
        if (!prepared.columns().length) {
          const result = prepared.run(...values);
          return { success: true, results: [], meta: { changes: Number(result.changes) } };
        }
        return { success: true, results: prepared.all(...values), meta: { changes: 0 } };
      }, first() { return sql.prepare(query).get(...values) ?? null; } };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const results = statements.map(s => s.all()); sql.exec("COMMIT"); return results; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const env = { TENANT_GOVERNANCE_ENABLED: "true", INTELLIGENCE_DB: db };
  const call = async body => {
    const response = await handleTenantGovernanceRequest(new Request("http://intelligence.internal/v1/tenant-governance", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
    }), env, { now: () => NOW });
    return { status: response.status, ...await response.json() };
  };
  return { sql, db, env, call };
}
const put = (team_id = null, policy = {}) => ({ operation: "put", org_id: "org1", team_id,
  actor: "alice", revision: 0, policy });
const reserve = (id, changes = {}) => ({ operation: "reserve", id: `tg_${id}`, context, amount: 400_000,
  key_daily: 1_000_000, key_monthly: null, base_day: 0, base_month: 0,
  day: "2026-10-09", month: "2026-10", ...changes });
const settle = (id, changes = {}) => ({ operation: "settle", id: `tg_${id}`, cost: 100_000,
  provider: "openai", model: "openai:actual", price_basis: "usage", before_dispatch: false, ...changes });

test("off, empty and invalid configuration return 404 without storage", async () => {
  for (const flag of [undefined, "", "false", "malformed"]) {
    const response = await handleTenantGovernanceRequest(new Request("http://intelligence.internal/v1/tenant-governance"),
      { TENANT_GOVERNANCE_ENABLED: flag, INTELLIGENCE_DB: { prepare() { assert.fail("disabled storage"); } } });
    assert.equal(response.status, 404);
  }
});

test("missing schema, missing column and unavailable binding return JSON 503", async t => {
  const { call, sql } = database(t, false);
  assert.equal((await call(reserve("one"))).error.code, "tenant_governance_unavailable");
  sql.exec(migration);
  sql.exec("ALTER TABLE tenant_governance_policies RENAME COLUMN models TO old_models");
  assert.equal((await call(reserve("two"))).status, 503);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_reservations").get().n, 0);
});

test("grant intersection never widens key or ancestor grants; absent rows allow", () => {
  assert.equal(intersectGrants(true, "openai:gpt", [{ models: ["openai:*"] }, { models: ["openai:gpt"] }]), true);
  assert.equal(intersectGrants(true, "openai:other", [{ models: ["openai:gpt"] }]), false);
  assert.equal(intersectGrants(false, "openai:gpt", [{ models: ["*"] }]), false);
  assert.equal(intersectGrants(true, "search", [{ tools: [] }], "tools"), false);
  assert.equal(intersectGrants(true, "search", [] , "tools"), true);
});

test("policy CAS and content-free audit reject role escalation", async t => {
  const { call, sql } = database(t);
  assert.equal((await call(put(null, { daily: 500_000 }))).policy.revision, 1);
  assert.equal((await call(put(null, { daily: 600_000 }))).status, 412);
  assert.equal((await call({ ...put(null, { role: "admin" }), revision: 1 })).status, 400);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_audit").get().n, 1);
  assert.equal((await call({ operation: "policies", context })).policies.length, 1);
});

test("every level rejects atomically, settles together and holds unknown costs", async t => {
  const { call, sql } = database(t);
  await call(put(null, { daily: 1_000_000 }));
  await call(put("team1", { daily: 500_000 }));
  assert.equal((await call(reserve("one"))).status, 200);
  const denied = await call(reserve("two", { amount: 200_000 }));
  assert.equal(denied.status, 429); assert.equal(denied.error.level, "team");
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_components").get().n, 6);
  assert.equal((await call(settle("one"))).status, 200);
  assert.equal((await call(reserve("three"))).status, 200);
  await call(settle("three", { cost: null, price_basis: null }));
  assert.equal((await call(reserve("four", { amount: 1 }))).status, 429);
  const usage = await call({ operation: "usage", context, role: "member" });
  assert.equal(usage.spent_micro_usd, 100_000); assert.equal(usage.holds_micro_usd, 400_000);
  assert.equal(usage.models.find(row => row.price_basis === "usage").model, "openai:actual");
});

test("concurrent request race admits exactly one; rejection writes nothing", async t => {
  const { call, sql } = database(t);
  await call(put(null, { monthly: 500_000 }));
  const results = await Promise.all(Array.from({ length: 12 }, (_, n) => call(reserve(String(n)))));
  assert.equal(results.filter(result => result.status === 200).length, 1);
  assert.equal(results.filter(result => result.status === 429).length, 11);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_reservations").get().n, 1);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_baselines").get().n, 2);
});

test("key exhaustion denies without touching ancestor or baseline state", async t => {
  const { call, sql } = database(t);
  const result = await call(reserve("one", { base_day: 800_000 }));
  assert.equal(result.status, 429); assert.equal(result.error.code, "budget_exceeded");
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_baselines").get().n, 0);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_components").get().n, 0);
});

test("private RPC preserves ancestor level and missing-schema remains HTTP 503", async t => {
  const { call } = database(t);
  await call(put(null, { daily: 100_000 }));
  const denied = await call({ ...reserve("one"), rpc: true });
  assert.equal(denied.status, 200);
  assert.equal(denied.decision.code, "tenant_budget_exceeded");
  assert.equal(denied.decision.level, "organisation");
  const absent = database(t, false);
  assert.equal((await absent.call({ ...reserve("two"), rpc: true })).status, 503);
});

test("usage is scoped to caller workspace and own principal unless billing/admin", async t => {
  const { call } = database(t);
  await call(reserve("one")); await call(settle("one"));
  await call(reserve("two", { context: { ...context, principal_id: "bob" } })); await call(settle("two"));
  await call(reserve("three", { context: { ...context, org_id: "org2" } })); await call(settle("three"));
  assert.equal((await call({ operation: "usage", context, role: "member" })).spent_micro_usd, 100_000);
  const billing = await call({ operation: "usage", context, role: "billing" });
  assert.equal(billing.spent_micro_usd, 200_000); assert.equal(billing.organisation.spent_micro_usd, 200_000);
  assert.equal((await call({ operation: "usage", context, role: "stranger" })).status, 403);
});

test("private transport rejects public URLs, content, oversized bodies and invalid money", async t => {
  const { call, env } = database(t);
  assert.equal((await call({ ...reserve("one"), prompt: "content" })).status, 400);
  for (const amount of [-1, 1.5, Number.MAX_SAFE_INTEGER, null]) {
    assert.equal((await call(reserve("one", { amount }))).status, 400);
  }
  const response = await handleTenantGovernanceRequest(new Request("https://public.example/v1/tenant-governance", { method: "POST" }), env);
  assert.equal(response.status, 404);
  const huge = await handleTenantGovernanceRequest(new Request("http://intelligence.internal/v1/tenant-governance", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ operation: "put", junk: "x".repeat(33000) }),
  }), env);
  assert.equal(huge.status, 400);
});

test("migration is additive and repeatable with existing rows", t => {
  const { sql } = database(t);
  sql.exec("CREATE TABLE old_usage (id TEXT); INSERT INTO old_usage VALUES ('kept');");
  sql.exec(migration);
  assert.equal(sql.prepare("SELECT id FROM old_usage").get().id, "kept");
});

test("duplicate reservation IDs cannot add components in another scope", async t => {
  const { call, sql } = database(t);
  assert.equal((await call(reserve("same"))).status, 200);
  assert.equal((await call(reserve("same", { context: { ...context, org_id: "org2", principal_id: "bob" } }))).status, 409);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_components").get().n, 6);
  assert.equal(sql.prepare("SELECT COUNT(*) n FROM tenant_governance_baselines").get().n, 2);
});

test("settlement is idempotent; conflicting amounts cannot replace settled cost", async t => {
  const { call } = database(t);
  await call(reserve("one")); await call(settle("one"));
  assert.equal((await call(settle("one"))).status, 200);
  assert.equal((await call(settle("one", { cost: 200_000 }))).status, 409);
});

test("native lifecycle uses injected verified tenant, intersection and atomic quotas", async t => {
  const { env, call } = database(t);
  await call(put(null, { daily: 500_000, models: ["openai:*"] }));
  const hooks = createGovernanceLifecycle(env, { call: async body => call(body),
    tenant_resolver: async () => new TenantContext(context) });
  await hooks.admit({ user: { id: "alice" }, model: "openai:gpt", key_allowed: true, amount: 400_000,
    key_daily: 1_000_000, base_day: 0, base_month: 0 });
  await hooks.before_dispatch();
  await hooks.finalize({ usage: { selected_model: "openai:actual", cost_micro_usd: 100_000, cost_basis: "usage" } });
  assert.equal((await call({ operation: "usage", context, role: "member" })).spent_micro_usd, 100_000);
  const denied = createGovernanceLifecycle(env, { call: async body => call(body), tenant_resolver: async () => new TenantContext(context) });
  await assert.rejects(denied.admit({ model: "other:gpt", key_allowed: true }), /model_not_allowed/);
});

test("disabled and legacy native lifecycle do not call storage", async () => {
  for (const flag of ["", "true"]) {
    const hooks = createGovernanceLifecycle({ TENANT_GOVERNANCE_ENABLED: flag }, {
      call: () => assert.fail("legacy storage"), tenant_resolver: async () => new TenantContext({ principal_id: "alice" }),
    });
    await hooks.admit({}); await hooks.before_dispatch(); await hooks.finalize({});
  }
});

test("native flat cache events release holds and ancestor errors retain the level", async t => {
  const { env, call } = database(t);
  await call(put(null, { daily: 500_000 }));
  const create = () => createGovernanceLifecycle(env, { call, tenant_resolver: async () => new TenantContext(context) });
  const cached = create();
  await cached.admit({ model: "openai:gpt", key_allowed: true, amount: 400_000 });
  await cached.finalize({ cost_basis: "cache", selected_model: "openai:gpt", handedOff: false });
  assert.equal((await call({ operation: "usage", context, role: "member" })).holds_micro_usd, 0);
  const held = create();
  await held.admit({ model: "openai:gpt", key_allowed: true, amount: 400_000 });
  await held.before_dispatch();
  await held.finalize({ cost_basis: "usage", cost_micro_usd: 100_000, selected_model: "openai:actual", handedOff: true });
  assert.equal((await call({ operation: "usage", context, role: "member" })).spent_micro_usd, 100_000);
  await assert.rejects(create().admit({ model: "openai:gpt", key_allowed: true, amount: 500_000 }),
    error => error.status === 429 && error.details.level === "organisation");
});


test("shared reconciliation vectors keep unknown holds and settle once", async t => {
  const { call } = database(t);
  const id = "tg_reconciliation";
  await call(reserve("reconciliation"));
  await call({ operation: "dispatch", id });
  await call({ operation: "settle", id, cost: null });
  const vectors = JSON.parse(readFileSync(new URL("./fixtures/governance_reconciliation.json", import.meta.url), "utf8"));
  for (const vector of vectors) {
    const values = Object.fromEntries(Object.entries(vector).filter(([key]) => !key.startsWith("expected_") && !["error", "status"].includes(key)));
    const result = await call({ operation: "reconcile", id, ...values });
    if (vector.error) { assert.equal(result.status, vector.status); assert.equal(result.error.code, vector.error); }
    else {
      assert.equal(result.status, 200); assert.equal(result.applied, vector.expected_applied);
      assert.equal(result.reservation.state, vector.expected_state);
      const totals = await call({ operation: "usage", context, role: "admin" });
      assert.equal(totals.holds_micro_usd, vector.cost === null ? 400000 : 0);
      assert.equal(totals.spent_micro_usd, vector.cost === null ? 0 : 100000);
    }
  }
});
