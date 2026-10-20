import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { spawnSync } from "node:child_process";
import { handleReservationsRequest, createReservationLifecycle } from "../worker/reservations-d1.mjs";

const MIGRATION = "0020_usage_reservations.sql";
const PYTHON = process.env.PYTHON || (existsSync(".venv/bin/python") ? ".venv/bin/python" : "python3");
const NOW = Date.UTC(2026, 9, 9);
const id = n => n.toString(16).padStart(32, "0");
// A local SQLite-backed D1 contract fake exercises the actual SQL without workerd.
function database(t, schema = true) {
  const sql = new DatabaseSync(":memory:");
  t.after(() => sql.close());
  if (schema) sql.exec(readFileSync(new URL(`../intelligence-migrations/${MIGRATION}`, import.meta.url), "utf8"));
  const db = { prepare(query) {
    let values = [];
    const statement = { bind(...args) { values = args; return statement; },
      run() { const result = sql.prepare(query).run(...values); return { success: true, meta: { changes: Number(result.changes) } }; },
      all() {
        const prepared = sql.prepare(query);
        if (!prepared.columns().length) {
          const result = prepared.run(...values);
          return { success: true, results: [], meta: { changes: Number(result.changes) } };
        }
        return { success: true, results: prepared.all(...values), meta: { changes: 0 } };
      },
      first() { return sql.prepare(query).get(...values) ?? null; } };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try {
      const results = statements.map(s => s.all());
      sql.exec("COMMIT");
      return results;
    } catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const env = { USAGE_RESERVATIONS_ENABLED: "true", INTELLIGENCE_DB: db };
  const call = async body => {
    const response = await handleReservationsRequest(new Request("http://intelligence.internal/v1/reservations", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
    }), env, { now: () => NOW });
    return { status: response.status, ...await response.json() };
  };
  return { call, db, env, sql };
}
const reserve = (n = 1, changes = {}) => ({ operation: "reserve", id: id(n), principal: "alice", estimate_usd: 0.6,
  daily_budget_usd: 1, monthly_budget_usd: 5, day_spent_usd: 0, month_spent_usd: 0, ...changes });
const transition = (state, revision, n, changes = {}) => ({ operation: "transition", id: id(1), revision,
  state, transition_id: id(n), ...changes });

test("unknown handoff holds survive review expiry; unknown fields remain null", async t => {
  const { call } = database(t);
  assert.equal((await call(reserve())).status, 200);
  assert.equal((await call(transition("dispatched", 0, 2))).status, 200);
  assert.equal((await call(transition("unknown", 1, 3, { input_tokens: 0 }))).status, 200);
  const row = (await call({ operation: "get", id: id(1) })).reservation;
  assert.equal(row.input_tokens, 0);
  assert.equal(row.output_tokens, null);
  assert.equal((await call(reserve(4, { estimate_usd: 0.5 }))).status, 429);
  const summary = (await call({ operation: "summary", principal: "alice" })).summary;
  assert.equal(summary.held_usd, 0.6);
});

test("pre-dispatch release, idempotent measured settlement and CAS reconciliation", async t => {
  const { call } = database(t);
  await call(reserve());
  await call(transition("dispatched", 0, 2));
  const measured = transition("settled", 1, 3, { cost_usd: 0.2, basis: "provider", settlement_id: id(4), input_tokens: 100, output_tokens: 100 });
  assert.equal((await call(measured)).applied, true);
  assert.equal((await call(measured)).applied, false);
  assert.equal((await call({ ...measured, cost_usd: 0.1 })).status, 409);
  assert.equal((await call({ operation: "summary", principal: "alice" })).summary.spent_today_usd, 0.2);
  await call(reserve(5, { estimate_usd: 0.4 }));
  const release = { ...transition("settled", 0, 6, { cost_usd: 0, basis: "released", settlement_id: id(7) }), id: id(5) };
  assert.equal((await call(release)).status, 200);
  assert.equal((await call({ ...transition("dispatched", 1, 8), id: id(5) })).status, 409);
});

test("reconciliation requires verified admin evidence and one claim wins", async t => {
  const { call } = database(t);
  await call(reserve());
  await call(transition("dispatched", 0, 2));
  await call(transition("unknown", 1, 3));
  const reconciliation = transition("reconciled", 2, 4, { cost_usd: 0.1, basis: "provider", settlement_id: id(5),
    admin: true, evidence: "receipt_1", reason: "provider_receipt" });
  assert.equal((await call({ ...reconciliation, admin: false })).status, 403);
  assert.equal((await call({ ...reconciliation, evidence: null })).status, 400);
  const results = await Promise.all([call(reconciliation), call({ ...reconciliation, transition_id: id(6), settlement_id: id(7) })]);
  assert.equal(results.filter(r => r.applied).length, 1);
  assert.equal(results.filter(r => r.status === 409).length, 1);
});

test("off and invalid settings do not touch D1; missing table fails with a bounded 503", async t => {
  const { call, env } = database(t, false);
  assert.equal((await call(reserve())).status, 503);
  for (const flag of [undefined, "", "false", "invalid"]) {
    const response = await handleReservationsRequest(new Request("http://intelligence.internal/v1/reservations", { method: "POST" }),
      { USAGE_RESERVATIONS_ENABLED: flag, INTELLIGENCE_DB: { prepare() { assert.fail("disabled storage"); } } });
    assert.equal(response.status, 404);
  }
  const hook = createReservationLifecycle(env, { call: () => assert.fail("disabled hook"), identity: () => assert.fail("disabled identity") });
  env.USAGE_RESERVATIONS_ENABLED = "false";
  await hook.admit({}); await hook.before_dispatch({}); await hook.finalize({});
});

test("private RPC rejects content, malformed money and unpriced bounded admissions", async t => {
  const { call, env } = database(t);
  for (const changes of [{ prompt: "secret" }, { estimate_usd: -1 }, { daily_budget_usd: null, monthly_budget_usd: null }]) {
    assert.equal((await call(reserve(1, changes))).status, 400);
  }
  assert.equal((await call(reserve(1, { estimate_usd: null }))).error.code, "unpriced_reservation");
  assert.equal((await call(reserve(1, { estimate_usd: 2 }))).status, 429);
  const response = await handleReservationsRequest(new Request("https://example.test/v1/reservations", { method: "POST" }), env);
  assert.equal(response.status, 404);
});


test("review threshold never changes held money or history and baselines seed once", async t => {
  const { call, db } = database(t);
  await call(reserve(1, { day_spent_usd: 0.1, month_spent_usd: 0.3 }));
  await call(transition("dispatched", 0, 2));
  await call(transition("unknown", 1, 3));
  const { reservationSummary } = await import("../worker/reservations-d1.mjs");
  const later = await reservationSummary(db, "alice", NOW + 40 * 86400_000, 259200);
  assert.equal(later.held_usd, 0.6);
  assert.equal(later.needs_review, 1);
  assert.equal((await call({ operation: "audit", id: id(1) })).transitions.length, 3);
  assert.equal((await call(reserve(4, { estimate_usd: 0.3, day_spent_usd: 0.9 }))).status, 200);
  assert.equal((await call({ operation: "summary", principal: "alice" })).summary.spent_today_usd, 0.1);
});

test("native request lifecycle owns admission, handoff, settlement and no pre-dispatch charge", async t => {
  const { call, env } = database(t);
  const hooks = createReservationLifecycle(env, { call, identity: () => {
    const { operation, id: ignored, ...values } = reserve();
    return values;
  } });
  await hooks.admit({});
  await hooks.before_dispatch({});
  await hooks.finalize({ usage: { cost_usd: 0.2, cost_basis: "usage", input_tokens: 100, output_tokens: 100 } });
  await hooks.finalize({ usage: { cost_usd: 0.2, cost_basis: "usage" } });
  assert.equal((await call({ operation: "summary", principal: "alice" })).summary.spent_today_usd, 0.2);
  const release = createReservationLifecycle(env, { call, identity: () => {
    const { operation, id: ignored, ...values } = reserve(2, { estimate_usd: 0.4 });
    return values;
  } });
  await release.admit({});
  await release.finalize({ outcome: "canceled" });
  assert.equal((await call({ operation: "summary", principal: "alice" })).summary.held_usd, 0);
});

test("native cancellation discards apparent usage and retains the estimate exactly once", async t => {
  const { call, env } = database(t);
  const hooks = createReservationLifecycle(env, { call, identity: () => {
    const { operation, id: ignored, ...values } = reserve();
    return values;
  } });
  await hooks.admit({}); await hooks.before_dispatch({});
  const event = { cancellationOutcome: { ambiguous: true }, usage: { cost_usd: 0, cost_basis: "usage", input_tokens: 0, output_tokens: 0 } };
  await hooks.finalize(event); await hooks.finalize(event);
  const summary = (await call({ operation: "summary", principal: "alice" })).summary;
  assert.equal(summary.held_usd, 0.6); assert.equal(summary.unknown, 1);
});

test("claim identifier collisions cannot commit an unaudited terminal update", async t => {
  const { call } = database(t);
  await call(reserve(1, { estimate_usd: 0.3 }));
  await call(reserve(4, { estimate_usd: 0.3 }));
  await call(transition("dispatched", 0, 2));
  await call({ ...transition("dispatched", 0, 5), id: id(4) });
  const first = transition("settled", 1, 6, { cost_usd: 0.1, basis: "provider", settlement_id: id(7) });
  const second = { ...first, id: id(4), settlement_id: id(8) };
  const results = await Promise.all([call(first), call(second)]);
  assert.equal(results.filter(result => result.status === 200).length, 1);
  assert.equal(results.filter(result => result.status === 409).length, 1);
  const rows = [(await call({ operation: "get", id: id(1) })).reservation, (await call({ operation: "get", id: id(4) })).reservation];
  assert.equal(rows.filter(row => row.state === "settled").length, 1);
});


test("SQLite and the D1 contract return identical reservation and summary shapes", async t => {
  const { call } = database(t);
  await call(reserve());
  await call(transition("dispatched", 0, 2));
  await call(transition("unknown", 1, 3, { input_tokens: 0 }));
  const observed = [(await call({ operation: "get", id: id(1) })).reservation,
    (await call({ operation: "summary", principal: "alice" })).summary];
  const code = `import os,sys,json,tempfile
from pathlib import Path
from datetime import datetime,timezone
sys.path.insert(0,os.getcwd())
from services.reservation_store import SqlReservationStore
with tempfile.TemporaryDirectory() as directory:
 store=SqlReservationStore(Path(directory)/'usage.sqlite3')
 now=datetime(2026,10,9,tzinfo=timezone.utc)
 identity='${id(1)}'
 store.reserve(identity,'alice',0.6,1,5,0,0,now)
 store.transition(identity,0,'dispatched',transition_id='${id(2)}',now=now)
 store.transition(identity,1,'unknown',transition_id='${id(3)}',input_tokens=0,now=now)
 print(json.dumps([store.get(identity),store.summary('alice',now)]))`;
  const python = spawnSync(PYTHON, ["-I", "-c", code], {
    cwd: new URL("..", import.meta.url), encoding: "utf8", timeout: 10000,
  });
  assert.equal(python.status, 0, python.stderr);
  assert.deepEqual(observed, JSON.parse(python.stdout));
});

test("registered native dispatch preserves response bytes and completes the injected hold", async t => {
  const { call, env } = database(t);
  env.MODEL_PRICING_USD_PER_MILLION = JSON.stringify({ "openai:test": { input: 1000, output: 1000 } });
  const hooks = createReservationLifecycle(env, { call, identity: () => {
    const { operation, id: ignored, ...values } = reserve();
    return values;
  } });
  const { nativeGenerationFetch } = await import("../worker/gateway-extensions.mjs");
  const body = '{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20}}';
  const response = await nativeGenerationFetch(new Request("http://localhost/openai/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model: "test" }),
  }), env, {}, { route: "/openai/v1/chat/completions", provider: "openai", principal: { id: "admin" } },
  async () => new Response(body, { headers: { "content-type": "application/json" } }), [hooks]);
  assert.equal(await response.text(), body);
  const summary = (await call({ operation: "summary", principal: "alice" })).summary;
  assert.equal(summary.spent_today_usd, 0.03); assert.equal(summary.held_usd, 0);
});

test("enabled hook failures expose a JSON 503 and prohibit provider dispatch", async t => {
  const { call, env } = database(t, false);
  const hooks = createReservationLifecycle(env, { call, identity: () => {
    const { operation, id: ignored, ...values } = reserve();
    return values;
  } });
  try { await hooks.admit({}); assert.fail("missing schema admitted"); }
  catch (error) {
    assert.equal(error.status, 503);
    assert.equal((await error.response().json()).error.code, "usage_reservations_unavailable");
  }
});


test("fractional budgets never round admission above the configured cap", async t => {
  const { call } = database(t);
  assert.equal((await call(reserve(1, { estimate_usd: 1e-11, daily_budget_usd: 1e-11, monthly_budget_usd: null }))).status, 429);
  assert.equal((await call({ operation: "summary", principal: "alice" })).summary.held_usd, 0);
});
