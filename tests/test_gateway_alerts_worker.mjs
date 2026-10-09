import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { handleAlertState, runAlertDelivery, alertSettings, validateDestination, normalizeAlertRules } from "../worker/alert-delivery.mjs";

const MIGRATION = "0022_gateway_alerts.sql";
const destination = "https://hooks.example/private-recipient";
const envBase = { GATEWAY_ALERTS_ENABLED: "true", GATEWAY_ALERT_WEBHOOK_ALLOWLIST: '["https://hooks.example"]' };
const rules = [{ kind: "spend", period: "day", budget_usd: 10 },
  { kind: "unknown_price", period: "day" }, { kind: "provider_circuit", provider: "openai" },
  { kind: "pool_exhaustion", provider: "openai" }, { kind: "provider_health", provider: "openai" }];
// Exercise the production SQL against SQLite without starting a network-capable runtime.
function database(t, migrate = true) {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  function execute(statements, script = null) {
    if (script) sqlite.exec(script);
    sqlite.exec("BEGIN");
    try {
      const results = statements.map(statement => {
        const prepared = sqlite.prepare(statement.sql);
        const rows = prepared.columns().length ? prepared.all(...statement.values) : (prepared.run(...statement.values), []);
        return { results: rows, meta: { changes: sqlite.prepare("SELECT changes() AS n").get().n } };
      });
      sqlite.exec("COMMIT");
      return results;
    } catch (error) { sqlite.exec("ROLLBACK"); throw error; }
  }
  const db = { prepare(sql) { return { sql, values: [], bind(...values) { this.values = values; return this; },
    async run() { return execute([this])[0]; }, async all() { return execute([this])[0]; },
    async first() { return execute([this])[0].results[0] ?? null; } }; },
    async batch(statements) { return execute(statements); } };
  execute([], "CREATE TABLE old_rows(value TEXT); INSERT INTO old_rows VALUES ('existing');");
  const migration = readFileSync(new URL(`../intelligence-migrations/${MIGRATION}`, import.meta.url), "utf8");
  if (migrate) { execute([], migration); execute([], migration); }
  return { db, migrate: () => execute([], migration) };
}
async function setup(t) {
  const { db } = database(t);
  const env = { ...envBase, INTELLIGENCE_DB: db };
  const now = [1791504000];
  const call = async body => {
    const response = await handleAlertState(env, { version: 1, ...body }, { clock: () => now[0] });
    return { status: response.status, body: await response.json() };
  };
  const saved = await call({ operation: "configure", revision: 0, configuration: { destination, rules } });
  assert.equal(saved.status, 200);
  return { db, env, now, call, rules: saved.body.rules };
}
const observation = (rule, value, window = "2026-10-09") => ({ rule_id: rule.id, value, window,
  basis: rule.kind === "spend" ? "gateway_cost_estimate" : rule.kind === "unknown_price" ? "unknown_price_coverage" : "observed_health" });


test("disabled and empty allowlist never read state, collect or transport", async () => {
  for (const flag of [undefined, "", "false", "invalid"]) {
    const response = await handleAlertState({ GATEWAY_ALERTS_ENABLED: flag }, { operation: "get" });
    assert.equal(response.status, 404);
  }
  for (const allowlist of ["", "[]", "invalid"]) {
    const result = await runAlertDelivery({ ...envBase, GATEWAY_ALERT_WEBHOOK_ALLOWLIST: allowlist }, {
      collect() { throw Error("collector touched"); }, transport() { throw Error("transport touched"); },
    });
    assert.deepEqual(result, { attempted: 0, delivered: 0, failed: 0 });
  }
});


test("strict destinations reject SSRF and redirects before transport", () => {
  const settings = alertSettings(envBase);
  for (const value of ["http://hooks.example", "https://evil.example", "https://localhost", "https://127.0.0.1",
    "https://169.254.169.254", "https://[::1]", "https://hooks.example@evil.example", "https://hooks.example/?secret=1",
    "https://hooks.example/#x", "https://hooks.example\\@evil.example", "https://hooks.example/\nprivate"]) {
    assert.throws(() => validateDestination(value, settings.allowlist));
  }
  assert.equal(validateDestination(destination, settings.allowlist), destination);
});


test("configuration CAS defaults, bounded private status and additive migration", async t => {
  const { db, call, rules: saved } = await setup(t);
  assert.deepEqual(saved[0].thresholds, [85, 100]);
  assert.equal((await call({ operation: "configure", revision: 0, configuration: { destination, rules } })).status, 409);
  assert.equal((await db.prepare("SELECT value FROM old_rows").first()).value, "existing");
  const status = (await call({ operation: "get" })).body;
  assert.equal(status.webhook_configured, true);
  assert.equal(JSON.stringify(status).includes("private-recipient"), false);
  assert.deepEqual(status.events, []);
});


test("missing tables and private driver failures return sanitized 503", async t => {
  const { db, migrate } = database(t, false);
  for (const operation of ["get", "configure", "observe"]) {
    const response = await handleAlertState({ ...envBase, INTELLIGENCE_DB: db }, {
      version: 1, operation, revision: 0, configuration: { destination, rules }, observations: [],
    });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error.code, "gateway_alert_storage_unavailable");
  }
  migrate();
  assert.equal((await db.prepare("SELECT value FROM old_rows").first()).value, "existing");
  const response = await handleAlertState({ ...envBase, INTELLIGENCE_DB: { prepare() { throw Error("private-secret"); } } },
    { version: 1, operation: "get" });
  assert.equal(response.status, 503);
  assert.equal((await response.text()).includes("private-secret"), false);
});


test("thresholds dedupe per event, rule and revision for 15 minutes", async t => {
  const { call, rules: saved, now } = await setup(t);
  const observe = value => call({ operation: "observe", revision: 1, observations: [observation(saved[0], value)] });
  assert.equal((await observe(8.49)).body.queued, 0);
  assert.equal((await observe(8.5)).body.queued, 1);
  assert.equal((await observe(9)).body.queued, 0);
  assert.equal((await observe(10)).body.queued, 1);
  now[0] += 899;
  assert.equal((await observe(10)).body.queued, 0);
  now[0] += 1;
  assert.equal((await observe(10)).body.queued, 2);
  assert.equal((await call({ operation: "configure", revision: 1, configuration: { destination, rules } })).status, 200);
  assert.equal((await call({ operation: "observe", revision: 1, observations: [] })).status, 409);
  assert.equal((await call({ operation: "observe", revision: 2, observations: [observation(saved[0], 9)] })).body.queued, 1);
});


test("unknown prices and passive provider health payloads contain no recipient or content", async t => {
  const { call, env, rules: saved, now } = await setup(t);
  const observations = [observation(saved[1], 30), observation(saved[2], 1, "current"),
    observation(saved[3], 1, "current"), observation(saved[4], 3, "current")];
  assert.equal((await call({ operation: "observe", revision: 1, observations })).body.queued, 4);
  const payloads = [];
  const result = await runAlertDelivery(env, { clock: () => now[0], transport: async (url, options) => {
    assert.equal(url, destination);
    assert.equal(options.redirect, "error");
    assert.equal(options.timeoutMs, 3000);
    assert.equal(options.signal instanceof AbortSignal, true);
    assert.ok(new TextEncoder().encode(options.body).length <= 8192);
    payloads.push(JSON.parse(options.body));
    return { status: 204 };
  } });
  assert.equal(result.delivered, 4);
  assert.equal(payloads[0].basis, "unknown_price_coverage");
  assert.equal(payloads.some(row => JSON.stringify(row).includes("private")), false);
  assert.equal((await call({ operation: "get" })).body.events.every(row => row.state === "delivered"), true);
});


test("one scheduled run attempts at most ten events and three attempts total", async t => {
  const { call, env, rules: saved, now } = await setup(t);
  for (let index = 1; index <= 12; index++) {
    await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9, `2026-10-${String(index).padStart(2, "0")}`)] });
  }
  let calls = 0;
  const transport = async () => { calls++; throw Error("private failure"); };
  assert.equal((await runAlertDelivery(env, { clock: () => now[0], transport })).attempted, 10);
  for (let index = 0; index < 4; index++) {
    now[0] += 61;
    await runAlertDelivery(env, { clock: () => now[0], transport });
  }
  assert.equal(calls, 36);
  const status = (await call({ operation: "get" })).body;
  assert.equal(status.events.length, 12);
  assert.equal(status.events.every(row => row.state === "failed" && row.attempts === 3), true);
  assert.equal(JSON.stringify(status).includes("private failure"), false);
  const attempts = (await dbRows(env.INTELLIGENCE_DB)).map(row => JSON.parse(row.attempt_times));
  assert.equal(attempts.every(row => row.length === 3), true);
});
async function dbRows(db) { return (await db.prepare("SELECT attempt_times FROM gateway_alert_events").all()).results; }


test("redirect status is a visible delivery failure without a second destination", async t => {
  const { call, env, rules: saved, now } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  let calls = 0;
  await runAlertDelivery(env, { clock: () => now[0], transport: async () => { calls++; return { status: 302 }; } });
  assert.equal(calls, 1);
  const event = (await call({ operation: "get" })).body.events[0];
  assert.equal(event.state, "pending");
  assert.equal(event.error_code, "delivery_failed");
});


test("hard timeout bounds a transport ignoring abort", async t => {
  const { call, env, rules: saved, now } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  let signal;
  const started = Date.now();
  const result = await runAlertDelivery(env, { clock: () => now[0], transport: (_url, options) => {
    signal = options.signal; return new Promise(() => {});
  } });
  assert.equal(result.attempted, 1);
  assert.ok(Date.now() - started < 4500);
  assert.equal(signal.aborted, true);
  assert.equal((await call({ operation: "get" })).body.events[0].error_code, "delivery_failed");
});


test("concurrent observers and delivery runners claim only once", async t => {
  const { call, env, rules: saved, now } = await setup(t);
  const results = await Promise.all(Array.from({ length: 4 }, () => call({ operation: "observe", revision: 1,
    observations: [observation(saved[0], 9)] })));
  assert.equal(results.reduce((sum, row) => sum + row.body.queued, 0), 1);
  let calls = 0;
  const transport = async () => { calls++; return { status: 204 }; };
  await Promise.all(Array.from({ length: 3 }, () => runAlertDelivery(env, { clock: () => now[0], transport })));
  assert.equal(calls, 1);
});


test("untrusted observations and stored oversized payloads never reach transport", async t => {
  const { call, env, rules: saved, now, db } = await setup(t);
  for (const change of [{ prompt: "private" }, { value: Infinity }, { basis: "actual_invoice" },
    { rule_id: "private-person" }, { window: "private-person" }]) {
    assert.equal((await call({ operation: "observe", revision: 1, observations: [{ ...observation(saved[0], 9), ...change }] })).status, 400);
  }
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  await assert.rejects(db.prepare("UPDATE gateway_alert_events SET payload = ?").bind(JSON.stringify({ prompt: "x".repeat(9000) })).run());
  await db.prepare("UPDATE gateway_alert_events SET payload = ?").bind(JSON.stringify({ prompt: "漢".repeat(3000) })).run();
  let calls = 0;
  const result = await runAlertDelivery(env, { clock: () => now[0], transport: async () => { calls++; return { status: 204 }; } });
  assert.equal(calls, 0);
  assert.equal(result.failed, 1);
});


test("allowlist changes and absent transport do not consume attempts", async t => {
  const { call, env, rules: saved, now } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  assert.equal((await runAlertDelivery(env, { clock: () => now[0] })).attempted, 0);
  const result = await runAlertDelivery({ ...env, GATEWAY_ALERT_WEBHOOK_ALLOWLIST: '["https://other.example"]' }, {
    clock: () => now[0], transport() { throw Error("must not send"); },
  });
  assert.equal(result.attempted, 0);
  assert.equal((await call({ operation: "get" })).body.events[0].attempts, 0);
});


test("fractional configuration has the same canonical rule identity in both runtimes", async () => {
  const [rule] = await normalizeAlertRules([{ kind: "spend", period: "month", budget_usd: 0.000001, thresholds: [0.001, 85.5, 100.0] }]);
  assert.equal(rule.id, "f699ee8b115fb123a1f3f9504e7004a9123d853c7886c9c767c4066f5e648d61");
});


test("scheduled collector is a bounded aggregate collaborator", async t => {
  const { env, rules: saved, now, call } = await setup(t);
  let calls = 0;
  const result = await runAlertDelivery(env, { clock: () => now[0],
    collect: async rules => { assert.deepEqual(rules, saved); return [observation(rules[0], 9)]; },
    transport: async () => { calls++; return { status: 204 }; },
  });
  assert.equal(result.delivered, 1);
  assert.equal(calls, 1);
  const rejected = await runAlertDelivery(env, { clock: () => now[0], collect: async () => [{ prompt: "private-content" }],
    transport: async () => { throw Error("No delivery for invalid observations"); },
  });
  assert.equal(rejected.error, "gateway_alert_observation_unavailable");
  assert.equal((await call({ operation: "get" })).body.events.length, 1);
});


test("expired history is never delivered and physical pruning is bounded", async t => {
  const { env, now, rules: saved, call, db } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  const row = await db.prepare("SELECT * FROM gateway_alert_events").first();
  await db.prepare("UPDATE gateway_alert_events SET created_at = ?, next_attempt_at = ?").bind(now[0] - 8 * 86400, now[0] - 8 * 86400).run();
  await db.prepare(`WITH RECURSIVE nums(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM nums WHERE n < 150)
    INSERT INTO gateway_alert_events(dedupe_key,event_id,rule_id,revision,payload,created_at,state,next_attempt_at)
    SELECT printf('%064x',n), printf('%064x',n), ?, 1, ?, ?, 'pending', ? FROM nums`)
    .bind(row.rule_id, row.payload, now[0] - 8 * 86400, now[0] - 8 * 86400).run();
  let calls = 0;
  const result = await runAlertDelivery(env, { clock: () => now[0], transport: async () => { calls++; return { status: 204 }; } });
  assert.equal(result.attempted, 0);
  assert.equal(calls, 0);
  assert.equal((await db.prepare("SELECT count(*) AS n FROM gateway_alert_events").first()).n, 51);
  assert.equal((await call({ operation: "get" })).body.events.length, 0);
});


test("configuration replacement cancels old waiting deliveries", async t => {
  const { env, now, rules: saved, call } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  assert.equal((await call({ operation: "configure", revision: 1, configuration: { destination, rules: [] } })).status, 200);
  const event = (await call({ operation: "get" })).body.events[0];
  assert.equal(event.state, "failed");
  assert.equal(event.error_code, "rule_replaced");
  assert.equal((await runAlertDelivery(env, { clock: () => now[0], transport() { throw Error("Old delivery must not run"); } })).attempted, 0);
});

test("status rejects malformed stored delivery metadata without exposing private values", async t => {
  const { db, call, rules: saved } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  for (const [column, value] of [["event_id", "private-recipient"], ["error_code", "private-response"],
    ["attempts", 1.5], ["last_attempt_at", "private-recipient"]]) {
    await db.prepare(`UPDATE gateway_alert_events SET ${column} = ?`).bind(value).run();
    const response = await call({ operation: "get" });
    assert.equal(response.status, 503, column);
    assert.equal(response.body.error.code, "gateway_alert_storage_unavailable");
    assert.equal(JSON.stringify(response.body).includes("private"), false);
    await db.prepare(`UPDATE gateway_alert_events SET event_id = ?, error_code = NULL, attempts = 0,
      last_attempt_at = NULL`).bind("a".repeat(64)).run();
  }
});

test("the durable queue cap rejects new distinct events and permits dedupe replacement", async t => {
  const { db, call, now, rules: saved } = await setup(t);
  await call({ operation: "observe", revision: 1, observations: [observation(saved[0], 9)] });
  const row = await db.prepare("SELECT * FROM gateway_alert_events").first();
  await db.prepare(`WITH RECURSIVE nums(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM nums WHERE n < 1999)
    INSERT INTO gateway_alert_events(dedupe_key,event_id,rule_id,revision,payload,created_at,state,next_attempt_at)
    SELECT printf('%064x',n), printf('%064x',n), ?, 1, ?, ?, 'pending', ? FROM nums`)
    .bind(row.rule_id, row.payload, now[0], now[0]).run();
  assert.equal((await call({ operation: "observe", revision: 1,
    observations: [observation(saved[0], 9, "2026-10-10")] })).body.queued, 0);
  now[0] += 900;
  assert.equal((await call({ operation: "observe", revision: 1,
    observations: [observation(saved[0], 9)] })).body.queued, 1);
  assert.equal((await db.prepare("SELECT count(*) AS n FROM gateway_alert_events").first()).n, 2000);
  const status = (await call({ operation: "get" })).body;
  assert.equal(status.events.length, 100);
  assert.ok(new TextEncoder().encode(JSON.stringify(status)).length <= 65536);
});
