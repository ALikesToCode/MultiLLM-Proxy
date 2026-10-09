import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleBatchRequest, runScheduledBatches, shouldForwardBatchSpillover, containerBatchDispatch } from "../worker/batch-jobs.mjs";

const NOW = 1800000000;
const item = n => ({ custom_id: `item-${n}`, method: "POST", url: "/v1/chat/completions",
  body: { model: "openai:test", messages: [{ role: "user", content: "hello" }], max_tokens: 10 } });
const envelope = { choices: [{ message: { content: "hi" }, finish_reason: "stop" }], usage: { prompt_tokens: 2, completion_tokens: 2 } };
function database(t, schema = true) {
  const sql = new DatabaseSync(":memory:");
  t.after(() => sql.close());
  if (schema) sql.exec(readFileSync(new URL("../intelligence-migrations/0027_gateway_batches.sql", import.meta.url), "utf8"));
  const db = { prepare(query) {
    let values = [];
    const stmt = { bind(...args) { values = args; return stmt; },
      run() { const r = sql.prepare(query).run(...values); return { meta: { changes: Number(r.changes) } }; },
      first() { return sql.prepare(query).get(...values) ?? null; },
      all() { return { results: sql.prepare(query).all(...values) }; } };
    return stmt;
  }, async batch(statements) {
    sql.exec("BEGIN");
    try { const r = statements.map(s => s.run()); sql.exec("COMMIT"); return r; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const objects = new Map();
  const bucket = {
    async put(key, value) { objects.set(key, typeof value === "string" ? value : new TextDecoder().decode(value)); },
    async get(key) { const value = objects.get(key); return value === undefined ? null : { text: async () => value, arrayBuffer: async () => new TextEncoder().encode(value).buffer }; },
    async delete(key) { objects.delete(key); },
  };
  const env = { GATEWAY_BATCHES_ENABLED: "true", INTELLIGENCE_DB: db, multillm_media: bucket };
  const call = async (operation, fields = {}) => {
    const response = await handleBatchRequest(new Request("http://intelligence.internal/v1/gateway-batches", {
      method: "POST", body: JSON.stringify({ version: 1, operation, owner: "alice", ...fields }), headers: { "content-type": "application/json" },
    }), env, { now: () => NOW });
    return { status: response.status, ...await response.json() };
  };
  const create = async (count = 3, budget = 10000000000) => {
    const items = Array.from({ length: count }, (_, n) => item(n));
    const uploaded = await call("file_create", { filename: "input.jsonl", content: Buffer.from(items.map(v => JSON.stringify(v)).join("\n")).toString("base64") });
    assert.equal(uploaded.status, 200);
    const made = await call("batch_create", { input_file_id: uploaded.file.id, endpoint: "/v1/chat/completions",
      completion_window: "24h", metadata: { multillm_budget_usd: "1" }, budget_units: budget,
      principal: "signed-principal", client_ip: "127.0.0.1", key_hash: "", key_prefix: "",
      estimates: items.map(v => ({ custom_id: v.custom_id, estimate_units: 2000000000 })) });
    assert.equal(made.status, 200);
    return made.batch;
  };
  return { call, create, env, sql, objects };
}
const dispatch = async () => ({ status_code: 200, body: envelope, cost_units: 1000000000, ambiguous: false });
const options = extra => ({ now: () => NOW, clock: () => 0, dispatch, ...extra });

test("off and malformed flags never touch storage or submit a request", async () => {
  for (const value of [undefined, "", "false", "garbage"]) {
    const env = { GATEWAY_BATCHES_ENABLED: value, INTELLIGENCE_DB: { prepare() { assert.fail("disabled storage"); } } };
    assert.equal((await handleBatchRequest(new Request("http://intelligence.internal/v1/gateway-batches", { method: "POST" }), env)).status, 404);
    assert.deepEqual(await runScheduledBatches(env, null), { claimed: 0 });
  }
});

test("missing schema fails closed and enabled storage never calls a provider", async t => {
  const { call, env } = database(t, false);
  assert.equal((await call("file_list")).status, 503);
  assert.equal((await call("batch_list")).error.code, "gateway_batches_unavailable");
  await assert.rejects(runScheduledBatches(env, null, options({ dispatch: () => assert.fail("provider call") })));
});

test("file shapes, content, foreign-owner privacy and input deletion protection", async t => {
  const { call, create } = database(t);
  const batch = await create(1);
  const id = batch.input_file_id;
  const file = (await call("file_get", { id })).file;
  assert.equal(file.object, "file"); assert.equal(file.purpose, "batch");
  assert.equal((await call("file_get", { id, owner: "bob" })).status, 404);
  assert.equal((await call("file_content", { id, owner: "bob" })).status, 404);
  assert.equal((await call("file_delete", { id, owner: "bob" })).status, 404);
  assert.equal((await call("batch_get", { id: batch.id, owner: "bob" })).status, 404);
  assert.equal((await call("batch_cancel", { id: batch.id, owner: "bob" })).status, 404);
  assert.equal((await call("file_delete", { id })).status, 409);
  assert.equal((await call("file_list", { owner: "bob" })).data.length, 0);
});

test("private uploads reject invalid and duplicate items before R2", async t => {
  const { call, objects } = database(t);
  for (const text of ["{}", JSON.stringify(item(0)) + "\n" + JSON.stringify(item(0)), "not-json", "\n"]) {
    assert.equal((await call("file_create", { filename: "input.jsonl", content: Buffer.from(text).toString("base64") })).status, 400);
  }
  assert.equal(objects.size, 0);
});

test("two-item continuation records complete JSONL by custom_id", async t => {
  const { call, create, env } = database(t);
  const batch = await create();
  assert.equal(batch.status, "validating");
  assert.equal((await runScheduledBatches(env, null, options())).claimed, 2);
  assert.equal((await call("batch_get", { id: batch.id })).batch.status, "in_progress");
  assert.equal((await runScheduledBatches(env, null, options())).claimed, 1);
  const completed = (await call("batch_get", { id: batch.id })).batch;
  assert.equal(completed.status, "completed");
  assert.deepEqual(completed.request_counts, { total: 3, completed: 3, failed: 0 });
  const output = Buffer.from((await call("file_content", { id: completed.output_file_id })).content, "base64").toString();
  assert.deepEqual(output.trim().split("\n").map(s => JSON.parse(s).custom_id), ["item-0", "item-1", "item-2"]);
});

test("concurrent schedules claim each item once with atomic budget holds", async t => {
  const { create, env, sql } = database(t);
  await create(4);
  const seen = [];
  await Promise.all([1, 2].map(() => runScheduledBatches(env, null, options({ dispatch: async item => { seen.push(item.custom_id); await Promise.resolve(); return dispatch(); } }))));
  assert.equal(new Set(seen).size, seen.length);
  assert.equal(seen.length, 4);
  assert.equal(sql.prepare("SELECT SUM(held_units) AS n FROM gateway_batch_items").get().n, 0);
});

test("ambiguous transport is never retried and holds exhaust remaining work", async t => {
  const { call, create, env, sql } = database(t);
  const batch = await create(3, 2000000000);
  let calls = 0;
  await runScheduledBatches(env, null, options({ dispatch: async () => { calls++; throw Error("transport lost"); } }));
  await runScheduledBatches(env, null, options({ dispatch: () => assert.fail("retry") }));
  assert.equal(calls, 1);
  assert.equal(sql.prepare("SELECT SUM(held_units) AS n FROM gateway_batch_items").get().n, 2000000000);
  const row = (await call("batch_get", { id: batch.id })).batch;
  const errors = Buffer.from((await call("file_content", { id: row.error_file_id })).content, "base64").toString();
  assert.match(errors, /outcome_unknown/); assert.match(errors, /budget_exhausted/);
});

test("expired leases fail unknown without redispatch", async t => {
  const { create, env, sql } = database(t);
  const b = await create(1);
  sql.prepare("UPDATE gateway_batch_items SET status='dispatched', lease_until=?, held_units=estimate_units WHERE batch_id=?").run(NOW - 1, b.id);
  await runScheduledBatches(env, null, options({ dispatch: () => assert.fail("retry") }));
  assert.equal(sql.prepare("SELECT error_code FROM gateway_batch_items").get().error_code, "outcome_unknown");
});

test("cancel race permits the already dispatched item and stops new ones", async t => {
  const { call, create, env } = database(t);
  const b = await create(3);
  let calls = 0;
  await runScheduledBatches(env, null, options({ dispatch: async () => { calls++; const cancelled = await call("batch_cancel", { id: b.id }); assert.equal(cancelled.batch.status, "cancelling"); return dispatch(); } }));
  const result = (await call("batch_get", { id: b.id })).batch;
  assert.equal(calls, 1); assert.equal(result.status, "cancelled");
  assert.equal(result.request_counts.completed, 1);
});

test("24-hour expiry preserves holds and prevents new work", async t => {
  const { call, create, env, sql } = database(t);
  const b = await create(2);
  await runScheduledBatches(env, null, options({ now: () => NOW + 86400, dispatch: () => assert.fail("expired dispatch") }));
  assert.equal((await call("batch_get", { id: b.id })).batch.status, "expired");
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM gateway_batch_items WHERE error_code='expired'").get().n, 2);
});

test("scheduler time budget starts no item without a full deadline", async t => {
  const { create, env } = database(t);
  await create(1);
  let clock = 0;
  const r = await runScheduledBatches(env, null, options({ clock: () => (clock += 40000), dispatch: () => assert.fail("time budget") }));
  assert.equal(r.claimed, 0);
});

test("spillover requires both flags and both headers on the managed route", () => {
  const request = headers => new Request("https://gateway.test/v1/chat/completions", { method: "POST", headers });
  const env = { GATEWAY_BATCHES_ENABLED: "true", BATCH_SPILLOVER_ENABLED: "true" };
  const headers = { "X-MultiLLM-Priority": "batch", Prefer: "respond-async" };
  assert.equal(shouldForwardBatchSpillover(request(headers), env), true);
  assert.equal(shouldForwardBatchSpillover(request({ Prefer: "respond-async" }), env), false);
  assert.equal(shouldForwardBatchSpillover(request(headers), { ...env, BATCH_SPILLOVER_ENABLED: "false" }), false);
});


test("a durable item capability starts once and cannot replay canonical content", async t => {
  const { call, create, env } = database(t);
  const b = await create(1);
  await runScheduledBatches(env, null, options({ dispatch: async item => {
    const fields = { id: b.id, idx: item.idx, lease_token: item.lease_token };
    assert.equal((await call("item_start", { ...fields, owner: "bob" })).status, 404);
    assert.equal((await call("item_start", { ...fields, lease_token: "wrong" })).status, 409);
    const started = await call("item_start", fields);
    assert.equal(started.status, 200);
    assert.equal(started.item.custom_id, "item-0");
    assert.equal(started.item.estimate_units, 2000000000);
    assert.equal((await call("item_start", fields)).status, 409);
    return dispatch();
  } }));
  assert.equal((await call("batch_get", { id: b.id })).batch.status, "completed");
});

test("Container transport sends only signed identity and a durable claim", async () => {
  const signal = new AbortController().signal;
  const result = await containerBatchDispatch({ idx: 2, lease_token: "lease-test", body: { messages: ["private"] } },
    { id: "batch-test", principal: "synthetic-capability" }, { async fetch(request) {
      assert.equal(new URL(request.url).pathname, "/internal/gateway/batch-item");
      assert.equal(request.headers.get("authorization"), "BatchPrincipal synthetic-capability");
      assert.deepEqual(await request.json(), { batch_id: "batch-test", idx: 2, lease_token: "lease-test" });
      return Response.json(await dispatch());
    } }, signal);
  assert.deepEqual(result, await dispatch());
  await assert.rejects(containerBatchDispatch({}, {}, { fetch: async () => Response.json({ choices: [] }) }, signal));
});

test("result storage loss retains the claim and unknown hold without resubmission", async t => {
  const { create, env, sql } = database(t);
  await create(1);
  const put = env.multillm_media.put;
  env.multillm_media.put = async key => { if (key.includes("/results/")) throw Error("storage unavailable"); };
  await assert.rejects(runScheduledBatches(env, null, options()));
  env.multillm_media.put = put;
  await runScheduledBatches(env, null, options({ now: () => NOW + 41, dispatch: () => assert.fail("resubmission") }));
  const stored = sql.prepare("SELECT * FROM gateway_batch_items").get();
  assert.equal(stored.error_code, "outcome_unknown");
  assert.equal(stored.held_units, 2000000000);
});

test("finalization resumes from an immutable checkpoint without duplicating custom ids", async t => {
  const { create, call, env, sql } = database(t);
  const b = await create(2);
  sql.prepare("UPDATE gateway_batch_items SET status='failed',error_code='cancelled'").run();
  let clockCalls = 0;
  await runScheduledBatches(env, null, options({ clock: () => ++clockCalls <= 4 ? 0 : 70000 }));
  const checkpoint = sql.prepare("SELECT checkpoint FROM gateway_batches").get().checkpoint;
  assert.ok(checkpoint);
  await runScheduledBatches(env, null, options());
  const completed = (await call("batch_get", { id: b.id })).batch;
  const text = Buffer.from((await call("file_content", { id: completed.error_file_id })).content, "base64").toString();
  assert.deepEqual(text.trim().split("\n").map(x => JSON.parse(x).custom_id), ["item-0", "item-1"]);
});

test("terminal files remain owned and the released input can be deleted", async t => {
  const { create, call, env } = database(t);
  const b = await create(1);
  await runScheduledBatches(env, null, options());
  const completed = (await call("batch_get", { id: b.id })).batch;
  assert.equal((await call("file_content", { id: completed.output_file_id, owner: "bob" })).status, 404);
  assert.equal((await call("file_delete", { id: b.input_file_id })).deleted, true);
  assert.equal((await call("file_get", { id: b.input_file_id })).status, 404);
});

test("migration is additive and repeatable around existing database rows", t => {
  const { sql } = database(t, false);
  sql.exec("CREATE TABLE existing_rows (value TEXT); INSERT INTO existing_rows VALUES ('preserved');");
  const migration = readFileSync(new URL("../intelligence-migrations/0027_gateway_batches.sql", import.meta.url), "utf8");
  sql.exec(migration); sql.exec(migration);
  assert.equal(sql.prepare("SELECT value FROM existing_rows").get().value, "preserved");
});

test("Worker outbound registration reaches the private handler with schema failures", async t => {
  const { loadWorkerModule } = await import("./helpers/load_cloudflare_worker.mjs");
  const worker = await loadWorkerModule({ transformSource: source => source.replace('from "./worker/batch-jobs.mjs";',
    `from "${new URL("../worker/batch-jobs.mjs", import.meta.url)}";`) });
  const { env } = database(t, false);
  const request = new Request("http://intelligence.internal/v1/gateway-batches", { method: "POST", body: JSON.stringify({ version: 1, owner: "alice", operation: "batch_list" }) });
  const response = await worker.MultiLLMProxyContainer.outboundByHost["intelligence.internal"](request, env);
  assert.equal(response.status, 503);
  assert.match((await response.json()).error.message, /migration/);
});


test("aggregate result caps preserve a compact error for every custom id across recovery", async t => {
  const { create, call, env, sql, objects } = database(t);
  const b = await create(20);
  for (let idx = 0; idx < 20; idx++) {
    const key = `batches/results/${b.id}/${idx}/test`;
    const result = JSON.stringify({ custom_id: `item-${idx}`, response: { body: { text: "x".repeat(1024 * 1024 - 200) } }, error: null }) + "\n";
    objects.set(key, result);
    sql.prepare("UPDATE gateway_batch_items SET status='completed',result_key=? WHERE batch_id=? AND idx=?").run(key, b.id, idx);
  }
  // Interrupt after the overflow statuses change; rebuilding must keep errors real.
  const put = env.multillm_media.put;
  env.multillm_media.put = async () => { throw Error("final output unavailable"); };
  await assert.rejects(runScheduledBatches(env, null, options()));
  env.multillm_media.put = put;
  await runScheduledBatches(env, null, options({ now: () => NOW + 91 }));
  const completed = (await call("batch_get", { id: b.id })).batch;
  const output = Buffer.from((await call("file_content", { id: completed.output_file_id })).content, "base64");
  const errors = Buffer.from((await call("file_content", { id: completed.error_file_id })).content, "base64");
  assert.ok(output.length <= 16 * 1024 * 1024);
  assert.ok(errors.length <= 16 * 1024 * 1024);
  const rows = (output.toString() + errors.toString()).trim().split("\n").map(x => JSON.parse(x));
  assert.equal(new Set(rows.map(x => x.custom_id)).size, 20);
  assert.equal(rows.filter(x => x.error?.code === "output_file_too_large").length, 4);
  assert.equal(completed.request_counts.failed, 4);
});


test("the thirty-second item deadline aborts transport and never retries the unknown outcome", async t => {
  const { create, call, env, sql } = database(t);
  const b = await create(1);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let started, signal;
  const submitted = new Promise(resolve => { started = resolve; });
  const running = runScheduledBatches(env, null, options({ dispatch: (_item, _batch, _container, abort) => {
    signal = abort;
    started();
    return new Promise(() => {});
  } }));
  await submitted;
  t.mock.timers.tick(30000);
  assert.equal((await running).claimed, 1);
  assert.equal(signal.aborted, true);
  await runScheduledBatches(env, null, options({ dispatch: () => assert.fail("deadline resubmission") }));
  const result = sql.prepare("SELECT error_code,held_units FROM gateway_batch_items").get();
  assert.equal(result.error_code, "outcome_unknown");
  assert.equal(result.held_units, 2000000000);
  assert.equal((await call("batch_get", { id: b.id })).batch.request_counts.failed, 1);
});
