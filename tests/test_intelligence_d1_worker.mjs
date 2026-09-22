import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Miniflare } from "miniflare";
import { handleIntelligenceStoreRequest } from "../worker/intelligence-d1.mjs";

const source = await readFile(new URL("../worker/intelligence-d1.mjs", import.meta.url), "utf8");
const migration = await readFile(new URL("../intelligence-migrations/0001_intelligence.sql", import.meta.url), "utf8");
const URL_STORE = "http://intelligence.internal/v1/store";
const id = (value) => value.toString(16).padStart(32, "0");
const policy = (overrides = {}) => ({
  version: 1, enabled: true, max_total_tokens: 1000,
  principal_daily_tokens: 1000, global_daily_tokens: 2000, max_inflight: 100,
  media: Object.fromEntries(["speech", "transcriptions", "embeddings"].map((kind) => [kind, {
    principal_daily_requests: 100, daily_requests: 200,
  }])), ...overrides,
});
const reservation = (value, overrides = {}) => ({
  id: id(value), principal: "integration:omni", kind: "chat", amount: 10, ...overrides,
});
const requestOptions = (operation, fields = {}) => ({
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ version: 1, operation, ...fields }),
});
const request = (operation, fields = {}) => new Request(URL_STORE, requestOptions(operation, fields));

async function fixture(t, initialPolicy = policy()) {
  const directory = await mkdtemp(join(tmpdir(), "multillm-intelligence-d1-"));
  const create = () => new Miniflare({
    cf: false, d1Persist: directory,
    workers: ["replica-a", "replica-b"].map((name) => ({
      name, modules: true, compatibilityDate: "2026-07-28",
      script: `${source}\nexport default { fetch: handleIntelligenceStoreRequest };`,
      d1Databases: { INTELLIGENCE_DB: "shared-intelligence-ledger" },
    })),
  });
  let mf = create();
  t.after(async () => { await mf.dispose(); await rm(directory, { recursive: true, force: true }); });
  let db = await mf.getD1Database("INTELLIGENCE_DB", "replica-a");
  const apply = () => db.batch(migration.split(";").map((sql) => sql.trim()).filter(Boolean).map((sql) => db.prepare(sql)));
  await apply();
  const call = async (operation, fields = {}, replica = "replica-a") => {
    const worker = await mf.getWorker(replica);
    const response = await worker.fetch(URL_STORE, requestOptions(operation, fields));
    return { status: response.status, body: await response.json() };
  };
  if (initialPolicy) assert.deepEqual(await call("seed", { policy: initialPolicy }), { status: 200, body: { version: 1, inserted: true } });
  return {
    call, apply, get db() { return db; }, worker: (name = "replica-a") => mf.getWorker(name),
    async reopen() {
      await mf.dispose(); mf = create();
      db = await mf.getD1Database("INTELLIGENCE_DB", "replica-a");
    },
  };
}

test("policy is first-seed-only, additive, validated, and durable across reopen", async (t) => {
  const f = await fixture(t, null);
  assert.deepEqual((await f.call("policy")).body, { version: 1, policy: null });
  assert.equal((await f.call("reserve", reservation(1))).status, 503);
  for (const changes of [
    { max_inflight: 0 }, { max_total_tokens: 2 ** 31 }, { global_daily_tokens: 1.5 },
    { principal_daily_tokens: true }, { media: { speech: { principal_daily_requests: 0, daily_requests: 1 } } },
  ]) assert.equal((await f.call("seed", { policy: policy(changes) })).status, 400);
  const results = await Promise.all(["replica-a", "replica-b"].map((replica) => f.call("seed", { policy: policy() }, replica)));
  assert.equal(results.filter((result) => result.body.inserted).length, 1);
  assert.equal((await f.call("seed", { policy: policy({ global_daily_tokens: 999 }) })).body.inserted, false);
  await f.apply();
  await f.reopen();
  assert.deepEqual((await f.call("policy")).body.policy, policy());
});

test("simultaneous replicas cannot overspend a principal allowance", async (t) => {
  const f = await fixture(t, policy({ principal_daily_tokens: 100 }));
  const results = await Promise.all(Array.from({ length: 30 }, (_, index) => f.call("reserve", reservation(index + 1),
    index % 2 ? "replica-a" : "replica-b")));
  assert.equal(results.filter((result) => result.status === 200).length, 10);
  assert.equal(results.filter((result) => result.status === 429).length, 20);
  assert.deepEqual(await f.db.prepare("SELECT COUNT(*) AS n, SUM(charged) AS charged FROM intelligence_reservations").first(), { n: 10, charged: 100 });
});

test("simultaneous principals cannot overspend the global allowance", async (t) => {
  const f = await fixture(t, policy({ global_daily_tokens: 100 }));
  const before = Date.now();
  const results = await Promise.all(Array.from({ length: 30 }, (_, index) => f.call("reserve", reservation(index + 1, {
    principal: `integration:caller-${index}`,
  }), index % 2 ? "replica-a" : "replica-b")));
  assert.equal(results.filter((result) => result.status === 200).length, 10);
  assert.equal(results.filter((result) => result.status === 429).length, 20);
  const row = await f.db.prepare("SELECT SUM(charged) AS charged, MIN(created_at) AS earliest, MAX(created_at) AS latest FROM intelligence_reservations").first();
  assert.equal(row.charged, 100);
  assert.ok(row.earliest >= before && row.latest <= Date.now());
});

test("inflight limits are atomic per kind and settlement opens exactly one slot", async (t) => {
  const f = await fixture(t, policy({ max_inflight: 2 }));
  const results = await Promise.all([1, 2, 3].map((value) => f.call("reserve", reservation(value), value % 2 ? "replica-a" : "replica-b")));
  const accepted = results.filter((result) => result.status === 200);
  assert.equal(accepted.length, 2);
  assert.equal((await f.call("reserve", reservation(4, { kind: "speech", amount: 1 }))).status, 200);
  assert.equal((await f.call("settle", { id: accepted[0].body.id, used: 0, complete: true })).body.settled, true);
  assert.equal((await f.call("reserve", reservation(5))).status, 200);
  assert.equal((await f.call("reserve", reservation(6))).status, 429);
});

test("duplicate IDs are idempotent only for the exact original reservation", async (t) => {
  const f = await fixture(t, policy({ principal_daily_tokens: 1, max_inflight: 1 }));
  const original = reservation(1, { amount: 1 });
  const results = await Promise.all(["replica-a", "replica-b"].map((replica) => f.call("reserve", original, replica)));
  assert.ok(results.every((result) => result.status === 200 && result.body.id === id(1)));
  for (const change of [{ amount: 2 }, { principal: "someone-else" }, { kind: "speech" }]) {
    assert.deepEqual(await f.call("reserve", { ...original, ...change }), {
      status: 409, body: { version: 1, error: { code: "reservation_conflict", message: "The reservation identifier already names different work." } },
    });
  }
  assert.equal((await f.db.prepare("SELECT COUNT(*) AS n FROM intelligence_reservations").first()).n, 1);
  await f.call("settle", { id: id(1), used: 0, complete: true });
  assert.equal((await f.call("reserve", original)).status, 409);
  const uncertain = reservation(2, { amount: 1 });
  assert.equal((await f.call("reserve", uncertain)).status, 200);
  await f.call("settle", { id: id(2), used: 0, complete: false });
  assert.equal((await f.call("reserve", uncertain)).status, 409);
});

test("media operations use their own stored principal and global request ceilings", async (t) => {
  const f = await fixture(t, policy({ enabled: false, media: { speech: { principal_daily_requests: 2, daily_requests: 3 } } }));
  assert.equal((await f.call("reserve", reservation(1))).status, 503);
  assert.equal((await f.call("reserve", reservation(1, { kind: "transcriptions", amount: 1 }))).status, 503);
  for (const value of [1, 2]) assert.equal((await f.call("reserve", reservation(value, { kind: "speech", amount: 1 }))).status, 200);
  assert.equal((await f.call("reserve", reservation(3, { kind: "speech", amount: 1 }))).status, 429);
  assert.equal((await f.call("reserve", reservation(3, { kind: "speech", amount: 1, principal: "other" }))).status, 200);
  assert.equal((await f.call("reserve", reservation(4, { kind: "speech", amount: 1, principal: "other" }))).status, 429);
});

test("settlement records complete usage, holds partial usage, and cannot be replayed to release charges", async (t) => {
  const f = await fixture(t);
  for (const value of [1, 2, 3, 4]) assert.equal((await f.call("reserve", reservation(value, { amount: 100 }))).status, 200);
  for (const [value, used, complete, charged, state] of [
    [1, 30, true, 30, "settled"], [2, 150, true, 150, "settled"],
    [3, 30, false, 100, "unknown"], [4, 150, false, 150, "unknown"],
  ]) {
    assert.equal((await f.call("settle", { id: id(value), used, complete })).body.settled, true);
    assert.equal((await f.call("settle", { id: id(value), used: 0, complete: true })).body.settled, false);
    assert.deepEqual(await f.db.prepare("SELECT charged, state FROM intelligence_reservations WHERE id = ?").bind(id(value)).first(), { charged, state });
  }
  assert.equal((await f.call("settle", { id: id(99), used: 0, complete: true })).body.settled, false);
});

test("old unknown and pending charges survive rolling windows and process replacement", async (t) => {
  const f = await fixture(t, policy({ principal_daily_tokens: 100, global_daily_tokens: 100, max_inflight: 3 }));
  for (const value of [1, 2, 3]) assert.equal((await f.call("reserve", reservation(value, { amount: 30 }))).status, 200);
  await f.call("settle", { id: id(1), used: 10, complete: false });
  await f.call("settle", { id: id(2), used: 30, complete: true });
  await f.db.prepare("UPDATE intelligence_reservations SET created_at = ?").bind(Date.now() - 3 * 86400000).run();
  await f.reopen();
  assert.equal((await f.call("reserve", reservation(4, { amount: 40 }))).status, 200);
  assert.equal((await f.call("reserve", reservation(5, { amount: 1 }))).status, 429);
  assert.equal((await f.call("settle", { id: id(1), used: 0, complete: true })).body.settled, false);
  assert.equal((await f.call("reserve", reservation(6, { amount: 1 }))).status, 429);
});

test("concurrent settlement transitions each reservation once", async (t) => {
  const f = await fixture(t);
  await f.call("reserve", reservation(1));
  const results = await Promise.all([
    f.call("settle", { id: id(1), used: 3, complete: true }, "replica-a"),
    f.call("settle", { id: id(1), used: 20, complete: false }, "replica-b"),
  ]);
  assert.ok(results.every((result) => result.status === 200));
  assert.equal(results.filter((result) => result.body.settled).length, 1);
  const expected = results[0].body.settled ? { charged: 3, state: "settled" } : { charged: 20, state: "unknown" };
  assert.deepEqual(await f.db.prepare("SELECT charged, state FROM intelligence_reservations WHERE id = ?").bind(id(1)).first(), expected);
});

test("overruns remain charged and policy changes between read and insert cannot admit stale limits", async (t) => {
  const f = await fixture(t, policy({ principal_daily_tokens: 50, global_daily_tokens: 50 }));
  await f.call("reserve", reservation(1));
  await f.call("settle", { id: id(1), used: 60, complete: true });
  assert.equal((await f.call("reserve", reservation(2))).status, 429);
  await f.db.prepare("UPDATE intelligence_policy SET document = ? WHERE id = 1").bind(JSON.stringify(policy())).run();
  const binding = {
    prepare: (...args) => f.db.prepare(...args),
    async batch(statements) {
      await f.db.prepare("UPDATE intelligence_policy SET document = ? WHERE id = 1").bind(JSON.stringify(policy({ enabled: false }))).run();
      return f.db.batch(statements);
    },
  };
  const response = await handleIntelligenceStoreRequest(request("reserve", reservation(2)), { INTELLIGENCE_DB: binding });
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error.code, "intelligence_policy_changed");
  assert.equal(await f.db.prepare("SELECT id FROM intelligence_reservations WHERE id = ?").bind(id(2)).first(), null);
});

test("the private endpoint rejects untrusted fields, invalid names and sizes before storage", async (t) => {
  const f = await fixture(t);
  for (const fields of [
    { amount: 0 }, { amount: 1.5 }, { amount: Number.MAX_SAFE_INTEGER + 1 },
    { kind: "other" }, { kind: "speech", amount: 2 }, { id: "invalid" }, { id: "A".repeat(32) },
    { principal: "" }, { principal: "a".repeat(257) }, { principal: "a\nb" },
    { policy: policy() }, { now: 0 }, { global_daily_tokens: 999999 }, { operation: ["reserve"] },
  ]) assert.equal((await f.call("reserve", reservation(1, fields))).status, 400);
  for (const fields of [{ used: -1 }, { used: 1.5 }, { complete: "true" }]) {
    assert.equal((await f.call("settle", { id: id(1), used: 0, complete: true, ...fields })).status, 400);
  }
  assert.equal((await f.call("reserve", reservation(1, { amount: 1001 }))).status, 429);
  assert.equal((await f.call("reserve", reservation(2, { principal: "नाम with ' SQL text" }))).status, 200);
  const worker = await f.worker();
  assert.equal((await worker.fetch("http://public.example/v1/store", requestOptions("policy"))).status, 404);
  assert.equal((await worker.fetch(URL_STORE)).status, 405);
  assert.equal((await worker.fetch(URL_STORE, { method: "POST", body: "{}" })).status, 415);
  assert.equal((await worker.fetch(URL_STORE, { method: "POST", headers: { "content-type": "application/json" }, body: "{" })).status, 400);
  assert.equal((await worker.fetch(URL_STORE, { method: "POST", headers: { "content-type": "application/json" }, body: " ".repeat(262145) })).status, 413);
});

test("unavailable storage fails closed without exposing database diagnostics", async () => {
  const db = { prepare() { throw new Error("sensitive database connection details"); }, batch() {} };
  for (const env of [{}, { INTELLIGENCE_DB: db }]) {
    const response = await handleIntelligenceStoreRequest(request("policy"), env);
    assert.equal(response.status, 503);
    const text = await response.text();
    assert.ok(!text.includes("sensitive"));
    assert.equal(JSON.parse(text).error.code, "intelligence_store_unavailable");
  }
});

test("chunked bodies are bounded even when stream cancellation does not finish", { timeout: 1000 }, async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(262145)); },
    cancel() { cancelled = true; return new Promise(() => {}); },
  });
  const response = await handleIntelligenceStoreRequest(new Request(URL_STORE, {
    method: "POST", headers: { "content-type": "application/json" }, body, duplex: "half",
  }), {});
  assert.equal(response.status, 413);
  assert.equal(cancelled, true);
});
