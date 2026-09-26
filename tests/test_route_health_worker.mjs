import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { fetchIfRunning, runScheduledHealth, scheduleSettings } from "../worker/health-schedule.mjs";
import { readStatusSnapshot } from "../worker/route-health-d1.mjs";
import { renderStatusHtml, resetStatusMemo } from "../worker/status-page.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const worker = (await loadWorkerModule()).default;
const ADMIN_KEY = "synthetic-admin-key";
const HALF_PAST = Date.UTC(2026, 8, 26, 12, 30);
const TWENTY_FIVE_PAST = Date.UTC(2026, 8, 26, 12, 25);

function state(overrides = {}) {
  return { kind: "candidate", ewma_success: 0.9, ewma_at: 1, ewma_latency_ms: 800, latency_at: 1, last_status: 200,
    last_outcome: "ok", consecutive_failures: 0, last_success_at: 1, last_failure_at: null, last_check_at: null,
    last_check_ok: null, last_check_status: null, samples: [[1, 1, 800]], updated_at: 1, ...overrides };
}

function snapshot(overrides = {}) {
  return { version: 1, generated_at: "2026-09-26T12:00:00+00:00", window_seconds: 3600, overall: "degraded",
    routes: [{ id: "auto:glm-5.2", kind: "chat", ordering: "health", status: "degraded", candidates: [
      { model: "nanogpt:zai-org/glm-5.2:thinking", provider: "nanogpt", priority: 1, status: "down", success_rate: 0.25,
        p50_latency_ms: 2400, last_success_at: null, last_failure_at: null, last_check_at: "2026-09-26T11:30:00+00:00" },
      { model: "opencode:glm-5.2", provider: "opencode", priority: 2, status: "up", success_rate: 1,
        p50_latency_ms: 850, last_success_at: null, last_failure_at: null, last_check_at: null }] }],
    providers: [{ id: "nanogpt", status: "down", success_rate: 0.25, p50_latency_ms: 2400,
      last_check_at: "2026-09-26T11:30:00+00:00", last_check: "failed" }], ...overrides };
}

async function database(t, options) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}",
    d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, options);
  const call = async (body, env = { INTELLIGENCE_DB: db }) => {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/route-health", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

/** A Container Durable Object stub that records how it was reached. */
function containerStub({ running = false, status = 200, body = "{}" } = {}) {
  const calls = { fetch: [], fetchIfRunning: [] };
  return {
    calls,
    async fetch(request) {
      calls.fetch.push({ path: new URL(request.url).pathname, method: request.method,
        authorization: request.headers.get("Authorization") });
      return new Response(body, { status });
    },
    async fetchIfRunning(path, init) {
      calls.fetchIfRunning.push({ path, init });
      return running ? { status, body } : null;
    },
  };
}

function workerEnv(db, container, overrides = {}) {
  return { INTELLIGENCE_DB: db, MULTILLM_PROXY_CONTAINER: { getByName: name => { assert.equal(name, "primary"); return container; } },
    ADMIN_API_KEY: ADMIN_KEY, ...overrides };
}

test("route health rows persist, and an older row never replaces a newer one", async t => {
  const { call } = await database(t);
  assert.deepEqual((await call({ operation: "list" })).body, { version: 1, rows: [] });
  const newer = { target: "opencode:glm-5.2", state: state({ last_status: 503 }), updated_at: "2026-09-26T12:00:00.000+00:00" };
  const older = { ...newer, state: state({ last_status: 200 }), updated_at: "2026-09-26T11:00:00.000+00:00" };
  assert.deepEqual((await call({ operation: "put", rows: [newer, { ...newer, target: "provider:opencode",
    state: state({ kind: "provider" }) }] })).body, { version: 1, stored: 2 });
  await call({ operation: "put", rows: [older] });
  const rows = (await call({ operation: "list" })).body.rows;
  assert.equal(rows.length, 2);
  assert.equal(rows.find(row => row.target === "opencode:glm-5.2").state.last_status, 503);
});

test("route health writes are validated before any statement runs and errors stay private", async t => {
  const { call } = await database(t);
  const row = { target: "opencode:glm-5.2", state: state(), updated_at: "2026-09-26T12:00:00.000+00:00" };
  for (const change of [{ target: "bad target" }, { updated_at: "yesterday" }, { state: { kind: "candidate" } },
    { state: state({ kind: "admin" }) }, { state: { ...state(), secret: "x" } }, { extra: true },
    { state: state({ samples: Array(33).fill([1, 1, 1]) }) }]) {
    assert.equal((await call({ operation: "put", rows: [{ ...row, ...change }] })).status, 400, JSON.stringify(change));
  }
  assert.equal((await call({ operation: "put", rows: [row, row] })).status, 400, "duplicate targets");
  assert.equal((await call({ operation: "put", rows: Array(65).fill(0).map((_, i) => ({ ...row, target: `p:m${i}` })) })).status, 400);
  assert.equal((await call({ operation: "snapshot", body: { version: 2 }, updated_at: row.updated_at })).status, 400);
  assert.equal((await call({ operation: "snapshot", body: snapshot({ pad: "x".repeat(200000) }), updated_at: row.updated_at })).status, 400);
  assert.equal((await call({ operation: "sql", statement: "DROP TABLE route_health" })).status, 400);
  const broken = await call({ operation: "list" }, { INTELLIGENCE_DB: { prepare() { throw new Error("private database detail"); } } });
  assert.equal(broken.status, 503);
  assert.equal(JSON.stringify(broken.body).includes("private"), false);
});

test("the status snapshot keeps the newest document", async t => {
  const { db, call } = await database(t);
  assert.equal(await readStatusSnapshot(db), null);
  await call({ operation: "snapshot", body: snapshot(), updated_at: "2026-09-26T12:00:00.000+00:00" });
  await call({ operation: "snapshot", body: snapshot({ overall: "up" }), updated_at: "2026-09-26T11:00:00.000+00:00" });
  assert.equal((await readStatusSnapshot(db)).overall, "degraded");
  const missing = await database(t, { skip: ["0009_route_health.sql"] });
  assert.equal(await readStatusSnapshot(missing.db), null, "an unmigrated D1 serves no snapshot instead of failing");
});

test("/status is served from D1 without waking the Container", async t => {
  resetStatusMemo();
  const { db, call } = await database(t);
  await call({ operation: "snapshot", body: snapshot(), updated_at: "2026-09-26T12:00:00.000+00:00" });
  const container = containerStub();

  const page = await worker.fetch(new Request("https://gateway.example/status"), workerEnv(db, container));
  const json = await worker.fetch(new Request("https://gateway.example/status.json?x=1"), workerEnv(db, container));

  assert.equal(page.status, 200);
  assert.equal(page.headers.get("Cache-Control"), "public, max-age=30, s-maxage=60");
  assert.match(page.headers.get("Content-Security-Policy"), /default-src 'none'/);
  const html = await page.text();
  assert.match(html, /<code>auto:glm-5\.2<\/code> <span class="badge badge--degraded">Degraded<\/span>/);
  assert.match(html, /<td>25\.0%<\/td><td>2\.4 s<\/td><td>2026-09-26 11:30 UTC<\/td>/);
  assert.match(html, /Last figures the gateway stored/);
  assert.equal(json.headers.get("Access-Control-Allow-Origin"), "*");
  assert.deepEqual(await json.json(), { ...snapshot(), source: "snapshot" });
  assert.deepEqual(container.calls, { fetch: [], fetchIfRunning: [] });
  assert.equal((await worker.fetch(new Request("https://gateway.example/status", { method: "POST" }), workerEnv(db, container))).status, 405);
});

test("without a snapshot the page asks a running Container, else reports unknown", async t => {
  const { db } = await database(t);
  resetStatusMemo();
  const running = containerStub({ running: true, body: JSON.stringify({ ...snapshot({ overall: "up" }), source: "live" }) });
  const live = await (await worker.fetch(new Request("https://gateway.example/status.json"), workerEnv(db, running))).json();
  assert.equal(live.overall, "up");
  assert.equal(live.source, "live");
  assert.equal(running.calls.fetch.length, 0, "never a normal fetch that would start or renew the Container");
  assert.equal(running.calls.fetchIfRunning[0].path, "/status.json");

  resetStatusMemo();
  const asleep = containerStub();
  const empty = await (await worker.fetch(new Request("https://gateway.example/status.json"), workerEnv(db, asleep))).json();
  assert.deepEqual([empty.overall, empty.routes, empty.source], ["unknown", [], "snapshot"]);
  assert.equal(asleep.calls.fetch.length, 0);
});

test("the edge cache answers repeated status requests", async t => {
  resetStatusMemo();
  const { db, call } = await database(t);
  await call({ operation: "snapshot", body: snapshot(), updated_at: "2026-09-26T12:00:00.000+00:00" });
  const stored = new Map();
  const original = globalThis.caches;
  globalThis.caches = { default: {
    async match(request) { return stored.get(request.url)?.clone(); },
    async put(request, response) { stored.set(request.url, response); },
  } };
  t.after(() => { globalThis.caches = original; });
  const waited = [];
  const ctx = { waitUntil: promise => waited.push(promise) };

  await worker.fetch(new Request("https://gateway.example/status.json?nocache=1"), workerEnv(db, containerStub()), ctx);
  await Promise.all(waited);
  assert.deepEqual([...stored.keys()], ["https://gateway.example/status.json"], "the query string never splits the cache");
  const brokenDb = { prepare() { throw new Error("D1 must not be read on a cache hit"); } };
  const cached = await worker.fetch(new Request("https://gateway.example/status.json"), workerEnv(brokenDb, containerStub()), ctx);
  assert.equal((await cached.json()).overall, "degraded");
});

test("the rendered page escapes stored values and ignores unknown statuses", () => {
  const html = renderStatusHtml(snapshot({ overall: "<script>", routes: [{ id: "auto:<img src=x>", status: "evil\"", candidates: [
    { model: "a:b</code><script>alert(1)</script>", status: "up", priority: "<1>", success_rate: "x" }] }] }), "snapshot");
  assert.equal(html.includes("<script>"), false);
  assert.equal(html.includes("<img"), false);
  assert.match(html, /auto:&lt;img src=x&gt;/);
  assert.match(html, /badge--unknown/);
  assert.match(html, /No recent health data/);
});

test("scheduled checks never wake a sleeping Container by default", async () => {
  const asleep = containerStub();
  const outcome = await runScheduledHealth({ cron: "*/5 * * * *", scheduledTime: HALF_PAST }, { ADMIN_API_KEY: ADMIN_KEY }, asleep);
  assert.deepEqual(outcome, { cron: "*/5 * * * *", checks: "skipped", reason: "container_asleep" });
  assert.equal(asleep.calls.fetch.length, 0);

  const running = containerStub({ running: true, body: "{\"results\":[]}" });
  assert.equal((await runScheduledHealth({ cron: "*/5 * * * *", scheduledTime: HALF_PAST }, { ADMIN_API_KEY: ADMIN_KEY }, running)).checks, "ran");
  assert.equal(running.calls.fetch.length, 0);
  const [{ path, init }] = running.calls.fetchIfRunning;
  assert.equal(path, "/v1/health/checks");
  assert.equal(init.method, "POST");
  assert.equal(init.headers.Authorization, `Bearer ${ADMIN_KEY}`);

  const offTick = containerStub({ running: true });
  assert.deepEqual(await runScheduledHealth({ cron: "*/5 * * * *", scheduledTime: TWENTY_FIVE_PAST }, { ADMIN_API_KEY: ADMIN_KEY }, offTick),
    { cron: "*/5 * * * *" });
  assert.deepEqual(offTick.calls, { fetch: [], fetchIfRunning: [] });

  const keyless = containerStub({ running: true });
  assert.equal((await runScheduledHealth({ cron: "c", scheduledTime: HALF_PAST }, {}, keyless)).reason, "admin_key_missing");
  assert.equal(keyless.calls.fetchIfRunning.length, 0);
});

test("wake and keep-warm settings reach the Container through a normal fetch", async () => {
  const wake = containerStub();
  const woken = await runScheduledHealth({ cron: "c", scheduledTime: HALF_PAST },
    { ADMIN_API_KEY: ADMIN_KEY, HEALTH_CHECKS_WAKE: "true" }, wake);
  assert.equal(woken.checks, "ran");
  assert.deepEqual(wake.calls.fetch.map(call => [call.path, call.method, call.authorization]),
    [["/v1/health/checks", "POST", `Bearer ${ADMIN_KEY}`]]);

  const warm = containerStub();
  const kept = await runScheduledHealth({ cron: "c", scheduledTime: TWENTY_FIVE_PAST }, { ADMIN_API_KEY: ADMIN_KEY, KEEP_WARM: "true" }, warm);
  assert.deepEqual(kept, { cron: "c", keepWarm: 200 });
  assert.deepEqual(warm.calls.fetch.map(call => call.path), ["/healthz"]);

  assert.deepEqual(scheduleSettings({}), { keepWarm: false, checksWake: false, checkEveryMinutes: 30 });
  assert.equal(scheduleSettings({ HEALTH_CHECK_INTERVAL_MINUTES: "1" }).checkEveryMinutes, 5);
});

test("the Worker's scheduled handler runs the health schedule in waitUntil", async () => {
  const container = containerStub({ running: true });
  const waited = [];
  await worker.scheduled({ cron: "*/5 * * * *", scheduledTime: HALF_PAST }, workerEnv(null, container),
    { waitUntil: promise => waited.push(promise) });
  await Promise.all(waited);
  assert.equal(container.calls.fetchIfRunning.length, 1);
});

test("fetchIfRunning reaches the port directly and never starts a stopped Container", async () => {
  let reached = null;
  const runtime = { running: true, getTcpPort(port) {
    return { async fetch(url, init) { reached = { port, url, method: init.method }; return new Response("ok", { status: 200 }); } };
  } };
  const durableObject = { defaultPort: 8080, ctx: { container: runtime }, async getState() { return { status: "healthy" }; },
    renewActivityTimeout() { throw new Error("must not renew sleepAfter"); } };
  assert.deepEqual(await fetchIfRunning(durableObject, "/status.json", { method: "GET" }), { status: 200, body: "ok" });
  assert.deepEqual(reached, { port: 8080, url: "http://container/status.json", method: "GET" });
  const stopped = { ...durableObject, async getState() { return { status: "stopped" }; } };
  assert.equal(await fetchIfRunning(stopped, "/status.json"), null);
});

test("the deploy config schedules the cron and keeps both wake settings off", async () => {
  const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.deepEqual(config.triggers.crons, ["*/5 * * * *"]);
  assert.equal(config.vars.KEEP_WARM, "false");
  assert.equal(config.vars.HEALTH_CHECKS_WAKE, "false");
  assert.equal(config.vars.HEALTH_CHECK_INTERVAL_MINUTES, "30");
});
