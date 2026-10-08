import assert from "node:assert/strict";
import test, { before } from "node:test";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { resetStatusMemo } from "../worker/status-page.mjs";
import { escapeLabel, renderStatusMetrics } from "../worker/prometheus.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

let worker;
before(async () => { worker = (await loadWorkerModule()).default; });
const now = Date.UTC(2026, 9, 9, 12);
const snapshot = { version: 1, generated_at: new Date(now - 120000).toISOString(), overall: "degraded",
  routes: [{ id: "auto:chat", status: "up", candidates: [{ model: "private-model" }] }],
  providers: [{ id: "example", status: "down" }], prompt: "private-prompt", api_key_prefix: "private-key" };

function fixture({ stored = null, live = null, enabled = "true" } = {}) {
  resetStatusMemo();
  const calls = { reads: 0, running: 0, fetch: 0 };
  const env = { PROMETHEUS_ENABLED: enabled, INTELLIGENCE_DB: { prepare() { return { async first() {
    calls.reads += 1;
    return stored ? { body: JSON.stringify(stored) } : null;
  } }; } }, MULTILLM_PROXY_CONTAINER: { getByName() { return {
    async fetchIfRunning() { calls.running += 1; return live ? { status: 200, body: JSON.stringify(live) } : null; },
    async fetch(request) { calls.fetch += 1; return new Response(request.headers.get("Authorization")); },
  }; } } };
  return { env, calls, fetch: (path, method = "GET") => worker.fetch(new Request(`https://gateway.example${path}`, {
    method, headers: { Authorization: "Bearer synthetic-key" },
  }), env) };
}

test("disabled metric paths never access or wake the Container", async () => {
  for (const enabled of [undefined, "false", "invalid"]) {
    const f = fixture({ enabled });
    delete f.env.PROMETHEUS_ENABLED;
    if (enabled !== undefined) f.env.PROMETHEUS_ENABLED = enabled;
    for (const path of ["/status.prometheus", "/v1/metrics/prometheus"]) {
      for (const method of ["GET", "HEAD", "POST"]) assert.equal((await f.fetch(path, method)).status, 404);
    }
    assert.deepEqual(f.calls, { reads: 0, running: 0, fetch: 0 });
    assert.equal((await f.fetch("/v1/metrics/prometheus", "OPTIONS")).status, 204);
  }
});

test("public GET and HEAD share retained status without waking or exposing private facts", async () => {
  const f = fixture({ stored: snapshot });
  const get = await f.fetch("/status.prometheus");
  assert.equal(get.status, 200);
  assert.equal(get.headers.get("Content-Type"), "text/plain; version=0.0.4; charset=utf-8");
  assert.equal(get.headers.get("Cache-Control"), "public, max-age=30, s-maxage=60");
  const body = await get.text();
  assert.match(body, /multillm_status_snapshot_available 1/);
  assert.match(body, /scope="overall",name="overall",state="degraded"} 1/);
  assert.match(body, /scope="route",name="auto:chat",state="up"} 1/);
  for (const secret of ["private-model", "private-prompt", "private-key", "synthetic-key"]) assert.ok(!body.includes(secret));
  const head = await f.fetch("/status.prometheus", "HEAD");
  assert.equal(await head.text(), "");
  assert.equal(head.headers.get("Cache-Control"), get.headers.get("Cache-Control"));
  assert.deepEqual(f.calls, { reads: 1, running: 0, fetch: 0 });
  const json = await (await f.fetch("/status.json")).json();
  assert.deepEqual(json, { ...snapshot, source: "snapshot" });
  assert.ok(!(await (await f.fetch("/status")).text()).includes("multillm_status"));
});

test("sleeping fallback omits fabricated age, live and retained snapshots have real age", async () => {
  const empty = fixture();
  const body = await (await empty.fetch("/status.prometheus")).text();
  assert.match(body, /multillm_status_snapshot_available 0/);
  assert.ok(!body.includes("multillm_status_snapshot_age_seconds"));
  assert.deepEqual(empty.calls, { reads: 1, running: 1, fetch: 0 });
  const live = fixture({ live: snapshot });
  assert.match(await (await live.fetch("/status.prometheus")).text(), /multillm_status_snapshot_available 1/);
  assert.equal(live.calls.fetch, 0);
  const rendered = renderStatusMetrics({ snapshot, available: true }, now);
  assert.match(rendered, /multillm_status_snapshot_age_seconds 120/);
  for (const generated_at of [null, "garbage", "2026-99-99T00:00:00Z", "2026-02-30T00:00:00Z", "123"]) {
    assert.ok(!renderStatusMetrics({ snapshot: { ...snapshot, generated_at }, available: true }, now)
      .includes("multillm_status_snapshot_age_seconds"));
  }
});

test("enabled methods are narrow, and API OPTIONS retains existing handling", async () => {
  const f = fixture();
  for (const method of ["POST", "PUT", "OPTIONS"]) {
    const r = await f.fetch("/status.prometheus", method);
    assert.equal(r.status, 405);
    assert.equal(r.headers.get("Allow"), "GET, HEAD");
  }
  for (const method of ["POST", "HEAD", "DELETE"]) {
    const r = await f.fetch("/v1/metrics/prometheus", method);
    assert.equal(r.status, 405);
    assert.equal(r.headers.get("Allow"), "GET, OPTIONS");
    assert.equal(r.headers.get("Cache-Control"), "no-store");
  }
  assert.equal((await f.fetch("/v1/metrics/prometheus", "OPTIONS")).status, 204);
  assert.equal(await (await f.fetch("/v1/metrics/prometheus")).text(), "Bearer synthetic-key");
  assert.equal(f.calls.fetch, 1);
});

test("states are one-hot, names escape safely, repeated public names are deduplicated", () => {
  assert.equal(escapeLabel('a\\b"c\nd'), 'a\\\\b\\"c\\nd');
  const special = 'a\\b"c\nd';
  const body = renderStatusMetrics({ available: true, snapshot: { overall: "weird",
    routes: [{ id: special, status: "weird" }, { id: special, status: "up" }], providers: [] } }, now);
  assert.match(body, /scope="overall",name="overall",state="unknown"} 1/);
  assert.ok(body.includes(`name="${escapeLabel(special)}",state="unknown"} 1`));
  assert.equal(body.split("\n").filter(line => line.startsWith("multillm_status_state{scope=\"route\"")).length, 4);
  assert.ok(!body.includes("NaN") && !body.includes("Infinity"));
});

test("output has deterministic cardinality and UTF-8 byte bounds with explicit truncation", () => {
  const huge = { overall: "up", routes: Array.from({ length: 1000 }, (_, i) => ({
    id: `${i}:${'漢\\"\n'.repeat(500)}`, status: "down",
  })), providers: [] };
  const body = renderStatusMetrics({ snapshot: huge, available: true }, now);
  assert.equal(body, renderStatusMetrics({ snapshot: huge, available: true }, now));
  assert.ok(Buffer.byteLength(body) <= 256 * 1024);
  const samples = body.split("\n").filter(line => line && !line.startsWith("#"));
  assert.ok(samples.length <= 512);
  assert.match(body, /multillm_prometheus_truncated 1/);
  assert.ok(samples.every(line => line.length < 2500));
});

test("the metrics setting passes through the Container allowlist only", () => {
  const settings = { PROMETHEUS_ENABLED: "true" };
  const env = collectContainerEnv({ ...settings, ARBITRARY_SETTING: "excluded" });
  for (const [key, value] of Object.entries(settings)) assert.equal(env[key], value);
  assert.equal(env.ARBITRARY_SETTING, undefined);
});
