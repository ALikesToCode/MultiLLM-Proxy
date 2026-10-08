import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { AdmissionCoordinator, acquireAdmission, admissionSettings, runWithAdmission } from "../worker/admission-do.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";

const identity = (request_id = "r1", principal_hash = "a".repeat(64), model_group = "heavy") =>
  ({ principal_hash, model_group, request_id, deadline_ms: 1_100_000 });
function authority(t, limits = { principal: 2, model_groups: { heavy: 1 } }) {
  let now = 1_000_000, touches = 0;
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const storage = { sql: { exec(query, ...args) {
    touches++;
    const statement = db.prepare(query);
    return { toArray: () => statement.columns().length ? statement.all(...args) : (statement.run(...args), []) };
  } }, transactionSync(callback) {
    db.exec("BEGIN");
    try { const result = callback(); db.exec("COMMIT"); return result; }
    catch (error) { db.exec("ROLLBACK"); throw error; }
  } };
  const env = { ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: JSON.stringify(limits) };
  const coordinator = new AdmissionCoordinator({ storage }, env, () => now);
  let accesses = 0;
  env.ADMISSION_COORDINATOR = { getByName(name) { accesses++; assert.match(name, /^admission-[0-9]+$/); return coordinator; } };
  const call = async body => {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/admission", {
      method: "POST", body: JSON.stringify({ version: 1, ...body }),
    }), env);
    return { status: response.status, headers: response.headers, body: await response.json() };
  };
  return { env, db, storage, coordinator, call, clock(value) { now = value; }, touches: () => touches, accesses: () => accesses };
}

test("disabled and malformed settings never touch authority, storage, headers or response identity", async t => {
  const a = authority(t);
  const response = new Response("unchanged", { headers: { "x-original": "yes" } });
  for (const env of [{}, { ADMISSION_ENABLED: "" }, { ADMISSION_ENABLED: "bad" },
    { ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: "bad" },
    { ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: "{}" }]) {
    env.ADMISSION_COORDINATOR = { getByName() { throw Error("unexpected access"); } };
    assert.equal(await runWithAdmission(null, env, () => response), response);
  }
  a.env.ADMISSION_ENABLED = "false";
  assert.equal((await a.coordinator.fetch(new Request("http://admission.internal/v1/admission", { method: "POST", body: "bad" }))).status, 200);
  await a.coordinator.alarm();
  assert.equal(a.touches(), 0);
});

test("Flask private and native callers share atomic keyed admission with real retry advice", async t => {
  const a = authority(t);
  const [first, second] = await Promise.all([
    a.call({ operation: "acquire", ...identity() }),
    a.call({ operation: "acquire", ...identity("r2") }),
  ]);
  assert.deepEqual([first.status, second.status].sort(), [200, 429]);
  const denied = first.status === 429 ? first : second;
  assert.equal(denied.headers.get("retry-after"), "30");
  await assert.rejects(acquireAdmission(identity("native"), a.env), error => error.status === 429);
  const lease = await acquireAdmission(identity("other", "b".repeat(64)), a.env, { clock: () => 1_000_000 });
  await lease.release();
});

test("renewal, expiry, request binding and duplicate release are durable and bounded", async t => {
  const a = authority(t);
  const first = await a.call({ operation: "acquire", ...identity() });
  const lease_id = first.body.lease.lease_id;
  assert.equal((await a.call({ operation: "acquire", ...identity() })).body.lease.lease_id, lease_id);
  a.clock(1_020_000);
  assert.equal((await a.call({ operation: "renew", ...identity(), lease_id })).body.lease.expires_at, 1_050_000);
  a.clock(1_031_000);
  assert.equal((await a.call({ operation: "acquire", ...identity("r2") })).status, 429);
  for (const change of [{ model_group: "small" }, { request_id: "wrong" }, { principal_hash: "b".repeat(64) }]) {
    const bad = await a.coordinator.fetch(new Request("http://admission.internal/v1/admission", {
      method: "POST", body: JSON.stringify({ version: 1, operation: "release", ...identity(), lease_id, ...change }),
    }));
    assert.equal(bad.status, 403);
  }
  a.clock(1_051_000);
  assert.equal((await a.call({ operation: "renew", ...identity(), lease_id })).status, 409);
  const replacement = await a.call({ operation: "acquire", ...identity("r2") });
  assert.equal(replacement.status, 200);
  const release = { operation: "release", ...identity("r2"), lease_id: replacement.body.lease.lease_id };
  assert.equal((await a.call(release)).body.released, true);
  assert.equal((await a.call(release)).body.released, false);
});

test("deadline cannot be extended; shard cap and authority outage fail closed", async t => {
  const a = authority(t, { principal: 10000 });
  const first = await a.call({ operation: "acquire", ...identity(), deadline_ms: 1_005_000 });
  assert.equal(first.body.lease.expires_at, 1_005_000);
  assert.equal((await a.call({ operation: "renew", ...identity(), lease_id: first.body.lease.lease_id })).status, 403);
  a.clock(1_005_000);
  assert.equal((await a.call({ operation: "renew", ...identity(), deadline_ms: 1_005_000, lease_id: first.body.lease.lease_id })).status, 409);
  const insert = a.db.prepare("INSERT INTO admission_leases VALUES (?, ?, ?, ?, ?, ?)");
  for (let n = 0; n < 10000; n++) insert.run(String(n), "c".repeat(64), "heavy", String(n), 1_100_000, 1_035_000);
  assert.equal((await a.call({ operation: "acquire", ...identity("cap") })).status, 429);
  a.env.ADMISSION_COORDINATOR = { getByName() { throw Error("down"); } };
  await assert.rejects(acquireAdmission(identity(), a.env), error => error.status === 503);
});

test("private allowlist rejects public targets, extra fields and raw principal keys", async t => {
  const a = authority(t);
  for (const [url, method, status] of [["https://public.test/v1/admission", "POST", 400],
    ["http://intelligence.internal/v1/admission?x=1", "POST", 400], ["http://intelligence.internal/v1/admission", "GET", 405]]) {
    assert.equal((await handleIntelligenceOutbound(new Request(url, { method }), a.env)).status, status);
  }
  for (const change of [{ principal_hash: "raw-key" }, { model_group: "bad group" }, { limit: 999 }, { version: 2 }, { deadline_ms: NaN }]) {
    assert.equal((await a.call({ operation: "acquire", ...identity(), ...change })).status, 400);
  }
  assert.equal(a.touches(), 0);
  assert.equal(admissionSettings({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: "" }).enabled, true);
});

test("stream completion, response errors and cancellation release once and preserve bytes", async t => {
  const a = authority(t);
  let releases = 0;
  const fetch = a.coordinator.fetch.bind(a.coordinator);
  a.coordinator.fetch = async request => {
    if ((await request.clone().json()).operation === "release") releases++;
    return fetch(request);
  };
  const result = await runWithAdmission(identity(), a.env, () => new Response("same bytes", { headers: { "x-provider": "raw" } }),
    { clock: () => 1_000_000 });
  assert.equal(await result.text(), "same bytes");
  assert.equal(result.headers.get("x-provider"), "raw");
  assert.equal(releases, 1);
  await assert.rejects(runWithAdmission(identity("error"), a.env, () => { throw Error("response failure"); },
    { clock: () => 1_000_000 }));
  assert.equal(releases, 2);
  const canceled = await runWithAdmission(identity("cancel"), a.env, () => new Response(new ReadableStream({ pull() {} })),
    { clock: () => 1_000_000 });
  await canceled.body.cancel();
  assert.equal(releases, 3);
  assert.equal(a.db.prepare("SELECT COUNT(*) AS n FROM admission_leases").get().n, 0);
});


test("principal limits span groups and leases survive authority reconstruction", async t => {
  const a = authority(t);
  const first = await a.call({ operation: "acquire", ...identity() });
  assert.equal(first.status, 200);
  assert.equal((await a.call({ operation: "acquire", ...identity("small", "a".repeat(64), "small") })).status, 200);
  assert.equal((await a.call({ operation: "acquire", ...identity("third", "a".repeat(64), "tiny") })).status, 429);
  const restarted = new AdmissionCoordinator({ storage: a.storage }, a.env, () => 1_000_000);
  const denied = await restarted.fetch(new Request("http://admission.internal/v1/admission", {
    method: "POST", body: JSON.stringify({ version: 1, operation: "acquire", ...identity("restart") }),
  }));
  assert.equal(denied.status, 429);
  assert.equal((await a.call({ operation: "acquire", ...identity(), model_group: "small" })).status, 403);
});

test("public caller headers cannot write the private admission route", async t => {
  const a = authority(t);
  const { default: worker } = await loadWorkerModule();
  const env = { ...a.env, MULTILLM_PROXY_CONTAINER: { getByName() { return { fetch() {
    return Response.json({ error: "not_found" }, { status: 404 });
  } }; } } };
  const response = await worker.fetch(new Request("https://proxy.example/v1/admission", {
    method: "POST", headers: { "x-principal-hash": "a".repeat(64), "x-model-group": "heavy" },
    body: JSON.stringify({ version: 1, operation: "acquire", ...identity() }),
  }), env);
  assert.equal(response.status, 404);
  assert.equal(a.accesses(), 0);
  assert.equal(a.touches(), 0);
});

test("renewal loss cancels pending reads, releases once and reports failure", async t => {
  const a = authority(t);
  let lease, canceled = 0, lost = 0;
  const response = await runWithAdmission(identity(), a.env, acquired => {
    lease = acquired;
    return new Response(new ReadableStream({ pull() {}, cancel() { canceled++; } }));
  }, { clock: () => 1_000_000, onLost() { lost++; throw Error("callback failure"); } });
  const original = a.coordinator.fetch.bind(a.coordinator);
  let releases = 0;
  a.coordinator.fetch = async request => {
    const { operation } = await request.clone().json();
    if (operation === "renew") return Response.json({ version: 1, error: { code: "down" } }, { status: 503 });
    if (operation === "release") releases++;
    return original(request);
  };
  const read = response.body.getReader().read();
  await lease.renew();
  await assert.rejects(read);
  await lease.release();
  assert.equal(canceled, 1);
  assert.equal(lost, 1);
  assert.equal(releases, 1);
});

test("abort before dispatch and while streaming cancels without replay", async t => {
  const a = authority(t);
  const controller = new AbortController();
  controller.abort();
  let dispatches = 0;
  await assert.rejects(runWithAdmission(identity(), a.env, () => { dispatches++; },
    { signal: controller.signal, clock: () => 1_000_000 }));
  assert.equal(dispatches, 0);
  const active = new AbortController();
  let lease, cancels = 0;
  await runWithAdmission(identity("active"), a.env, acquired => {
    lease = acquired;
    return new Response(new ReadableStream({ pull() {}, cancel() { cancels++; } }));
  }, { signal: active.signal, clock: () => 1_000_000 });
  active.abort();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(lease.closed, true);
  assert.equal(cancels, 1);
});

test("storage failures are real 503 and unknown groups stay unlimited", async t => {
  const a = authority(t, { model_groups: { heavy: 1 } });
  for (const group of ["small", "constructor", "toString"]) {
    const value = await acquireAdmission(identity("small", "a".repeat(64), group), a.env);
    assert.equal(value, null);
  }
  assert.equal(a.accesses(), 0);
  a.storage.sql.exec = () => { throw Error("storage down"); };
  assert.equal((await a.call({ operation: "acquire", ...identity() })).status, 503);
});


test("Wrangler retains existing bindings and migrations with one additive SQLite class", () => {
  const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.deepEqual(config.durable_objects.bindings, [
    { name: "MULTILLM_PROXY_CONTAINER", class_name: "MultiLLMProxyContainer" },
    { name: "ROLEPLAY_SESSION", class_name: "RoleplaySession" },
    { name: "ADMISSION_COORDINATOR", class_name: "AdmissionCoordinator" },
  ]);
  assert.deepEqual(config.migrations, [
    { tag: "v1", new_sqlite_classes: ["MultiLLMProxyContainer"] },
    { tag: "v2", new_sqlite_classes: ["RoleplaySession"] },
    { tag: "v3_admission", new_sqlite_classes: ["AdmissionCoordinator"] },
  ]);
  assert.equal(config.vars.ADMISSION_ENABLED, undefined);
});
