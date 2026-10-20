import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { validCascade } from "../worker/cascades-d1.mjs";
import { CORS_EXPOSE_HEADERS } from "../worker/cors-policy.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

const config = { name: "cascade:synthetic", tiers: [{ model: "opencode:cheap" }, { model: "auto:strong" }], checks: ["complete"], updated_at: "2026-10-07T00:00:00Z" };
async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  const call = async (body, env = { INTELLIGENCE_DB: db }, target = "http://intelligence.internal/v1/cascades") => {
    const response = await handleIntelligenceOutbound(new Request(target, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

test("cascade D1 stores, updates and normalizes check order/defaults", async t => {
  const { call } = await database(t);
  assert.deepEqual((await call({ operation: "list" })).body.cascades, []);
  assert.equal((await call({ operation: "put", cascade: config })).status, 200);
  const updated = { ...config, checks: ["judge", "complete"], judge: { model: "free:text" } };
  assert.equal((await call({ operation: "put", cascade: updated })).status, 200);
  assert.deepEqual((await call({ operation: "list" })).body.cascades, [{ ...updated, checks: ["complete", "judge"], judge: { model: "free:text", min_score: 7 } }]);
});

test("cascade config rejects malformed bounds, nested cascades and fields", () => {
  for (const change of [{ name: "auto:bad" }, { tiers: [] }, { tiers: Array(5).fill({ model: "p:m" }) },
    { tiers: [{ model: "cascade:recursive" }, { model: "p:m" }] },
    { tiers: [{ model: "p:m", max_output_tokens: true }, { model: "p:m" }] }, { checks: ["complete", "complete"] },
    { checks: ["judge"] }, { judge: { model: "p:m", min_score: 11 } }, { judge: { model: "p:m", min_score: true } },
    { judge: { model: "p:m", min_score: NaN } }, { agreement: { extra: 1 } }, { extra: true }]) {
    assert.equal(validCascade({ ...config, ...change }), false, JSON.stringify(change));
  }
  assert.equal(validCascade({ ...config, agreement: {}, judge: { model: "gemini:explicit", min_score: 0 } }), true);
});

test("cascade private storage rejects invalid requests, bad targets and outages", async t => {
  const { call } = await database(t);
  for (const body of [{ operation: "sql", sql: "synthetic" }, { operation: "put", cascade: { ...config, tiers: [] } }, { operation: "put", cascade: config, extra: true }]) {
    assert.equal((await call(body)).status, 400);
  }
  assert.equal((await call({ operation: "list" }, {}, "http://intelligence.internal/v1/cascades?x=1")).status, 400);
  const failed = await call({ operation: "list" }, { INTELLIGENCE_DB: { prepare() { throw new Error("synthetic private details"); } } });
  assert.equal(failed.status, 503);
  assert.equal(JSON.stringify(failed.body).includes("private details"), false);
});

test("cascade storage caps creations at 200 and permits edits at capacity", async t => {
  const { call, db } = await database(t);
  await db.batch(Array.from({ length: 200 }, (_, i) => {
    const row = { ...config, name: `cascade:synthetic-${i}` };
    return db.prepare("INSERT INTO cascades VALUES (?, ?, ?)").bind(row.name, JSON.stringify(row), row.updated_at);
  }));
  assert.equal((await call({ operation: "put", cascade: config })).status, 409);
  assert.equal((await call({ operation: "put", cascade: { ...config, name: "cascade:synthetic-1" } })).status, 200);
  assert.equal((await call({ operation: "list" })).body.cascades.length, 200);
});

test("cascade receipt is exposed by edge CORS", () => {
  assert.match(CORS_EXPOSE_HEADERS, /X-MultiLLM-Cascade/);
});


test("cascade free pools validate and persist through D1", async t => {
  const { call } = await database(t);
  for (const pool of ["free:text", "free:vision"]) {
    const cascade = { ...config, tiers: [{ model: pool }, { model: "opencode:strong" }] };
    assert.equal(validCascade(cascade), true);
    assert.equal((await call({ operation: "put", cascade })).status, 200);
    assert.deepEqual((await call({ operation: "list" })).body.cascades, [cascade]);
  }
});
