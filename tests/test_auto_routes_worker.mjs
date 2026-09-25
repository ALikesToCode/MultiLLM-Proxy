import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  const call = async (body, env = { INTELLIGENCE_DB: db }) => {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/auto-routes", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

test("auto routes persist in D1 and replace a route's candidates in order", async t => {
  const { call } = await database(t);
  assert.deepEqual((await call({ operation: "list" })).body.routes, []);
  const route = { route_id: "auto:gpt-image-2.5", candidates: ["gguu:gpt-image-2.5", "openai:gpt-image-2.5"], updated_at: "2026-09-25T00:00:00+00:00" };
  assert.equal((await call({ operation: "put", ...route })).status, 200);
  await call({ operation: "put", ...route, candidates: ["openai:gpt-image-2.5", "gguu:gpt-image-2.5"], updated_at: "2026-09-25T01:00:00+00:00" });
  assert.deepEqual((await call({ operation: "list" })).body.routes, [{ route_id: "auto:gpt-image-2.5",
    candidates: ["openai:gpt-image-2.5", "gguu:gpt-image-2.5"], updated_at: "2026-09-25T01:00:00+00:00" }]);
});

test("auto route writes are validated before any statement runs and storage errors stay private", async t => {
  const { call } = await database(t);
  const valid = { route_id: "auto:x", candidates: ["nanogpt:glm-5.2"], updated_at: "2026-09-25T00:00:00Z" };
  for (const change of [{ route_id: "gpt:x" }, { candidates: [] }, { candidates: ["a:b", "a:b"] }, { candidates: Array(17).fill(0).map((_, i) => `p:m${i}`) },
    { candidates: ["bad model"] }, { updated_at: "yesterday" }, { extra: true }]) {
    assert.equal((await call({ operation: "put", ...valid, ...change })).status, 400, JSON.stringify(change));
  }
  assert.equal((await call({ operation: "sql", statement: "DROP TABLE auto_routes" })).status, 400);
  const broken = await call({ operation: "list" }, { INTELLIGENCE_DB: { prepare() { throw new Error("private database detail"); } } });
  assert.equal(broken.status, 503);
  assert.equal(JSON.stringify(broken.body).includes("private"), false);
});
