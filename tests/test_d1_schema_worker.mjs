import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { d1Readiness, REQUIRED_D1_TABLES } from "../worker/d1-schema.mjs";
import { applyMigrations, migrationNames } from "./d1_migrations.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

async function database(t, options) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}",
    d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, options);
  return db;
}

test("readiness checks every table the migrations create", async () => {
  const created = [];
  for (const name of await migrationNames()) {
    const sql = await readFile(new URL(`../intelligence-migrations/${name}`, import.meta.url), "utf8");
    created.push(...[...sql.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map(match => match[1]));
  }
  assert.deepEqual([...REQUIRED_D1_TABLES].sort(), created.sort());
});

test("/ready reports a D1 schema that was never migrated instead of forwarding", async t => {
  const worker = (await loadWorkerModule()).default;
  let forwarded = 0;
  const container = { getByName: () => ({ fetch: async () => { forwarded += 1; return Response.json({ status: "healthy" }); } }) };
  // 0007 alters control_users, so skipping 0003 skips it too.
  const partial = await database(t, { skip: ["0003_control_users.sql", "0005_auto_routes.sql", "0007_usage_ledger.sql"] });
  assert.deepEqual(await d1Readiness(partial), { ready: false, checked: true, missing: ["control_users", "auto_routes", "usage_events", "usage_daily", "usage_batches"] });
  const blocked = await worker.fetch(new Request("https://gateway.example/ready"), { INTELLIGENCE_DB: partial, MULTILLM_PROXY_CONTAINER: container });
  assert.equal(blocked.status, 503);
  assert.deepEqual(await blocked.json(), { status: "not_ready", reason: "d1_schema_missing", missing_tables: ["control_users", "auto_routes", "usage_events", "usage_daily", "usage_batches"] });
  assert.equal(forwarded, 0);
  const complete = await database(t);
  const ready = await worker.fetch(new Request("https://gateway.example/ready"), { INTELLIGENCE_DB: complete, MULTILLM_PROXY_CONTAINER: container });
  assert.equal(ready.status, 200);
  assert.equal(forwarded, 1);
  const broken = { prepare() { throw new Error("D1_ERROR: storage unavailable"); } };
  const unavailable = await worker.fetch(new Request("https://gateway.example/ready"), { INTELLIGENCE_DB: broken, MULTILLM_PROXY_CONTAINER: container });
  assert.equal((await unavailable.json()).reason, "d1_unavailable");
});

test("the deploy guard stops when any migration file is not applied remotely", async () => {
  const { appliedFromWrangler, pendingMigrations } = await import("../scripts/verify_d1_migrations.mjs");
  const files = await migrationNames();
  const output = JSON.stringify([{ success: true, results: files.slice(0, 3).map(name => ({ name })), meta: {} }]);
  assert.deepEqual(pendingMigrations(files, appliedFromWrangler(output)), files.slice(3));
  assert.deepEqual(pendingMigrations(files, files), []);
  assert.throws(() => appliedFromWrangler(JSON.stringify([{ success: false, results: [] }])));
});
