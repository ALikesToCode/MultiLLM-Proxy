import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

const config = candidates => ({ routes: [{ route_id: "auto:review", candidates }] });
async function database(t, { missing = false, enabled = true } = {}) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response(\"ok\")}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, { skip: missing ? ["0015_config_snapshots.sql"] : [] });
  const env = { INTELLIGENCE_DB: db, ...(enabled ? { CONFIG_SNAPSHOTS_ENABLED: "true" } : {}) };
  const call = async body => {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/auto-routes", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  const create = async (revision, candidates = ["openai:model-a"]) => call({ operation: "snapshot_create", domain: "auto_routes", base_revision: revision, configuration: config(candidates), actor: "a".repeat(64) });
  const apply = async (id, revision, confirm = true) => call({ operation: "snapshot_apply", id, current_revision: revision, confirm, actor: "a".repeat(64) });
  return { db, env, call, create, apply };
}

test("disabled snapshots make no statements and legacy saves stay unchanged", async t => {
  const { db, call } = await database(t, { enabled: false, missing: true });
  assert.equal((await call({ operation: "snapshot_list" })).status, 404);
  const route = { operation: "put", route_id: "auto:old", candidates: ["openai:model"], updated_at: "2026-10-09T00:00:00Z" };
  assert.deepEqual((await call(route)).body, { version: 1, stored: true });
  assert.deepEqual((await call({ operation: "list" })).body.routes, [{ route_id: route.route_id, candidates: route.candidates, updated_at: route.updated_at }]);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM auto_routes").first()).n, 1);
});

test("missing migration fails closed including enabled legacy save", async t => {
  const { call, db } = await database(t, { missing: true });
  assert.equal((await call({ operation: "snapshot_list" })).status, 503);
  assert.equal((await call({ operation: "put", route_id: "auto:x", candidates: ["openai:model"], updated_at: "2026-10-09T00:00:00Z" })).status, 503);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM auto_routes").first()).n, 0);
});

test("preview is read only, concurrent CAS applies once, rollback adds history", async t => {
  const { db, call, create, apply } = await database(t);
  const [first, other] = await Promise.all([create(0), create(0, ["openai:model-b"])]);
  assert.equal(first.status, 200);
  assert.equal(other.status, 200);
  const id = first.body.snapshot.id;
  const listed = await call({ operation: "snapshot_list" });
  assert.equal(listed.body.current_revision, 0);
  assert.equal(listed.body.snapshots.length, 2);
  assert.ok(listed.body.snapshots.every(row => !Object.hasOwn(row, "configuration")));
  const diff = await call({ operation: "snapshot_diff", id });
  assert.deepEqual(diff.body.changes, [{ route_id: "auto:review", before: [], after: ["openai:model-a"] }]);
  assert.equal((await call({ operation: "list" })).body.routes.length, 0);
  assert.equal((await apply(id, 0, false)).status, 409);
  const attempts = await Promise.all([apply(id, 0), apply(other.body.snapshot.id, 0)]);
  assert.deepEqual(attempts.map(item => item.status).sort(), [200, 409]);
  const current = (await call({ operation: "list" })).body.routes[0].candidates;
  assert.equal((await create(0)).status, 409);
  const next = await create(1, ["openai:changed"]);
  assert.equal((await apply(next.body.snapshot.id, 1)).body.revision, 2);
  const rollback = await create(2, current);
  assert.equal((await apply(rollback.body.snapshot.id, 2)).body.revision, 3);
  assert.deepEqual((await call({ operation: "list" })).body.routes[0].candidates, current);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM config_snapshot_applications").first()).n, 3);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM config_snapshots").first()).n, 4);
  assert.equal((await apply(rollback.body.snapshot.id, 3)).status, 409);
});

test("ordinary enabled save invalidates pending snapshots and retains old routes", async t => {
  const { call, create, apply, db } = await database(t);
  await db.prepare("INSERT INTO auto_routes VALUES (?, ?, ?)").bind("auto:untouched", "[\"openai:old\"]", "2026-10-09T00:00:00Z").run();
  const pending = await create(0);
  assert.equal((await call({ operation: "put", route_id: "auto:ordinary", candidates: ["openai:new"], updated_at: "2026-10-09T00:00:00Z" })).status, 200);
  assert.equal((await apply(pending.body.snapshot.id, 0)).status, 409);
  const reviewed = await create(1);
  assert.equal((await apply(reviewed.body.snapshot.id, 1)).status, 200);
  assert.equal((await call({ operation: "list" })).body.routes.length, 3);
});

test("unapproved secrets and invalid configuration are rejected without persistence", async t => {
  const { create, call, db } = await database(t);
  for (const extra of ["api_key", "headers", "prompts", "connections", "env", "gateway_keys"]) {
    const result = await call({ operation: "snapshot_create", domain: "auto_routes", base_revision: 0,
      configuration: { ...config(["openai:model"]), [extra]: "synthetic-secret" }, actor: "a".repeat(64) });
    assert.equal(result.status, 400);
    assert.equal(JSON.stringify(result.body).includes("synthetic-secret"), false);
  }
  for (const models of [["openai:sk-syntheticsecret123"], ["openai:model", "openai:model"], ["auto:nested"], ["bad"], []]) {
    assert.equal((await create(0, models)).status, 400);
  }
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM config_snapshots").first()).n, 0);
});

test("snapshot count and bytes are bounded without automatic deletion", async t => {
  const { call, create, db } = await database(t);
  const huge = { routes: Array.from({ length: 200 }, (_, i) => ({ route_id: `auto:r${i}`, candidates: Array.from({ length: 16 }, (_, j) => `openai:m${j}${"x".repeat(230)}`) })) };
  assert.equal((await call({ operation: "snapshot_create", domain: "auto_routes", base_revision: 0, configuration: huge, actor: "a".repeat(64) })).status, 413);
  await db.batch(Array.from({ length: 99 }, (_, i) => db.prepare("INSERT INTO config_snapshots (id,domain,base_revision,configuration,created_at,created_by,size_bytes,base_fingerprint) VALUES (?,?,0,?,?,?,?,?)")
    .bind(i.toString(16).padStart(32, "0"), "auto_routes", JSON.stringify(config(["openai:model"])), "2026-10-09T00:00:00Z", "a".repeat(64), 79, "b".repeat(64))));
  const finalSlots = await Promise.all([create(0), create(0)]);
  assert.deepEqual(finalSlots.map(result => result.status).sort(), [200, 409]);
  assert.equal((await create(0)).status, 409);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM config_snapshots").first()).n, 100);
});

test("failed atomic apply keeps route, revision and audit unchanged", async t => {
  const { db, create, apply, call } = await database(t);
  const snapshot = await create(0);
  await db.prepare("CREATE TRIGGER refuse_route BEFORE INSERT ON auto_routes BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END").run();
  const result = await apply(snapshot.body.snapshot.id, 0);
  assert.equal(result.status, 503);
  assert.equal(JSON.stringify(result.body).includes("synthetic failure"), false);
  assert.equal((await call({ operation: "snapshot_list" })).body.current_revision, 0);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM config_snapshot_applications").first()).n, 0);
});


test("saves while disabled invalidate old reviews when re-enabled", async t => {
  const { env, call, create, apply } = await database(t);
  const pending = await create(0);
  delete env.CONFIG_SNAPSHOTS_ENABLED;
  assert.equal((await call({ operation: "put", route_id: "auto:review", candidates: ["openai:newer"], updated_at: "2026-10-09T00:00:00Z" })).status, 200);
  env.CONFIG_SNAPSHOTS_ENABLED = "true";
  assert.equal((await apply(pending.body.snapshot.id, 0)).status, 409);
  assert.deepEqual((await call({ operation: "list" })).body.routes[0].candidates, ["openai:newer"]);
});


test("apply cannot exceed the active route read bound", async t => {
  const { db, create, apply, call } = await database(t);
  await db.batch(Array.from({ length: 200 }, (_, i) => db.prepare("INSERT INTO auto_routes VALUES (?, ?, ?)")
    .bind(`auto:r${i}`, "[\"openai:model\"]", "2026-10-09T00:00:00Z")));
  const pending = await create(0);
  assert.equal((await apply(pending.body.snapshot.id, 0)).status, 409);
  assert.equal((await call({ operation: "snapshot_list" })).body.current_revision, 0);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM auto_routes").first()).n, 200);
});

test("diff pages are bounded and malformed legacy storage never leaks", async t => {
  const { db, call } = await database(t);
  const configuration = { routes: Array.from({ length: 21 }, (_, i) => ({ route_id: `auto:r${i.toString().padStart(2, "0")}`, candidates: ["openai:model"] })) };
  const made = await call({ operation: "snapshot_create", domain: "auto_routes", base_revision: 0, configuration, actor: "a".repeat(64) });
  const id = made.body.snapshot.id;
  const first = await call({ operation: "snapshot_diff", id });
  assert.equal(first.body.changes.length, 20);
  assert.equal(first.body.next_offset, 20);
  const last = await call({ operation: "snapshot_diff", id, offset: 20 });
  assert.equal(last.body.changes.length, 1);
  assert.equal(last.body.next_offset, null);
  await db.prepare("INSERT INTO auto_routes VALUES (?, ?, ?)")
    .bind("auto:r00", "[\"openai:sk-syntheticsecret123\"]", "2026-10-09T00:00:00Z").run();
  const broken = await call({ operation: "snapshot_diff", id });
  assert.equal(broken.status, 503);
  assert.equal(JSON.stringify(broken.body).includes("syntheticsecret123"), false);
});
