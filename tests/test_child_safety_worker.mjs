import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { handleControlUsersRequest } from "../worker/control-users-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true,
    script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  const env = { INTELLIGENCE_DB: db };
  const call = async (body, endpoint = "state/safety") => {
    const request = new Request(`http://intelligence.internal/v1/${endpoint}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
    });
    const response = endpoint === "users" ? await handleControlUsersRequest(request, env)
      : await handleIntelligenceOutbound(request, env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

test("screening defaults off and concurrent saves use atomic revisions", async t => {
  const { call } = await database(t);
  assert.deepEqual(await call({ operation: "get" }), { status: 200,
    body: { version: 1, settings: { enabled: false, failure_mode: "allow", revision: 0 } } });
  const saved = await Promise.all(["allow", "block"].map(failure_mode => call({
    operation: "configure", enabled: true, failure_mode, revision: 0,
  })));
  assert.deepEqual(saved.map(value => value.status).sort(), [200, 409]);
  const winner = saved.find(value => value.status === 200).body.settings;
  assert.deepEqual((await call({ operation: "get" })).body.settings, winner);
  assert.equal(winner.revision, 1);
  assert.equal((await call({ operation: "configure", enabled: false, failure_mode: "allow", revision: 1 })).status, 200);
  assert.equal((await call({ operation: "get" })).body.settings.enabled, false);
});

test("malformed settings and arbitrary operations cannot change policy", async t => {
  const { call, db } = await database(t);
  const valid = { operation: "configure", enabled: true, failure_mode: "block", revision: 0 };
  for (const change of [{ enabled: "true" }, { failure_mode: "ignore" }, { revision: -1 }, { revision: true },
    { revision: Number.MAX_SAFE_INTEGER }, { prompt: "Synthetic marker" }, { operation: "sql" }]) {
    assert.equal((await call({ ...valid, ...change })).status, 400);
  }
  assert.equal((await call({ operation: "get", extra: true })).status, 400);
  assert.equal((await db.prepare("SELECT revision FROM control_child_safety_settings").first()).revision, 0);
});

test("child-safety audit rows contain only fixed decision metadata", async t => {
  const { call, db } = await database(t);
  const metadata = { kind: "child_safety", decision: "blocked", reason: "sexual_minors", input_count: 1, revision: 3, score: 0.9 };
  const event = { operation: "audit_record", action: "safety_check", outcome: "refused", actor: "a".repeat(64),
    target: "images", detail: JSON.stringify(metadata) };
  assert.equal((await call(event, "users")).status, 200);
  for (const change of [{ actor: "private@example.com" }, { target: "https://example.com/private-image" },
    { detail: JSON.stringify({ ...metadata, prompt: "Synthetic private marker" }) },
    { detail: JSON.stringify({ ...metadata, reason: "Untrusted provider message" }) },
    { detail: JSON.stringify({ ...metadata, score: "high" }) }]) {
    assert.equal((await call({ ...event, ...change }, "users")).status, 400);
  }
  const page = await call({ operation: "audit_list", actor: null, target: null, action: "safety_check",
    before_account: null, before_event: null, limit: 50 }, "users");
  assert.equal(page.status, 200);
  assert.equal(page.body.entries.length, 1);
  assert.equal(page.body.entries[0].action, "safety_check");
  assert.deepEqual(JSON.parse(page.body.entries[0].detail), metadata);
  const row = await db.prepare("SELECT action, detail FROM control_audit_events").first();
  assert.equal(row.action, "setting_change");
  assert.deepEqual(JSON.parse(row.detail), metadata);
});
