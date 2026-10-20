import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

const hash = character => character.repeat(64);
const id = character => character.repeat(32);

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  const call = async (domain, body, env = { INTELLIGENCE_DB: db }) => {
    const response = await handleIntelligenceOutbound(new Request(`http://intelligence.internal/v1/state/${domain}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

test("usage increments are shared across ledgers, exclude the reader's own, and count once per flush", async t => {
  const { db, call } = await database(t);
  const minute = Math.floor(Date.now() / 60000);
  const increment = { identity: hash("a"), provider: "openai", minute, requests: 3, tokens: 300 };
  const sync = (instance, flush, increments, read = [], prune = false) => call("limits",
    { operation: "sync", instance, flush_id: flush, increments, read, prune });
  assert.equal((await sync(id("1"), id("f"), [increment, { ...increment, minute: minute - 1, requests: 2, tokens: 50 }])).status, 200);
  // The same flush sent again after a lost reply adds nothing.
  assert.equal((await sync(id("1"), id("f"), [increment])).status, 200);
  await sync(id("2"), id("e"), [{ ...increment, requests: 1, tokens: 10 }]);
  const key = { identity: hash("a"), provider: "openai" };
  const other = await sync(id("3"), null, [], [key]);
  assert.equal(other.status, 200);
  const [usage] = other.body.usage;
  assert.equal(Math.abs(other.body.minute - minute) <= 1, true);
  if (other.body.minute === minute) {
    assert.deepEqual(usage, { ...key, current_requests: 4, current_tokens: 310, previous_requests: 2, previous_tokens: 50, day_requests: 6 });
  }
  const own = (await sync(id("1"), null, [], [key])).body.usage[0];
  assert.equal(own.day_requests, 1, "a ledger reads only the usage the others recorded");
  const rows = (await db.prepare("SELECT COUNT(*) AS count FROM control_rate_flushes").first()).count;
  assert.equal(rows, 2);
  await db.prepare("INSERT INTO control_rate_usage (identity, provider, span, bucket, instance, requests, tokens) VALUES (?, 'openai', 60, ?, ?, 1, 1)")
    .bind(hash("b"), minute - 30, id("9")).run();
  assert.equal((await sync(id("3"), null, [], [], true)).status, 200);
  assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM control_rate_usage WHERE identity = ?").bind(hash("b")).first()).count, 0);
});

test("usage syncs are validated before any statement runs", async t => {
  const { call } = await database(t);
  const minute = Math.floor(Date.now() / 60000);
  const valid = { operation: "sync", instance: id("1"), flush_id: id("f"),
    increments: [{ identity: hash("a"), provider: "openai", minute, requests: 1, tokens: 0 }], read: [], prune: false };
  for (const change of [{ instance: "short" }, { flush_id: null }, { increments: [] }, { read: [{ identity: "raw-user", provider: "openai" }] },
    { increments: [{ ...valid.increments[0], minute: minute + 60 }] }, { increments: [{ ...valid.increments[0], requests: -1 }] },
    { increments: [{ ...valid.increments[0], identity: [hash("a")] }] }, { increments: Array(13).fill(valid.increments[0]) },
    { prune: "yes" }, { extra: true }]) {
    assert.equal((await call("limits", { ...valid, ...change })).status, 400, JSON.stringify(change));
  }
  assert.equal((await call("limits", valid)).status, 200);
});

test("login failures lock an identity atomically, keep a running lock, and clear on success", async t => {
  const { call } = await database(t);
  const failure = now => call("login", { operation: "failure", identity: hash("c"), now, max_attempts: 3,
    window_seconds: 60, lockout_seconds: 120, retention_seconds: 240 });
  assert.deepEqual((await failure(10)).body.state, { failures: 1, window_started: 10, locked_until: 0 });
  assert.deepEqual((await failure(11)).body.state, { failures: 2, window_started: 10, locked_until: 0 });
  assert.deepEqual((await failure(12)).body.state, { failures: 3, window_started: 10, locked_until: 132 });
  assert.deepEqual((await failure(20)).body.state, { failures: 3, window_started: 10, locked_until: 132 }, "a lock is not extended");
  assert.equal((await call("login", { operation: "check", identity: hash("c") })).body.state.locked_until, 132);
  assert.deepEqual((await failure(300)).body.state, { failures: 1, window_started: 300, locked_until: 0 }, "an expired window restarts");
  assert.deepEqual((await call("login", { operation: "success", identity: hash("c") })).body, { version: 1, deleted: true });
  assert.deepEqual((await call("login", { operation: "check", identity: hash("c") })).body, { version: 1, state: null });
  assert.equal((await call("login", { operation: "check", identity: "user@example" })).status, 400);
  assert.equal((await call("login", { operation: "failure", identity: hash("c"), now: 1, max_attempts: 0,
    window_seconds: 60, lockout_seconds: 120, retention_seconds: 240 })).status, 400);
});

test("model overrides and free-route cooldowns persist with validation", async t => {
  const { call } = await database(t);
  const put = body => call("models", { operation: "put", updated_at: "2026-09-26T00:00:00Z", ...body });
  assert.equal((await put({ model_id: "openai:gpt-4.1", status: "disabled" })).status, 200);
  assert.deepEqual((await call("models", { operation: "list" })).body.overrides, [{ model_id: "openai:gpt-4.1", status: "disabled" }]);
  for (const body of [{ model_id: "no-provider", status: "disabled" }, { model_id: "openai:x", status: "deleted" }, { model_id: "openai:bad id", status: "disabled" }]) {
    assert.equal((await put(body)).status, 400, JSON.stringify(body));
  }
  const now = Date.now() / 1000;
  const block = cooldowns => call("quotas", { operation: "block", cooldowns });
  assert.deepEqual((await block([{ scope: "provider:groq", blocked_until: now + 120 }, { scope: "model:groq:llama", blocked_until: now - 5 }])).body,
    { version: 1, stored: 2 });
  await block([{ scope: "provider:groq", blocked_until: now + 10 }]);
  assert.deepEqual((await call("quotas", { operation: "list" })).body.cooldowns, [{ scope: "provider:groq", blocked_until: now + 120 }],
    "a shorter cooldown never replaces a longer one, and expired ones are not listed");
  for (const cooldowns of [[], [{ scope: "account:x", blocked_until: now }], [{ scope: "provider:groq", blocked_until: now + 30 * 86400 }]]) {
    assert.equal((await block(cooldowns)).status, 400, JSON.stringify(cooldowns));
  }
});

test("workbench profiles and reports are owner-scoped and limited atomically", async t => {
  const { call } = await database(t);
  const settings = { name: "Flash", kind: "roleplay", provider: "nanogpt", model: "z-ai/glm-5.3-flash", mode: "pinned",
    effort: "high", billing: "configured", fallback: "none", memory: "auto", recovery: "off" };
  const save = (owner, index) => call("workbench", { operation: "save_profile", owner, id: index.toString(16).padStart(32, "0"),
    settings, created_at: 1000 + index });
  const results = await Promise.all(Array.from({ length: 52 }, (_, index) => save("owner", index)));
  assert.equal(results.filter(result => result.status === 200).length, 50);
  assert.deepEqual(results.filter(result => result.status === 409).map(result => result.body.error.code), ["limit_reached", "limit_reached"]);
  const listed = (await call("workbench", { operation: "profiles", owner: "owner" })).body.profiles;
  assert.equal(listed.length, 50);
  assert.deepEqual(listed[0].settings, settings);
  assert.deepEqual((await call("workbench", { operation: "profiles", owner: "other" })).body.profiles, []);
  assert.equal((await call("workbench", { operation: "save_profile", owner: "o", id: id("a"), settings: { ...settings, api_key: "x" },
    created_at: 1 })).status, 400);
  const data = [{ provider: "nanogpt", rating: 4 }, { provider: "nanogpt", rating: 5 }];
  assert.equal((await call("workbench", { operation: "save_report", owner: "owner", id: id("b"), data, created_at: 5 })).status, 200);
  assert.deepEqual((await call("workbench", { operation: "reports", owner: "owner" })).body.reports, [{ id: id("b"), created_at: 5, data }]);
  assert.equal((await call("workbench", { operation: "save_report", owner: "owner", id: id("c"), data: [data[0]], created_at: 5 })).status, 400);
});

test("catalog snapshots are split into chunks and read back whole", async t => {
  const { db, call } = await database(t);
  const data = Buffer.from(Array.from({ length: 150000 }, (_, index) => index % 251)).toString("base64");
  assert.equal((await call("catalog", { operation: "put", provider: "nanogpt", updated_at: "2026-09-26T00:00:00Z", data })).status, 200);
  assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM control_provider_catalog").first()).count, Math.ceil(data.length / 60000));
  assert.deepEqual((await call("catalog", { operation: "list" })).body.snapshots, [{ provider: "nanogpt", updated_at: "2026-09-26T00:00:00Z" }]);
  assert.deepEqual((await call("catalog", { operation: "get", provider: "nanogpt" })).body.snapshot,
    { provider: "nanogpt", updated_at: "2026-09-26T00:00:00Z", data });
  await call("catalog", { operation: "put", provider: "nanogpt", updated_at: "2026-09-26T01:00:00Z", data: "AAAA" });
  assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM control_provider_catalog").first()).count, 1, "a replacement removes old chunks");
  assert.deepEqual((await call("catalog", { operation: "get", provider: "openai" })).body, { version: 1, snapshot: null });
  for (const change of [{ data: "not base64!" }, { data: "A".repeat(240004) }, { provider: "Bad Provider" }]) {
    assert.equal((await call("catalog", { operation: "put", provider: "nanogpt", updated_at: "2026-09-26T00:00:00Z", data: "AAAA", ...change })).status,
      400, JSON.stringify(change).slice(0, 60));
  }
});

test("control state rejects unknown domains, SQL and oversized bodies, and keeps storage errors private", async t => {
  const { call } = await database(t);
  assert.equal((await call("unknown", { operation: "list" })).status, 404);
  assert.equal((await call("constructor", { operation: "list" })).status, 404);
  assert.equal((await call("models", { operation: "sql", statement: "DROP TABLE control_model_overrides" })).status, 400);
  const oversized = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/state/login", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "check", pad: "x".repeat(5000) }) }),
  { INTELLIGENCE_DB: {} });
  assert.equal(oversized.status, 400);
  assert.equal((await call("models", { operation: "list" }, {})).status, 503);
  const broken = await call("models", { operation: "list" }, { INTELLIGENCE_DB: { prepare() { throw new Error("private database detail"); } } });
  assert.equal(broken.status, 503);
  assert.equal(JSON.stringify(broken.body).includes("private"), false);
});
