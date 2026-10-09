import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { handleIdempotencyRequest } from "../worker/idempotency-d1.mjs";
import { handleManagedStateRequest } from "../worker/managed-state-dispatch.mjs";

const MIGRATION = new URL("../intelligence-migrations/0023_idempotency.sql", import.meta.url);
const scope = "a".repeat(64), digest = "b".repeat(64), owner = "c".repeat(32);
const body = (operation, changes = {}) => ({ version: 1, operation, scope, digest, owner, ...changes });
function fixture(t, missing = false, dispatch = handleIntelligenceOutbound) {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  sqlite.exec("CREATE TABLE existing_usage (amount INTEGER); INSERT INTO existing_usage VALUES (9)");
  if (!missing) { sqlite.exec(readFileSync(MIGRATION, "utf8")); sqlite.exec(readFileSync(MIGRATION, "utf8")); }
  const wrap = (sql, values = []) => ({ bind: (...values) => wrap(sql, values),
    async first() { return sqlite.prepare(sql).get(...values) ?? null; },
    async all() { return { results: sqlite.prepare(sql).all(...values) }; },
    async run() { const result = sqlite.prepare(sql).run(...values); return { meta: { changes: Number(result.changes) } }; } });
  const objects = new Map();
  const bucket = { async put(key, value) { objects.set(key, value); }, async get(key) {
    const value = objects.get(key); return value === undefined ? null : { size: new TextEncoder().encode(value).length, async text() { return value; } };
  }, async delete(key) { objects.delete(key); } };
  const env = { MANAGED_IDEMPOTENCY_ENABLED: "true", INTELLIGENCE_DB: { prepare: wrap, async batch(statements) {
    sqlite.exec("BEGIN"); try { const results = []; for (const statement of statements) results.push(await statement.all()); sqlite.exec("COMMIT"); return results; }
    catch (error) { sqlite.exec("ROLLBACK"); throw error; }
  } }, multillm_media: bucket };
  const call = async (payload, target = env, path = "/v1/managed-state/idempotency") => {
    const response = await dispatch(new Request(`http://intelligence.internal${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }), target);
    return { status: response.status, data: await response.json() };
  };
  return { sqlite, env, objects, call };
}
const response = { status: 200, headers: [["Content-Type", "application/json"]], body: btoa('{"choices":[1]}') };

test("private registered path atomically admits one owner and preserves old data", async t => {
  const { call, sqlite } = fixture(t);
  const claims = await Promise.all([call(body("claim")), call(body("claim", { owner: "d".repeat(32) }))]);
  assert.deepEqual(claims.map(item => item.data.result.status).sort(), ["claimed", "pending"]);
  assert.equal(sqlite.prepare("SELECT amount FROM existing_usage").get().amount, 9);
  assert.equal((await call(body("claim", { digest: "f".repeat(64) }))).data.result.status, "conflict");
  assert.equal((await call(body("claim", { scope: "e".repeat(64) }))).data.result.status, "claimed");
});

test("completion CAS persists exact bounded response and replays across instances", async t => {
  const { call, objects } = fixture(t);
  await call(body("claim"));
  assert.equal((await call(body("handoff"))).data.result.changed, true);
  assert.equal((await call(body("complete", { response }))).data.result.changed, true);
  assert.equal(objects.size, 1);
  const replay = await call(body("claim", { owner: "e".repeat(32) }));
  assert.deepEqual(replay.data.result, { status: "completed", response });
  assert.equal((await call(body("unknown"))).data.result.changed, false);
});

test("wrong owner and repeated handoff never authorize another submission", async t => {
  const { call } = fixture(t);
  await call(body("claim"));
  assert.equal((await call(body("handoff", { owner: "d".repeat(32) }))).data.result.changed, false);
  assert.equal((await call(body("handoff"))).data.result.changed, true);
  assert.equal((await call(body("handoff"))).data.result.changed, false);
  assert.equal((await call(body("complete", { owner: "d".repeat(32), response }))).data.result.changed, false);
});

test("ambiguity, stalled claims and expired results never reclaim a key", async t => {
  const { call, sqlite, objects } = fixture(t);
  await call(body("claim"));
  await call(body("handoff"));
  await call(body("unknown"));
  assert.equal((await call(body("claim"))).data.result.status, "unknown");
  sqlite.prepare("UPDATE managed_idempotency SET expires_at=0, pending_until=0").run();
  assert.equal((await call(body("claim"))).data.result.status, "unknown");
  await call(body("claim", { scope: "e".repeat(64) }));
  sqlite.prepare("UPDATE managed_idempotency SET pending_until=0 WHERE scope=?").run("e".repeat(64));
  assert.equal((await call(body("claim", { scope: "e".repeat(64) }))).data.result.status, "unknown");
  assert.equal(objects.size, 0);
});

test("expired completion and missing R2 response are unknown rather than regenerated", async t => {
  const { call, sqlite, objects } = fixture(t);
  await call(body("claim")); await call(body("handoff")); await call(body("complete", { response }));
  objects.clear();
  assert.equal((await call(body("claim"))).data.result.status, "unknown");
  assert.equal(sqlite.prepare("SELECT status FROM managed_idempotency").get().status, "unknown");
  const scope2 = "e".repeat(64);
  await call(body("claim", { scope: scope2 })); await call(body("handoff", { scope: scope2 })); await call(body("complete", { scope: scope2, response }));
  sqlite.prepare("UPDATE managed_idempotency SET expires_at=0 WHERE scope=?").run(scope2);
  assert.equal((await call(body("claim", { scope: scope2 }))).data.result.status, "unknown");
  assert.equal(objects.size, 0);
});

test("response limits and unsafe headers fail before content storage", async t => {
  const { call, objects } = fixture(t);
  await call(body("claim")); await call(body("handoff"));
  for (const invalid of [ { ...response, body: btoa("x".repeat(1048577)) }, { ...response, headers: [["Set-Cookie", "private"]] },
    { ...response, status: 502 }, { ...response, body: "invalid-base64!" } ]) {
    assert.equal((await call(body("complete", { response: invalid }))).status, 400);
  }
  assert.equal(objects.size, 0);
});

test("disabled flags perform no storage; missing migration and R2 fail closed", async t => {
  const { call, env } = fixture(t, true);
  for (const flag of [undefined, "", "false", "garbage"]) assert.equal((await call(body("claim"), { MANAGED_IDEMPOTENCY_ENABLED: flag })).status, 404);
  assert.equal((await call(body("claim"))).status, 503);
  assert.equal((await call(body("claim"), { ...env, multillm_media: undefined })).status, 503);
});

test("private boundary rejects unreviewed domains and accepts only injected sibling handlers", async () => {
  const request = path => new Request(`http://intelligence.internal${path}`, { method: "POST" });
  assert.equal(await handleManagedStateRequest(request("/v1/state/models"), {}), null);
  for (const path of ["/v1/managed-state/reservations", "/v1/managed-state/tool-grants", "/v1/managed-state/unknown"])
    assert.equal((await handleManagedStateRequest(request(path), {})).status, 404);
  const called = [];
  const handlers = { reservations: async () => { called.push("reservations"); return Response.json({ ok: true }); },
    toolGrants: async () => { called.push("grants"); return Response.json({ ok: true }); } };
  assert.equal((await handleManagedStateRequest(request("/v1/managed-state/reservations"), {}, handlers)).status, 200);
  assert.equal((await handleManagedStateRequest(request("/v1/managed-state/tool-grants"), {}, handlers)).status, 200);
  assert.deepEqual(called, ["reservations", "grants"]);
});


test("durable authority claims, handoff, exact replay and principal isolation without hub registration", async t => {
  const { call, env, sqlite, objects } = fixture(t, false, handleIdempotencyRequest);
  const claims = await Promise.all([call(body("claim")), call(body("claim", { owner: "d".repeat(32) }))]);
  assert.deepEqual(claims.map(item => item.data.result.status).sort(), ["claimed", "pending"]);
  assert.equal((await call(body("claim", { digest: "f".repeat(64) }))).data.result.status, "conflict");
  assert.equal((await call(body("claim", { scope: "e".repeat(64) }))).data.result.status, "claimed");
  assert.equal((await call(body("handoff"))).data.result.changed, true);
  assert.equal((await call(body("handoff"))).data.result.changed, false);
  assert.equal((await call(body("complete", { response }))).data.result.changed, true);
  assert.deepEqual((await call(body("claim"))).data.result, { status: "completed", response });
  assert.equal(objects.size, 1);
  sqlite.prepare("UPDATE managed_idempotency SET expires_at=0").run();
  assert.equal((await call(body("claim"))).data.result.status, "unknown");
  assert.equal(objects.size, 0);
  assert.equal((await call(body("handoff"))).data.result.changed, false);
  assert.equal((await call(body("claim"), { ...env, multillm_media: undefined })).status, 503);
});

test("authority validates one-MiB boundary, integrity, failure and pending expiry without hub registration", async t => {
  const { call, sqlite, objects, env } = fixture(t, false, handleIdempotencyRequest);
  await call(body("claim")); await call(body("handoff"));
  const atLimit = { ...response, body: btoa("x".repeat(1048576)) };
  assert.equal((await call(body("complete", { response: { ...atLimit, body: btoa("x".repeat(1048577)) } }))).status, 400);
  assert.equal((await call(body("complete", { response: atLimit }))).status, 200);
  assert.deepEqual((await call(body("claim"))).data.result.response, atLimit);
  objects.set([...objects.keys()][0], "corrupt content");
  assert.equal((await call(body("claim"))).data.result.status, "unknown");
  const other = "e".repeat(64);
  await call(body("claim", { scope: other }));
  sqlite.prepare("UPDATE managed_idempotency SET pending_until=0 WHERE scope=?").run(other);
  assert.equal((await call(body("claim", { scope: other }))).data.result.status, "unknown");
  for (const invalid of [{ ...response, headers: [["Set-Cookie", "private"]] }, { ...response, status: 502 }, { ...response, body: "bad!" }])
    assert.equal((await call(body("complete", { response: invalid }))).status, 400);
  for (const flag of [undefined, "", "false", "invalid"]) assert.equal((await call(body("claim"), { MANAGED_IDEMPOTENCY_ENABLED: flag })).status, 404);
  env.multillm_media.put = async () => { throw new Error("private storage detail"); };
  const third = "f".repeat(64);
  await call(body("claim", { scope: third })); await call(body("handoff", { scope: third }));
  const failed = await call(body("complete", { scope: third, response }));
  assert.equal(failed.status, 503);
  assert.ok(!JSON.stringify(failed.data).includes("private storage detail"));
  assert.equal((await call(body("claim", { scope: third }))).data.result.status, "pending");
});
