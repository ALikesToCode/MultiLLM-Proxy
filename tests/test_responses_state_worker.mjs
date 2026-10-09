import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { ID_PREFIX, MAX_STATE_BYTES, responsesStateEnabled } from "../worker/responses-state-d1.mjs";

const owner = "a".repeat(64), id = ID_PREFIX + "b".repeat(32);
const document = { input: [{ role: "user", content: "one" }], response: { id, object: "response", status: "completed",
  output: [{ type: "function_call", call_id: "call_1", name: "f", arguments: "{}", status: "completed" }], usage: null } };
const payload = (operation, changes = {}) => ({ version: 1, operation, owner, id, ...changes });
const completion = (changes = {}) => payload("put", { provider: "opencode", model: "grok-4.6", parent_id: null,
  policy_revision: "c".repeat(64), depth: 1, document, ...changes });

function fixture(t, missing = false) {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  sqlite.exec("CREATE TABLE old_rows (n INTEGER); INSERT INTO old_rows VALUES (7)");
  if (!missing) {
    const sql = readFileSync(new URL("../intelligence-migrations/0028_responses_state.sql", import.meta.url), "utf8");
    sqlite.exec(sql); sqlite.exec(sql);
  }
  const wrap = (sql, values = []) => ({ bind: (...args) => wrap(sql, args),
    async first() { return sqlite.prepare(sql).get(...values) ?? null; },
    async run() { return { meta: { changes: Number(sqlite.prepare(sql).run(...values).changes) } }; } });
  const objects = new Map(), deleted = [];
  const bucket = { async head() { return null; }, async put(key, value) { objects.set(key, value); },
    async get(key) { const value = objects.get(key); return value === undefined ? null : {
      size: new TextEncoder().encode(value).length, async text() { return value; } }; },
    async delete(key) { deleted.push(key); objects.delete(key); } };
  const env = { HOSTED_RESPONSES_ENABLED: "true", INTELLIGENCE_DB: { prepare: wrap }, multillm_media: bucket };
  const call = async (body, target = env, url = "http://intelligence.internal/v1/managed-state/responses") => {
    const response = await handleIntelligenceOutbound(new Request(url, { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify(body) }), target);
    return { status: response.status, data: await response.json() };
  };
  return { call, env, sqlite, objects, deleted };
}

test("registered private probe fails closed for missing migration and bindings", async t => {
  const { call, env, sqlite } = fixture(t, true);
  assert.equal((await call({ version: 1, operation: "probe" })).status, 503);
  sqlite.exec("CREATE TABLE hosted_responses (id TEXT)");
  assert.equal((await call({ version: 1, operation: "probe" })).status, 503);
  for (const key of ["INTELLIGENCE_DB", "multillm_media"])
    assert.equal((await call({ version: 1, operation: "probe" }, { ...env, [key]: undefined })).status, 503);
});

test("disabled and malformed flags never access state", async t => {
  const { call } = fixture(t);
  for (const flag of [undefined, "", "false", "off", "malformed"])
    assert.equal((await call({ version: 1, operation: "probe" }, { HOSTED_RESPONSES_ENABLED: flag })).status, 404);
  assert.equal(responsesStateEnabled({ HOSTED_RESPONSES_ENABLED: "true" }), true);
});

test("completed object preserves order, ownership, metadata and old rows", async t => {
  const { call, sqlite, objects } = fixture(t);
  assert.equal((await call({ version: 1, operation: "probe" })).data.result.ready, true);
  assert.equal((await call(completion())).data.result.stored, true);
  const found = (await call(payload("get"))).data.result.state;
  assert.deepEqual(found.document, document);
  assert.equal(found.depth, 1); assert.equal(found.owner, owner);
  const row = sqlite.prepare("SELECT * FROM hosted_responses").get();
  assert.equal(row.status, "completed"); assert.equal(row.expires_at - row.created_at, 86400);
  assert.match(row.body_key, /^responses-state\//); assert.match(row.body_sha256, /^[0-9a-f]{64}$/);
  assert.equal(row.body_bytes, new TextEncoder().encode([...objects.values()][0]).length);
  assert.equal(sqlite.prepare("SELECT n FROM old_rows").get().n, 7);
});

test("foreign read and delete never reveal or remove owner content", async t => {
  const { call, objects } = fixture(t);
  await call(completion());
  assert.equal((await call(payload("get", { owner: "d".repeat(64) }))).data.result.state, null);
  assert.equal((await call(payload("delete", { owner: "d".repeat(64) }))).data.result.deleted, false);
  assert.equal(objects.size, 1);
  assert.equal((await call(payload("delete"))).data.result.deleted, true);
  assert.equal(objects.size, 0);
  assert.equal((await call(payload("get"))).data.result.state, null);
});

test("expired content is inaccessible; expiry alone may remove it", async t => {
  const { call, sqlite, objects } = fixture(t);
  await call(completion());
  sqlite.prepare("UPDATE hosted_responses SET expires_at=0").run();
  assert.equal((await call(payload("get"))).data.result.state, null);
  assert.equal(objects.size, 0);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM hosted_responses").get().n, 0);
});

test("incomplete, invalid and oversized state is rejected before storage", async t => {
  const { call, objects } = fixture(t);
  for (const invalid of [completion({ depth: 17 }), completion({ depth: 0 }), completion({ parent_id: "resp_native" }),
    completion({ document: { ...document, response: { ...document.response, status: "incomplete" } } }),
    completion({ document: { ...document, response: { ...document.response, error: { message: "failure" } } } }),
    completion({ document: { ...document, input: [{ role: "user", content: "x".repeat(MAX_STATE_BYTES) }] } })])
    assert.equal((await call(invalid)).status, 400);
  assert.equal(objects.size, 0);
});

test("concurrent identical completions are idempotent and conflicting content cannot replace a winner", async t => {
  const { call, objects } = fixture(t);
  const results = await Promise.all([call(completion()), call(completion())]);
  assert.ok(results.every(result => result.data.result.stored));
  assert.equal(objects.size, 1);
  assert.equal((await call(completion({ model: "different" }))).status, 409);
  assert.deepEqual((await call(payload("get"))).data.result.state.document, document);
});

test("corrupt or absent objects fail visibly without automatic deletion or regeneration", async t => {
  const { call, objects, deleted } = fixture(t);
  await call(completion());
  objects.set([...objects.keys()][0], "corrupt");
  assert.equal((await call(payload("get"))).status, 503);
  assert.equal(deleted.length, 0);
  objects.clear();
  assert.equal((await call(payload("get"))).status, 503);
});

test("R2 write, read and delete failures are sanitized and preserve recoverable metadata", async t => {
  const { call, env, sqlite } = fixture(t);
  const bucket = env.multillm_media;
  assert.equal((await call(completion(), { ...env, multillm_media: { ...bucket, put() { throw Error("private detail"); } } })).status, 503);
  assert.equal(sqlite.prepare("SELECT status FROM hosted_responses").get().status, "writing");
  assert.equal((await call(payload("get"))).data.result.state, null);
  await call(completion());
  for (const [operation, method] of [["get", "get"], ["delete", "delete"]]) {
    const result = await call(payload(operation), { ...env, multillm_media: { ...bucket, [method]() { throw Error("private detail"); } } });
    assert.equal(result.status, 503); assert.ok(!JSON.stringify(result).includes("private detail"));
    assert.equal(sqlite.prepare("SELECT count(*) AS n FROM hosted_responses").get().n, 1);
  }
});

test("only the fixed private path and versioned operations are accepted", async t => {
  const { call } = fixture(t);
  for (const url of ["https://external.invalid/v1/managed-state/responses", "http://intelligence.internal/v1/managed-state/responses?q=1"])
    assert.equal((await call(payload("get"), undefined, url)).status, 400);
  for (const body of [payload("replay"), payload("get", { id: "resp_native" }), payload("get", { extra: true }), { version: 2, operation: "probe" }])
    assert.equal((await call(body)).status, 400);
});

test("same owner continuation verifies parent and chain depth", async t => {
  const { call } = fixture(t);
  await call(completion());
  const child = ID_PREFIX + "e".repeat(32);
  const next = completion({ id: child, parent_id: id, depth: 2,
    document: { input: [...document.input, ...document.response.output, { type: "function_call_output", call_id: "call_1", output: "result" }],
      response: { ...document.response, id: child, previous_response_id: id } } });
  assert.equal((await call({ ...next, depth: 3 })).status, 404);
  assert.equal((await call({ ...next, owner: "f".repeat(64) })).status, 404);
  assert.equal((await call(next)).status, 200);
  const row = (await call(payload("get", { id: child }))).data.result.state;
  assert.equal(row.parent_id, id); assert.equal(row.depth, 2);
  assert.deepEqual(row.document, next.document);
});

test("expiry during a storage write cannot publish completed state", async t => {
  const { call, env, sqlite } = fixture(t);
  const clock = Date.now;
  const instant = clock();
  t.after(() => { Date.now = clock; });
  Date.now = () => instant;
  const bucket = env.multillm_media;
  const late = { ...bucket, async put(...args) { await bucket.put(...args); Date.now = () => instant + 20; } };
  assert.equal((await call(completion({ deadline_ms: instant - 1 }))).status, 503);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM hosted_responses").get().n, 0);
  assert.equal((await call(completion({ deadline_ms: instant + 10 }), { ...env, multillm_media: late })).status, 503);
  assert.equal(sqlite.prepare("SELECT status FROM hosted_responses").get().status, "writing");
  assert.equal((await call(payload("get"))).data.result.state, null);
});

test("cancellation failure marker hides completed content without deleting it", async t => {
  const { call, objects } = fixture(t);
  await call(completion());
  assert.equal((await call(payload("fail", { owner: "d".repeat(64) }))).data.result.failed, false);
  assert.equal((await call(payload("fail"))).data.result.failed, true);
  assert.equal((await call(payload("get"))).data.result.state, null);
  assert.equal(objects.size, 1);
  assert.equal((await call(completion())).status, 409);
  assert.equal((await call(payload("delete"))).data.result.deleted, true);
  assert.equal(objects.size, 0);
});

test("explicit deletion racing an unpublished body removes the late object", async t => {
  const { call, env, objects, sqlite } = fixture(t);
  let started, release;
  const began = new Promise(resolve => { started = resolve; });
  const ready = new Promise(resolve => { release = resolve; });
  const bucket = env.multillm_media;
  const slow = { ...bucket, async put(...args) { started(); await ready; return bucket.put(...args); } };
  const write = call(completion(), { ...env, multillm_media: slow });
  await began;
  assert.equal((await call(payload("delete"))).data.result.deleted, true);
  release();
  assert.equal((await write).status, 503);
  assert.equal(objects.size, 0);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM hosted_responses").get().n, 0);
});

test("expiry during completion CAS leaves an inaccessible failed state", async t => {
  const { call, env, sqlite } = fixture(t);
  const originalClock = Date.now, instant = originalClock();
  t.after(() => { Date.now = originalClock; });
  Date.now = () => instant;
  const db = env.INTELLIGENCE_DB;
  const delayed = { prepare(sql) {
    const stmt = db.prepare(sql);
    if (!sql.startsWith("UPDATE hosted_responses SET status='completed'")) return stmt;
    return { bind(...values) { const bound = stmt.bind(...values); return { async run() {
      const result = await bound.run(); Date.now = () => instant + 20; return result;
    } }; } };
  } };
  assert.equal((await call(completion({ deadline_ms: instant + 10 }), { ...env, INTELLIGENCE_DB: delayed })).status, 503);
  assert.equal(sqlite.prepare("SELECT status FROM hosted_responses").get().status, "failed");
  assert.equal((await call(payload("get"))).data.result.state, null);
  assert.equal((await call(completion())).status, 409);
});
