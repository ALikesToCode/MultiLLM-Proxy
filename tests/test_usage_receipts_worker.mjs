import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { canonicalBytes, appendReceipt, verifyChain, handleUsageReceiptRequest, handleUsageReceiptStoreRequest } from "../worker/usage-receipts.mjs";
import { handleManagedStateRequest } from "../worker/managed-state-dispatch.mjs";
import { handleUsageLedgerRequest } from "../worker/usage-ledger-d1.mjs";

// Public RFC 8032 vector; never a deployment identity.
const PRIVATE = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g";
const PUBLIC = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const RECORD = { cost_usd: null, cost_basis: "unknown", extra: { fraction: 0.5, zero: 0, text: "é", nullable: null } };
const CANONICAL = '{"event_id":"settlement-1","key_id":"test-1","previous_hash":null,"principal":"alice","record":{"cost_basis":"unknown","cost_usd":null,"extra":{"fraction":0.5,"nullable":null,"text":"é","zero":0}},"sequence":1,"version":1}';
const SIGNATURE = "bj6tfJIYOfMT4NdUChDUckhAsA4PLn+ZRTkFoMgFkJ688dug9EXuyw01kUt39d17bJJ+qAP7rzhdROvEgJ9ADg==";
const HASH = "500716026bf9836219938f4e6bba0cb435e940bcf6db76910f1ee9f6279ad256";

function database(t, schema = true) {
  const sql = new DatabaseSync(":memory:");
  t.after(() => sql.close());
  if (schema) {
    sql.exec(readFileSync(new URL("../intelligence-migrations/0032_usage_receipts.sql", import.meta.url), "utf8"));
    sql.prepare("INSERT INTO usage_receipt_keys VALUES (?, ?, 1)").run("test-1", PUBLIC);
  }
  const db = { prepare(query) {
    let values = [];
    const statement = { bind(...args) { values = args; return statement; },
      first() { return sql.prepare(query).get(...values) ?? null; },
      all() {
        const prepared = sql.prepare(query);
        if (prepared.columns().length) return { results: prepared.all(...values), meta: { changes: 0 } };
        return { results: [], meta: { changes: Number(prepared.run(...values).changes) } };
      } };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const result = statements.map(statement => statement.all()); sql.exec("COMMIT"); return result; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const env = { USAGE_RECEIPTS_ENABLED: "true", USAGE_RECEIPTS_KEY_ID: "test-1",
    USAGE_RECEIPTS_SIGNING_KEY_REF: "RECEIPT_TEST_PRIVATE", RECEIPT_TEST_PRIVATE: PRIVATE, INTELLIGENCE_DB: db };
  const call = async body => {
    const response = await handleManagedStateRequest(new Request("http://intelligence.internal/v1/managed-state/usage-receipts", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
    }), env);
    return { status: response.status, ...await response.json() };
  };
  return { db, env, sql, call };
}

test("cross-runtime signed canonical vector keeps unknown metadata and nulls", async t => {
  const { env } = database(t);
  const row = await appendReceipt(env, "alice", "settlement-1", RECORD);
  assert.equal(Buffer.from(row.canonical_bytes_base64, "base64").toString(), CANONICAL);
  assert.equal(row.signature_ed25519, SIGNATURE);
  assert.equal(row.record_hash, HASH);
  assert.deepEqual(row.record, RECORD);
  assert.equal(await verifyChain([row], { "test-1": PUBLIC }, { principal: "alice" }), true);
});

test("canonical finite exact numbers, scalar Unicode and bounded JSON", () => {
  assert.equal(new TextDecoder().decode(canonicalBytes({ z: -0, n: 0.1, "😀": 1, "\ue000": 2 })),
    '{"n":0.1000000000000000055511151231257827021181583404541015625,"z":0,"\ue000":2,"😀":1}');
  for (const value of [NaN, Infinity, 2 ** 53, "\ud800", undefined, { value: undefined }, { x: "a".repeat(65536) }]) {
    assert.throws(() => canonicalBytes(value));
  }
});

test("CAS serializes concurrent appends and duplicate events, corrections append", async t => {
  const { env, call } = database(t);
  const rows = await Promise.all(Array.from({ length: 6 }, (_, n) => appendReceipt(env, "alice", `event-${n}`, RECORD)));
  rows.sort((a, b) => a.sequence - b.sequence);
  assert.deepEqual(rows.map(row => row.sequence), [1, 2, 3, 4, 5, 6]);
  assert.equal(await verifyChain(rows, { "test-1": PUBLIC }, { principal: "alice" }), true);
  const a = await appendReceipt(env, "alice", "duplicate", RECORD);
  const duplicates = await Promise.all(Array.from({ length: 6 }, () => appendReceipt(env, "alice", "same-event", RECORD)));
  assert.equal(new Set(duplicates.map(item => item.record_hash)).size, 1);
  assert.deepEqual(await appendReceipt(env, "alice", "duplicate", RECORD), a);
  const changed = await call({ operation: "append", principal: "alice", event_id: "duplicate", record: { cost_usd: 0 } });
  assert.equal(changed.status, 409);
  const b = await appendReceipt(env, "alice", "correction", { ...RECORD, cost_usd: 0.5, corrects: a.record_hash });
  assert.equal(b.previous_hash, duplicates[0].record_hash);
  assert.equal(b.record.corrects, a.record_hash);
  assert.deepEqual((await call({ operation: "get", principal: "alice", id: a.record_hash })).receipt, a);
  assert.equal((await call({ operation: "get", principal: "bob", id: a.record_hash })).receipt, null);
});

test("verification detects tampering, reordering, gaps and principal substitution", async t => {
  const { env } = database(t);
  const a = await appendReceipt(env, "alice", "a", RECORD), b = await appendReceipt(env, "alice", "b", RECORD);
  for (const rows of [[b, a], [b], [a, { ...b, sequence: 3 }], [{ ...a, record: { cost_usd: 0 } }]]) {
    assert.equal(await verifyChain(rows, { "test-1": PUBLIC }, { principal: "alice" }), false);
  }
  assert.equal(await verifyChain([a], { "test-1": PUBLIC }, { principal: "bob" }), false);
});

test("reviewed rotated keys are retained; missing, unreviewed or unsupported signing fails closed", async t => {
  const { env, sql, call } = database(t);
  sql.prepare("INSERT INTO usage_receipt_keys VALUES (?, ?, ?)").run("unreviewed", PUBLIC, 0);
  sql.prepare("INSERT INTO usage_receipt_keys VALUES (?, ?, ?)").run("test-2", PUBLIC, 1);
  const a = await appendReceipt(env, "alice", "a", RECORD);
  env.USAGE_RECEIPTS_KEY_ID = "test-2";
  const b = await appendReceipt(env, "alice", "b", RECORD);
  const keys = (await call({ operation: "keys" })).keys;
  assert.deepEqual(keys.map(key => key.key_id), ["test-1", "test-2"]);
  assert.equal(await verifyChain([a, b], Object.fromEntries(keys.map(key => [key.key_id, key.public_key_base64])), { principal: "alice" }), true);
  env.USAGE_RECEIPTS_KEY_ID = "unreviewed";
  assert.equal((await call({ operation: "keys" })).status, 503);
  env.USAGE_RECEIPTS_KEY_ID = "test-1";
  for (const value of ["", "invalid"]) {
    env.RECEIPT_TEST_PRIVATE = value;
    assert.equal((await call({ operation: "keys" })).status, 503);
  }
  env.RECEIPT_TEST_PRIVATE = PRIVATE;
  const original = crypto.subtle.importKey.bind(crypto.subtle);
  t.mock.method(crypto.subtle, "importKey", (...args) => args[2] === "Ed25519" ? Promise.reject(new Error("unsupported")) : original(...args));
  assert.equal((await call({ operation: "keys" })).status, 503);
});

test("registered public routes authenticate owners and return unavailable safely", async t => {
  const { env } = database(t);
  const a = await appendReceipt(env, "alice", "a", RECORD);
  const request = new Request(`https://gateway.test/v1/usage/receipts/${a.record_hash}`);
  assert.equal((await handleUsageReceiptRequest(request, env, { principal: "alice" })).status, 200);
  assert.equal((await handleUsageReceiptRequest(request, env, { principal: "bob" })).status, 404);
  assert.equal((await handleUsageReceiptRequest(request, env, null)).status, 401);
  env.RECEIPT_TEST_PRIVATE = "";
  assert.equal((await handleUsageReceiptRequest(request, env, { principal: "alice" })).status, 503);
});

test("private dispatcher flag, target, missing table and size bounds precede storage", async t => {
  const { env, call } = database(t, false);
  assert.equal((await call({ operation: "append", principal: "alice", event_id: "a", record: RECORD })).status, 503);
  for (const flag of [undefined, "", "false", "invalid"]) {
    const response = await handleManagedStateRequest(new Request("http://intelligence.internal/v1/managed-state/usage-receipts", { method: "POST" }),
      { USAGE_RECEIPTS_ENABLED: flag, INTELLIGENCE_DB: { prepare() { assert.fail("disabled storage"); } } });
    assert.equal(response.status, 404);
  }
  assert.equal((await handleUsageReceiptStoreRequest(new Request("https://external.test/v1/managed-state/usage-receipts", { method: "POST" }), env)).status, 404);
  const oversized = new Request("http://intelligence.internal/v1/managed-state/usage-receipts", {
    method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(131073) });
  assert.equal((await handleManagedStateRequest(oversized, env)).status, 400);
});

test("ledger flush records once, default rows and responses stay unchanged, missing key preserves usage", async t => {
  const { env, sql } = database(t);
  sql.exec("CREATE TABLE control_users (id TEXT PRIMARY KEY)");
  for (const migration of ["0007_usage_ledger.sql", "0016_usage_buckets.sql"]) {
    sql.exec(readFileSync(new URL(`../intelligence-migrations/${migration}`, import.meta.url), "utf8"));
  }
  const row = { at: "2026-10-09T00:00:00Z", principal: "alice", key_prefix: null, kind: "chat", endpoint: "/v1/chat/completions",
    requested_model: "test:model", selected_model: "test:model", status: 200, latency_ms: 1,
    input_tokens: null, output_tokens: null, cost_usd: null, cost_basis: null, request_id: "test" };
  const call = async (batch, currentEnv) => {
    const response = await handleUsageLedgerRequest(new Request("http://intelligence.internal/v1/usage", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "record", batch, rows: [row] }) }), currentEnv);
    return await response.json();
  };
  assert.deepEqual(await call("a".repeat(32), { ...env, USAGE_RECEIPTS_ENABLED: "false" }), { version: 1, recorded: 1, duplicate: false });
  assert.equal(sql.prepare("SELECT COUNT(*) AS count FROM usage_receipts").get().count, 0);
  assert.deepEqual(await call("b".repeat(32), env), { version: 1, recorded: 1, duplicate: false });
  assert.deepEqual(await call("b".repeat(32), env), { version: 1, recorded: 0, duplicate: true });
  assert.equal(sql.prepare("SELECT COUNT(*) AS count FROM usage_receipts").get().count, 1);
  env.RECEIPT_TEST_PRIVATE = "";
  assert.deepEqual(await call("c".repeat(32), env), { version: 1, recorded: 1, duplicate: false });
  assert.equal(sql.prepare("SELECT COUNT(*) AS count FROM usage_events").get().count, 3);
});

test("workerd Ed25519 signs the same receipt through the real D1 authority", async t => {
  const source = readFileSync(new URL("../worker/usage-receipts.mjs", import.meta.url), "utf8")
    .replace('import { boundedBody } from "./control-users-d1.mjs";',
      'async function boundedBody(request, maximum) { const text = await request.text(); if (new TextEncoder().encode(text).length > maximum) throw new Error("body limit"); return text; }');
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, compatibilityDate: "2026-08-18",
    script: source + '\nexport default { fetch(request, env) { return handleUsageReceiptStoreRequest(new Request("http://intelligence.internal/v1/managed-state/usage-receipts", request), env); } };',
    d1Databases: ["INTELLIGENCE_DB"], bindings: { USAGE_RECEIPTS_ENABLED: "true", USAGE_RECEIPTS_KEY_ID: "test-1",
      USAGE_RECEIPTS_SIGNING_KEY_REF: "RECEIPT_TEST_PRIVATE", RECEIPT_TEST_PRIVATE: PRIVATE } }));
  t.after(() => mf.dispose());
  const call = () => mf.dispatchFetch("http://receipt.test/", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ version: 1, operation: "append", principal: "alice", event_id: "settlement-1", record: RECORD }) });
  assert.equal((await call()).status, 503);
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  const migration = readFileSync(new URL("../intelligence-migrations/0032_usage_receipts.sql", import.meta.url), "utf8");
  await db.batch(migration.split(";").filter(sql => sql.trim()).map(sql => db.prepare(sql)));
  await db.prepare("INSERT INTO usage_receipt_keys VALUES (?, ?, 1)").bind("test-1", PUBLIC).run();
  const response = await call();
  assert.equal(response.status, 200);
  const row = (await response.json()).receipt;
  assert.equal(row.signature_ed25519, SIGNATURE);
  assert.equal(row.record_hash, HASH);
  assert.equal(Buffer.from(row.canonical_bytes_base64, "base64").toString(), CANONICAL);
  assert.deepEqual((await (await call()).json()).receipt, row);
});
