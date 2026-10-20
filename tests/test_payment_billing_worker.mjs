import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { handlePaymentStoreRequest, verifyPaymentSignature, paymentSettings } from "../worker/payment-webhooks.mjs";

const NOW = 1700000000;
const SECRET = "public-test-webhook-secret";
const VECTOR = '{"id":"evt_vector","object":"event","type":"unknown","livemode":false}';
const SIGNATURE = createHmac("sha256", SECRET).update(`${NOW}.${VECTOR}`).digest("hex");
const ENV = { PAYMENTS_ENABLED: "true", PAYMENT_PROCESSOR_CONFIG_JSON: JSON.stringify({ processor: "stripe",
  secret_key_ref: "PAYMENT_TEST_KEY", return_origins: ["https://portal.test"], product_name: "Gateway credits" }),
  PAYMENT_WEBHOOK_KEY_REF: "PAYMENT_TEST_WEBHOOK" };
const context = { principal_id: "alice", org_id: null, team_id: null, grants_revision: 0 };

function database(t, schema = true) {
  const sql = new DatabaseSync(":memory:");
  t.after(() => sql.close());
  sql.exec("CREATE TABLE old_rows (value TEXT); INSERT INTO old_rows VALUES ('retained')");
  const migration = readFileSync(new URL("../intelligence-migrations/0038_payment_billing.sql", import.meta.url), "utf8");
  if (schema) { sql.exec(migration); sql.exec(migration); }
  const db = { prepare(query) {
    let values = [];
    const statement = { bind(...args) { values = args; return statement; },
      first() { return sql.prepare(query).get(...values) ?? null; },
      all() {
        const prepared = sql.prepare(query);
        return prepared.columns().length ? { results: prepared.all(...values), meta: { changes: 0 } }
          : { results: [], meta: { changes: Number(prepared.run(...values).changes) } };
      }, run() { return statement.all(); } };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const result = statements.map(statement => statement.all()); sql.exec("COMMIT"); return result; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const env = { ...ENV, INTELLIGENCE_DB: db };
  const call = async (operation, data = {}) => {
    const response = await handlePaymentStoreRequest(new Request("http://intelligence.internal/v1/managed-state/payments", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation, ...data }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { sql, env, call };
}
function reserve(overrides = {}) {
  return { context, body_hash: "a".repeat(64), idempotency_key: "order-1", checkout_id: "pay_one",
    amount: 500000, now: NOW, token: "token_one", ...overrides };
}
function claim(overrides = {}) {
  return { event_id: "evt_one", evidence_hash: "b".repeat(64), checkout_id: "pay_one", kind: "credit",
    status: "processing", amount: 500000, target_amount: 0, operation_id: "credit:pay_one",
    payment_intent: "pi_one", now: NOW, token: "claim_one", ...overrides };
}
async function saved(call) {
  assert.equal((await call("reserve", reserve())).status, 200);
  assert.equal((await call("save", { checkout_id: "pay_one", token: "token_one", session_id: "cs_one",
    url: "https://checkout.stripe.com/c/pay_test", livemode: false, merchant: "direct" })).status, 200);
}

test("shared raw signature vectors, rotation, timestamp, no downgrade", async () => {
  const raw = new TextEncoder().encode(VECTOR);
  assert.equal(await verifyPaymentSignature(raw, `t=${NOW},v1=${"0".repeat(64)},v1=${SIGNATURE}`, SECRET, NOW), true);
  assert.equal(await verifyPaymentSignature(raw, `t=${NOW},v1=${SIGNATURE}`, SECRET, NOW+300), true);
  for (const [body, header, now] of [
    [VECTOR+" ", `t=${NOW},v1=${SIGNATURE}`, NOW], [VECTOR, `t=${NOW},v0=${SIGNATURE}`, NOW],
    [VECTOR, `t=${NOW},t=${NOW},v1=${SIGNATURE}`, NOW], [VECTOR, `t=${NOW},v1=${SIGNATURE}`, NOW+301],
    [VECTOR, `t=${NOW},v1=${SIGNATURE}`, NOW-301], [VECTOR, "garbage", NOW],
  ]) assert.equal(await verifyPaymentSignature(new TextEncoder().encode(body), header, SECRET, now), false);
});

test("default off and invalid config perform no storage, warning excludes values", async () => {
  for (const flag of [undefined, "", "false", "junk"]) {
    const response = await handlePaymentStoreRequest(new Request("http://intelligence.internal/v1/managed-state/payments", { method: "POST" }),
      { ...ENV, PAYMENTS_ENABLED: flag, INTELLIGENCE_DB: { prepare() { assert.fail("disabled storage"); } } });
    assert.equal(response.status, 404);
  }
  assert.equal(paymentSettings({ ...ENV, PAYMENT_PROCESSOR_CONFIG_JSON: "[]" }), null);
  assert.equal(paymentSettings({ ...ENV, PAYMENT_WEBHOOK_KEY_REF: "bad ref" }), null);
});

test("private target validation and missing table fail closed", async t => {
  const { env, call } = database(t, false);
  assert.equal((await call("reserve", reserve())).status, 503);
  for (const url of ["https://outside.test/v1/managed-state/payments", "http://intelligence.internal/v1/managed-state/payments?x=1"]) {
    assert.equal((await handlePaymentStoreRequest(new Request(url, { method: "POST" }), env)).status, 404);
  }
  assert.equal((await call("unknown")).status, 400);
  assert.equal((await call("reserve", reserve({ amount: 500001 }))).status, 400);
  assert.equal((await call("reserve", { ...reserve(), secret: "unwanted" })).status, 400);
  assert.equal((await call("reserve", reserve({ idempotency_key: "order-1\n" }))).status, 400);
});

test("migration preserves old rows, reserve CAS scopes, velocity and retry", async t => {
  const { sql, call } = database(t);
  assert.equal(sql.prepare("SELECT value FROM old_rows").get().value, "retained");
  const rows = await Promise.all(Array.from({ length: 4 }, () => call("reserve", reserve())));
  assert.ok(rows.every(row => row.status === 200 && row.body.result.checkout_id === "pay_one"));
  assert.equal(sql.prepare("SELECT attempts FROM payment_velocity").get().attempts, 1);
  assert.equal((await call("reserve", reserve({ body_hash: "c".repeat(64) }))).status, 409);
  for (let n = 2; n <= 10; n++) assert.equal((await call("reserve", reserve({ idempotency_key: `order-${n}`, checkout_id: `pay_${n}` }))).status, 200);
  assert.equal((await call("reserve", reserve({ idempotency_key: "eleven", checkout_id: "pay_11" }))).status, 429);
  assert.equal((await call("reserve", reserve({ context: { ...context, principal_id: "bob" }, checkout_id: "pay_bob" }))).status, 200);
  assert.equal((await call("reserve", reserve({ context: { ...context, org_id: "org_one" }, checkout_id: "pay_org", now: NOW+86400 }))).status, 200);
});

test("event CAS before callback, retries and distinct completion events credit once", async t => {
  const { call, sql } = database(t);
  await saved(call);
  const rows = await Promise.all(Array.from({ length: 4 }, (_, n) => call("claim", claim({ token: `claim_${n}` }))));
  assert.equal(rows.filter(row => row.status === 200 && row.body.result.claimed).length, 1);
  const winner = rows.find(row => row.status === 200).body.result;
  assert.equal((await call("finish", { event_id: "evt_one", token: winner.claim_token, status: "pending_credit", now: NOW })).status, 200);
  const retry = await call("claim", claim({ token: "claim_retry" }));
  assert.equal(retry.body.result.operation_id, "credit:pay_one");
  assert.equal((await call("finish", { event_id: "evt_one", token: "claim_retry", status: "credited", now: NOW })).status, 200);
  const duplicate = await call("claim", claim());
  assert.equal(duplicate.body.result.claimed, false);
  const asyncEvent = await call("claim", claim({ event_id: "evt_async" }));
  assert.equal(asyncEvent.body.result.claimed, false);
  assert.equal(sql.prepare("SELECT credited,revision FROM payment_checkouts").get().credited, 1);
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM payment_events").get().n, 2);
});

test("refund deltas, operation deduplication and content-free audit", async t => {
  const { call, sql } = database(t);
  await saved(call);
  await call("claim", claim());
  await call("finish", { event_id: "evt_one", token: "claim_one", status: "credited", now: NOW });
  const refund = claim({ event_id: "evt_refund", kind: "refund", target_amount: 200000,
    operation_id: "refund:pay_one:200000", token: "refund_one" });
  assert.equal((await call("claim", refund)).body.result.amount, 200000);
  await call("finish", { event_id: "evt_refund", token: "refund_one", status: "refunded", now: NOW });
  assert.equal((await call("claim", { ...refund, event_id: "evt_refund_again" })).body.result.claimed, false);
  assert.equal(sql.prepare("SELECT refunded FROM payment_checkouts").get().refunded, 200000);
  assert.deepEqual(sql.prepare("PRAGMA table_info(payment_audit)").all().map(row => row.name), ["id", "checkout_id", "event_id", "outcome", "created_at"]);
  assert.equal((await call("finish", { event_id: "evt_refund", token: "foreign", status: "refunded", now: NOW })).status, 503);
});

test("unmatched event evidence resumes after the verified intent is linked", async t => {
  const { call, sql } = database(t);
  await saved(call);
  const unmatched = claim({ event_id: "evt_early", checkout_id: null, kind: "ignored", status: "pending_match",
    amount: 0, target_amount: 0, operation_id: null, payment_intent: null });
  assert.equal((await call("claim", unmatched)).body.result.status, "pending_match");
  await call("claim", claim());
  await call("finish", { event_id: "evt_one", token: "claim_one", status: "credited", now: NOW });
  const matched = claim({ event_id: "evt_early", kind: "refund", target_amount: 200000,
    operation_id: "refund:pay_one:200000", token: "refund_early" });
  assert.equal((await call("claim", matched)).body.result.amount, 200000);
  await call("finish", { event_id: "evt_early", token: "refund_early", status: "refunded", now: NOW });
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM payment_events WHERE event_id='evt_early'").get().n, 1);
});

test("unknown events and mismatches are recorded without credit claims", async t => {
  const { call, sql } = database(t);
  for (const status of ["ignored", "mismatch"]) {
    const result = await call("claim", claim({ event_id: `evt_${status}`, checkout_id: null,
      kind: "ignored", status, amount: 0, operation_id: null, payment_intent: null }));
    assert.equal(result.status, 200);
    assert.equal(result.body.result.claimed, false);
  }
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM payment_events").get().n, 2);
});

test("Worker forwards unauthenticated webhook raw bytes and signature to the Container", async t => {
  const worker = (await loadWorkerModule()).default;
  const raw = new TextEncoder().encode(' {"fixture":"é"}\r\n');
  let forwards = 0;
  t.mock.method(globalThis, "fetch", () => assert.fail("unexpected external network"));
  const env = { MULTILLM_PROXY_CONTAINER: { getByName(name) {
    assert.equal(name, "primary");
    return { async fetch(request) {
      forwards++;
      assert.equal(new URL(request.url).pathname, "/v1/payments/webhook");
      assert.equal(request.headers.get("Authorization"), null);
      assert.equal(request.headers.get("Stripe-Signature"), "signature-fixture");
      assert.deepEqual(new Uint8Array(await request.arrayBuffer()), raw);
      return Response.json({ received: true });
    } };
  } } };
  const response = await worker.fetch(new Request("https://gateway.test/v1/payments/webhook", {
    method: "POST", headers: { "content-type": "application/json", "Stripe-Signature": "signature-fixture" }, body: raw }), env,
    { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.equal(forwards, 1);
});

test("real D1 batches preserve velocity and event CAS", async t => {
  const entry = fileURLToPath(new URL("../worker/payment-test-entry.mjs", import.meta.url));
  const modules = [
    { type: "ESModule", path: entry, contents: 'import {handlePaymentStoreRequest} from "./payment-webhooks.mjs"; export default {fetch(request,env) {return handlePaymentStoreRequest(new Request("http://intelligence.internal/v1/managed-state/payments",request),env);}}' },
    ...["payment-webhooks.mjs", "enterprise-contract.mjs"].map(name => ({ type: "ESModule",
      path: fileURLToPath(new URL(`../worker/${name}`, import.meta.url)),
      contents: readFileSync(new URL(`../worker/${name}`, import.meta.url), "utf8") })),
  ];
  const mf = new Miniflare(convertV4MiniflareOptions({ modules, compatibilityDate: "2026-08-18",
    d1Databases: ["INTELLIGENCE_DB"], bindings: ENV }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  const migration = readFileSync(new URL("../intelligence-migrations/0038_payment_billing.sql", import.meta.url), "utf8");
  await db.batch(migration.split(";").map(sql => sql.trim()).filter(Boolean).map(sql => db.prepare(sql)));
  const call = async (operation, data) => {
    const response = await mf.dispatchFetch("https://payment.test/", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: 1, operation, ...data }) });
    return { status: response.status, body: await response.json() };
  };
  await saved(call);
  assert.equal((await call("reserve", reserve())).body.result.checkout_id, "pay_one");
  assert.equal((await db.prepare("SELECT attempts FROM payment_velocity").first()).attempts, 1);
  const claims = await Promise.all(Array.from({ length: 4 }, (_, n) => call("claim", claim({ token: `claim_${n}` }))));
  assert.equal(claims.filter(result => result.status === 200 && result.body.result.claimed).length, 1);
  const token = claims.find(result => result.status === 200).body.result.claim_token;
  assert.equal((await call("finish", { event_id: "evt_one", token, status: "credited", now: NOW })).status, 200);
  assert.equal((await call("claim", claim())).body.result.claimed, false);
});
