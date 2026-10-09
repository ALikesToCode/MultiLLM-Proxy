/** Private, durable payment domain. Public Stripe delivery stays in the Container. */
import { TenantContext } from "./enterprise-contract.mjs";

const MAX_BODY = 65536, LEASE = 60;
const LABEL = /^[A-Za-z0-9_:.-]{1,128}(?![\s\S])/, REF = /^[A-Za-z_][A-Za-z0-9_]{0,127}(?![\s\S])/, HASH = /^[0-9a-f]{64}(?![\s\S])/;
const columns = {
  payment_checkouts: "checkout_id,principal,context_json,idempotency_key,body_hash,amount_microusd,currency,status,checkout_url,session_id,payment_intent,merchant,livemode,credited,refunded,revision,claim_token,claim_until,active_event,created_at",
  payment_events: "event_id,evidence_hash,checkout_id,kind,status,amount,target_amount,operation_id,revision,claim_token,claim_until,created_at",
  payment_velocity: "principal,utc_day,attempts", payment_audit: "id,checkout_id,event_id,outcome,created_at",
};
let warnedFlag = false, warnedConfig = false;
class PaymentError extends Error {
  constructor(code = "payments_unavailable", status = 503) { super(code); this.code = code; this.status = status; }
}
function invalid() { throw new PaymentError("invalid_payment_operation", 400); }
function label(value, nullable = false) {
  if (nullable && value === null) return;
  if (typeof value !== "string" || !LABEL.test(value)) invalid();
}
function integer(value, maximum = 1000000000) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) invalid();
}
function origin(value) {
  if (typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f\\]/.test(value)) invalid();
  const url = new URL(value);
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password) invalid();
  return url.origin;
}
export function paymentSettings(env = {}, warn = message => console.warn(message)) {
  const raw = env.PAYMENTS_ENABLED;
  const flag = raw == null ? "" : typeof raw === "string" ? raw.trim().toLowerCase() : "invalid";
  if (["", "0", "false", "off", "no"].includes(flag)) return null;
  if (!["1", "true", "on", "yes"].includes(flag)) {
    if (!warnedFlag) { warnedFlag = true; warn("Invalid payment flag; payments disabled"); }
    return null;
  }
  try {
    const config = JSON.parse(env.PAYMENT_PROCESSOR_CONFIG_JSON || "{}");
    if (!config || Array.isArray(config) || Object.keys(config).sort().join() !== "processor,product_name,return_origins,secret_key_ref"
      || config.processor !== "stripe" || typeof config.secret_key_ref !== "string" || !REF.test(config.secret_key_ref)
      || typeof env.PAYMENT_WEBHOOK_KEY_REF !== "string" || !REF.test(env.PAYMENT_WEBHOOK_KEY_REF)
      || typeof config.product_name !== "string" || config.product_name.length < 1 || config.product_name.length > 128
      || /[\x00-\x1f]/.test(config.product_name) || !Array.isArray(config.return_origins)
      || config.return_origins.length < 1 || config.return_origins.length > 16
      || config.return_origins.some(value => origin(value) !== value)) throw new Error();
    return Object.freeze({ ...config, webhook_key_ref: env.PAYMENT_WEBHOOK_KEY_REF });
  } catch {
    if (!warnedConfig) { warnedConfig = true; warn("Invalid payment configuration; payments disabled"); }
    return null;
  }
}

export async function verifyPaymentSignature(raw, header, secret, now) {
  try {
    if (!(raw instanceof Uint8Array) || raw.byteLength > MAX_BODY || typeof secret !== "string" || !secret
      || typeof header !== "string" || header.length > 8192 || !Number.isSafeInteger(now)) return false;
    const pieces = header.split(",").map(piece => {
      const index = piece.indexOf("=");
      if (index < 0) throw new Error();
      return [piece.slice(0, index).trim(), piece.slice(index+1).trim()];
    });
    const timestamps = pieces.filter(([key]) => key === "t").map(([, value]) => value);
    if (timestamps.length !== 1 || !/^[0-9]{1,12}$/.test(timestamps[0]) || Math.abs(now-Number(timestamps[0])) > 300) return false;
    const prefix = new TextEncoder().encode(`${timestamps[0]}.`);
    const signed = new Uint8Array(prefix.length+raw.length); signed.set(prefix); signed.set(raw, prefix.length);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    // WebCrypto performs the HMAC comparison rather than JavaScript string equality.
    let matched = false;
    for (const [scheme, value] of pieces) {
      if (scheme !== "v1" || !HASH.test(value)) continue;
      const signature = Uint8Array.from(value.match(/../g).map(byte => parseInt(byte, 16)));
      matched = await crypto.subtle.verify("HMAC", key, signature, signed) || matched;
    }
    return matched;
  } catch { return false; }
}

function checked(body) {
  const fields = {
    reserve: ["context", "body_hash", "idempotency_key", "checkout_id", "amount", "now", "token"],
    save: ["checkout_id", "token"], find: ["checkout_id", "payment_intent"],
    claim: ["event_id", "evidence_hash", "checkout_id", "kind", "status", "amount", "target_amount", "operation_id", "payment_intent", "now", "token"],
    finish: ["event_id", "token", "status", "now"],
  };
  if (!body || Array.isArray(body) || body.version !== 1 || !Object.hasOwn(fields, body.operation)) invalid();
  const optional = body.operation === "save" ? ["session_id", "url", "livemode", "merchant"] : [];
  const required = ["version", "operation", ...fields[body.operation]];
  if (required.some(name => !Object.hasOwn(body, name)) || Object.keys(body).some(name => !required.includes(name) && !optional.includes(name))) invalid();
  for (const name of ["checkout_id", "payment_intent", "operation_id"]) if (name in body) label(body[name], true);
  for (const name of ["token", "event_id", "idempotency_key"]) if (name in body) label(body[name]);
  for (const name of ["now", "amount", "target_amount"]) if (name in body) integer(body[name], name === "now" ? 999999999999 : 1000000000);
  for (const name of ["body_hash", "evidence_hash"]) if (name in body && (typeof body[name] !== "string" || !HASH.test(body[name]))) invalid();
  if (body.operation === "reserve") {
    body.context = new TenantContext(body.context);
    if (body.amount < 500000 || body.amount % 10000 || !body.checkout_id) invalid();
  }
  if (body.operation === "save" && body.session_id != null) {
    label(body.session_id);
    if (origin(body.url) !== "https://checkout.stripe.com" || typeof body.livemode !== "boolean" || body.merchant !== "direct"
      || optional.some(name => !Object.hasOwn(body, name))) invalid();
  } else if (body.operation === "save" && optional.some(name => Object.hasOwn(body, name))) invalid();
  if (body.operation === "claim") {
    if (!["credit", "refund", "dispute", "ignored"].includes(body.kind) || !["processing", "ignored", "mismatch", "failed", "pending_match"].includes(body.status)) invalid();
    if (body.status === "processing" && (!body.checkout_id || !body.operation_id || body.kind === "ignored" || body.amount === 0)) invalid();
    if (body.kind === "refund" && body.target_amount > body.amount) invalid();
  }
  if (body.operation === "finish" && !["pending_credit", "credited", "refunded", "disputed"].includes(body.status)) invalid();
  return body;
}
async function ready(env) {
  const db = env.INTELLIGENCE_DB;
  if (!db?.prepare || !db?.batch) throw new PaymentError();
  for (const [table, names] of Object.entries(columns)) await db.prepare(`SELECT ${names} FROM ${table} LIMIT 0`).all();
  return db;
}
function canonicalContext(context) {
  return JSON.stringify({ grants_revision: context.grants_revision, org_id: context.org_id,
    principal_id: context.principal_id, team_id: context.team_id });
}
const stmt = (db, sql, ...args) => db.prepare(sql).bind(...args);

async function reserve(db, b) {
  const scope = canonicalContext(b.context), principal = b.context.principal_id;
  const lookup = () => stmt(db, "SELECT * FROM payment_checkouts WHERE principal=? AND context_json=? AND idempotency_key=?", principal, scope, b.idempotency_key).first();
  let row = await lookup();
  if (row && row.body_hash !== b.body_hash) throw new PaymentError("payment_idempotency_conflict", 409);
  if (!row) {
    const day = new Date(b.now*1000).toISOString().slice(0, 10);
    await db.batch([
      stmt(db, "INSERT INTO payment_velocity VALUES (?,?,0) ON CONFLICT DO NOTHING", principal, day),
      stmt(db, "INSERT INTO payment_checkouts (checkout_id,principal,context_json,idempotency_key,body_hash,amount_microusd,currency,claim_token,claim_until,created_at) SELECT ?,?,?,?,?,?,'USD',?,?,? WHERE EXISTS (SELECT 1 FROM payment_velocity WHERE principal=? AND utc_day=? AND attempts<10) ON CONFLICT(principal,context_json,idempotency_key) DO NOTHING",
        b.checkout_id, principal, scope, b.idempotency_key, b.body_hash, b.amount, b.token, b.now+LEASE, b.now, principal, day),
      stmt(db, "UPDATE payment_velocity SET attempts=attempts+1 WHERE principal=? AND utc_day=? AND changes()=1", principal, day),
      stmt(db, "INSERT INTO payment_audit (checkout_id,outcome,created_at) SELECT ?,'created',? WHERE changes()=1", b.checkout_id, b.now),
    ]);
    row = await lookup();
    if (!row) throw new PaymentError("payment_velocity_limited", 429);
    if (row.body_hash !== b.body_hash) throw new PaymentError("payment_idempotency_conflict", 409);
  } else if (!row.checkout_url && row.claim_until <= b.now) {
    await stmt(db, "UPDATE payment_checkouts SET claim_token=?,claim_until=? WHERE checkout_id=? AND claim_until<=? AND checkout_url IS NULL",
      b.token, b.now+LEASE, row.checkout_id, b.now).run();
    row = await lookup();
  }
  return row;
}
async function save(db, b) {
  if (b.session_id == null) {
    await stmt(db, "UPDATE payment_checkouts SET claim_until=0 WHERE checkout_id=? AND claim_token=?", b.checkout_id, b.token).run();
  } else {
    const result = await stmt(db, "UPDATE payment_checkouts SET session_id=?,checkout_url=?,livemode=?,merchant=?,status='pending',claim_until=0,claim_token=NULL WHERE checkout_id=? AND claim_token=?",
      b.session_id, b.url, Number(b.livemode), b.merchant, b.checkout_id, b.token).run();
    if (result.meta.changes !== 1) throw new PaymentError("payment_checkout_processing", 503);
  }
  return null;
}
async function find(db, b) {
  return b.checkout_id ? await stmt(db, "SELECT * FROM payment_checkouts WHERE checkout_id=?", b.checkout_id).first()
    : await stmt(db, "SELECT * FROM payment_checkouts WHERE payment_intent=?", b.payment_intent).first();
}
async function claim(db, b) {
  let existing = await stmt(db, "SELECT * FROM payment_events WHERE event_id=?", b.event_id).first();
  if (existing) {
    if (existing.evidence_hash !== b.evidence_hash) throw new PaymentError("payment_event_conflict", 400);
    if (!["processing", "pending_credit", "pending_match"].includes(existing.status)) return { ...existing, claimed: false };
    if (existing.status === "pending_match") {
      if (b.status === "pending_match") return { ...existing, claimed: false };
      existing = null;
    }
    if (existing && existing.claim_until > b.now) throw new PaymentError("payment_credit_unavailable", 503);
  }
  const row = b.checkout_id ? await find(db, b) : null;
  let status = b.status, amount = b.amount;
  if (status === "processing") {
    if (!row || (row.active_event && row.active_event !== b.event_id)) throw new PaymentError("payment_credit_unavailable", 503);
    if (!existing) {
      const prior = await stmt(db, "SELECT status FROM payment_events WHERE operation_id=? AND status IN ('credited','refunded','disputed') LIMIT 1", b.operation_id).first();
      if (prior || (b.kind === "credit" && row.credited)) status = "ignored";
      if (b.kind !== "credit" && !row.credited) throw new PaymentError("payment_credit_unavailable", 503);
      if (b.kind === "refund") { amount = Math.max(0, b.target_amount-row.refunded); if (amount === 0) status = "ignored"; }
    }
  }
  const statements = [];
  if (existing) {
    statements.push(stmt(db, "UPDATE payment_events SET status='processing',claim_token=?,claim_until=? WHERE event_id=? AND claim_until<=? AND EXISTS (SELECT 1 FROM payment_checkouts WHERE checkout_id=? AND active_event=? AND revision=?)",
      b.token, b.now+LEASE, b.event_id, b.now, existing.checkout_id, b.event_id, existing.revision));
  } else {
    const guard = row ? " WHERE EXISTS (SELECT 1 FROM payment_checkouts WHERE checkout_id=? AND revision=? AND (active_event IS NULL OR active_event=?))" : "";
    statements.push(stmt(db, "INSERT INTO payment_events (event_id,evidence_hash,checkout_id,kind,status,amount,target_amount,operation_id,revision,claim_token,claim_until,created_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?" + guard + " ON CONFLICT(event_id) DO UPDATE SET checkout_id=excluded.checkout_id,kind=excluded.kind,status=excluded.status,amount=excluded.amount,target_amount=excluded.target_amount,operation_id=excluded.operation_id,revision=excluded.revision,claim_token=excluded.claim_token,claim_until=excluded.claim_until WHERE payment_events.status='pending_match' AND payment_events.evidence_hash=excluded.evidence_hash",
      b.event_id, b.evidence_hash, b.checkout_id, b.kind, status, amount, b.target_amount, b.operation_id, row?.revision ?? 0,
      b.token, status === "processing" ? b.now+LEASE : 0, b.now, ...(row ? [row.checkout_id, row.revision, b.event_id] : [])));
  }
  if (status === "processing") {
    statements.push(stmt(db, "UPDATE payment_checkouts SET active_event=?,payment_intent=COALESCE(payment_intent,?) WHERE checkout_id=? AND EXISTS (SELECT 1 FROM payment_events WHERE event_id=? AND claim_token=? AND status='processing')",
      b.event_id, b.payment_intent, b.checkout_id, b.event_id, b.token));
  } else if (status === "failed" && row && !row.credited) {
    statements.push(stmt(db, "UPDATE payment_checkouts SET status='failed' WHERE checkout_id=? AND credited=0 AND EXISTS (SELECT 1 FROM payment_events WHERE event_id=? AND claim_token=?)", row.checkout_id, b.event_id, b.token));
  }
  statements.push(stmt(db, "INSERT INTO payment_audit (checkout_id,event_id,outcome,created_at) SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM payment_events WHERE event_id=? AND claim_token=?)",
    b.checkout_id, b.event_id, status, b.now, b.event_id, b.token));
  const results = await db.batch(statements);
  existing = await stmt(db, "SELECT * FROM payment_events WHERE event_id=?", b.event_id).first();
  if (!existing || (results[0].meta.changes !== 1 && ["processing", "pending_credit"].includes(existing.status))) throw new PaymentError("payment_credit_unavailable", 503);
  if (existing.evidence_hash !== b.evidence_hash) throw new PaymentError("payment_event_conflict", 400);
  return { ...existing, claimed: existing.status === "processing" && existing.claim_token === b.token };
}
async function finish(db, b) {
  const row = await stmt(db, "SELECT * FROM payment_events WHERE event_id=? AND claim_token=? AND status='processing'", b.event_id, b.token).first();
  if (!row) throw new PaymentError("payment_credit_unavailable", 503);
  const expected = { credit: "credited", refund: "refunded", dispute: "disputed" }[row.kind];
  if (b.status !== "pending_credit" && b.status !== expected) invalid();
  const statements = [stmt(db, "UPDATE payment_events SET status=?,claim_until=0 WHERE event_id=? AND claim_token=? AND status='processing'", b.status, b.event_id, b.token)];
  if (b.status !== "pending_credit") statements.push(stmt(db, "UPDATE payment_checkouts SET active_event=NULL,revision=revision+1,credited=CASE WHEN ?='credit' THEN 1 ELSE credited END,refunded=CASE WHEN ?='refund' THEN ? ELSE refunded END,status=? WHERE checkout_id=? AND active_event=? AND revision=? AND changes()=1",
    row.kind, row.kind, row.target_amount, b.status, row.checkout_id, b.event_id, row.revision));
  statements.push(stmt(db, "INSERT INTO payment_audit (checkout_id,event_id,outcome,created_at) SELECT ?,?,?,? WHERE changes()=1", row.checkout_id, b.event_id, b.status, b.now));
  const results = await db.batch(statements);
  if (results[0].meta.changes !== 1) throw new PaymentError("payment_credit_unavailable", 503);
  return null;
}
const operations = { reserve, save, find, claim, finish };

export async function handlePaymentStoreRequest(request, env) {
  const failed = error => Response.json({ error: { code: error instanceof PaymentError ? error.code : "payments_unavailable",
    message: "Payment operation unavailable." } }, { status: error instanceof PaymentError ? error.status : 503, headers: { "Cache-Control": "no-store" } });
  if (!paymentSettings(env)) return failed(new PaymentError("not_found", 404));
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/managed-state/payments"
    || url.search || url.hash || url.username || url.password || request.method !== "POST") return failed(new PaymentError("not_found", 404));
  let body;
  try {
    if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") invalid();
    const reader = request.body?.getReader();
    if (!reader) invalid();
    const chunks = []; let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        length += value.length;
        if (length > MAX_BODY) { await reader.cancel(); invalid(); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    body = checked(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
  } catch { return failed(new PaymentError("invalid_payment_operation", 400)); }
  try {
    const db = await ready(env), result = await operations[body.operation](db, body);
    return Response.json({ version: 1, result }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) { return failed(error); }
}
