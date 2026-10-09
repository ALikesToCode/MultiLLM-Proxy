/** Immutable, opt-in usage provenance with reviewed Ed25519 verification history. */
import { boundedBody } from "./control-users-d1.mjs";

const DOMAIN = new TextEncoder().encode("MultiLLM usage receipt v1\\n");
const MAX_BYTES = 65536, MAX_BODY_BYTES = 131072;
const LABEL = /^[A-Za-z0-9_.:-]{1,128}$/, REF = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/, HASH = /^[0-9a-f]{64}$/;
const CONTENT_FIELDS = new Set(["prompt", "messages", "content", "input", "output", "response", "api_key",
  "authorization", "password", "secret", "private_key", "signing_key"]);
let warned = false;

class ReceiptError extends Error {
  constructor(code = "usage_receipts_unavailable", status = 503) { super(code); this.code = code; this.status = status; }
}
const invalid = () => { throw new ReceiptError("invalid_usage_receipt", 400); };
const reply = (value, status = 200) => Response.json(value, { status, headers: { "cache-control": "no-store" } });
const failed = error => reply({ version: 1, error: { code: error instanceof ReceiptError ? error.code : "usage_receipts_unavailable",
  message: "Usage receipt operation unavailable." } }, error instanceof ReceiptError ? error.status : 503);
const b64 = bytes => btoa(String.fromCharCode(...bytes));
function unb64(value) {
  if (typeof value !== "string" || value.length > 131072 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) invalid();
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}
const signedBytes = bytes => { const result = new Uint8Array(DOMAIN.length + bytes.length); result.set(DOMAIN); result.set(bytes, DOMAIN.length); return result; };
const digest = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("");

export function usageReceiptsEnabled(env) {
  const flag = String(env.USAGE_RECEIPTS_ENABLED ?? "").trim().toLowerCase();
  if (!["", "0", "false", "no", "off", "1", "true", "yes", "on"].includes(flag)) {
    if (!warned) { warned = true; console.warn("Invalid USAGE_RECEIPTS_ENABLED; usage receipts disabled"); }
    return false;
  }
  return ["1", "true", "yes", "on"].includes(flag);
}

function exactNumber(value) {
  if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) invalid();
  if (value === 0) return "0";
  if (Number.isInteger(value)) return String(value);
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, Math.abs(value));
  const bits = view.getBigUint64(0), exponent = Number((bits >> 52n) & 2047n);
  let numerator = bits & ((1n << 52n) - 1n);
  if (exponent) numerator += 1n << 52n;
  let denominatorPower = 1074 - (exponent ? exponent - 1 : 0);
  while (denominatorPower > 0 && numerator % 2n === 0n) { numerator /= 2n; denominatorPower--; }
  if (denominatorPower <= 0) return (value < 0 ? "-" : "") + String(numerator << BigInt(-denominatorPower));
  const digits = String(numerator * 5n ** BigInt(denominatorPower)).padStart(denominatorPower + 1, "0");
  return (value < 0 ? "-" : "") + digits.slice(0, -denominatorPower) + "." + digits.slice(-denominatorPower);
}

function scalarString(value) {
  if (value.length > MAX_BYTES) invalid();
  for (const char of value) { const point = char.codePointAt(0); if (point >= 0xd800 && point <= 0xdfff) invalid(); }
  return JSON.stringify(value);
}
function codepointOrder(a, b) {
  const left = Array.from(a, char => char.codePointAt(0)), right = Array.from(b, char => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
}
export function canonicalBytes(value) {
  let nodes = 0, scalarBytes = 0;
  function scalar(text) {
    scalarBytes += new TextEncoder().encode(text).length;
    if (scalarBytes > MAX_BYTES) invalid();
    return text;
  }
  function encode(item, depth = 0) {
    if (++nodes > 4096 || depth > 32) invalid();
    if (item === null || typeof item === "boolean") return scalar(JSON.stringify(item));
    if (typeof item === "number") return scalar(exactNumber(item));
    if (typeof item === "string") return scalar(scalarString(item));
    if (Array.isArray(item)) {
      if (Object.keys(item).length !== item.length) invalid();
      return "[" + item.map(child => encode(child, depth + 1)).join(",") + "]";
    }
    if (item && typeof item === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(item))) {
      if (Object.getOwnPropertySymbols(item).length) invalid();
      return "{" + Object.keys(item).sort(codepointOrder).map(key => encode(key, depth + 1) + ":" + encode(item[key], depth + 1)).join(",") + "}";
    }
    invalid();
  }
  const bytes = new TextEncoder().encode(encode(value));
  if (bytes.length > MAX_BYTES) invalid();
  return bytes;
}
const canonicalText = value => new TextDecoder().decode(canonicalBytes(value));
function checkedRecord(record) {
  if (!record || Array.isArray(record) || typeof record !== "object") invalid();
  const text = canonicalText(record);
  function check(value) {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (CONTENT_FIELDS.has(key.toLowerCase())) invalid();
      check(child);
    }
  }
  check(record);
  return JSON.parse(text);
}
function principal(value) {
  if (typeof value !== "string" || !value.length || Array.from(value).length > 256 || /[\x00-\x1f\x7f]/.test(value)) invalid();
  scalarString(value); return value;
}
function identifier(value) { if (typeof value !== "string" || !LABEL.test(value)) invalid(); return value; }

async function ready(env) {
  if (!usageReceiptsEnabled(env)) throw new ReceiptError("not_found", 404);
  try {
    if (!env.INTELLIGENCE_DB || typeof env.USAGE_RECEIPTS_KEY_ID !== "string" || !LABEL.test(env.USAGE_RECEIPTS_KEY_ID)
      || typeof env.USAGE_RECEIPTS_SIGNING_KEY_REF !== "string" || !REF.test(env.USAGE_RECEIPTS_SIGNING_KEY_REF)) throw new ReceiptError();
    const material = env[env.USAGE_RECEIPTS_SIGNING_KEY_REF];
    if (typeof material !== "string" || !material.length || material.length > 8192) throw new ReceiptError();
    const key = await crypto.subtle.importKey("pkcs8", unb64(material), "Ed25519", true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const publicKey = b64(unb64(jwk.x.replaceAll("-", "+").replaceAll("_", "/") + "="));
    const reviewed = await env.INTELLIGENCE_DB.prepare("SELECT public_key_base64 FROM usage_receipt_keys WHERE key_id = ? AND reviewed = 1")
      .bind(env.USAGE_RECEIPTS_KEY_ID).first();
    if (!reviewed || reviewed.public_key_base64 !== publicKey) throw new ReceiptError();
    await env.INTELLIGENCE_DB.prepare("SELECT principal FROM usage_receipt_heads LIMIT 0").all();
    await env.INTELLIGENCE_DB.prepare("SELECT id FROM usage_receipts LIMIT 0").all();
    return { key, key_id: env.USAGE_RECEIPTS_KEY_ID };
  } catch { throw new ReceiptError(); }
}
async function eventReceipt(db, owner, eventId) {
  const row = await db.prepare("SELECT receipt_json FROM usage_receipts WHERE principal = ? AND event_id = ?").bind(owner, eventId).first();
  return row ? JSON.parse(row.receipt_json) : null;
}
async function makeReceipt(owner, eventId, record, sequence, previousHash, signer) {
  const canonical = canonicalBytes({ version: 1, principal: owner, event_id: eventId, record, sequence, previous_hash: previousHash, key_id: signer.key_id });
  const signed = signedBytes(canonical);
  return { record, canonical_bytes_base64: b64(canonical), signature_ed25519: b64(new Uint8Array(await crypto.subtle.sign("Ed25519", signer.key, signed))),
    key_id: signer.key_id, previous_hash: previousHash, record_hash: await digest(signed), sequence };
}

export async function appendReceipt(env, owner, eventId, metadata) {
  if (!usageReceiptsEnabled(env)) throw new ReceiptError("not_found", 404);
  principal(owner); identifier(eventId);
  const record = checkedRecord(metadata), signer = await ready(env), db = env.INTELLIGENCE_DB;
  await db.batch([db.prepare("INSERT INTO usage_receipt_heads (principal, sequence, record_hash) VALUES (?, 0, NULL) ON CONFLICT(principal) DO NOTHING").bind(owner)]);
  for (let attempt = 0; attempt < 16; attempt++) {
    const existing = await eventReceipt(db, owner, eventId);
    if (existing) {
      if (canonicalText(existing.record) !== canonicalText(record)) throw new ReceiptError("usage_receipt_event_conflict", 409);
      return existing;
    }
    const head = await db.prepare("SELECT sequence, record_hash FROM usage_receipt_heads WHERE principal = ?").bind(owner).first();
    const receipt = await makeReceipt(owner, eventId, record, head.sequence + 1, head.record_hash, signer);
    // The guarded insert and head advance share a D1 transaction. Losing CAS does
    // not write a receipt; a retry only signs metadata, never calls a provider.
    const [inserted] = await db.batch([
      db.prepare("INSERT INTO usage_receipts (id, principal, event_id, sequence, previous_hash, key_id, receipt_json) "
        + "SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM usage_receipt_heads WHERE principal = ? AND sequence = ? AND COALESCE(record_hash, '') = ?) "
        + "ON CONFLICT(principal, event_id) DO NOTHING").bind(receipt.record_hash, owner, eventId, receipt.sequence, receipt.previous_hash,
        receipt.key_id, JSON.stringify(receipt), owner, head.sequence, head.record_hash ?? ""),
      db.prepare("UPDATE usage_receipt_heads SET sequence = ?, record_hash = ? WHERE principal = ? AND sequence = ? AND COALESCE(record_hash, '') = ? "
        + "AND EXISTS (SELECT 1 FROM usage_receipts WHERE id = ? AND principal = ? AND sequence = ?)")
        .bind(receipt.sequence, receipt.record_hash, owner, head.sequence, head.record_hash ?? "", receipt.record_hash, owner, receipt.sequence),
    ]);
    if (inserted.meta.changes === 1) return receipt;
  }
  throw new ReceiptError("usage_receipt_conflict", 409);
}

export async function verifyChain(receipts, keys, { principal: owner, sequence = 0, previous_hash: previousHash = null }) {
  try {
    for (const receipt of receipts) {
      const canonical = unb64(receipt.canonical_bytes_base64), payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(canonical));
      if (b64(canonical) !== b64(canonicalBytes(payload)) || payload.version !== 1 || payload.principal !== owner
        || payload.sequence !== sequence + 1 || payload.previous_hash !== previousHash
        || ["record", "key_id", "sequence", "previous_hash"].some(name => canonicalText(payload[name]) !== canonicalText(receipt[name]))) return false;
      const signed = signedBytes(canonical);
      if (await digest(signed) !== receipt.record_hash) return false;
      const key = await crypto.subtle.importKey("raw", unb64(keys[receipt.key_id]), "Ed25519", false, ["verify"]);
      if (!await crypto.subtle.verify("Ed25519", key, unb64(receipt.signature_ed25519), signed)) return false;
      sequence = receipt.sequence; previousHash = receipt.record_hash;
    }
    return true;
  } catch { return false; }
}
async function readReceipt(env, owner, id) {
  principal(owner);
  await ready(env);
  if (typeof id !== "string" || !HASH.test(id)) return null;
  const row = await env.INTELLIGENCE_DB.prepare("SELECT receipt_json FROM usage_receipts WHERE principal = ? AND id = ?").bind(owner, id).first();
  return row ? JSON.parse(row.receipt_json) : null;
}
async function reviewedKeys(env) {
  await ready(env);
  return (await env.INTELLIGENCE_DB.prepare("SELECT key_id, public_key_base64 FROM usage_receipt_keys WHERE reviewed = 1 ORDER BY key_id").all()).results;
}

export async function handleUsageReceiptStoreRequest(request, env) {
  if (!usageReceiptsEnabled(env)) return failed(new ReceiptError("not_found", 404));
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/managed-state/usage-receipts"
    || url.search || url.hash || url.username || url.password || request.method !== "POST") return failed(new ReceiptError("not_found", 404));
  let body;
  try {
    if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") invalid();
    const length = request.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) invalid();
    body = JSON.parse(await boundedBody(request, MAX_BODY_BYTES));
    if (!body || Array.isArray(body) || body.version !== 1) invalid();
    const fields = { append: ["version", "operation", "principal", "event_id", "record"], get: ["version", "operation", "principal", "id"], keys: ["version", "operation"] };
    if (!Object.hasOwn(fields, body.operation) || Object.keys(body).length !== fields[body.operation].length
      || !fields[body.operation].every(name => Object.hasOwn(body, name))) invalid();
  } catch { return failed(new ReceiptError("invalid_usage_receipt", 400)); }
  try {
    if (body.operation === "append") return reply({ version: 1, receipt: await appendReceipt(env, body.principal, body.event_id, body.record) });
    if (body.operation === "get") return reply({ version: 1, receipt: await readReceipt(env, body.principal, body.id) });
    return reply({ version: 1, keys: await reviewedKeys(env) });
  } catch (error) { return failed(error); }
}

/** Caller supplies identity only after existing authentication/scope enforcement. */
export async function handleUsageReceiptRequest(request, env, identity) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/v1/usage/receipts/") && url.pathname !== "/v1/usage/receipt-keys") return null;
  if (!usageReceiptsEnabled(env)) return failed(new ReceiptError("not_found", 404));
  if (!identity?.principal) return failed(new ReceiptError("authentication_required", 401));
  if (request.method !== "GET") return failed(new ReceiptError("method_not_allowed", 405));
  try {
    if (url.pathname === "/v1/usage/receipt-keys") return reply({ keys: await reviewedKeys(env) });
    const receipt = await readReceipt(env, identity.principal, url.pathname.slice("/v1/usage/receipts/".length));
    return receipt ? reply(receipt) : failed(new ReceiptError("not_found", 404));
  } catch (error) { return failed(error); }
}

export async function recordSettledUsage(env, owner, eventId, record) {
  if (!usageReceiptsEnabled(env)) return null;
  try { return await appendReceipt(env, owner, eventId, record); }
  catch { console.warn("Usage receipt unavailable"); return null; }
}
export async function recordFlushedUsage(env, batchId, rows) {
  if (!usageReceiptsEnabled(env)) return;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index], record = { ...row };
    if (record.cost_basis == null && !Object.hasOwn(record, "usage_basis")) record.usage_basis = "unknown";
    await recordSettledUsage(env, row.principal, `${batchId}:${index}`, record);
  }
}
