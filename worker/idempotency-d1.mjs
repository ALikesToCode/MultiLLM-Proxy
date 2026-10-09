/** Atomic managed request claims and bounded complete response objects. */
import { boundedBody } from "./control-users-d1.mjs";

export const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_DOCUMENT_BYTES = 1_420_000;
const TTL_SECONDS = 86_400;
const PREFIX = "managed-idempotency/";
const HASH = /^[0-9a-f]{64}$/;
const OWNER = /^[0-9a-f]{32}$/;
const HEADERS = new Set(["content-type", "content-length", "cache-control", "x-multillm-model", "x-multillm-tool-repair"]);
const encoder = new TextEncoder();
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (body, fields) => object(body) && Object.keys(body).length === fields.length && fields.every(name => Object.hasOwn(body, name));
const reply = (result, status = 200) => Response.json(status === 200 ? { version: 1, result }
  : { version: 1, error: { code: result, message: "Managed idempotency authority could not accept the operation." } },
  { status, headers: { "cache-control": "no-store" } });
let warned = false;

export function idempotencyEnabled(env) {
  const flag = String(env.MANAGED_IDEMPOTENCY_ENABLED ?? "").trim().toLowerCase();
  if (!["", "0", "false", "no", "off", "1", "true", "yes", "on"].includes(flag)) {
    if (!warned) { warned = true; console.warn("Invalid MANAGED_IDEMPOTENCY_ENABLED; managed idempotency disabled"); }
    return false;
  }
  return ["1", "true", "yes", "on"].includes(flag);
}

function validResponse(value) {
  if (!exact(value, ["status", "headers", "body"]) || !Number.isInteger(value.status) || value.status < 200 || value.status >= 300
      || !Array.isArray(value.headers) || value.headers.length > 32 || encoder.encode(JSON.stringify(value.headers)).length > 16_384
      || !value.headers.every(pair => Array.isArray(pair) && pair.length === 2 && pair.every(v => typeof v === "string")
        && HEADERS.has(pair[0].toLowerCase()) && !/[\r\n\x00]/.test(pair[1]))
      || typeof value.body !== "string" || value.body.length > Math.ceil(MAX_RESPONSE_BYTES / 3) * 4
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.body)) return false;
  try { return atob(value.body).length <= MAX_RESPONSE_BYTES; } catch { return false; }
}

function validBody(body) {
  if (!object(body) || body.version !== 1 || !["claim", "handoff", "complete", "unknown"].includes(body.operation)
      || typeof body.scope !== "string" || !HASH.test(body.scope) || typeof body.digest !== "string" || !HASH.test(body.digest)
      || typeof body.owner !== "string" || !OWNER.test(body.owner)) return false;
  const fields = ["version", "operation", "scope", "digest", "owner"];
  if (body.operation === "claim" && Object.hasOwn(body, "pending_seconds")) {
    fields.push("pending_seconds");
    if (!Number.isInteger(body.pending_seconds) || body.pending_seconds < 1 || body.pending_seconds > TTL_SECONDS) return false;
  }
  if (body.operation === "complete") { fields.push("response"); if (!validResponse(body.response)) return false; }
  return exact(body, fields);
}

const hash = async text => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text))))
  .map(byte => byte.toString(16).padStart(2, "0")).join("");
const responseKey = row => typeof row.response_key === "string"
  && new RegExp(`^${PREFIX}${row.scope}/${row.owner}/[0-9a-f]{32}$`).test(row.response_key);

async function block(db, row, bucket) {
  await db.prepare("UPDATE managed_idempotency SET status='unknown', response_key=NULL, response_digest=NULL WHERE scope=? AND owner=? AND status=?")
    .bind(row.scope, row.owner, row.status).run();
  if (responseKey(row)) await bucket.delete(row.response_key);
  return { status: "unknown" };
}

async function replay(db, row, bucket, now) {
  if (row.expires_at <= now || !responseKey(row) || !HASH.test(row.response_digest ?? "")) return block(db, row, bucket);
  const stored = await bucket.get(row.response_key);
  if (!stored || stored.size > MAX_DOCUMENT_BYTES) return block(db, row, bucket);
  const document = await stored.text();
  if (encoder.encode(document).length > MAX_DOCUMENT_BYTES || await hash(document) !== row.response_digest) return block(db, row, bucket);
  let response;
  try { response = JSON.parse(document); } catch { return block(db, row, bucket); }
  if (!validResponse(response)) return block(db, row, bucket);
  return { status: "completed", response };
}

async function claim(db, bucket, body, now) {
  const inserted = await db.prepare(`INSERT INTO managed_idempotency
    (scope, request_digest, owner, status, created_at, pending_until, expires_at)
    VALUES (?, ?, ?, 'pending', ?, ?, ?) ON CONFLICT(scope) DO NOTHING`)
    .bind(body.scope, body.digest, body.owner, now, now + (body.pending_seconds ?? 3600), now + TTL_SECONDS).run();
  if (inserted.meta.changes === 1) return { status: "claimed" };
  const row = await db.prepare("SELECT * FROM managed_idempotency WHERE scope=?").bind(body.scope).first();
  if (!row) throw new Error("Claim disappeared");
  if (row.request_digest !== body.digest) return { status: "conflict" };
  if (row.status === "completed") return replay(db, row, bucket, now);
  if (row.status === "pending" && row.pending_until <= now) return block(db, row, bucket);
  return { status: row.status === "pending" ? "pending" : "unknown" };
}

async function complete(db, bucket, body, now) {
  const row = await db.prepare("SELECT * FROM managed_idempotency WHERE scope=?").bind(body.scope).first();
  if (!row || row.owner !== body.owner || row.request_digest !== body.digest || row.status !== "pending" || !row.handed_off) return { changed: false };
  if (row.expires_at <= now || row.pending_until <= now) { await block(db, row, bucket); return { changed: false }; }
  const key = `${PREFIX}${body.scope}/${body.owner}/${crypto.randomUUID().replaceAll("-", "")}`;
  const document = JSON.stringify(body.response);
  await bucket.put(key, document, { httpMetadata: { contentType: "application/json" }, customMetadata: { expires_at: String(row.expires_at) } });
  // Each completion has its own object, so a losing CAS cannot overwrite the winner.
  const changed = await db.prepare(`UPDATE managed_idempotency SET status='completed', response_key=?, response_digest=?
    WHERE scope=? AND request_digest=? AND owner=? AND status='pending' AND handed_off=1 AND pending_until>? AND expires_at>?`)
    .bind(key, await hash(document), body.scope, body.digest, body.owner, now, now).run();
  if (changed.meta.changes !== 1) await bucket.delete(key);
  return { changed: changed.meta.changes === 1 };
}

export async function handleIdempotencyRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/managed-state/idempotency"
      || url.search || url.hash || url.username || url.password) return reply("not_found", 404);
  if (!idempotencyEnabled(env)) return reply("not_found", 404);
  let body;
  try {
    if (request.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") throw new Error();
    body = JSON.parse(await boundedBody(request, MAX_DOCUMENT_BYTES));
    if (!validBody(body)) throw new Error();
  } catch { return reply("invalid_idempotency_request", 400); }
  const db = env.INTELLIGENCE_DB, bucket = env.multillm_media;
  if (!db || !bucket) return reply("idempotency_store_unavailable", 503);
  const now = Math.floor(Date.now() / 1000);
  try {
    if (body.operation === "claim") return reply(await claim(db, bucket, body, now));
    if (body.operation === "complete") return reply(await complete(db, bucket, body, now));
    const query = body.operation === "handoff"
      ? "UPDATE managed_idempotency SET handed_off=1 WHERE scope=? AND request_digest=? AND owner=? AND status='pending' AND handed_off=0 AND pending_until>? AND expires_at>?"
      : "UPDATE managed_idempotency SET status='unknown' WHERE scope=? AND request_digest=? AND owner=? AND status='pending'";
    const args = [body.scope, body.digest, body.owner];
    if (body.operation === "handoff") args.push(now, now);
    const changed = await db.prepare(query).bind(...args).run();
    return reply({ changed: changed.meta.changes === 1 });
  } catch {
    // Neither caller identities, content nor underlying storage errors belong in logs.
    console.warn("Managed idempotency authority unavailable");
    return reply("idempotency_store_unavailable", 503);
  }
}
