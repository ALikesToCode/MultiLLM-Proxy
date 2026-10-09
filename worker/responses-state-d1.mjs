import { organisationsEnabled, tenantStorageKey } from "./tenants-d1.mjs";
/** Principal-owned metadata and bounded immutable continuation bodies. */
import { boundedBody } from "./control-users-d1.mjs";

export const ID_PREFIX = "gwresp_";
export const MAX_STATE_BYTES = 1_048_576;
const MAX_DOCUMENT_BYTES = MAX_STATE_BYTES + 16_384;
const TTL_SECONDS = 86_400;
const PATH = "/v1/managed-state/responses";
const PREFIX = "responses-state/";
const ID = /^gwresp_[0-9a-f]{32}$/;
const HASH = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (body, keys) => object(body) && Object.keys(body).length === keys.length && keys.every(key => Object.hasOwn(body, key));
const reply = (result, status = 200) => Response.json(status === 200 ? { version: 1, result }
  : { version: 1, error: { code: result, message: "Hosted Responses storage could not accept the operation." } },
  { status, headers: { "cache-control": "no-store" } });
let warned = false;

export function responsesStateEnabled(env) {
  const flag = String(env.HOSTED_RESPONSES_ENABLED ?? "").trim().toLowerCase();
  if (!["", "0", "false", "off", "no", "1", "true", "on", "yes"].includes(flag)) {
    if (!warned) { warned = true; console.warn("Invalid HOSTED_RESPONSES_ENABLED; hosted Responses disabled"); }
    return false;
  }
  return ["1", "true", "on", "yes"].includes(flag);
}

function validDocument(document, id) {
  const response = document?.response;
  return exact(document, ["input", "response"]) && Array.isArray(document.input) && document.input.every(object)
    && object(response) && response.id === id && response.object === "response" && response.status === "completed"
    && !response.error && Array.isArray(response.output)
    && response.output.every(item => object(item) && (!Object.hasOwn(item, "status") || item.status === "completed"))
    && encoder.encode(JSON.stringify(document)).length <= MAX_STATE_BYTES;
}

function validBody(body) {
  if (!object(body) || body.version !== 1) return false;
  if (body.operation === "probe") return exact(body, ["version", "operation"]);
  if (!HASH.test(body.owner ?? "") || !ID.test(body.id ?? "")) return false;
  const keys = ["version", "operation", "owner", "id"];
  if (["get", "delete", "fail"].includes(body.operation)) return exact(body, keys);
  if (body.operation !== "put") return false;
  keys.push("provider", "model", "parent_id", "policy_revision", "depth", "document");
  if (Object.hasOwn(body, "deadline_ms")) {
    keys.push("deadline_ms");
    if (!Number.isSafeInteger(body.deadline_ms) || body.deadline_ms < 1) return false;
  }
  return exact(body, keys) && typeof body.provider === "string" && /^[a-z][a-z0-9-]{0,31}$/.test(body.provider)
    && typeof body.model === "string" && body.model.length >= 1 && body.model.length <= 256 && !/[\r\n\x00]/.test(body.model)
    && (body.parent_id === null || typeof body.parent_id === "string" && ID.test(body.parent_id))
    && typeof body.policy_revision === "string" && HASH.test(body.policy_revision)
    && Number.isInteger(body.depth) && body.depth >= 1 && body.depth <= 16
    && validDocument(body.document, body.id);
}

const hash = async text => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text))))
  .map(byte => byte.toString(16).padStart(2, "0")).join("");
const bodyKey = row => HASH.test(row.body_sha256 ?? "") && row.body_key === `${PREFIX}${row.owner}/${row.id}/${row.body_sha256}`;
const find = (db, body) => db.prepare("SELECT * FROM hosted_responses WHERE id=? AND owner=?").bind(body.id, body.owner).first();

async function remove(db, bucket, row) {
  if (!bodyKey(row)) throw Error("Invalid body pointer");
  // A durable tombstone prevents a concurrent completion from restoring deleted content.
  await db.prepare("UPDATE hosted_responses SET status='deleting' WHERE id=? AND owner=? AND body_key=?")
    .bind(row.id, row.owner, row.body_key).run();
  await bucket.delete(row.body_key);
  const result = await db.prepare("DELETE FROM hosted_responses WHERE id=? AND owner=? AND status='deleting' AND body_key=?")
    .bind(row.id, row.owner, row.body_key).run();
  return result.meta.changes === 1;
}

async function get(db, bucket, body, now) {
  const row = await find(db, body);
  if (!row) return { state: null };
  if (row.expires_at <= now) { await remove(db, bucket, row); return { state: null }; }
  if (row.status !== "completed") return { state: null };
  if (!bodyKey(row) || row.body_bytes > MAX_STATE_BYTES) throw Error("Invalid body pointer");
  const stored = await bucket.get(row.body_key);
  if (!stored || stored.size !== row.body_bytes || stored.size > MAX_STATE_BYTES) throw Error("Missing body");
  const text = await stored.text();
  if (encoder.encode(text).length !== row.body_bytes || await hash(text) !== row.body_sha256) throw Error("Invalid body");
  const document = JSON.parse(text);
  if (!validDocument(document, row.id)) throw Error("Invalid body");
  // DELETE may have taken ownership while R2 was read.
  const current = await find(db, body);
  if (!current || current.status !== "completed" || current.expires_at <= Math.floor(Date.now() / 1000)) return { state: null };
  return { state: { id: row.id, owner: row.owner, provider: row.provider, model: row.model,
    parent_id: row.parent_id, policy_revision: row.policy_revision, depth: row.depth, expires_at: row.expires_at, document } };
}

function matches(row, body, digest) {
  return row && row.owner === body.owner && row.body_sha256 === digest && row.provider === body.provider
    && row.model === body.model && row.parent_id === body.parent_id && row.depth === body.depth
    && row.policy_revision === body.policy_revision;
}

async function put(db, bucket, body, now) {
  const expired = () => Object.hasOwn(body, "deadline_ms") && Date.now() >= body.deadline_ms;
  if (expired()) return reply("responses_store_unavailable", 503);
  const text = JSON.stringify(body.document), digest = await hash(text);
  const key = `${PREFIX}${body.owner}/${body.id}/${digest}`;
  if (body.parent_id !== null) {
    const parent = await find(db, { id: body.parent_id, owner: body.owner });
    if (!parent || parent.status !== "completed" || parent.expires_at <= now || body.depth !== parent.depth + 1) return reply("response_not_found", 404);
  } else if (body.depth !== 1) return reply("invalid_responses_state_request", 400);
  // Reserve immutable identity first. A failed write exposes no replayable body;
  // retries of this storage operation can write only the same content and metadata.
  await db.prepare(`INSERT INTO hosted_responses
    (id, owner, status, provider, model, parent_id, policy_revision, depth, created_at, expires_at, body_key, body_bytes, body_sha256)
    VALUES (?, ?, 'writing', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`)
    .bind(body.id, body.owner, body.provider, body.model, body.parent_id, body.policy_revision, body.depth,
      now, now + TTL_SECONDS, key, encoder.encode(text).length, digest).run();
  const row = await find(db, body);
  if (!matches(row, body, digest) || row.status === "deleting" || row.expires_at <= now) return reply("response_state_conflict", 409);
  if (row.status === "completed") return reply({ stored: true });
  if (row.status !== "writing") return reply("response_state_conflict", 409);
  await bucket.put(key, text, { httpMetadata: { contentType: "application/json" }, customMetadata: { expires_at: String(row.expires_at) } });
  if (expired()) return reply("responses_store_unavailable", 503);
  const result = await db.prepare("UPDATE hosted_responses SET status='completed' WHERE id=? AND owner=? AND status='writing' AND body_sha256=? AND expires_at>?")
    .bind(body.id, body.owner, digest, Math.floor(Date.now() / 1000)).run();
  if (expired()) {
    await db.prepare("UPDATE hosted_responses SET status='failed' WHERE id=? AND owner=? AND body_sha256=? AND status='completed'")
      .bind(body.id, body.owner, digest).run();
    return reply("responses_store_unavailable", 503);
  }
  if (result.meta.changes === 1) return reply({ stored: true });
  const current = await find(db, body);
  if (matches(current, body, digest) && current.status === "completed" && current.expires_at > now) return reply({ stored: true });
  // Complete the explicit DELETE (or TTL removal) that raced this unpublished write.
  if (!current || current.status === "deleting") await bucket.delete(key);
  return reply("responses_store_unavailable", 503);
}

export async function handleResponsesStateRequest(request, env, { tenantContext } = {}) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal" || url.pathname !== PATH
      || url.search || url.hash || url.username || url.password) return reply("not_found", 404);
  if (!responsesStateEnabled(env)) return reply("not_found", 404);
  let body;
  try {
    if (request.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") throw Error();
    body = JSON.parse(await boundedBody(request, MAX_DOCUMENT_BYTES));
    if (!validBody(body)) throw Error();
  } catch { return reply("invalid_responses_state_request", 400); }
  if (organisationsEnabled(env) && tenantContext && body.owner) body.owner = tenantStorageKey(body.owner, tenantContext);
  const db = env.INTELLIGENCE_DB, bucket = env.multillm_media;
  if (!db || !bucket) return reply("responses_store_unavailable", 503);
  const now = Math.floor(Date.now() / 1000);
  try {
    if (body.operation === "probe") {
      await db.prepare(`SELECT id, owner, status, provider, model, parent_id, policy_revision,
        depth, created_at, expires_at, body_key, body_bytes, body_sha256 FROM hosted_responses LIMIT 1`).first();
      await bucket.head(`${PREFIX}.readiness`);
      return reply({ ready: true });
    }
    if (body.operation === "put") return await put(db, bucket, body, now);
    if (body.operation === "get") return reply(await get(db, bucket, body, now));
    if (body.operation === "fail") {
      const result = await db.prepare("UPDATE hosted_responses SET status='failed' WHERE id=? AND owner=? AND status='completed'")
        .bind(body.id, body.owner).run();
      return reply({ failed: result.meta.changes === 1 });
    }
    const row = await find(db, body);
    if (!row) return reply({ deleted: false });
    const deleted = await remove(db, bucket, row);
    return reply({ deleted: deleted && row.expires_at > now });
  } catch {
    console.warn("Hosted Responses storage unavailable");
    return reply("responses_store_unavailable", 503);
  }
}
