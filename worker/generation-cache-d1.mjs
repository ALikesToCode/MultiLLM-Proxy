/** Fixed, scoped D1 metadata and immutable R2 bodies for exact generation replay. */
export const CACHE_PREFIX = "generation-cache/v1/";
export const MAX_BODY_BYTES = 1024 * 1024;
export const MAX_RPC_BYTES = 1_500_000;
export const TTL_SECONDS = 300;
const MAX_ENTRIES = 512;
const MAX_PRINCIPAL_BYTES = 16 * 1024 * 1024;
const HASH = /^[0-9a-f]{64}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const HEADERS = new Set(["X-MultiLLM-Auto-Route", "X-MultiLLM-Auto-Selected-Model", "X-MultiLLM-Auto-Selected-Priority",
  "X-MultiLLM-Cascade", "X-MultiLLM-Auto-Ordering", "X-MultiLLM-Prompt-Cache", "X-MultiLLM-Prompt-Cache-Mode"]);
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const text = value => typeof value === "string" && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value);
export const validIdentity = value => object(value) && ["principal_hash", "cache_key", "policy_hash"].every(key => HASH.test(value[key]))
  && typeof value.model === "string" && MODEL.test(value.model);
export function validCacheMetadata(value) {
  return object(value) && Object.keys(value).length === 4 && value.content_type === "application/json"
    && object(value.headers) && Object.entries(value.headers).every(([key, item]) => HEADERS.has(key)
      && typeof item === "string" && item.length <= 1024 && !/[\x00-\x1f\x7f]/.test(item))
    && ["provider", "model"].every(key => value[key] === null || text(value[key]));
}
export function completeCacheBody(bytes) {
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!object(value) || Object.hasOwn(value, "error") || !Array.isArray(value.choices) || value.choices.length !== 1) return false;
    const choice = value.choices[0];
    return object(choice) && ["stop", "end_turn", "stop_sequence", "eos"].includes(choice.finish_reason)
      && object(choice.message) && (choice.message.tool_calls == null || Array.isArray(choice.message.tool_calls)
        && choice.message.tool_calls.length === 0) && !choice.message.function_call;
  } catch { return false; }
}
export async function digest(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const result = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(result), byte => byte.toString(16).padStart(2, "0")).join("");
}
export function encodeBody(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return btoa(binary);
}
export function decodeBody(value) {
  if (typeof value !== "string" || value.length > Math.ceil(MAX_BODY_BYTES / 3) * 4
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  try { const binary = atob(value); return Uint8Array.from(binary, character => character.charCodeAt(0)); } catch { return null; }
}

// D1 serializes the transaction: simultaneous instances cannot both pass a capacity check.
const INSERT = `INSERT INTO generation_cache
  (principal_hash, cache_key, policy_hash, model, created_at, expires_at, body_pointer, body_bytes, body_hash, metadata)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
  WHERE (SELECT COUNT(*) FROM generation_cache WHERE principal_hash=?1 AND cache_key != ?2) < ${MAX_ENTRIES}
    AND (SELECT COALESCE(SUM(body_bytes), 0) FROM generation_cache WHERE principal_hash=?1 AND cache_key != ?2) + ?8 <= ${MAX_PRINCIPAL_BYTES}
  ON CONFLICT(principal_hash, cache_key) DO UPDATE SET policy_hash=excluded.policy_hash, model=excluded.model,
    created_at=excluded.created_at, expires_at=excluded.expires_at, body_pointer=excluded.body_pointer,
    body_bytes=excluded.body_bytes, body_hash=excluded.body_hash, metadata=excluded.metadata`;

export class GenerationCacheD1 {
  constructor(env, { clock = () => Date.now() / 1000 } = {}) { this.env = env; this.clock = clock; }
  async get(identity, { maxAge = null } = {}) {
    if (!validIdentity(identity)) return null;
    const now = this.clock();
    const row = await this.env.INTELLIGENCE_DB.prepare(`SELECT created_at, expires_at, body_pointer, body_bytes, body_hash, metadata
      FROM generation_cache WHERE principal_hash=? AND cache_key=? AND policy_hash=? AND model=? AND expires_at>?`)
      .bind(identity.principal_hash, identity.cache_key, identity.policy_hash, identity.model, now).first();
    if (!row || !Number.isFinite(row.created_at) || row.created_at > now || row.expires_at > row.created_at + TTL_SECONDS
      || !Number.isInteger(row.body_bytes) || row.body_bytes < 1 || row.body_bytes > MAX_BODY_BYTES || !HASH.test(row.body_hash)) return null;
    const age = now - row.created_at;
    if (maxAge !== null && age > maxAge) return null;
    const prefix = `${CACHE_PREFIX}${identity.principal_hash}/${identity.cache_key}/`;
    if (typeof row.body_pointer !== "string" || !row.body_pointer.startsWith(prefix) || !/^[0-9a-f]{32}$/.test(row.body_pointer.slice(prefix.length))) return null;
    let metadata;
    try { metadata = JSON.parse(row.metadata); } catch { return null; }
    if (!validCacheMetadata(metadata)) return null;
    const object = await this.env.multillm_media.get(row.body_pointer);
    if (!object || object.size !== row.body_bytes) return null;
    const body = new Uint8Array(await object.arrayBuffer());
    if (body.length !== row.body_bytes || await digest(body) !== row.body_hash || !completeCacheBody(body)) return null;
    return { body, metadata, age };
  }
  async put(identity, body, metadata) {
    if (!validIdentity(identity) || !(body instanceof Uint8Array) || body.length > MAX_BODY_BYTES
      || !validCacheMetadata(metadata) || !completeCacheBody(body)) return false;
    // Check the deployed schema before creating any blob.
    await this.env.INTELLIGENCE_DB.prepare("SELECT cache_key FROM generation_cache LIMIT 0").all();
    const now = this.clock(), expires = now + TTL_SECONDS;
    const pointer = `${CACHE_PREFIX}${identity.principal_hash}/${identity.cache_key}/${crypto.randomUUID().replaceAll("-", "")}`;
    const hash = await digest(body);
    await this.env.multillm_media.put(pointer, body, { httpMetadata: {contentType: "application/json"},
      customMetadata: { expires_at: String(expires) } });
    let stored = false;
    try {
      const results = await this.env.INTELLIGENCE_DB.batch([
        this.env.INTELLIGENCE_DB.prepare("DELETE FROM generation_cache WHERE principal_hash=? AND expires_at<=?").bind(identity.principal_hash, now),
        this.env.INTELLIGENCE_DB.prepare(INSERT).bind(identity.principal_hash, identity.cache_key, identity.policy_hash,
          identity.model, now, expires, pointer, body.length, hash, JSON.stringify(metadata)),
      ]);
      stored = results[1].meta.changes === 1;
      return stored;
    } finally {
      // Old/replaced pointers expire naturally; an active reader may still own one.
      if (!stored) await this.env.multillm_media.delete(pointer).catch(() => {});
    }
  }
}

export async function cleanupGenerationCache(env, { now = Date.now() / 1000, limit = 100, cursor } = {}) {
  if (!Number.isFinite(now) || !Number.isInteger(limit) || limit < 1 || limit > 1000) throw new TypeError("invalid_cleanup_bounds");
  const result = await env.INTELLIGENCE_DB.prepare(`DELETE FROM generation_cache WHERE (principal_hash, cache_key) IN
    (SELECT principal_hash, cache_key FROM generation_cache WHERE expires_at<=? LIMIT ?)`).bind(now, limit).run();
  const page = await env.multillm_media.list({prefix: CACHE_PREFIX, limit, cursor, include: ["customMetadata"]});
  let deleted = 0;
  for (const object of page.objects) {
    const expiry = Number(object.customMetadata?.expires_at);
    if (object.key.startsWith(CACHE_PREFIX) && object.customMetadata?.expires_at && Number.isFinite(expiry) && expiry <= now) {
      await env.multillm_media.delete(object.key); deleted++;
    }
  }
  return { rows: result.meta.changes, objects: deleted, cursor: page.truncated ? page.cursor : null };
}

const exactFields = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const IDENTITY_FIELDS = ["version", "operation", "principal_hash", "cache_key", "policy_hash", "model"];
export async function handleGenerationCache(db, value, env) {
  const store = new GenerationCacheD1({...env, INTELLIGENCE_DB: db});
  if (value.operation === "prune") {
    if (!exactFields(value, ["version", "operation", "limit", "cursor"]) || !Number.isInteger(value.limit) || value.limit < 1 || value.limit > 1000
      || !(value.cursor === null || typeof value.cursor === "string" && value.cursor.length <= 2048)) return null;
    if (!env.multillm_media) throw new Error("cache_storage_unavailable");
    return Response.json({version: 1, pruned: await cleanupGenerationCache(env, {limit: value.limit, cursor: value.cursor ?? undefined})},
      {headers: {"cache-control": "no-store"}});
  }
  if (!validIdentity(value)) return null;
  if (value.operation === "get") {
    if (!exactFields(value, [...IDENTITY_FIELDS, "max_age"]) || !(value.max_age === null
      || Number.isSafeInteger(value.max_age) && value.max_age >= 0 && value.max_age <= 999999999)) return null;
    if (!env.multillm_media) throw new Error("cache_storage_unavailable");
    const entry = await store.get(value, {maxAge: value.max_age});
    return Response.json({version: 1, entry: entry ? {...entry, body: encodeBody(entry.body)} : null}, {headers: {"cache-control": "no-store"}});
  }
  if (value.operation === "put") {
    if (!exactFields(value, [...IDENTITY_FIELDS, "body", "metadata"]) || !validCacheMetadata(value.metadata)) return null;
    const body = decodeBody(value.body);
    if (!body || body.length > MAX_BODY_BYTES || !completeCacheBody(body)) return null;
    if (!env.multillm_media) throw new Error("cache_storage_unavailable");
    return Response.json({version: 1, stored: await store.put(value, body, value.metadata)}, {headers: {"cache-control": "no-store"}});
  }
  return null;
}
