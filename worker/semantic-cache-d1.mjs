/** Scoped exact vector scans and immutable bodies in the existing media bucket. */
import { digest, encodeBody, decodeBody, completeCacheBody, validCacheMetadata, MAX_BODY_BYTES } from "./generation-cache-d1.mjs";
export const SEMANTIC_PREFIX = "semantic-cache/v1/";
export const SEMANTIC_TTL = 300;
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{32}$/;
const object = value => value && typeof value === "object" && !Array.isArray(value);
export const validSemanticIdentity = value => object(value)
  && ["principal_hash", "partition_hash", "model_revision"].every(key => HASH.test(value[key]));
export function validVector(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= 8192
    && value.every(x => typeof x === "number" && Number.isFinite(x))
    && Number.isFinite(value.reduce((n, x) => n + x*x, 0)) && value.reduce((n, x) => n + x*x, 0) > 0;
}
export function vectorSimilarity(one, two) {
  if (!validVector(one) || !validVector(two) || one.length !== two.length) return -1;
  return one.reduce((n,x,i)=>n+x*two[i],0) / Math.sqrt(one.reduce((n,x)=>n+x*x,0)) / Math.sqrt(two.reduce((n,x)=>n+x*x,0));
}
export function schemaMissing(error) {
  return /no such table:\s*semantic_generation_cache\b/i.test(String(error?.message ?? ""));
}
export function schemaErrorResponse() {
  return Response.json({error: "semantic_cache_schema_missing",
    message: "The semantic generation cache schema is missing. Apply its migration before enabling it."},
  {status: 503, headers: {"cache-control": "no-store"}});
}
const FIELDS = "entry_id, partition_hash, model_revision, vector, guard_hash, created_at, expires_at, body_pointer, body_bytes, body_hash, metadata";
const INSERT = `INSERT INTO semantic_generation_cache
  (principal_hash, entry_id, partition_hash, model_revision, vector, guard_hash,
   created_at, expires_at, body_pointer, body_bytes, body_hash, metadata)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
  WHERE (SELECT COUNT(*) FROM semantic_generation_cache WHERE principal_hash=?1) < 256`;

export class SemanticCacheD1 {
  constructor(env, {clock = () => Date.now()/1000} = {}) {this.env = env; this.clock = clock;}
  async ready() {
    await this.env.INTELLIGENCE_DB.prepare("SELECT entry_id FROM semantic_generation_cache LIMIT 0").all();
    if (!this.env.multillm_media) throw new Error("semantic_cache_storage_unavailable");
  }
  async scan(identity) {
    if (!validSemanticIdentity(identity)) return [];
    const now = this.clock();
    const result = await this.env.INTELLIGENCE_DB.prepare(`SELECT ${FIELDS} FROM semantic_generation_cache
      WHERE principal_hash=? AND partition_hash=? AND model_revision=? AND expires_at>? ORDER BY created_at DESC, entry_id DESC LIMIT 256`)
      .bind(identity.principal_hash, identity.partition_hash, identity.model_revision, now).all();
    return result.results.flatMap(row => {
      try {
        const vector = JSON.parse(row.vector);
        return validVector(vector) && HASH.test(row.guard_hash) && ID.test(row.entry_id)
          && Number.isFinite(row.created_at) && row.created_at <= now && row.expires_at <= row.created_at + SEMANTIC_TTL
          ? [{...row, vector}] : [];
      } catch {return [];}
    });
  }
  async body(identity, row) {
    if (!validSemanticIdentity(identity) || !ID.test(row?.entry_id)) return null;
    // Never trust a caller's pointer or metadata: re-read the scoped row.
    const saved = await this.env.INTELLIGENCE_DB.prepare(`SELECT ${FIELDS} FROM semantic_generation_cache
      WHERE principal_hash=? AND entry_id=? AND partition_hash=? AND model_revision=? AND expires_at>?`)
      .bind(identity.principal_hash, row.entry_id, identity.partition_hash, identity.model_revision, this.clock()).first();
    if (!saved || saved.created_at > this.clock() || saved.expires_at > saved.created_at + SEMANTIC_TTL
      || !Number.isInteger(saved.body_bytes) || saved.body_bytes < 1 || saved.body_bytes > MAX_BODY_BYTES || !HASH.test(saved.body_hash)) return null;
    const prefix = `${SEMANTIC_PREFIX}${identity.principal_hash}/${saved.entry_id}/`;
    if (typeof saved.body_pointer !== "string" || !saved.body_pointer.startsWith(prefix) || !ID.test(saved.body_pointer.slice(prefix.length))) return null;
    let metadata;
    try {metadata = JSON.parse(saved.metadata);} catch {return null;}
    if (!validCacheMetadata(metadata)) return null;
    const object = await this.env.multillm_media.get(saved.body_pointer);
    if (!object || object.size !== saved.body_bytes) return null;
    const body = new Uint8Array(await object.arrayBuffer());
    if (body.length !== saved.body_bytes || await digest(body) !== saved.body_hash || !completeCacheBody(body)) return null;
    const age = this.clock() - saved.created_at;
    return age >= 0 && age < SEMANTIC_TTL ? {body, metadata, age} : null;
  }
  async put(identity, vector, guard, body, metadata) {
    if (!validSemanticIdentity(identity) || !validVector(vector) || !HASH.test(guard) || !(body instanceof Uint8Array)
      || body.length > MAX_BODY_BYTES || !completeCacheBody(body) || !validCacheMetadata(metadata)) return false;
    await this.ready();
    const now = this.clock(), expiry = now + SEMANTIC_TTL;
    const id = crypto.randomUUID().replaceAll("-", "");
    const pointer = `${SEMANTIC_PREFIX}${identity.principal_hash}/${id}/${crypto.randomUUID().replaceAll("-", "")}`;
    await this.env.multillm_media.put(pointer, body, {httpMetadata: {contentType: "application/json"}, customMetadata: {expires_at: String(expiry)}});
    let stored = false;
    try {
      const results = await this.env.INTELLIGENCE_DB.batch([
        this.env.INTELLIGENCE_DB.prepare("DELETE FROM semantic_generation_cache WHERE principal_hash=? AND expires_at<=?").bind(identity.principal_hash, now),
        this.env.INTELLIGENCE_DB.prepare(`DELETE FROM semantic_generation_cache WHERE principal_hash=?1 AND entry_id IN
          (SELECT entry_id FROM semantic_generation_cache WHERE principal_hash=?1 ORDER BY created_at, entry_id
           LIMIT MAX(0, (SELECT COUNT(*) FROM semantic_generation_cache WHERE principal_hash=?1) - 255))`).bind(identity.principal_hash),
        this.env.INTELLIGENCE_DB.prepare(INSERT).bind(identity.principal_hash, id, identity.partition_hash, identity.model_revision,
          JSON.stringify(vector), guard, now, expiry, pointer, body.length, await digest(body), JSON.stringify(metadata)),
      ]);
      stored = results[2].meta.changes === 1;
      return stored;
    } finally {if (!stored) await this.env.multillm_media.delete(pointer).catch(() => {});}
  }
}

export async function cleanupSemanticCache(env, {now = Date.now()/1000, limit = 100, cursor} = {}) {
  if (!Number.isFinite(now) || !Number.isInteger(limit) || limit < 1 || limit > 1000) throw new TypeError("invalid_cleanup_bounds");
  const result = await env.INTELLIGENCE_DB.prepare(`DELETE FROM semantic_generation_cache WHERE (principal_hash, entry_id) IN
    (SELECT principal_hash, entry_id FROM semantic_generation_cache WHERE expires_at<=? LIMIT ?)`).bind(now, limit).run();
  const page = await env.multillm_media.list({prefix: SEMANTIC_PREFIX, limit, cursor, include: ["customMetadata"]});
  let deleted = 0;
  for (const object of page.objects) {
    const expiry = Number(object.customMetadata?.expires_at);
    if (object.key.startsWith(SEMANTIC_PREFIX) && object.customMetadata?.expires_at && Number.isFinite(expiry) && expiry <= now) {
      await env.multillm_media.delete(object.key); deleted++;
    }
  }
  return {rows: result.meta.changes, objects: deleted, cursor: page.truncated ? page.cursor : null};
}

const exactFields = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k));
const IDENTITY = ["version", "operation", "principal_hash", "partition_hash", "model_revision"];
export async function handleSemanticCache(db, value, env) {
  if (!object(value) || value.version !== 1) return null;
  const store = new SemanticCacheD1({...env, INTELLIGENCE_DB: db});
  const reply = value => Response.json({version: 1, ...value}, {headers: {"cache-control": "no-store"}});
  try {
    if (value.operation === "ready" && exactFields(value, ["version", "operation"])) {await store.ready(); return reply({ready: true});}
    if (!validSemanticIdentity(value)) return null;
    if (value.operation === "scan" && exactFields(value, [...IDENTITY, "vector", "guard_hash"])
      && validVector(value.vector) && HASH.test(value.guard_hash)) {
      const rows = await store.scan(value);
      // Scan the full scoped set, but bound the private reply even for 8,192-dimensional vectors.
      const candidates = rows.filter(row=>row.guard_hash === value.guard_hash && vectorSimilarity(value.vector,row.vector)>=0.98)
        .sort((a,b)=>vectorSimilarity(value.vector,b.vector)-vectorSimilarity(value.vector,a.vector)).slice(0,4);
      return reply({rows: candidates.map(({entry_id, vector, guard_hash}) => ({entry_id, vector, guard_hash}))});
    }
    if (value.operation === "body" && exactFields(value, [...IDENTITY, "entry_id"]) && ID.test(value.entry_id)) {
      const entry = await store.body(value, value);
      return reply({entry: entry ? {...entry, body: encodeBody(entry.body)} : null});
    }
    if (value.operation === "put" && exactFields(value, [...IDENTITY, "vector", "guard_hash", "body", "metadata"])
      && validVector(value.vector) && HASH.test(value.guard_hash) && validCacheMetadata(value.metadata)) {
      const body = decodeBody(value.body);
      if (!body || !completeCacheBody(body)) return null;
      return reply({stored: await store.put(value, value.vector, value.guard_hash, body, value.metadata)});
    }
    return null;
  } catch (error) {
    if (schemaMissing(error)) return schemaErrorResponse();
    return Response.json({error: "semantic_cache_unavailable", message: "Semantic cache storage is unavailable."}, {status: 503});
  }
}
