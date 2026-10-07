import { fields, fail, integer, parseQuery, string } from "./contracts.mjs";
import { scanText } from "../secret-scan.mjs";

export const MEMO_SHARD_LIMIT = 2000;
export const MEMO_TOTAL_LIMIT = 20000;
export const MEMO_BUNDLE_BYTES = 256 * 1024;
export const memoQueryNorm = query => query.toLowerCase().replace(/\s+/g, " ").trim().replace(/[\p{P}\s]+$/u, "");
export const memoKey = request => ({ product: request.product || "", version: request.version || "", repository: request.repository || "" });
const target = request => JSON.stringify([request.product || "", request.version || "", request.repository || "", request.mode]);
const bytes = value => new TextEncoder().encode(JSON.stringify(value)).byteLength;

// Memos are shared across principals, so even a heuristic finding keeps a query out.
export function memoSecretQuery(query) {
  return /-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|\b(?:sk-|AIza|ghp_|xox)/.test(query) || scanText(query).length > 0;
}

export function quantizeEmbedding(vector) {
  if (!Array.isArray(vector) || !vector.length || vector.length > 1024 || vector.some(value => typeof value !== "number" || !Number.isFinite(value))) return null;
  const maximum = Math.max(...vector.map(Math.abs));
  if (!maximum) return null;
  const scale = maximum / 127;
  if (!Number.isFinite(scale) || scale <= 0) return null;
  return { values: vector.map(value => Math.round(value / scale)), scale };
}

function validEmbedding(embedding) {
  return embedding && Number.isFinite(embedding.scale) && embedding.scale > 0
    && Array.isArray(embedding.values) && embedding.values.length > 0 && embedding.values.length <= 1024
    && embedding.values.every(value => Number.isInteger(value) && value >= -127 && value <= 127)
    && embedding.values.some(value => value !== 0);
}

export function embeddingCosine(left, right) {
  if (!left || !right || left.length !== right.length) return -1;
  let dot = 0, a = 0, b = 0;
  for (let i = 0; i < left.length; i++) { dot += left[i] * right[i]; a += left[i] ** 2; b += right[i] ** 2; }
  return a && b ? Math.min(1, Math.max(-1, dot / Math.sqrt(a * b))) : -1;
}

export function parseMemoPurge(payload) {
  fields(payload, ["product", "all"]);
  if (payload.all !== undefined && typeof payload.all !== "boolean") fail("invalid_request", "all must be a boolean.");
  if (payload.product !== undefined) {
    if (payload.all === true) fail("invalid_request", "Choose a product or all, not both.");
    // The empty product selects the unscoped shard.
    if (payload.product !== "") payload.product = string(payload.product, 100, "product").toLowerCase();
    return { product: payload.product };
  }
  if (payload.all !== true) fail("invalid_request", "Specify product or all: true to purge memos.");
  return { all: true };
}

function validateMemo(record) {
  fields(record, ["id", "created_at", "last_hit_at", "hits", "key", "query", "query_norm", "mode", "token_budget", "embedding", "bundle", "citations", "state"],
    ["id", "created_at", "last_hit_at", "hits", "key", "query", "query_norm", "mode", "token_budget", "embedding", "bundle", "citations"]);
  if (!/^[a-f0-9]{64}$/.test(record.id ?? "")) fail("invalid_memo", "Invalid memo identity.");
  if (record.state !== undefined && !/^[a-f0-9]{64}$/.test(record.state)) fail("invalid_memo", "Invalid memo policy state.");
  fields(record.key, ["product", "version", "repository"], ["product", "version", "repository"]);
  const request = parseQuery({ ...record.key, query: record.query, mode: record.mode, token_budget: record.token_budget });
  if (memoSecretQuery(record.query) || record.query_norm !== memoQueryNorm(record.query)
    || !Number.isFinite(Date.parse(record.created_at)) || !Number.isFinite(Date.parse(record.last_hit_at))
    || record.embedding !== null && !validEmbedding(record.embedding)) fail("invalid_memo", "Invalid memo metadata.");
  integer(record.hits, 0, Number.MAX_SAFE_INTEGER, "hits");
  const bundle = record.bundle;
  if (!bundle || !["ok", "partial"].includes(bundle.status) || !Array.isArray(bundle.excerpts) || !bundle.excerpts.length
    || !Number.isSafeInteger(bundle.token_count) || bundle.token_count < 0 || bundle.token_count > request.token_budget
    || Object.hasOwn(bundle, "usage") || Object.hasOwn(bundle, "served_at") || bytes(bundle) > MEMO_BUNDLE_BYTES) fail("invalid_memo", "Invalid memo bundle.");
  if (!Array.isArray(record.citations) || !record.citations.length || record.citations.length > 100
    || record.citations.some(item => !/^[a-f0-9]{64}$/.test(item.artifact_id ?? "")
      || !/^[a-f0-9]{64}$/.test(item.content_hash ?? "") || !Number.isFinite(Date.parse(item.expires_at)))) fail("invalid_memo", "Invalid memo citations.");
  const cited = new Map(record.citations.map(item => [item.artifact_id, item]));
  if ([...bundle.excerpts, ...(bundle.related_evidence || [])].some(item => {
    const citation = cited.get(item.artifact_id);
    return !citation || citation.content_hash !== item.content_hash || citation.expires_at !== item.expires_at;
  })) fail("invalid_memo", "Every excerpt must have a citation manifest.");
  return request;
}

// Logical product shards share one SQLite transaction so global LRU and purge cannot race.
export class MemoStore {
  constructor(storage, { shardLimit = MEMO_SHARD_LIMIT, totalLimit = MEMO_TOTAL_LIMIT } = {}) {
    this.storage = storage;
    this.sql = storage.sql;
    this.shardLimit = shardLimit;
    this.totalLimit = totalLimit;
    this.vectors = null;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS memos (
      id TEXT PRIMARY KEY, product TEXT NOT NULL, target TEXT NOT NULL, query_norm TEXT NOT NULL,
      token_count INTEGER NOT NULL, created_at TEXT NOT NULL, last_hit_at TEXT NOT NULL, hits INTEGER NOT NULL,
      embedding TEXT, record TEXT NOT NULL)`);
    this.sql.exec("CREATE INDEX IF NOT EXISTS memo_exact ON memos(target, query_norm, token_count)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS memo_lru ON memos(last_hit_at, created_at, id)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS memo_product ON memos(product, last_hit_at, created_at, id)");
  }

  rows(query, ...args) { return [...this.sql.exec(query, ...args)]; }

  remove(id) {
    this.sql.exec("DELETE FROM memos WHERE id = ?", id);
    this.vectors?.entries.delete(id);
  }

  put(record) {
    const request = validateMemo(record);
    this.storage.transactionSync(() => {
      this.sql.exec(`INSERT OR REPLACE INTO memos VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        record.id, request.product, target(request), record.query_norm, record.bundle.token_count,
        record.created_at, record.last_hit_at, record.hits, record.embedding ? JSON.stringify(record.embedding) : null, JSON.stringify(record));
      const evict = (where, args, limit) => {
        const count = this.rows(`SELECT COUNT(*) AS count FROM memos ${where}`, ...args)[0].count;
        for (const row of this.rows(`SELECT id FROM memos ${where} ORDER BY last_hit_at, created_at, id LIMIT ?`, ...args, Math.max(0, count - limit))) this.remove(row.id);
      };
      evict("WHERE product = ?", [request.product], this.shardLimit);
      evict("", [], this.totalLimit);
    });
    // Rebuild only the active product's bounded vector set after a mutation.
    this.vectors = null;
    return { stored: this.rows("SELECT id FROM memos WHERE id = ?", record.id).length > 0 };
  }

  find(payload) {
    fields(payload, ["request", "kind", "embedding", "similarity"], ["request", "kind"]);
    const request = parseQuery(payload.request);
    if (payload.kind === "exact") {
      const row = this.rows(`SELECT record FROM memos WHERE target = ? AND query_norm = ? AND token_count <= ?
        ORDER BY last_hit_at DESC, created_at DESC, id LIMIT 1`, target(request), memoQueryNorm(request.query), request.token_budget)[0];
      return row ? { record: JSON.parse(row.record), similarity: 1 } : null;
    }
    if (payload.kind !== "semantic" || !validEmbedding(payload.embedding)
      || !Number.isFinite(payload.similarity) || payload.similarity < 0.85 || payload.similarity > 0.99) fail("invalid_memo", "Invalid semantic lookup.");
    if (this.vectors?.product !== request.product) {
      const rows = this.rows("SELECT id, target, token_count, embedding FROM memos WHERE product = ? AND embedding IS NOT NULL LIMIT ?", request.product, this.shardLimit);
      this.vectors = { product: request.product, entries: new Map(rows.map(row => [row.id,
        { ...row, vector: Int8Array.from(JSON.parse(row.embedding).values) }])) };
    }
    let best = null;
    const query = Int8Array.from(payload.embedding.values);
    for (const row of this.vectors.entries.values()) {
      if (row.target !== target(request) || row.token_count > request.token_budget) continue;
      const similarity = embeddingCosine(query, row.vector);
      if (similarity >= payload.similarity && (!best || similarity > best.similarity)) best = { id: row.id, similarity };
    }
    if (!best) return null;
    const row = this.rows("SELECT record FROM memos WHERE id = ?", best.id)[0];
    return row ? { record: JSON.parse(row.record), similarity: best.similarity } : null;
  }

  hit(id, now) {
    const row = this.rows("SELECT record FROM memos WHERE id = ?", id)[0];
    if (!row) return { hit: false };
    const record = JSON.parse(row.record);
    record.hits = Math.min(Number.MAX_SAFE_INTEGER, record.hits + 1);
    record.last_hit_at = new Date(now).toISOString();
    this.sql.exec("UPDATE memos SET hits = ?, last_hit_at = ?, record = ? WHERE id = ?", record.hits, record.last_hit_at, JSON.stringify(record), id);
    return { hit: true };
  }

  stats() {
    const aggregate = "COUNT(*) AS count, COALESCE(SUM(hits), 0) AS hits, MIN(created_at) AS oldest, MAX(created_at) AS newest";
    return { shards: this.rows(`SELECT product, ${aggregate} FROM memos GROUP BY product ORDER BY product LIMIT ?`, this.totalLimit),
      totals: this.rows(`SELECT ${aggregate} FROM memos`)[0], limits: { per_shard: this.shardLimit, total: this.totalLimit } };
  }

  purge(payload) {
    const parsed = parseMemoPurge(payload);
    return this.storage.transactionSync(() => {
      const where = parsed.all ? "" : "WHERE product = ?";
      const args = parsed.all ? [] : [parsed.product];
      const purged = this.rows(`SELECT COUNT(*) AS count FROM memos ${where}`, ...args)[0].count;
      this.sql.exec(`DELETE FROM memos ${where}`, ...args);
      this.vectors = null;
      return { purged };
    });
  }

  call(operation, payload = {}, now = Date.now()) {
    if (operation === "put") { fields(payload, ["record"], ["record"]); return this.put(payload.record); }
    if (operation === "find") return this.find(payload);
    if (operation === "stats") { fields(payload, []); return this.stats(); }
    if (operation === "purge") return this.purge(payload);
    if (["delete", "hit"].includes(operation)) {
      fields(payload, ["id"], ["id"]);
      if (!/^[a-f0-9]{64}$/.test(payload.id ?? "")) fail("invalid_memo", "Invalid memo identity.");
      if (operation === "hit") return this.hit(payload.id, now);
      this.remove(payload.id);
      return { deleted: true };
    }
    fail("unknown_operation", "Unknown memo operation.", 404);
  }
}
