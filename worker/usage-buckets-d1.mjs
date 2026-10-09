/** Opt-in strict bucket serialization; the ledger owner injects transaction writers. */

export const BUCKET_FIELDS = Object.freeze(["ordinary_input_tokens", "cache_read_input_tokens", "cache_write_input_tokens",
  "ordinary_input_cost_microusd", "cache_read_input_cost_microusd", "cache_write_input_cost_microusd", "output_cost_microusd",
  "bucket_basis", "bucket_source"]);
const BASE_FIELDS = Object.freeze(["at", "principal", "key_prefix", "kind", "endpoint", "requested_model", "selected_model",
  "status", "latency_ms", "input_tokens", "output_tokens", "cost_usd", "cost_basis", "request_id"]);
const KINDS = new Set(["chat", "responses", "images", "videos", "embeddings", "audio", "proxy"]);
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const ENDPOINT = /^\/[A-Za-z0-9._~:/@+-]{0,255}$/;
const REQUEST_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const CONTROL = /[\x00-\x1f\x7f]/;
const AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));
const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !CONTROL.test(value);
const optional = (value, test) => value === null || test(value);
const count = (value, maximum = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const timestamp = value => typeof value === "string" && AT.test(value) && Number.isFinite(Date.parse(value));

export function validBaseUsageRow(row) {
  return row !== null && typeof row === "object" && !Array.isArray(row) && fields(row, BASE_FIELDS)
    && timestamp(row.at) && text(row.principal, 256) && optional(row.key_prefix, value => text(value, 64))
    && KINDS.has(row.kind) && typeof row.endpoint === "string" && ENDPOINT.test(row.endpoint)
    && optional(row.requested_model, value => typeof value === "string" && MODEL.test(value))
    && optional(row.selected_model, value => typeof value === "string" && MODEL.test(value))
    && Number.isSafeInteger(row.status) && row.status >= 100 && row.status <= 599
    && count(row.latency_ms, 86_400_000) && optional(row.input_tokens, count) && optional(row.output_tokens, count)
    && optional(row.cost_usd, value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1_000_000)
    && (row.cost_basis === null || row.cost_basis === "usage" || row.cost_basis === "estimate")
    && optional(row.request_id, value => typeof value === "string" && REQUEST_ID.test(value));
}

const warned = new Set();
const warn = name => { if (!warned.has(name)) { warned.add(name); console.warn(`Invalid ${name}; prompt cache buckets disabled`); } };
export function usageBucketsEnabled(env) {
  const flag = String(env.PROMPT_CACHE_USAGE_BUCKETS_ENABLED ?? "").trim().toLowerCase();
  if (["", "0", "false", "no", "off"].includes(flag)) return false;
  if (!["1", "true", "yes", "on"].includes(flag)) { warn("PROMPT_CACHE_USAGE_BUCKETS_ENABLED"); return false; }
  const raw = String(env.PROMPT_CACHE_PRICE_METADATA_JSON ?? "").trim();
  try {
    const parsed = JSON.parse(raw || "{}");
    if (raw.length > 262144 || !parsed || Array.isArray(parsed) || typeof parsed !== "object"
      || Object.values(parsed).some(value => !value || Array.isArray(value) || typeof value !== "object"
        || Object.values(value).some(price => !["number", "string"].includes(typeof price)
          || !/^[+\-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+\-]?\d+)?$/i.test(String(price).trim())
          || !Number.isFinite(Number(price)) || Number(price) < 0 || Number(price) > 1e12))) throw new Error();
  } catch { warn("PROMPT_CACHE_PRICE_METADATA_JSON"); return false; }
  return true;
}

export function serializeUsageBuckets(row, env) {
  if (!row || typeof row !== "object" || Array.isArray(row)) throw new TypeError("invalid usage row");
  const base = Object.fromEntries(BASE_FIELDS.map(name => [name, row[name]]));
  if (!validBaseUsageRow(base)) throw new TypeError("invalid usage row");
  const allowed = new Set([...BASE_FIELDS, ...BUCKET_FIELDS]);
  if (Object.keys(row).some(name => !allowed.has(name))) throw new TypeError("invalid usage fields");
  if (!usageBucketsEnabled(env)) return base;
  const result = { ...base };
  for (const name of BUCKET_FIELDS) {
    const value = row[name] ?? null;
    let valid = value === null;
    if (name.endsWith("tokens")) valid ||= Number.isSafeInteger(value) && value >= 0;
    else if (name.endsWith("microusd")) valid ||= typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1e12;
    else if (name === "bucket_basis") valid ||= ["measured", "estimated", "unknown"].includes(value);
    else valid ||= ["openai", "anthropic", "request_estimate", "unknown"].includes(value);
    if (!valid) throw new TypeError("invalid usage bucket");
    result[name] = value;
  }
  return result;
}

/** Fixed JSON insertion replaces INSERT_EVENTS inside the existing batch transaction. */
export function bucketInsertStatement(baseFields = BASE_FIELDS) {
  if (baseFields.length !== BASE_FIELDS.length || baseFields.some((name, i) => name !== BASE_FIELDS[i])) {
    throw new TypeError("invalid ledger columns");
  }
  const names = [...BASE_FIELDS, ...BUCKET_FIELDS];
  return `INSERT INTO usage_events (day, ${names.join(", ")})
    SELECT substr(json_extract(value, '$.at'), 1, 10), ${names.map(name => `json_extract(value, '$.${name}')`).join(", ")}
    FROM json_each(?1) WHERE EXISTS (SELECT 1 FROM usage_batches WHERE id = ?2 AND token = ?3)`;
}

/** Extended writes must be atomic/idempotent; on failure the legacy writer saves the base row. */
export async function recordUsageWithBuckets(env, body, { recordBase, recordExtended }) {
  const enabled = usageBucketsEnabled(env);
  let rows;
  try {
    if (!Array.isArray(body.rows) || body.rows.length < 1 || body.rows.length > 500) throw new TypeError();
    rows = body.rows.map(row => serializeUsageBuckets(row, env));
  } catch {
    return Response.json({ version: 1, error: { code: "invalid_request", message: "Usage ledger operation failed" } }, { status: 400 });
  }
  const legacy = { ...body, rows: rows.map(row => Object.fromEntries(BASE_FIELDS.map(name => [name, row[name]]))) };
  const headers = { "cache-control": "no-store" };
  if (!enabled) return Response.json(await recordBase(legacy), { headers });
  try {
    return Response.json(await recordExtended({ ...body, rows }), { headers });
  } catch {
    try { await recordBase(legacy); } catch {
      return Response.json({ version: 1, error: { code: "storage_unavailable", message: "Usage ledger operation failed" } },
        { status: 503, headers });
    }
    return Response.json({ version: 1, error: { code: "usage_buckets_unavailable",
      message: "Prompt cache usage storage unavailable; verify migration 0016" } }, { status: 503, headers });
  }
}
