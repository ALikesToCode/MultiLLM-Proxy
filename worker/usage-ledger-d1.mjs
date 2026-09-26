/**
 * Durable usage ledger in D1, reachable only through the Container's private outbound
 * handler. The Container batches billable requests and flushes them here; every flush
 * writes the raw rows and the daily per-key, per-model totals in one transaction.
 * Fixed statements, no client SQL.
 */
import { boundedBody } from "./control-users-d1.mjs";
import { logFailure } from "./log.mjs";

// Upper bounds in milliseconds of the usage_daily latency buckets; the last bucket is open.
export const LATENCY_BUCKETS = Object.freeze([250, 500, 1000, 2000, 4000, 8000, 15000, 30000, 60000, 120000]);
const BUCKET_COLUMNS = [...LATENCY_BUCKETS.map(bound => `lat_le_${bound}`), "lat_gt_120000"];
const KINDS = new Set(["chat", "responses", "images", "videos", "embeddings", "audio", "proxy"]);
const GROUPS = Object.freeze({ day: "day", model: "model", principal: "principal" });
const EVENT_COLUMNS = ["id", "at", "principal", "key_prefix", "kind", "endpoint", "requested_model", "selected_model",
  "status", "latency_ms", "input_tokens", "output_tokens", "cost_usd", "cost_basis", "request_id"];
const ROW_FIELDS = EVENT_COLUMNS.slice(1);
const MAX_BODY_BYTES = 262144;
const MAX_ROWS = 500;
const MAX_PAGE = 500;
const MAX_PRUNE = 5000;
const MAX_ANALYTICS_POINTS = 250;
const CONTROL = /[\x00-\x1f\x7f]/;
const AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const ENDPOINT = /^\/[A-Za-z0-9._~:/@+-]{0,255}$/;
const REQUEST_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const BATCH_ID = /^[0-9a-f]{32}$/;

const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Usage ledger operation failed" } }
  : value, { status, headers: { "cache-control": "no-store" } });
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));
const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !CONTROL.test(value);
const optional = (value, test) => value === null || test(value);
const count = (value, maximum = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const timestamp = value => typeof value === "string" && AT.test(value) && Number.isFinite(Date.parse(value));
const day = value => typeof value === "string" && DAY.test(value) && Number.isFinite(Date.parse(`${value}T00:00:00Z`));

export const latencyBucket = latency => {
  const index = LATENCY_BUCKETS.findIndex(bound => latency <= bound);
  return index < 0 ? LATENCY_BUCKETS.length : index;
};

export function validRow(row) {
  return row !== null && typeof row === "object" && !Array.isArray(row) && fields(row, ROW_FIELDS)
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

const field = name => `json_extract(value, '$.${name}')`;
const APPLIED = "EXISTS (SELECT 1 FROM usage_batches WHERE id = ?2 AND token = ?3)";
const INSERT_EVENTS = `INSERT INTO usage_events (at, day, ${ROW_FIELDS.slice(1).join(", ")})
  SELECT ${field("at")}, substr(${field("at")}, 1, 10), ${ROW_FIELDS.slice(1).map(field).join(", ")}
  FROM json_each(?1) WHERE ${APPLIED}`;
const TOTALS = ["requests", "errors", "input_tokens", "output_tokens", "cost_usd", "priced_requests", "latency_ms_total", ...BUCKET_COLUMNS];
const UPSERT_DAILY = `INSERT INTO usage_daily (day, principal, model, ${TOTALS.join(", ")})
  SELECT substr(${field("at")}, 1, 10) AS usage_day, ${field("principal")} AS usage_principal,
    COALESCE(${field("selected_model")}, ${field("requested_model")}, 'unknown') AS usage_model,
    COUNT(*), SUM(${field("status")} >= 400), COALESCE(SUM(${field("input_tokens")}), 0),
    COALESCE(SUM(${field("output_tokens")}), 0), COALESCE(SUM(${field("cost_usd")}), 0),
    SUM(${field("cost_usd")} IS NOT NULL), SUM(${field("latency_ms")}),
    ${BUCKET_COLUMNS.map((_, index) => `SUM(${field("bucket")} = ${index})`).join(", ")}
  FROM json_each(?1) WHERE ${APPLIED}
  GROUP BY usage_day, usage_principal, usage_model
  ON CONFLICT(day, principal, model) DO UPDATE SET ${TOTALS.map(name => `${name} = ${name} + excluded.${name}`).join(", ")}`;
const SUMS = TOTALS.map(name => `SUM(${name}) AS ${name}`).join(", ");

function summaryRow(group, row) {
  const result = { [group]: row[group] };
  for (const name of TOTALS.slice(0, 7)) result[name] = row[name] ?? 0;
  result.latency_buckets = BUCKET_COLUMNS.map(name => row[name] ?? 0);
  return result;
}

// Optional Workers Analytics Engine mirror for high-volume querying; D1 stays the record.
function mirror(env, rows) {
  const dataset = env.USAGE_ANALYTICS;
  if (!dataset || typeof dataset.writeDataPoint !== "function") return;
  try {
    for (const row of rows.slice(0, MAX_ANALYTICS_POINTS)) {
      dataset.writeDataPoint({
        indexes: [new TextEncoder().encode(row.principal).length <= 96 ? row.principal : row.principal.slice(0, 24)],
        blobs: [row.kind, row.endpoint, row.requested_model ?? "", row.selected_model ?? "", row.cost_basis ?? ""],
        doubles: [row.status, row.latency_ms, row.input_tokens ?? 0, row.output_tokens ?? 0, row.cost_usd ?? 0],
      });
    }
  } catch (error) { logFailure("usage_analytics_failed", error); }
}

async function record(db, env, body) {
  if (!fields(body, ["version", "operation", "batch", "rows"]) || typeof body.batch !== "string" || !BATCH_ID.test(body.batch)
    || !Array.isArray(body.rows) || body.rows.length < 1 || body.rows.length > MAX_ROWS || !body.rows.every(validRow)) return null;
  const rows = body.rows.map(row => ({ ...row, bucket: latencyBucket(row.latency_ms) }));
  const token = crypto.randomUUID();
  const json = JSON.stringify(rows);
  // One transaction: a batch ID seen before inserts nothing, so a retried flush is not counted twice.
  const [applied] = await db.batch([
    db.prepare("INSERT OR IGNORE INTO usage_batches (id, token, at) VALUES (?1, ?2, ?3)").bind(body.batch, token, new Date().toISOString()),
    db.prepare(INSERT_EVENTS).bind(json, body.batch, token),
    db.prepare(UPSERT_DAILY).bind(json, body.batch, token),
  ]);
  const duplicate = applied.meta.changes !== 1;
  if (!duplicate) mirror(env, body.rows);
  return { version: 1, recorded: duplicate ? 0 : rows.length, duplicate };
}

async function totals(db, body) {
  if (!fields(body, ["version", "operation", "principal", "day", "month_start"]) || !text(body.principal, 256)
    || !day(body.day) || !day(body.month_start) || body.month_start > body.day) return null;
  const row = await db.prepare(`SELECT COALESCE(SUM(CASE WHEN day = ?2 THEN cost_usd ELSE 0 END), 0) AS day_usd,
      COALESCE(SUM(cost_usd), 0) AS month_usd, COALESCE(SUM(CASE WHEN day = ?2 THEN requests ELSE 0 END), 0) AS day_requests,
      COALESCE(SUM(requests), 0) AS month_requests
    FROM usage_daily WHERE principal = ?1 AND day >= ?3 AND day <= ?2`).bind(body.principal, body.day, body.month_start).first();
  return { version: 1, totals: { day_usd: row.day_usd, month_usd: row.month_usd,
    day_requests: row.day_requests, month_requests: row.month_requests } };
}

async function summary(db, body) {
  if (!fields(body, ["version", "operation", "group", "since", "until", "principal", "limit"])
    || !Object.hasOwn(GROUPS, body.group) || !day(body.since) || !day(body.until) || body.since > body.until
    || !optional(body.principal, value => text(value, 256)) || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > MAX_PAGE) return null;
  const group = GROUPS[body.group];
  const order = group === "day" ? "day DESC" : "cost_usd DESC, requests DESC";
  const statement = body.principal === null
    ? db.prepare(`SELECT ${group}, ${SUMS} FROM usage_daily WHERE day >= ?1 AND day <= ?2 GROUP BY ${group} ORDER BY ${order}, ${group} LIMIT ?3`)
      .bind(body.since, body.until, body.limit)
    : db.prepare(`SELECT ${group}, ${SUMS} FROM usage_daily WHERE day >= ?1 AND day <= ?2 AND principal = ?4 GROUP BY ${group} ORDER BY ${order}, ${group} LIMIT ?3`)
      .bind(body.since, body.until, body.limit, body.principal);
  const { results } = await statement.all();
  return { version: 1, rows: results.map(row => summaryRow(group, row)) };
}

async function recent(db, body) {
  if (!fields(body, ["version", "operation", "since", "principal", "before", "limit"]) || !timestamp(body.since)
    || !optional(body.principal, value => text(value, 256)) || !optional(body.before, value => Number.isSafeInteger(value) && value > 0)
    || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > MAX_PAGE) return null;
  const values = [body.since, body.limit];
  let filters = "";
  if (body.principal !== null) filters += ` AND principal = ?${values.push(body.principal)}`;
  if (body.before !== null) filters += ` AND id < ?${values.push(body.before)}`;
  const { results } = await db.prepare(`SELECT ${EVENT_COLUMNS.join(", ")} FROM usage_events
    WHERE at >= ?1${filters} ORDER BY id DESC LIMIT ?2`).bind(...values).all();
  return { version: 1, rows: results };
}

async function prune(db, body) {
  if (!fields(body, ["version", "operation", "events_before", "rollups_before", "limit"]) || !timestamp(body.events_before)
    || !day(body.rollups_before) || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > MAX_PRUNE) return null;
  const [events, batches, rollups] = await db.batch([
    db.prepare("DELETE FROM usage_events WHERE id IN (SELECT id FROM usage_events WHERE at < ?1 ORDER BY id LIMIT ?2)")
      .bind(body.events_before, body.limit),
    db.prepare("DELETE FROM usage_batches WHERE id IN (SELECT id FROM usage_batches WHERE at < ?1 LIMIT ?2)")
      .bind(body.events_before, body.limit),
    db.prepare("DELETE FROM usage_daily WHERE rowid IN (SELECT rowid FROM usage_daily WHERE day < ?1 LIMIT ?2)")
      .bind(body.rollups_before, body.limit),
  ]);
  return { version: 1, pruned: { events: events.meta.changes, batches: batches.meta.changes, rollups: rollups.meta.changes } };
}

const OPERATIONS = { record, totals, summary, recent, prune };

export async function handleUsageLedgerRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal"
    || url.pathname !== "/v1/usage" || url.search || url.hash || url.username || url.password) return reply({ error: "not_found" }, 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return reply({ error: "invalid_request" }, 400);
  }
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) return reply({ error: "invalid_request" }, 400);
  if (!env.INTELLIGENCE_DB) return reply({ error: "storage_unavailable" }, 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request, MAX_BODY_BYTES));
    if (!body || Array.isArray(body) || typeof body !== "object" || body.version !== 1) return reply({ error: "invalid_request" }, 400);
  } catch { return reply({ error: "invalid_request" }, 400); }
  const operation = Object.hasOwn(OPERATIONS, body.operation) ? OPERATIONS[body.operation] : null;
  if (!operation) return reply({ error: "invalid_request" }, 400);
  try {
    const result = operation === record ? await record(env.INTELLIGENCE_DB, env, body) : await operation(env.INTELLIGENCE_DB, body);
    return result ? reply(result) : reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("usage_ledger_failed", error, { operation: body.operation });
    return reply({ error: "storage_unavailable" }, 503);
  }
}
