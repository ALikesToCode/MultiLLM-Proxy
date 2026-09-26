/**
 * Route health rows and the public status snapshot in D1. The Container writes them in
 * batches through its private outbound handler; the Worker reads the snapshot to serve
 * /status while the Container sleeps. Fixed statements, no client SQL.
 */
import { boundedBody } from "./control-users-d1.mjs";
import { logFailure } from "./log.mjs";

const TARGET = /^(?:provider:[a-z0-9][a-z0-9._-]{0,63}|[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255})$/;
const TIMESTAMP = /^[0-9T:.+\-Z]{10,40}$/;
const STATE_FIELDS = ["kind", "ewma_success", "ewma_at", "ewma_latency_ms", "latency_at", "last_status",
  "last_outcome", "consecutive_failures", "last_success_at", "last_failure_at", "last_check_at", "last_check_ok",
  "last_check_status", "samples", "updated_at"];
const MAX_LIST_ROWS = 512;
const MAX_PUT_ROWS = 64;
const MAX_STATE_BYTES = 4096;
export const MAX_SNAPSHOT_BYTES = 196608;
const MAX_BODY_BYTES = 262144;

const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Route health storage operation failed" } }
  : value, { status, headers: { "cache-control": "no-store" } });
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);

function validState(state) {
  return isObject(state) && fields(state, STATE_FIELDS) && ["candidate", "provider"].includes(state.kind)
    && Array.isArray(state.samples) && state.samples.length <= 32
    && JSON.stringify(state).length <= MAX_STATE_BYTES;
}

const validRow = row => isObject(row) && fields(row, ["target", "state", "updated_at"])
  && typeof row.target === "string" && TARGET.test(row.target) && validState(row.state)
  && typeof row.updated_at === "string" && TIMESTAMP.test(row.updated_at);

/** The stored public status document, or null when none was written or D1 is unreadable. */
export async function readStatusSnapshot(db) {
  if (!db) return null;
  try {
    const row = await db.prepare("SELECT body, updated_at FROM route_health_snapshot WHERE id = 'public'").first();
    if (!row) return null;
    const body = JSON.parse(row.body);
    return isObject(body) && body.version === 1 ? body : null;
  } catch (error) {
    logFailure("status_snapshot_read_failed", error);
    return null;
  }
}

export async function handleRouteHealthRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal"
    || url.pathname !== "/v1/route-health" || url.search || url.hash || url.username || url.password) return reply({ error: "not_found" }, 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return reply({ error: "invalid_request" }, 400);
  }
  if (!env.INTELLIGENCE_DB) return reply({ error: "storage_unavailable" }, 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request, MAX_BODY_BYTES));
    if (!isObject(body) || body.version !== 1) return reply({ error: "invalid_request" }, 400);
  } catch { return reply({ error: "invalid_request" }, 400); }
  const db = env.INTELLIGENCE_DB;
  const operation = ["list", "put", "snapshot"].includes(body.operation) ? body.operation : "invalid";
  try {
    if (operation === "list" && fields(body, ["version", "operation"])) {
      const { results } = await db.prepare(`SELECT target, state, updated_at FROM route_health
        ORDER BY updated_at DESC LIMIT ${MAX_LIST_ROWS}`).all();
      return reply({ version: 1, rows: results.map(row => ({ target: row.target, state: JSON.parse(row.state),
        updated_at: row.updated_at })) });
    }
    if (operation === "put" && fields(body, ["version", "operation", "rows"]) && Array.isArray(body.rows)
      && body.rows.length > 0 && body.rows.length <= MAX_PUT_ROWS && body.rows.every(validRow)
      && new Set(body.rows.map(row => row.target)).size === body.rows.length) {
      const statement = db.prepare(`INSERT INTO route_health (target, state, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(target) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at
        WHERE excluded.updated_at >= route_health.updated_at`);
      await db.batch(body.rows.map(row => statement.bind(row.target, JSON.stringify(row.state), row.updated_at)));
      return reply({ version: 1, stored: body.rows.length });
    }
    if (operation === "snapshot" && fields(body, ["version", "operation", "body", "updated_at"])
      && isObject(body.body) && body.body.version === 1 && typeof body.updated_at === "string"
      && TIMESTAMP.test(body.updated_at) && JSON.stringify(body.body).length <= MAX_SNAPSHOT_BYTES) {
      await db.prepare(`INSERT INTO route_health_snapshot (id, body, updated_at) VALUES ('public', ?, ?)
        ON CONFLICT(id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at
        WHERE excluded.updated_at >= route_health_snapshot.updated_at`)
        .bind(JSON.stringify(body.body), body.updated_at).run();
      return reply({ version: 1, stored: true });
    }
    return reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("route_health_storage_failed", error, { operation });
    return reply({ error: "storage_unavailable" }, 503);
  }
}
