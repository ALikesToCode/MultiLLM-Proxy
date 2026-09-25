/**
 * Operator-edited automatic routes in D1, reachable only through the Container's private
 * outbound handler. Container disk is reset on sleep and replacement; these rows are not.
 * Fixed statements, no client SQL.
 */
import { boundedBody } from "./control-users-d1.mjs";
import { logFailure } from "./log.mjs";

const ROUTE_ID = /^auto:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const MAX_CANDIDATES = 16;
const MAX_ROUTES = 200;
const MAX_BODY_BYTES = 16384;
const TIMESTAMP = /^[0-9T:.+\-Z]{10,40}$/;
const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Auto route storage operation failed" } }
  : value, { status, headers: { "cache-control": "no-store" } });
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));

export const validCandidates = value => Array.isArray(value) && value.length > 0 && value.length <= MAX_CANDIDATES
  && value.every(item => typeof item === "string" && MODEL_ID.test(item)) && new Set(value).size === value.length;

export async function handleAutoRoutesRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal"
    || url.pathname !== "/v1/auto-routes" || url.search || url.hash || url.username || url.password) return reply({ error: "not_found" }, 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return reply({ error: "invalid_request" }, 400);
  }
  if (!env.INTELLIGENCE_DB) return reply({ error: "storage_unavailable" }, 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request, MAX_BODY_BYTES));
    if (!body || Array.isArray(body) || typeof body !== "object" || body.version !== 1) return reply({ error: "invalid_request" }, 400);
  } catch { return reply({ error: "invalid_request" }, 400); }
  const db = env.INTELLIGENCE_DB;
  try {
    if (body.operation === "list" && fields(body, ["version", "operation"])) {
      const { results } = await db.prepare(`SELECT route_id, candidates, updated_at FROM auto_routes
        ORDER BY route_id LIMIT ${MAX_ROUTES}`).all();
      return reply({ version: 1, routes: results.map(row => ({ route_id: row.route_id,
        candidates: JSON.parse(row.candidates), updated_at: row.updated_at })) });
    }
    if (body.operation === "put" && fields(body, ["version", "operation", "route_id", "candidates", "updated_at"])
      && typeof body.route_id === "string" && ROUTE_ID.test(body.route_id) && validCandidates(body.candidates)
      && typeof body.updated_at === "string" && TIMESTAMP.test(body.updated_at)) {
      await db.prepare(`INSERT INTO auto_routes (route_id, candidates, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(route_id) DO UPDATE SET candidates=excluded.candidates, updated_at=excluded.updated_at`)
        .bind(body.route_id, JSON.stringify(body.candidates), body.updated_at).run();
      return reply({ version: 1, stored: true });
    }
    return reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("auto_route_storage_failed", error, { operation: body.operation === "list" ? "list" : "put" });
    return reply({ error: "storage_unavailable" }, 503);
  }
}
