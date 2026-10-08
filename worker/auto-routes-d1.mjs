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
const SNAPSHOT_BYTES = 256 * 1024;
const SNAPSHOT_COUNT = 100;
const DIFF_PAGE = 20;
const DOMAIN = "auto_routes";
const SNAPSHOT_ID = /^[0-9a-f]{32}$/;
const ACTOR = /^[0-9a-f]{64}$/;
const SECRET_ID = /sk-[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{12,}|mllm_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}/;
const snapshotEnabled = env => ["1", "true", "yes", "on"].includes(String(env.CONFIG_SNAPSHOTS_ENABLED || "").trim().toLowerCase());
const validRevision = value => Number.isSafeInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER - 1;
const identifier = () => crypto.randomUUID().replaceAll("-", "");
const metadataColumns = "id, domain, base_revision, created_at, created_by, size_bytes";
const routeStateSQL = `SELECT json_group_array(json_object('route_id',route_id,'candidates',candidates,'updated_at',updated_at))
  FROM (SELECT route_id,candidates,updated_at FROM auto_routes ORDER BY route_id)`;
async function routeState(db) {
  const row = await db.prepare(`SELECT (${routeStateSQL}) AS state`).first();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(row.state));
  const fingerprint = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  return { state: row.state, fingerprint };
}
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
    body = JSON.parse(await boundedBody(request, snapshotEnabled(env) ? SNAPSHOT_BYTES : MAX_BODY_BYTES));
    if (!body || Array.isArray(body) || typeof body !== "object" || body.version !== 1) {
      return reply({ error: "invalid_request" }, 400);
    }
  } catch (error) {
    return reply({ error: "invalid_request" }, snapshotEnabled(env) && error?.message === "Oversized body" ? 413 : 400);
  }
  if (String(body.operation).startsWith("snapshot_") && !snapshotEnabled(env)) return reply({ error: "not_found" }, 404);
  const db = env.INTELLIGENCE_DB;
  try {
    if (String(body.operation).startsWith("snapshot_")) return await snapshotOperation(db, body);
    if (body.operation === "list" && fields(body, ["version", "operation"])) {
      const { results } = await db.prepare(`SELECT route_id, candidates, updated_at FROM auto_routes
        ORDER BY route_id LIMIT ${MAX_ROUTES}`).all();
      return reply({ version: 1, routes: results.map(row => ({ route_id: row.route_id,
        candidates: JSON.parse(row.candidates), updated_at: row.updated_at })) });
    }
    if (body.operation === "put" && fields(body, ["version", "operation", "route_id", "candidates", "updated_at"])
      && typeof body.route_id === "string" && ROUTE_ID.test(body.route_id) && validCandidates(body.candidates)
      && typeof body.updated_at === "string" && TIMESTAMP.test(body.updated_at)) {
      if (snapshotEnabled(env)) {
        await revisionedSave(db, body);
      } else {
        await db.prepare(`INSERT INTO auto_routes (route_id, candidates, updated_at) VALUES (?, ?, ?)
          ON CONFLICT(route_id) DO UPDATE SET candidates=excluded.candidates, updated_at=excluded.updated_at`)
          .bind(body.route_id, JSON.stringify(body.candidates), body.updated_at).run();
      }
      return reply({ version: 1, stored: true });
    }
    return reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("auto_route_storage_failed", snapshotEnabled(env) ? new Error("Snapshot storage is unavailable") : error,
      { operation: body.operation === "list" ? "list" : "put" });
    return reply({ error: "storage_unavailable" }, 503);
  }
}


function validConfiguration(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !fields(value, ["routes"])
    || !Array.isArray(value.routes) || !value.routes.length || value.routes.length > MAX_ROUTES) return false;
  const ids = new Set();
  return value.routes.every(row => {
    if (!row || typeof row !== "object" || !fields(row, ["route_id", "candidates"])
      || typeof row.route_id !== "string" || !ROUTE_ID.test(row.route_id) || ids.has(row.route_id)
      || SECRET_ID.test(row.route_id) || !validCandidates(row.candidates)
      || row.candidates.some(model => SECRET_ID.test(model) || !model.includes(":") || model.startsWith("auto:")
        || model.includes("://"))) return false;
    ids.add(row.route_id);
    return true;
  });
}

async function requireSnapshotSchema(db) {
  // Probe every required table before a write; deployment does not apply migrations.
  await db.prepare(`SELECT (SELECT COUNT(*) FROM config_snapshots) AS snapshots,
    (SELECT COUNT(*) FROM config_snapshot_applications) AS applications,
    (SELECT COUNT(*) FROM config_snapshot_revisions) AS domains`).first();
}

const initializeRevision = db => db.prepare(`INSERT OR IGNORE INTO config_snapshot_revisions
  (domain, revision) VALUES ('auto_routes', 0)`);
const changed = result => result?.success === true && result.meta?.changes === 1;

async function revisionedSave(db, body) {
  await requireSnapshotSchema(db);
  const statements = [initializeRevision(db),
    db.prepare(`UPDATE config_snapshot_revisions SET revision=revision+1 WHERE domain=?
      AND revision < ?`).bind(DOMAIN, Number.MAX_SAFE_INTEGER),
    db.prepare(`INSERT INTO auto_routes (route_id, candidates, updated_at)
      SELECT ?, ?, ? WHERE changes()=1
      ON CONFLICT(route_id) DO UPDATE SET candidates=excluded.candidates, updated_at=excluded.updated_at`)
      .bind(body.route_id, JSON.stringify(body.candidates), body.updated_at)];
  const results = await db.batch(statements);
  if (!changed(results[1]) || !changed(results[2])) throw new Error("Revisioned save was not confirmed");
}

async function snapshotOperation(db, body) {
  const operation = body.operation;
  if (operation === "snapshot_create") {
    if (!fields(body, ["version", "operation", "domain", "base_revision", "configuration", "actor"])
      || body.domain !== DOMAIN || !validRevision(body.base_revision) || typeof body.actor !== "string"
      || !ACTOR.test(body.actor) || !validConfiguration(body.configuration)) return reply({ error: "invalid_request" }, 400);
    const size = new TextEncoder().encode(JSON.stringify(body.configuration)).byteLength;
    if (size > SNAPSHOT_BYTES) return reply({ error: "snapshot_too_large" }, 413);
    await requireSnapshotSchema(db);
    return await createSnapshot(db, body, size);
  }
  if (operation === "snapshot_list" && fields(body, ["version", "operation"])) {
    await requireSnapshotSchema(db);
    const results = await db.batch([
      db.prepare("SELECT COALESCE((SELECT revision FROM config_snapshot_revisions WHERE domain=?), 0) AS revision").bind(DOMAIN),
      db.prepare(`SELECT ${metadataColumns} FROM config_snapshots WHERE domain=? ORDER BY created_at DESC, id DESC LIMIT ?`).bind(DOMAIN, SNAPSHOT_COUNT),
      db.prepare(`SELECT id, snapshot_id, base_revision, revision, applied_at, applied_by FROM config_snapshot_applications
        WHERE domain=? ORDER BY revision DESC LIMIT ?`).bind(DOMAIN, SNAPSHOT_COUNT)]);
    return reply({ version: 1, domain: DOMAIN, current_revision: results[0].results[0].revision,
      snapshots: results[1].results, applications: results[2].results });
  }
  if (operation === "snapshot_diff" && (fields(body, ["version", "operation", "id"])
      || fields(body, ["version", "operation", "id", "offset"]))
    && typeof body.id === "string" && SNAPSHOT_ID.test(body.id)
    && (body.offset === undefined || Number.isInteger(body.offset) && body.offset >= 0 && body.offset <= MAX_ROUTES)) {
    await requireSnapshotSchema(db);
    return await diffSnapshot(db, body.id, body.offset || 0);
  }
  if (operation === "snapshot_apply") {
    if (!fields(body, ["version", "operation", "id", "current_revision", "confirm", "actor"])
      || body.confirm !== true || !validRevision(body.current_revision)) return reply({ error: "revision_conflict" }, 409);
    if (typeof body.id !== "string" || !SNAPSHOT_ID.test(body.id)
      || typeof body.actor !== "string" || !ACTOR.test(body.actor)) return reply({ error: "invalid_request" }, 400);
    await requireSnapshotSchema(db);
    return await applySnapshot(db, body);
  }
  return reply({ error: "invalid_request" }, 400);
}

async function createSnapshot(db, body, size) {
  const id = identifier(), now = new Date().toISOString();
  const configuration = JSON.stringify({ routes: [...body.configuration.routes].sort((a, b) => a.route_id.localeCompare(b.route_id)) });
  const baseline = await routeState(db);
  const results = await db.batch([initializeRevision(db),
    db.prepare(`INSERT INTO config_snapshots (${metadataColumns}, configuration, base_fingerprint)
      SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE (${routeStateSQL})=? AND
      (SELECT revision FROM config_snapshot_revisions WHERE domain=?)=?
      AND (SELECT COUNT(*) FROM config_snapshots WHERE domain=?) < ?`)
      .bind(id, DOMAIN, body.base_revision, now, body.actor, size, configuration, baseline.fingerprint, baseline.state, DOMAIN, body.base_revision, DOMAIN, SNAPSHOT_COUNT)]);
  if (!changed(results[1])) return reply({ error: "snapshot_limit_or_revision_conflict" }, 409);
  return reply({ version: 1, snapshot: { id, domain: DOMAIN, base_revision: body.base_revision,
    created_at: now, created_by: body.actor, size_bytes: size } });
}

async function readSnapshot(db, id) {
  const row = await db.prepare(`SELECT ${metadataColumns}, configuration, base_fingerprint FROM config_snapshots WHERE id=? AND domain=?`).bind(id, DOMAIN).first();
  if (!row) return null;
  const configuration = JSON.parse(row.configuration);
  if (!validConfiguration(configuration) || new TextEncoder().encode(row.configuration).byteLength > SNAPSHOT_BYTES) {
    throw new Error("Invalid stored snapshot");
  }
  return { ...row, configuration };
}

async function diffSnapshot(db, id, offset) {
  const snapshot = await readSnapshot(db, id);
  if (!snapshot) return reply({ error: "not_found" }, 404);
  const results = await db.batch([
    db.prepare("SELECT COALESCE((SELECT revision FROM config_snapshot_revisions WHERE domain=?), 0) AS revision").bind(DOMAIN),
    db.prepare("SELECT route_id, candidates FROM auto_routes ORDER BY route_id")]);
  const stored = new Map(results[1].results.map(row => [row.route_id, JSON.parse(row.candidates)]));
  const changes = snapshot.configuration.routes.slice(offset, offset + DIFF_PAGE).map(row => {
    const before = stored.get(row.route_id) || [];
    if (before.length && (!validCandidates(before) || before.some(model => SECRET_ID.test(model)))) throw new Error("Invalid stored route");
    return { route_id: row.route_id, before, after: row.candidates };
  });
  const next = offset + DIFF_PAGE < snapshot.configuration.routes.length ? offset + DIFF_PAGE : null;
  return reply({ version: 1, id, domain: DOMAIN, base_revision: snapshot.base_revision,
    current_revision: results[0].results[0].revision, changes, next_offset: next });
}

async function applySnapshot(db, body) {
  const snapshot = await readSnapshot(db, body.id);
  if (!snapshot) return reply({ error: "not_found" }, 404);
  if (snapshot.base_revision !== body.current_revision) return reply({ error: "revision_conflict" }, 409);
  const baseline = await routeState(db);
  if (snapshot.base_fingerprint !== baseline.fingerprint) return reply({ error: "revision_conflict" }, 409);
  const action = identifier(), now = new Date().toISOString();
  const revision = body.current_revision + 1;
  const statements = [initializeRevision(db),
    db.prepare(`UPDATE config_snapshot_revisions SET revision=revision+1 WHERE domain=? AND revision=?
      AND (${routeStateSQL})=?
      AND (SELECT COUNT(*) FROM auto_routes) + (SELECT COUNT(*) FROM json_each(?) AS incoming
        WHERE NOT EXISTS (SELECT 1 FROM auto_routes WHERE route_id=json_extract(incoming.value, '$.route_id'))) <= ?`)
      .bind(DOMAIN, body.current_revision, baseline.state, JSON.stringify(snapshot.configuration.routes), MAX_ROUTES),
    db.prepare(`INSERT INTO config_snapshot_applications
      (id, domain, snapshot_id, base_revision, revision, applied_at, applied_by)
      SELECT ?, ?, ?, ?, ?, ?, ? WHERE changes()=1`)
      .bind(action, DOMAIN, body.id, body.current_revision, revision, now, body.actor)];
  for (const row of snapshot.configuration.routes) {
    statements.push(db.prepare(`INSERT INTO auto_routes (route_id, candidates, updated_at)
      SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM config_snapshot_applications WHERE id=?)
      ON CONFLICT(route_id) DO UPDATE SET candidates=excluded.candidates, updated_at=excluded.updated_at`)
      .bind(row.route_id, JSON.stringify(row.candidates), now, action));
  }
  // D1 batch is transactional: route failures roll back the revision and audit together.
  const results = await db.batch(statements);
  if (!changed(results[1])) return reply({ error: "revision_conflict" }, 409);
  if (!changed(results[2]) || results.slice(3).some(result => !changed(result))) throw new Error("Apply was not confirmed");
  return reply({ version: 1, applied: true, application_id: action, revision });
}
