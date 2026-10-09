/** Reviewed cohort policy; trusted identity is supplied by the authentication boundary. */
export const CANARY_HEADER = "X-MultiLLM-Canary-Cohort";
const warned = new Set();
function warnOnce(reason, warn = console.warn, baseline = true) {
  if (warned.has(reason)) return;
  warned.add(reason);
  warn(`Canary traffic ${reason}${baseline ? "; using baseline routing" : ""}`);
}
const flagOn = value => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
const record = value => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, names) => record(value) && Object.keys(value).length === names.length
  && names.every(name => Object.hasOwn(value, name));

export function canaryEnabled(env = {}, warn = console.warn) {
  const flag = String(env.CANARY_TRAFFIC_ENABLED || "").trim().toLowerCase();
  if (!["", "0", "false", "no", "off", "1", "true", "yes", "on"].includes(flag)) {
    warnOnce("flag is invalid", warn);
    return false;
  }
  return flagOn(flag);
}

export function normalizeCanary(value, candidates) {
  const allowed = ["enabled", "mode", "weights", "salt_revision", "approved_candidates"];
  if (!record(value) || Object.keys(value).some(name => !allowed.includes(name))) throw new Error("Invalid canary configuration");
  const enabled = Object.hasOwn(value, "enabled") ? value.enabled : false;
  const mode = Object.hasOwn(value, "mode") ? value.mode : "shadow";
  const weights = Object.hasOwn(value, "weights") ? value.weights : { baseline: 100, candidate: 0 };
  const revision = Object.hasOwn(value, "salt_revision") ? value.salt_revision : "1";
  const approved = Object.hasOwn(value, "approved_candidates") ? value.approved_candidates : [];
  if (typeof enabled !== "boolean" || !["shadow", "live"].includes(mode)
    || !fields(weights, ["baseline", "candidate"])
    || !Object.values(weights).every(n => Number.isSafeInteger(n) && n >= 0)
    || weights.baseline + weights.candidate !== 100
    || typeof revision !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(revision)
    || !Array.isArray(approved) || approved.length > 16
    || !approved.every(model => typeof model === "string" && candidates.includes(model))
    || new Set(approved).size !== approved.length || enabled && weights.candidate > 0 && !approved.length) {
    throw new Error("Invalid canary configuration");
  }
  return Object.freeze({ enabled, mode, weights: Object.freeze({ ...weights }), salt_revision: revision,
    approved_candidates: Object.freeze([...approved]) });
}

export async function assignCohort(policy, { principal, session, routeId, key, warn = console.warn }) {
  if (!policy.enabled) return "baseline";
  if (typeof key !== "string" || !key) {
    warnOnce("assignment secret is unavailable", warn);
    return "baseline";
  }
  if (typeof principal !== "string" || !principal.trim() || typeof session !== "string" || !session.trim()) return "baseline";
  if ([principal, session, routeId, key].some(value => /[\uD800-\uDFFF]/u.test(value))) return "baseline";
  const text = JSON.stringify(["multillm-canary-v1", principal, session, routeId, policy.salt_revision]);
  const encoder = new TextEncoder();
  const secret = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = await crypto.subtle.sign("HMAC", secret, encoder.encode(text));
  const bucket = new DataView(digest).getUint32(0, false) % 100;
  return bucket < policy.weights.baseline ? "baseline" : "candidate";
}

export function authenticatedPrincipal(user) {
  const identity = user?.id || user?.username;
  return identity ? JSON.stringify([user.tenant_id ?? null, identity]) : null;
}

/** Match Container prompt cache affinity, without assigning a missing session. */
export function sessionIdentifier(headers, payload = {}, user = {}) {
  const metadata = record(payload.metadata) ? payload.metadata : {};
  return [headers.get("x-opencode-session"), headers.get("session-id"), headers.get("thread-id"),
    payload.session_id, payload.conversation_id, metadata.session_id, metadata.conversation_id, user.session_id]
    .find(value => typeof value === "string" && value.trim()) ?? null;
}

/** Call before existing eligibility and health ordering; never dispatches a provider. */
export async function prepareCanary(route, { env = {}, principal, session, observe = () => {}, warn = console.warn } = {}) {
  if (!canaryEnabled(env, warn) || !route.canary?.enabled) return null;
  let policy;
  try { policy = normalizeCanary(route.canary, route.candidates); }
  catch { warnOnce("stored configuration is invalid", warn); return null; }
  const cohort = await assignCohort(policy, { principal, session, routeId: route.id, key: env.JWT_SECRET, warn });
  const approved = new Set(policy.approved_candidates);
  const candidateOrder = [...route.candidates.filter(model => approved.has(model)), ...route.candidates.filter(model => !approved.has(model))];
  const proposedOrder = cohort === "candidate" ? candidateOrder : route.candidates;
  const candidates = cohort === "candidate" && policy.mode === "live" ? proposedOrder : route.candidates;
  try { await observe({ route_id: route.id, cohort, mode: policy.mode, proposed_order: [...proposedOrder] }); }
  catch { warnOnce("observation is unavailable", warn, false); }
  return Object.freeze({ cohort, mode: policy.mode, proposedOrder, candidates,
    decorate(response) { response.headers.set(CANARY_HEADER, `${cohort}; mode=${policy.mode}`); return response; } });
}

const reply = (body, status = 200) => Response.json(body, { status, headers: { "cache-control": "no-store" } });
const failure = (code, status) => reply({ version: 1, error: { code, message: "Canary route storage operation failed" } }, status);
const routeIdValid = value => typeof value === "string" && /^auto:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
const candidateListValid = value => Array.isArray(value) && value.length > 0 && value.length <= 16
  && new Set(value).size === value.length && value.every(model => typeof model === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/.test(model) && model.includes(":") && !model.startsWith("auto:"));
const revisionValid = value => Number.isSafeInteger(value) && value >= 0 && value < Number.MAX_SAFE_INTEGER;

/** Parsed operations from handleAutoRoutesRequest's existing private authorization boundary. */
export async function handleCanaryRouteOperation(db, body, env = {}, warn = console.warn) {
  if (!["canary_list", "canary_put"].includes(body?.operation)) return null;
  if (body.version !== 1) return failure("invalid_request", 400);
  try {
    if (body.operation === "canary_list") {
      if (!fields(body, ["version", "operation"])) return failure("invalid_request", 400);
      const { results } = await db.prepare(`SELECT policy.route_id, policy.route_updated_at, policy.configuration
        FROM canary_traffic AS policy JOIN auto_routes AS route ON policy.route_id=route.route_id
        AND policy.route_updated_at=route.updated_at ORDER BY policy.route_id LIMIT 200`).all();
      return reply({ version: 1, routes: results.map(row => ({ route_id: row.route_id,
        updated_at: row.route_updated_at, canary: JSON.parse(row.configuration) })) });
    }
    const names = ["version", "operation", "route_id", "candidates", "updated_at", "canary", "current_revision"];
    if (!fields(body, names) || !routeIdValid(body.route_id) || !candidateListValid(body.candidates)
      || typeof body.updated_at !== "string" || !/^[0-9T:.+\-Z]{10,40}$/.test(body.updated_at)
      || body.current_revision !== null && !revisionValid(body.current_revision)) return failure("invalid_request", 400);
    let policy;
    try { policy = normalizeCanary(body.canary, body.candidates); }
    catch { return failure("invalid_request", 400); }
    const revisioned = flagOn(env.CONFIG_SNAPSHOTS_ENABLED) || flagOn(env.CONFIG_REVISION_SYNC_ENABLED)
      || body.current_revision !== null;
    if (revisioned && body.current_revision === null) return failure("revision_conflict", 409);
    return await saveRoute(db, body, policy, revisioned);
  } catch {
    warnOnce("configuration storage is unavailable", warn);
    return failure("canary_route_storage_unavailable", 503);
  }
}

async function saveRoute(db, body, policy, revisioned) {
  // Probe before any route write: a code deployment does not apply the migration.
  await db.prepare("SELECT route_id FROM canary_traffic LIMIT 1").all();
  const statements = [];
  if (revisioned) statements.push(
    db.prepare("INSERT OR IGNORE INTO config_snapshot_revisions (domain, revision) VALUES ('auto_routes', 0)"),
    db.prepare(`UPDATE config_snapshot_revisions SET revision=revision+1
      WHERE domain='auto_routes' AND revision=? AND revision < 9007199254740991`).bind(body.current_revision));
  const condition = revisioned ? "WHERE changes()=1" : "";
  statements.push(db.prepare(`INSERT INTO auto_routes (route_id, candidates, updated_at)
    SELECT ?, ?, ? ${condition} ON CONFLICT(route_id) DO UPDATE SET
    candidates=excluded.candidates, updated_at=excluded.updated_at`)
    .bind(body.route_id, JSON.stringify(body.candidates), body.updated_at));
  statements.push(db.prepare(`INSERT INTO canary_traffic (route_id, route_updated_at, configuration)
    SELECT ?, ?, ? ${condition} ON CONFLICT(route_id) DO UPDATE SET
    route_updated_at=excluded.route_updated_at, configuration=excluded.configuration`)
    .bind(body.route_id, body.updated_at, JSON.stringify(policy)));
  const results = await db.batch(statements);
  const confirmed = results.slice(revisioned ? 1 : 0).every(result => result?.success === true && result.meta?.changes === 1);
  return confirmed ? reply({ version: 1, stored: true }) : failure("revision_conflict", 409);
}
