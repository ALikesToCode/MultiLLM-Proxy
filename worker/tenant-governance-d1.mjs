/** Private governance domain: intersected grants, CAS policy and atomic quota components. */
import { TenantContext, AuthorityOperation, legacyTenant, MAX_INTEGER } from "./enterprise-contract.mjs";

const PERMISSIONS = Object.freeze({ admin: ["edit", "budgets", "usage", "all_usage"],
  billing: ["budgets", "usage", "all_usage"], member: ["usage"] });
const FIELDS = {
  get: ["org_id", "team_id"], put: ["org_id", "team_id", "actor", "revision", "policy"],
  policies: ["context"], usage: ["context", "role", "since", "until"],
  reserve: ["id", "context", "amount", "day", "month", "key_daily", "key_monthly", "base_day", "base_month"],
  dispatch: ["id"], settle: ["id", "cost", "provider", "model", "price_basis", "before_dispatch"],
};
const SCHEMA = [
  "SELECT org_id,team_id,revision,models,tools,daily,monthly FROM tenant_governance_policies LIMIT 0",
  "SELECT id,principal_id,org_id,team_id,day,month,estimate,charged,state,revision,provider,model,price_basis,created_at,operation_id FROM tenant_governance_reservations LIMIT 0",
  "SELECT reservation_id,level,scope_org,scope_id,period_kind,period,limit_units FROM tenant_governance_components LIMIT 0",
  "SELECT principal_id,period,amount FROM tenant_governance_baselines LIMIT 0",
  "SELECT operation_id,actor,org_id,team_id,revision,kind,at FROM tenant_governance_audit LIMIT 0",
];
let warned = false;
export class GovernanceError extends Error {
  constructor(code = "tenant_governance_unavailable", status = 503, details = {}) {
    super(code); Object.assign(this, { code, status, details });
  }
}
const fail = (code = "invalid_governance_operation", status = 400, details = {}) => { throw new GovernanceError(code, status, details); };
export function governanceEnabled(env = {}, warn = message => console.warn(message)) {
  const raw = env.TENANT_GOVERNANCE_ENABLED;
  const flag = raw === undefined ? "" : typeof raw === "string" ? raw.trim().toLowerCase() : "invalid";
  if (["", "false", "0", "off", "no"].includes(flag)) return false;
  if (["true", "1", "on", "yes"].includes(flag)) return true;
  if (!warned) { warned = true; warn("Invalid TENANT_GOVERNANCE_ENABLED; tenant governance disabled"); }
  return false;
}
const permitted = (role, permission) => Object.hasOwn(PERMISSIONS, role) && PERMISSIONS[role].includes(permission);
const integer = n => Number.isSafeInteger(n) && n >= 0 && n < MAX_INTEGER;
function opaque(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_:.\-]{1,128}$/.test(value)) fail();
}
function policy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some(key => !["models", "tools", "daily", "monthly"].includes(key))) fail();
  const result = { models: value.models ?? null, tools: value.tools ?? null,
    daily: value.daily ?? null, monthly: value.monthly ?? null };
  for (const name of ["models", "tools"]) {
    if (result[name] !== null && (!Array.isArray(result[name]) || result[name].length > 64 ||
        result[name].some(pattern => typeof pattern !== "string" || !/^[A-Za-z0-9._:/+@*\-]{1,256}$/.test(pattern)))) fail();
  }
  for (const name of ["daily", "monthly"]) if (result[name] !== null && !integer(result[name])) fail();
  return result;
}
function decoded(row) {
  try {
    return { revision: row.revision, ...policy({ models: row.models === null ? null : JSON.parse(row.models),
      tools: row.tools === null ? null : JSON.parse(row.tools), daily: row.daily, monthly: row.monthly }) };
  } catch { throw new GovernanceError(); }
}
export function intersectGrants(keyAllowed, candidate, policies, kind = "models") {
  if (!["models", "tools"].includes(kind)) fail();
  return keyAllowed && policies.every(row => row[kind] == null || typeof candidate === "string" &&
    row[kind].some(pattern => new RegExp(`^${pattern.toLowerCase().split("*")
      .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`).test(candidate.trim().toLowerCase())));
}
function validate(body) {
  if (!body || typeof body !== "object" || Array.isArray(body) || body.version !== 1 || !Object.hasOwn(FIELDS, body.operation)) fail();
  const allowed = new Set(["version", "operation", "rpc", ...FIELDS[body.operation]]);
  if (Object.keys(body).some(key => !allowed.has(key))) fail();
  if (body.rpc !== undefined && typeof body.rpc !== "boolean") fail();
  const op = body.operation;
  if (["get", "put"].includes(op)) {
    opaque(body.org_id); if (body.team_id != null) opaque(body.team_id);
    if (op === "put") { opaque(body.actor); if (!integer(body.revision)) fail(); body.policy = policy(body.policy); }
  }
  if (["policies", "usage", "reserve"].includes(op)) {
    try { body.context = new TenantContext(body.context); } catch { fail(); }
    if (body.context.org_id === null) fail("tenant_scope_denied", 403);
  }
  if (op === "usage" && !permitted(body.role, "usage")) fail("tenant_role_denied", 403);
  if (op === "usage") for (const key of ["since", "until"]) {
    if (body[key] !== undefined && (typeof body[key] !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(body[key]))) fail();
  }
  if (["reserve", "dispatch", "settle"].includes(op)) opaque(body.id);
  if (op === "reserve") {
    for (const key of ["amount", "base_day", "base_month"]) if (!integer(body[key])) fail();
    for (const key of ["key_daily", "key_monthly"]) if (body[key] !== null && !integer(body[key])) fail();
    if (typeof body.day !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(body.day) ||
        typeof body.month !== "string" || body.month !== body.day.slice(0, 7)) fail();
  }
  if (op === "settle") {
    if (body.cost !== null && !integer(body.cost)) fail();
    if (body.before_dispatch !== undefined && typeof body.before_dispatch !== "boolean") fail();
    if (body.price_basis != null && !["usage", "estimate", "cache", "released"].includes(body.price_basis)) fail();
    if (body.cost !== null && !["usage", "cache", "released"].includes(body.price_basis)) fail();
    if (body.before_dispatch && (body.cost !== 0 || body.price_basis !== "released")) fail();
    for (const key of ["provider", "model"]) if (body[key] != null &&
        (typeof body[key] !== "string" || !/^[A-Za-z0-9._:/+@\-]{1,256}$/.test(body[key]))) fail();
  }
  return body;
}
async function batch(db, statements) {
  const results = await db.batch(statements);
  if (!Array.isArray(results) || results.some(result => result.success === false)) throw new GovernanceError();
  return results;
}
async function policies(db, context) {
  const rows = await db.prepare("SELECT * FROM tenant_governance_policies WHERE org_id=? AND (team_id='' OR team_id=?)")
    .bind(context.org_id, context.team_id ?? "").all();
  return { policies: rows.results.map(decoded) };
}
async function admin(db, body, now) {
  const org = body.org_id, team = body.team_id ?? "";
  if (body.operation === "get") {
    const row = await db.prepare("SELECT * FROM tenant_governance_policies WHERE org_id=? AND team_id=?").bind(org, team).first();
    return { policy: row ? decoded(row) : { revision: 0, models: null, tools: null, daily: null, monthly: null } };
  }
  const operationId = crypto.randomUUID();
  const { models, tools, daily, monthly } = body.policy;
  const results = await batch(db, [
    db.prepare(`INSERT INTO tenant_governance_audit
      SELECT ?,?,?,?,?+1,'policy',? WHERE COALESCE((SELECT revision FROM tenant_governance_policies
      WHERE org_id=? AND team_id=?),0)=?`).bind(operationId, body.actor, org, team, body.revision,
      new Date(now).toISOString(), org, team, body.revision),
    db.prepare(`INSERT INTO tenant_governance_policies (org_id,team_id,revision,models,tools,daily,monthly)
      SELECT ?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM tenant_governance_audit WHERE operation_id=?)
      ON CONFLICT(org_id,team_id) DO UPDATE SET revision=excluded.revision,models=excluded.models,
        tools=excluded.tools,daily=excluded.daily,monthly=excluded.monthly`)
      .bind(org, team, body.revision + 1, models === null ? null : JSON.stringify(models),
        tools === null ? null : JSON.stringify(tools), daily, monthly, operationId),
    db.prepare("SELECT p.* FROM tenant_governance_policies p WHERE org_id=? AND team_id=? AND EXISTS (SELECT 1 FROM tenant_governance_audit WHERE operation_id=?)")
      .bind(org, team, operationId),
  ]);
  if (!results[2].results.length) fail("revision_stale", 412);
  return { policy: decoded(results[2].results[0]) };
}

// All scope reads, admission and component writes run in one D1 batch transaction.
const SCOPES = `WITH scopes(level,scope_org,scope_id,period_kind,period,limit_units) AS (
  SELECT 'key','',?1,'daily',?4,?6 UNION ALL SELECT 'key','',?1,'monthly',?5,?7
  UNION ALL SELECT 'organisation',?2,?2,'daily',?4,(SELECT daily FROM tenant_governance_policies WHERE org_id=?2 AND team_id='')
  UNION ALL SELECT 'organisation',?2,?2,'monthly',?5,(SELECT monthly FROM tenant_governance_policies WHERE org_id=?2 AND team_id='')
  UNION ALL SELECT 'team',?2,?3,'daily',?4,(SELECT daily FROM tenant_governance_policies WHERE org_id=?2 AND team_id=?3) WHERE ?3!=''
  UNION ALL SELECT 'team',?2,?3,'monthly',?5,(SELECT monthly FROM tenant_governance_policies WHERE org_id=?2 AND team_id=?3) WHERE ?3!=''
), totals AS (SELECT s.*, COALESCE((SELECT SUM(CASE WHEN r.state!='settled' THEN r.estimate
    WHEN c.period=s.period THEN r.charged ELSE 0 END) FROM tenant_governance_components c
    JOIN tenant_governance_reservations r ON r.id=c.reservation_id WHERE c.level=s.level AND c.scope_org=s.scope_org
    AND c.scope_id=s.scope_id AND c.period_kind=s.period_kind),0)
    + CASE WHEN s.level='key' THEN COALESCE((SELECT amount FROM tenant_governance_baselines WHERE principal_id=?1 AND period=s.period),
      CASE WHEN s.period_kind='daily' THEN ?10 ELSE ?11 END) ELSE 0 END AS used FROM scopes s
), denied AS (SELECT * FROM totals WHERE limit_units IS NOT NULL AND (used>=limit_units OR ?8>limit_units-used))`;

async function reserve(db, body, now) {
  const c = body.context;
  const args = [c.principal_id, c.org_id, c.team_id ?? "", body.day, body.month, body.key_daily, body.key_monthly,
    body.amount, body.id, body.base_day, body.base_month, new Date(now).toISOString(), crypto.randomUUID()];
  const admission = `${SCOPES} INSERT INTO tenant_governance_reservations
    (id,principal_id,org_id,team_id,day,month,estimate,state,created_at,operation_id)
    SELECT ?9,?1,?2,?3,?4,?5,?8,'reserved',?12,?13 WHERE NOT EXISTS (SELECT 1 FROM denied)
    ON CONFLICT(id) DO NOTHING RETURNING id`;
  const results = await batch(db, [
    db.prepare(admission).bind(...args),
    db.prepare(`${SCOPES} INSERT OR IGNORE INTO tenant_governance_components
      SELECT ?9,level,scope_org,scope_id,period_kind,period,limit_units FROM scopes
      WHERE EXISTS (SELECT 1 FROM tenant_governance_reservations WHERE id=?9 AND operation_id=?13)`)
      .bind(...args),
    db.prepare(`INSERT OR IGNORE INTO tenant_governance_baselines SELECT ?1,?2,?3
      WHERE EXISTS (SELECT 1 FROM tenant_governance_reservations WHERE id=?4 AND operation_id=?5)`)
      .bind(c.principal_id, body.day, body.base_day, body.id, args[12]),
    db.prepare(`INSERT OR IGNORE INTO tenant_governance_baselines SELECT ?1,?2,?3
      WHERE EXISTS (SELECT 1 FROM tenant_governance_reservations WHERE id=?4 AND operation_id=?5)`)
      .bind(c.principal_id, body.month, body.base_month, body.id, args[12]),
    db.prepare(`${SCOPES} SELECT level,period_kind FROM denied ORDER BY CASE level WHEN 'key' THEN 0 WHEN 'organisation' THEN 1 ELSE 2 END LIMIT 1`)
      .bind(...args.slice(0, 11)),
    db.prepare("SELECT id FROM tenant_governance_reservations WHERE id=?").bind(body.id),
  ]);
  if (!results[0].results.length) {
    if (results[5].results.length) fail("reservation_conflict", 409);
    const denied = results[4].results[0];
    if (!denied) fail("reservation_conflict", 409);
    fail(denied.level === "key" ? "budget_exceeded" : "tenant_budget_exceeded", 429,
      { level: denied.level, period: denied.period_kind });
  }
  return { id: body.id };
}
async function settle(db, body) {
  const state = body.operation === "dispatch" ? "dispatched" : body.cost === null ? "unknown" : "settled";
  const row = await db.prepare("SELECT * FROM tenant_governance_reservations WHERE id=?").bind(body.id).first();
  if (!row) fail("reservation_conflict", 409);
  if (["settled", "unknown"].includes(row.state)) {
    if (row.state === "settled" && body.operation === "settle" && body.cost !== null && row.charged !== body.cost) fail("reservation_conflict", 409);
    return { state: row.state };
  }
  if (body.before_dispatch && row.state !== "reserved") fail("reservation_conflict", 409);
  const results = await batch(db, [db.prepare(`UPDATE tenant_governance_reservations SET state=?,charged=?,
      provider=COALESCE(?,provider),model=COALESCE(?,model),price_basis=COALESCE(?,price_basis),revision=revision+1
      WHERE id=? AND revision=? AND state IN ('reserved','dispatched') RETURNING state`)
    .bind(state, body.cost ?? null, body.provider ?? null, body.model ?? null, body.price_basis ?? null, body.id, row.revision)]);
  if (!results[0].results.length) fail("reservation_conflict", 409);
  return { state };
}
async function usage(db, body) {
  const c = body.context, all = permitted(body.role, "all_usage");
  const where = "org_id=? AND (?='' OR team_id=?) AND (?=1 OR principal_id=?) AND day>=? AND day<=?";
  const since = body.since ?? "0000-01-01", until = body.until ?? "9999-12-31";
  const args = [c.org_id, c.team_id ?? "", c.team_id ?? "", all ? 1 : 0, c.principal_id, since, until];
  const results = await batch(db, [
    db.prepare(`SELECT COALESCE(SUM(charged),0) AS spent_micro_usd,
      COALESCE(SUM(CASE WHEN state!='settled' THEN estimate ELSE 0 END),0) AS holds_micro_usd,
      COUNT(*) AS requests FROM tenant_governance_reservations WHERE ${where}`).bind(...args),
    db.prepare(`SELECT provider,model,price_basis,COUNT(*) AS requests,COALESCE(SUM(charged),0) AS spent_micro_usd
      FROM tenant_governance_reservations WHERE ${where} GROUP BY provider,model,price_basis ORDER BY model LIMIT 200`).bind(...args),
    ...(all ? [db.prepare(`SELECT COALESCE(SUM(charged),0) AS spent_micro_usd,
      COALESCE(SUM(CASE WHEN state!='settled' THEN estimate ELSE 0 END),0) AS holds_micro_usd
      FROM tenant_governance_reservations WHERE org_id=? AND day>=? AND day<=?`).bind(c.org_id, since, until)] : []),
    db.prepare(`SELECT day,COUNT(*) AS requests,COALESCE(SUM(charged),0) AS spent_micro_usd
      FROM tenant_governance_reservations WHERE ${where} GROUP BY day ORDER BY day LIMIT 90`).bind(...args),
  ]);
  const totals = results[0].results[0];
  return { org_id: c.org_id, team_id: c.team_id, principal_id: c.principal_id,
    cost_description: "Gateway cost estimates, not invoices", ...totals, models: results[1].results,
    daily: results[all ? 3 : 2].results, range: { since, until },
    ...(all ? { organisation: results[2].results[0], team: c.team_id ? totals : null } : {}) };
}
async function readBody(request) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json" || !request.body) fail();
  const reader = request.body.getReader(), chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 32768) fail();
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return validate(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
  } catch (error) { if (error instanceof GovernanceError) throw error; fail(); }
  finally { void reader.cancel().catch(() => {}); reader.releaseLock(); }
}
const reply = (value, status = 200) => Response.json({ version: 1, ...value },
  { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });

/** Mount only in the authenticated private managed-state dispatcher. */
export async function handleTenantGovernanceRequest(request, env, { now = Date.now } = {}) {
  if (!governanceEnabled(env)) return reply({ error: { code: "not_found" } }, 404);
  let rpc = false;
  try {
    const url = new URL(request.url);
    if (url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/tenant-governance" || url.search || url.hash) fail("not_found", 404);
    if (request.method !== "POST") fail("method_not_allowed", 405);
    const body = await readBody(request), db = env.INTELLIGENCE_DB;
    rpc = body.rpc === true;
    if (!db?.prepare || !db?.batch) throw new GovernanceError();
    for (const query of SCHEMA) await db.prepare(query).all();
    let result;
    if (["get", "put"].includes(body.operation)) result = await admin(db, body, now());
    else if (body.operation === "policies") result = await policies(db, body.context);
    else if (body.operation === "reserve") result = await reserve(db, body, now());
    else if (body.operation === "usage") result = await usage(db, body);
    else result = await settle(db, body);
    return reply(result);
  } catch (error) {
    const failure = error instanceof GovernanceError ? error : new GovernanceError();
    // The bounded Container transport keeps only the code of HTTP errors.
    if (rpc && failure.code === "tenant_budget_exceeded") {
      return reply({ decision: { allowed: false, code: failure.code, status: failure.status, ...failure.details } });
    }
    return reply({ error: { code: failure.code, ...failure.details } }, failure.status);
  }
}

function defaultTenantResolver(event) {
  const context = new TenantContext({ principal_id: event.user?.id ?? event.user?.username ?? "legacy" });
  return legacyTenant(new AuthorityOperation({ context, scoped_id: context.principal_id, revision: 0, operation_id: "governance.resolve" }));
}
/** Named native hooks consume trusted admission metadata; no caller header selects tenancy. */
export function createGovernanceLifecycle(env, { call, tenant_resolver = defaultTenantResolver }) {
  let id, finished = false;
  const rpc = async (operation, values) => {
    const result = await call({ version: 1, operation, ...values });
    const failure = result.error ?? (result.decision?.allowed === false ? result.decision : null);
    if (failure) throw new GovernanceError(failure.code, failure.status ?? result.status ?? 503,
      { ...(failure.level ? { level: failure.level } : {}), ...(failure.period ? { period: failure.period } : {}) });
    return result;
  };
  return {
    async admit(event) {
      if (!governanceEnabled(env)) return;
      const context = await tenant_resolver(event);
      if (!(context instanceof TenantContext)) fail("tenant_scope_denied", 403);
      if (context.org_id === null) return;
      const rows = (await rpc("policies", { context })).policies;
      if (!intersectGrants(event.key_allowed === true, event.model, rows)) fail("model_not_allowed", 403);
      for (const tool of event.tools ?? []) if (!intersectGrants(event.key_tools?.includes(tool) === true, tool, rows, "tools")) fail("tool_not_allowed", 403);
      const candidateId = `tg_${crypto.randomUUID().replaceAll("-", "")}`;
      const day = new Date().toISOString().slice(0, 10);
      await rpc("reserve", { id: candidateId, context, amount: event.amount, day, month: day.slice(0, 7),
        key_daily: event.key_daily ?? null, key_monthly: event.key_monthly ?? null,
        base_day: event.base_day ?? 0, base_month: event.base_month ?? 0 });
      id = candidateId;
    },
    async before_dispatch() { if (id && !finished) await rpc("dispatch", { id }); },
    async finalize(event) {
      if (!id || finished) return;
      const row = event.usage ?? event, model = row.selected_model ?? null;
      const cached = row.cost_basis === "cache";
      const released = event.handedOff === false;
      const measured = !event.cancellationOutcome?.ambiguous && row.cost_basis === "usage";
      await rpc("settle", { id, cost: released || cached ? 0 : measured ? row.cost_micro_usd ?? null : null,
        provider: model?.includes(":") ? model.split(":", 1)[0] : null, model,
        price_basis: cached ? "cache" : released ? "released" : row.cost_basis ?? null, before_dispatch: released && !cached });
      finished = true;
    },
  };
}
