/** Fixed private tenant operations; no caller-selected identity or executable SQL. */
import { createHash } from "node:crypto";
import { AuthorityOperation, TenantContext, legacyTenant } from "./enterprise-contract.mjs";

export const TENANT_STORE_PATH = "/v1/managed-state/tenants";
const MAX_BYTES = 8192;
const OBJECT = value => value !== null && typeof value === "object" && !Array.isArray(value);
const IDENTIFIER = /^[A-Za-z0-9_:.\-]{1,128}$/;
const text = (value, maximum = 128) => typeof value === "string" && value.trim().length > 0 && value.length <= maximum && !/[\x00-\x1f\x7f]/.test(value);
const id = () => crypto.randomUUID().replaceAll("-", "");
let warned = false;
export function organisationsEnabled(env = {}, warn = message => console.warn(message)) {
  const flag = env.ORGANISATIONS_ENABLED === undefined ? "" : typeof env.ORGANISATIONS_ENABLED === "string" ? env.ORGANISATIONS_ENABLED.trim().toLowerCase() : "invalid";
  if (["", "false", "0", "no", "off"].includes(flag)) return false;
  if (["true", "1", "yes", "on"].includes(flag)) return true;
  if (!warned) { warned = true; warn("Invalid ORGANISATIONS_ENABLED; organisations disabled"); }
  return false;
}
export class TenantError extends Error {
  constructor(code, status = 400) { super(code); this.code = code; this.status = status; }
  response(privateReply = false) {
    return Response.json({ ...(privateReply ? { version: 1, status: this.status } : {}),
      error: { code: this.code, message: "The workspace operation could not be authorized or stored." } },
    { status: this.status, headers: { "cache-control": "no-store" } });
  }
}
function identifier(value) { if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TenantError("invalid_request"); return value; }
function revision(value) {
  if (value === undefined || value === null) throw new TenantError("revision_required", 428);
  if (!Number.isSafeInteger(value) || value < 0 || value >= 9007199254740000) throw new TenantError("invalid_revision");
  return value;
}
function requireText(value, maximum) { if (!text(value, maximum)) throw new TenantError("invalid_request"); return value; }
function fields(value, allowed, required = []) {
  if (!OBJECT(value) || Object.keys(value).some(name => !allowed.includes(name)) || required.some(name => !Object.hasOwn(value, name))) throw new TenantError("invalid_request");
}
function cas(row, value) { if ((row?.revision ?? 0) !== revision(value)) throw new TenantError("revision_conflict", 412); }
function legacy(principal) {
  const principal_id = IDENTIFIER.test(principal) ? principal : `principal:${createHash("sha256").update(principal).digest("hex")}`;
  return legacyTenant(new AuthorityOperation({ context: new TenantContext({ principal_id }), scoped_id: "workspace", revision: 0, operation_id: "resolve" }));
}
export function tenantNamespace(context) {
  return context.org_id === null ? "" : `org:${context.org_id}${context.team_id === null ? "" : `/team:${context.team_id}`}`;
}
/** Trusted callers append workspace scope; legacy bytes remain untouched. */
export function tenantStorageKey(value, context) {
  if (context == null) return value;
  if (!(context instanceof TenantContext)) throw new TenantError("workspace_forbidden", 403);
  const namespace = tenantNamespace(context);
  return namespace ? createHash("sha256").update(JSON.stringify([value, namespace])).digest("hex") : value;
}
const one = (db, sql, values = []) => db.prepare(sql).bind(...values).first();
const rows = async (db, sql, values = []) => (await db.prepare(sql).bind(...values).all()).results;
async function requireSchema(db) {
  if (!db) throw new TenantError("tenant_storage_unavailable", 503);
  // Reads also verify the complete authority, so an absent binding table cannot mean legacy.
  for (const sql of ["SELECT id,name,status,revision FROM tenant_organisations LIMIT 0",
    "SELECT id,org_id,name,status,revision FROM tenant_teams LIMIT 0",
    "SELECT org_id,principal,team_id,role,status,revision FROM tenant_memberships LIMIT 0",
    "SELECT principal,org_id,team_id,revision FROM tenant_bindings LIMIT 0",
    "SELECT id,actor,action,org_id,team_id,principal,old_revision,new_revision,at FROM tenant_audit LIMIT 0"]) {
    await db.prepare(sql).all();
  }
}
async function organisation(db, orgId, active = false) {
  const org = await one(db, "SELECT * FROM tenant_organisations WHERE id=?", [identifier(orgId)]);
  if (!org) throw new TenantError("workspace_not_found", 404);
  if (active && org.status !== "active") throw new TenantError("workspace_forbidden", 403);
  return org;
}
async function team(db, orgId, teamId, active = false) {
  const value = await one(db, "SELECT * FROM tenant_teams WHERE org_id=? AND id=?", [orgId, identifier(teamId)]);
  if (!value) throw new TenantError("workspace_not_found", 404);
  if (active && value.status !== "active") throw new TenantError("workspace_forbidden", 403);
  return value;
}
async function workspace(db, principal, orgId, teamId) {
  await organisation(db, orgId, true);
  if (teamId !== null) await team(db, orgId, teamId, true);
  const membership = await one(db, "SELECT * FROM tenant_memberships WHERE org_id=? AND principal=?", [orgId, principal]);
  if (!membership || membership.status !== "active" || membership.team_id !== teamId) throw new TenantError("workspace_forbidden", 403);
}
async function resolve(db, principal) {
  const value = await one(db, `SELECT b.org_id,b.team_id,b.revision AS binding_revision,
    o.id AS found_org,o.status AS org_status,o.revision AS org_revision,
    t.id AS found_team,t.status AS team_status,t.revision AS team_revision,
    m.status AS member_status,m.team_id AS member_team,m.revision AS member_revision
    FROM tenant_bindings b LEFT JOIN tenant_organisations o ON o.id=b.org_id
    LEFT JOIN tenant_teams t ON t.id=b.team_id AND t.org_id=b.org_id
    LEFT JOIN tenant_memberships m ON m.org_id=b.org_id AND m.principal=b.principal WHERE b.principal=?`, [principal]);
  if (!value) return legacy(principal);
  if (!value.found_org || value.team_id !== null && !value.found_team) throw new TenantError("workspace_not_found", 404);
  if (value.org_status !== "active" || value.team_id !== null && value.team_status !== "active"
    || value.member_status !== "active" || value.member_team !== value.team_id) throw new TenantError("workspace_forbidden", 403);
  return new TenantContext({ principal_id: legacy(principal).principal_id, org_id: value.org_id, team_id: value.team_id,
    grants_revision: value.binding_revision + value.org_revision + (value.team_revision ?? 0) + value.member_revision });
}
export async function resolveAccountTenant(db, principal, env = {}) {
  if (!organisationsEnabled(env)) return legacy(principal);
  try { requireText(principal); await requireSchema(db); return await resolve(db, principal); }
  catch (error) { if (error instanceof TenantError) throw error; throw new TenantError("tenant_storage_unavailable", 503); }
}
function audit(db, mutationId, v, action, orgId, teamId, principal, old, next) {
  return db.prepare(`INSERT INTO tenant_audit (id,actor,action,org_id,team_id,principal,old_revision,new_revision,at)
    SELECT ?,?,?,?,?,?,?,?,? WHERE changes()=1`).bind(mutationId, requireText(v.actor), action, orgId, teamId, principal, old, next, new Date().toISOString());
}
async function mutate(db, statement, v, action, orgId, teamId, principal, old, next, extra = []) {
  const mutationId = id();
  const statements = [statement, audit(db, mutationId, v, action, orgId, teamId, principal, old, next), ...extra.map(factory => factory(mutationId))];
  const result = await db.batch(statements);
  if (result[0].meta.changes !== 1) throw new TenantError("revision_conflict", 412);
}
const ACTIVE_ORG = "EXISTS (SELECT 1 FROM tenant_organisations WHERE id=? AND status='active')";
const ACTIVE_TEAM = "(? IS NULL OR EXISTS (SELECT 1 FROM tenant_teams WHERE id=? AND org_id=? AND status='active'))";
const ACTIVE_MEMBER = "EXISTS (SELECT 1 FROM tenant_memberships WHERE org_id=? AND principal=? AND status='active' AND team_id IS ?)";
const BINDING_CAS = "COALESCE((SELECT revision FROM tenant_bindings WHERE principal=?),0)=?";

async function namedWrite(db, operation, v) {
  const creating = operation.endsWith("create"), isTeam = operation.startsWith("team");
  fields(v.data, ["name", "status"], creating ? ["name"] : []);
  if (!Object.keys(v.data).length || creating && Object.hasOwn(v.data, "status") && v.data.status !== "active") throw new TenantError("invalid_request");
  const org = operation === "org_create" ? null : await organisation(db, v.org_id, creating && isTeam);
  const previous = creating ? null : isTeam ? await team(db, v.org_id, v.team_id) : org;
  if (!creating) cas(previous, v.revision);
  const name = requireText(Object.hasOwn(v.data, "name") ? v.data.name : previous?.name, 200);
  const status = Object.hasOwn(v.data, "status") ? v.data.status : previous?.status ?? "active";
  if (!["active", "deactivated"].includes(status)) throw new TenantError("invalid_request");
  const old = previous?.revision ?? 0, next = old + 1, target = creating ? id() : previous.id;
  let statement;
  if (isTeam && creating) {
    if ((await one(db, "SELECT count(*) AS count FROM tenant_teams WHERE org_id=?", [v.org_id])).count >= 100) throw new TenantError("tenant_limit_reached", 409);
    statement = db.prepare(`INSERT INTO tenant_teams SELECT ?,?,?,?,? WHERE ${ACTIVE_ORG}
      AND (SELECT count(*) FROM tenant_teams WHERE org_id=?)<100`).bind(target, v.org_id, name, status, next, v.org_id, v.org_id);
  } else if (creating) statement = db.prepare("INSERT INTO tenant_organisations VALUES (?,?,?,?)").bind(target, name, status, next);
  else if (isTeam) statement = db.prepare("UPDATE tenant_teams SET name=?,status=?,revision=? WHERE id=? AND org_id=? AND revision=?").bind(name, status, next, target, v.org_id, old);
  else statement = db.prepare("UPDATE tenant_organisations SET name=?,status=?,revision=? WHERE id=? AND revision=?").bind(name, status, next, target, old);
  try { await mutate(db, statement, v, operation, isTeam ? v.org_id : target, isTeam ? target : null, null, old, next); }
  catch (error) {
    if (isTeam && creating && error instanceof TenantError) {
      await organisation(db, v.org_id, true);
      if ((await one(db, "SELECT count(*) AS count FROM tenant_teams WHERE org_id=?", [v.org_id])).count >= 100) throw new TenantError("tenant_limit_reached", 409);
    }
    throw error;
  }
  return { id: target, ...(isTeam ? { org_id: v.org_id } : {}), name, status, revision: next };
}
async function memberWrite(db, v) {
  const orgId = identifier(v.org_id), principal = requireText(v.principal);
  fields(v.data, ["role", "team_id", "status", "bind", "binding_revision"]);
  if (!Object.keys(v.data).length || "bind" in v.data && typeof v.data.bind !== "boolean" || "binding_revision" in v.data && !v.data.bind) throw new TenantError("invalid_request");
  await organisation(db, orgId);
  if (!await one(db, "SELECT username FROM control_users WHERE username=?", [principal])) throw new TenantError("principal_not_found", 404);
  const previous = await one(db, "SELECT * FROM tenant_memberships WHERE org_id=? AND principal=?", [orgId, principal]);
  cas(previous, v.revision);
  if (!previous && (await one(db, "SELECT count(*) AS count FROM tenant_memberships WHERE org_id=?", [orgId])).count >= 1000) throw new TenantError("tenant_limit_reached", 409);
  const role = Object.hasOwn(v.data, "role") ? v.data.role : previous?.role ?? "member";
  const status = Object.hasOwn(v.data, "status") ? v.data.status : previous?.status ?? "active";
  const teamId = Object.hasOwn(v.data, "team_id") ? v.data.team_id : previous?.team_id ?? null;
  if (!["admin", "billing", "member"].includes(role) || !["active", "deactivated"].includes(status)) throw new TenantError("invalid_request");
  if (status === "active") await organisation(db, orgId, true);
  if (teamId !== null) await team(db, orgId, teamId, status === "active");
  if (v.data.bind) {
    if (status !== "active") throw new TenantError("workspace_forbidden", 403);
    cas(await one(db, "SELECT * FROM tenant_bindings WHERE principal=?", [principal]), v.data.binding_revision);
  }
  const old = previous?.revision ?? 0, next = old + 1;
  const conditions = `EXISTS (SELECT 1 FROM control_users WHERE username=?) AND
    COALESCE((SELECT revision FROM tenant_memberships WHERE org_id=? AND principal=?),0)=?
    AND (? > 0 OR (SELECT count(*) FROM tenant_memberships WHERE org_id=?)<1000)
    AND (? <> 'active' OR (${ACTIVE_ORG} AND ${ACTIVE_TEAM}))
    AND (? IS NULL OR EXISTS (SELECT 1 FROM tenant_teams WHERE id=? AND org_id=?))
    AND (?=0 OR ${BINDING_CAS})`;
  const statement = db.prepare(`INSERT INTO tenant_memberships (org_id,principal,team_id,role,status,revision)
    SELECT ?,?,?,?,?,? WHERE ${conditions}
    ON CONFLICT(org_id,principal) DO UPDATE SET team_id=excluded.team_id,role=excluded.role,status=excluded.status,revision=excluded.revision`).bind(
    orgId, principal, teamId, role, status, next, principal, orgId, principal, old, old, orgId,
    status, orgId, teamId, teamId, orgId, teamId, teamId, orgId, v.data.bind ? 1 : 0, principal, v.data.binding_revision ?? 0);
  const extra = v.data.bind ? [mutation => db.prepare(`INSERT INTO tenant_bindings (principal,org_id,team_id,revision)
    SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM tenant_audit WHERE id=?)
    ON CONFLICT(principal) DO UPDATE SET org_id=excluded.org_id,team_id=excluded.team_id,revision=excluded.revision`)
    .bind(principal, orgId, teamId, v.data.binding_revision + 1, mutation),
    () => audit(db, id(), v, "binding_set", orgId, teamId, principal, v.data.binding_revision, v.data.binding_revision + 1)] : [];
  try { await mutate(db, statement, v, "member_set", orgId, teamId, principal, old, next, extra); }
  catch (error) {
    if (error instanceof TenantError && error.code === "revision_conflict" && !previous
      && (await one(db, "SELECT count(*) AS count FROM tenant_memberships WHERE org_id=?", [orgId])).count >= 1000) throw new TenantError("tenant_limit_reached", 409);
    throw error;
  }
  return { org_id: orgId, principal, team_id: teamId, role, status, revision: next };
}
async function bindingWrite(db, v) {
  const principal = requireText(v.principal);
  if (v.actor !== principal) throw new TenantError("workspace_forbidden", 403);
  fields(v.data, ["org_id", "team_id"], ["org_id", "team_id"]);
  const orgId = identifier(v.data.org_id), teamId = v.data.team_id;
  await workspace(db, principal, orgId, teamId);
  const previous = await one(db, "SELECT * FROM tenant_bindings WHERE principal=?", [principal]);
  cas(previous, v.revision);
  const old = previous?.revision ?? 0, next = old + 1;
  const statement = db.prepare(`INSERT INTO tenant_bindings (principal,org_id,team_id,revision)
    SELECT ?,?,?,? WHERE ${BINDING_CAS} AND ${ACTIVE_ORG} AND ${ACTIVE_TEAM} AND ${ACTIVE_MEMBER}
    ON CONFLICT(principal) DO UPDATE SET org_id=excluded.org_id,team_id=excluded.team_id,revision=excluded.revision`).bind(
    principal, orgId, teamId, next, principal, old, orgId, teamId, teamId, orgId, orgId, principal, teamId);
  try { await mutate(db, statement, v, "binding_set", orgId, teamId, principal, old, next); }
  catch (error) { if (error instanceof TenantError) await workspace(db, principal, orgId, teamId); throw error; }
  return { principal, org_id: orgId, team_id: teamId, revision: next };
}
const OPERATIONS = Object.freeze({
  org_list: [], org_get: ["org_id"], org_create: ["actor", "data"], org_update: ["actor", "org_id", "revision", "data"],
  team_list: ["org_id"], team_create: ["actor", "org_id", "data"], team_update: ["actor", "org_id", "team_id", "revision", "data"],
  member_list: ["org_id"], member_set: ["actor", "org_id", "principal", "revision", "data"],
  workspaces: ["principal"], binding_set: ["actor", "principal", "revision", "data"], resolve: ["principal"],
});
async function execute(db, v) {
  if (v.operation === "resolve") return resolve(db, requireText(v.principal));
  if (v.operation === "org_list") return { organisations: await rows(db, "SELECT * FROM tenant_organisations ORDER BY id") };
  if (v.operation === "workspaces") {
    const principal = requireText(v.principal);
    const memberships = await rows(db, `SELECT m.* FROM tenant_memberships m JOIN tenant_organisations o ON o.id=m.org_id
      LEFT JOIN tenant_teams t ON t.id=m.team_id AND t.org_id=m.org_id
      WHERE m.principal=? AND m.status='active' AND o.status='active' AND (m.team_id IS NULL OR t.status='active') ORDER BY m.org_id`, [principal]);
    return { memberships, binding: await one(db, "SELECT * FROM tenant_bindings WHERE principal=?", [principal])
      ?? { principal, org_id: null, team_id: null, revision: 0 } };
  }
  if (v.operation === "binding_set") return bindingWrite(db, v);
  if (v.operation.endsWith("create") || v.operation.endsWith("update")) return namedWrite(db, v.operation, v);
  const org = await organisation(db, v.org_id);
  if (v.operation === "org_get") return org;
  if (v.operation === "team_list") return { teams: await rows(db, "SELECT * FROM tenant_teams WHERE org_id=? ORDER BY id", [v.org_id]) };
  if (v.operation === "member_list") return { members: await rows(db, "SELECT * FROM tenant_memberships WHERE org_id=? ORDER BY principal", [v.org_id]) };
  return memberWrite(db, v);
}
async function boundedJson(request) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json" || !request.body) throw new TenantError("invalid_request");
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES)) throw new TenantError("invalid_request");
  const reader = request.body.getReader(), chunks = []; let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) { void reader.cancel().catch(() => {}); throw new TenantError("invalid_request"); }
      chunks.push(value);
    }
    const data = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
  } catch { throw new TenantError("invalid_request"); }
  finally { reader.releaseLock(); }
}
export async function handleTenantRequest(request, env) {
  if (!organisationsEnabled(env)) return new TenantError("not_found", 404).response(true);
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.pathname !== TENANT_STORE_PATH || url.search || url.hash || url.username || url.password || request.method !== "POST") return new TenantError("not_found", 404).response(true);
  let v;
  try {
    v = await boundedJson(request);
    if (!OBJECT(v) || v.version !== 1 || !Object.hasOwn(OPERATIONS, v.operation)) throw new TenantError("invalid_request");
    const required = OPERATIONS[v.operation];
    fields(v, ["version", "operation", ...required], ["version", "operation", ...required.filter(name => name !== "revision")]);
    if (required.includes("revision")) revision(v.revision);
    if (required.includes("actor")) requireText(v.actor);
    await requireSchema(env.INTELLIGENCE_DB);
    const result = await execute(env.INTELLIGENCE_DB, v);
    return Response.json({ version: 1, result }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return (error instanceof TenantError ? error : new TenantError("tenant_storage_unavailable", 503)).response(true);
  }
}

function scimTenantGuard(db, org, principal) {
  // A failed conditional mutation aborts the entire SCIM/account/revision batch.
  return db.prepare(`INSERT INTO tenant_memberships (org_id,principal,role,status,revision)
    SELECT ?,?,'member','active',0 WHERE changes()!=1`).bind(org, principal);
}
/** No binding or privileged role is created by provisioning. */
export function scimPrincipalStatements(db, { org_id, resource }) {
  identifier(org_id); requireText(resource.userName);
  return [db.prepare(`INSERT INTO tenant_memberships (org_id,principal,team_id,role,status,revision)
    SELECT ?1,?2,NULL,'member',?3,1 WHERE EXISTS
      (SELECT 1 FROM tenant_organisations WHERE id=?1 AND status='active')
      AND ((SELECT COUNT(*) FROM tenant_memberships WHERE org_id=?1)<1000
        OR EXISTS (SELECT 1 FROM tenant_memberships WHERE org_id=?1 AND principal=?2))
    ON CONFLICT(org_id,principal) DO UPDATE SET status=excluded.status,revision=tenant_memberships.revision+1
      WHERE tenant_memberships.role='member'`)
    .bind(org_id, resource.userName, resource.active ? "active" : "deactivated"),
    scimTenantGuard(db, org_id, resource.userName)];
}
/** Team and membership mutations join the SCIM resource transaction. */
export function scimTeamStatements(db, { org_id, resource, prior, deactivated }) {
  identifier(org_id); identifier(resource.id); requireText(resource.displayName);
  const statements = [db.prepare(`INSERT INTO tenant_teams (id,org_id,name,status,revision)
    SELECT ?1,?2,?3,?4,1 WHERE EXISTS
      (SELECT 1 FROM tenant_organisations WHERE id=?2 AND status='active')
      AND ((SELECT COUNT(*) FROM tenant_teams WHERE org_id=?2)<100
        OR EXISTS (SELECT 1 FROM tenant_teams WHERE id=?1 AND org_id=?2))
    ON CONFLICT(id) DO UPDATE SET name=excluded.name,status=excluded.status,revision=tenant_teams.revision+1
      WHERE tenant_teams.org_id=excluded.org_id`)
    .bind(resource.id, org_id, resource.displayName, deactivated ? "deactivated" : "active"),
    scimTenantGuard(db, org_id, resource.id)];
  // Explicit group updates may move members of this group, never members of another team.
  statements.push(db.prepare(`UPDATE tenant_memberships SET team_id=NULL,revision=revision+1
    WHERE org_id=? AND team_id=? AND role='member'`).bind(org_id, resource.id));
  for (const member of deactivated ? [] : resource.members) {
    statements.push(db.prepare(`UPDATE tenant_memberships SET team_id=?1,revision=revision+1
      WHERE org_id=?2 AND principal=(SELECT user_name FROM scim_resources
        WHERE org_id=?2 AND kind='Users' AND id=?3 AND deactivated=0)
        AND role='member' AND status='active' AND team_id IS NULL`)
      .bind(resource.id, org_id, member.value), scimTenantGuard(db, org_id, member.value));
  }
  return statements;
}
