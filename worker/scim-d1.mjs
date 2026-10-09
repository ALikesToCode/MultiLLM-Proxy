/** Atomic SCIM identity, account, team and security-revision storage. */
import { boundedBody, USER_FIELDS, validUser } from "./control-users-d1.mjs";
import { commitRevision, requireRevisionSchema, revisionSyncSettings } from "./config-revision.mjs";

const PATH = "/v1/managed-state/scim";
const ID = /^[a-f0-9]{32}$/;
const ORG = /^[A-Za-z0-9_:.\-]{1,128}$/;
const HASH = /^[a-f0-9]{64}$/;
const VERSION = /^W\/"([1-9][0-9]{0,15})"$/;
const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const TABLE_COLUMNS = {
  scim_resources: "org_id,kind,id,external_id,user_name,display_name,deactivated,revision,document",
  scim_group_members: "org_id,group_id,user_id",
  scim_token_digests: "org_id,digest_sha256,updated_at",
  scim_audit: "sequence,org_id,kind,resource_id,revision,operation,at",
};
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value, names) => object(value) && Object.keys(value).length === names.length && names.every(key => Object.hasOwn(value, key));
const string = (value, max = 1024) => typeof value === "string" && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const version = resource => Number(VERSION.exec(resource.meta.version)?.[1]);
let warned = false;

export function scimEnabled(env) {
  const raw = env.SCIM_ENABLED ?? "";
  const flag = typeof raw === "string" ? raw.trim().toLowerCase() : "invalid";
  if (["", "false", "0", "no", "off"].includes(flag)) return false;
  if (["true", "1", "yes", "on"].includes(flag)) return true;
  if (!warned) { warned = true; console.warn("Invalid SCIM_ENABLED; SCIM provisioning disabled"); }
  return false;
}

const reply = (value, status = 200) => Response.json(status === 200 ? { version: 1, ...value }
  : { version: 1, error: { code: value, message: "SCIM storage could not accept the operation" } },
  { status, headers: { "cache-control": "no-store" } });

function validResource(resource, kind, expected) {
  if (!object(resource) || !ID.test(resource.id ?? "") || !object(resource.meta)) return false;
  const attrs = kind === "Users" ? ["userName", "active", "displayName", "externalId", "name", "emails"]
    : ["displayName", "externalId", "members"];
  if (Object.keys(resource).some(key => !["schemas", "id", "meta", ...attrs].includes(key))
    || JSON.stringify(resource.schemas) !== JSON.stringify([kind === "Users" ? USER_SCHEMA : GROUP_SCHEMA])
    || Object.keys(resource.meta).some(key => !["resourceType", "version", "created", "lastModified", "location"].includes(key))
    || resource.meta.resourceType !== (kind === "Users" ? "User" : "Group")
    || !VERSION.test(resource.meta.version ?? "") || version(resource) !== expected + 1
    || resource.meta.location !== `/scim/v2/${kind}/${resource.id}`
    || !["created", "lastModified"].every(key => string(resource.meta[key], 64) && Number.isFinite(Date.parse(resource.meta[key])))
    || ["displayName", "externalId"].some(key => key in resource && !string(resource[key]))) return false;
  if (kind === "Groups") return string(resource.displayName) && Array.isArray(resource.members) && resource.members.length <= 1000
    && new Set(resource.members.map(m => m?.value)).size === resource.members.length
    && resource.members.every(m => object(m) && ID.test(m.value ?? "")
      && Object.keys(m).every(key => ["value", "display", "$ref"].includes(key))
      && ["display", "$ref"].every(key => !(key in m) || string(m[key])));
  if (!string(resource.userName, 128) || resource.userName.trim() !== resource.userName || typeof resource.active !== "boolean") return false;
  if ("name" in resource && (!object(resource.name) || Object.keys(resource.name).some(key =>
    !["formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"].includes(key))
    || !Object.values(resource.name).every(value => string(value)))) return false;
  if ("emails" in resource && (!Array.isArray(resource.emails) || resource.emails.length > 100
    || resource.emails.filter(e => e?.primary === true).length > 1 || !resource.emails.every(e => object(e) && string(e.value)
      && Object.keys(e).every(key => ["value", "type", "display", "primary"].includes(key))
      && (!Object.hasOwn(e, "primary") || typeof e.primary === "boolean")
      && ["type", "display"].every(key => !(key in e) || string(e[key]))))) return false;
  return true;
}

function validBody(body) {
  if (!object(body) || body.version !== 1) return false;
  if (body.operation === "probe") return exact(body, ["version", "operation"]);
  if (body.operation === "account") return exact(body, ["version", "operation", "username"]) && string(body.username, 128);
  if (!ORG.test(body.org_id ?? "") || !["Users", "Groups"].includes(body.kind)) return false;
  const base = ["version", "operation", "org_id", "kind"];
  if (body.operation === "get") return exact(body, [...base, "id"]) && ID.test(body.id ?? "");
  if (body.operation === "list") return exact(body, [...base, "attribute", "value", "start", "count"])
    && Number.isInteger(body.start) && body.start >= 1 && body.start <= 999999999
    && Number.isInteger(body.count) && body.count >= 0 && body.count <= 100
    && (body.attribute === null && body.value === null || ["userName", "externalId", "displayName"].includes(body.attribute) && string(body.value));
  return body.operation === "put" && exact(body, [...base, "resource", "expected", "account", "token_digest", "deactivate"])
    && Number.isSafeInteger(body.expected) && body.expected >= 0 && body.expected < 9007199254740991
    && validResource(body.resource, body.kind, body.expected)
    && (body.token_digest === null || HASH.test(body.token_digest ?? ""))
    && typeof body.deactivate === "boolean" && (!body.deactivate || body.kind === "Groups" && body.resource.members.length === 0)
    && (body.account === null || body.kind === "Users" && validUser(body.account) && body.account.is_admin === 0
      && (body.expected !== 0 || body.account.scopes === "chat,models") && body.account.username === body.resource.userName
      && (body.resource.active ? body.account.revoked_at === null : body.account.revoked_at !== null));
}

async function requireSchema(db) {
  if (!db) throw new Error("Storage unavailable");
  // Probe every owned table and all account columns before preparing any account change.
  for (const [table, columns] of Object.entries(TABLE_COLUMNS)) await db.prepare(`SELECT ${columns} FROM ${table} LIMIT 0`).all();
  await db.prepare(`SELECT ${USER_FIELDS.join(",")} FROM control_users LIMIT 0`).all();
  await requireRevisionSchema(db);
}

async function get(db, org, kind, id) {
  const row = await db.prepare("SELECT document FROM scim_resources WHERE org_id=? AND kind=? AND id=?")
    .bind(org, kind, id).first();
  return row ? JSON.parse(row.document) : null;
}

async function list(db, body) {
  const column = { userName: "user_name", externalId: "external_id", displayName: "display_name" }[body.attribute];
  const where = `org_id=? AND kind=?${column ? ` AND ${column}=?` : ""}`;
  const args = [body.org_id, body.kind, ...(column ? [body.value] : [])];
  const count = await db.prepare(`SELECT count(*) AS total FROM scim_resources WHERE ${where}`).bind(...args).first();
  const rows = await db.prepare(`SELECT document FROM scim_resources WHERE ${where} ORDER BY id LIMIT ? OFFSET ?`)
    .bind(...args, body.count, body.start - 1).all();
  return reply({ resources: rows.results.map(row => JSON.parse(row.document)), total: count.total });
}

function casGuard(db, body) {
  return db.prepare(`INSERT INTO scim_resources (org_id,kind,id,revision,document)
    SELECT ?,?,?,-1,'' WHERE changes() != 1`).bind(body.org_id, body.kind, body.resource.id);
}

function resourceStatements(db, body) {
  const { org_id: org, kind, resource: row, expected } = body;
  const values = [row.externalId ?? null, row.userName ?? null, row.displayName ?? null, expected + 1, JSON.stringify(row), Number(body.deactivate)];
  const statement = expected === 0
    ? db.prepare("INSERT INTO scim_resources (external_id,user_name,display_name,revision,document,deactivated,org_id,kind,id) VALUES (?,?,?,?,?,?,?,?,?)")
      .bind(...values, org, kind, row.id)
    : db.prepare("UPDATE scim_resources SET external_id=?,user_name=?,display_name=?,revision=?,document=?,deactivated=? WHERE org_id=? AND kind=? AND id=? AND revision=?")
      .bind(...values, org, kind, row.id, expected);
  return [statement, casGuard(db, body)];
}

function accountStatements(db, body, priorAccount) {
  if (!body.account) return [];
  const { account, expected } = body;
  if (expected === 0) return [db.prepare(`INSERT INTO control_users (${USER_FIELDS.join(",")}) VALUES (${USER_FIELDS.map(() => "?").join(",")})`)
    .bind(...USER_FIELDS.map(key => account[key]))];
  return [db.prepare(`UPDATE control_users SET api_key_hash=?,api_key_prefix=?,revoked_at=?
    WHERE username=? AND is_admin=0 AND api_key_hash=? AND api_key_prefix=? AND revoked_at IS ?`)
    .bind(account.api_key_hash, account.api_key_prefix, account.revoked_at, account.username,
      priorAccount.api_key_hash, priorAccount.api_key_prefix, priorAccount.revoked_at), casGuard(db, body)];
}

async function prepareAccount(db, body, old) {
  if (body.kind !== "Users") return null;
  const existing = await db.prepare(`SELECT ${USER_FIELDS.join(",")} FROM control_users WHERE username=?`).bind(body.resource.userName).first();
  if (body.expected === 0) {
    if (!body.account) throw Object.assign(new Error(), { status: 400 });
    if (existing) throw Object.assign(new Error(), { status: 409 });
    return null;
  }
  if (!existing || existing.is_admin !== 0 || body.resource.userName !== old.userName) throw Object.assign(new Error(), { status: 400 });
  const changed = body.resource.active !== old.active;
  if (changed !== (body.account !== null)) throw Object.assign(new Error(), { status: 400 });
  if (body.account) {
    for (const field of USER_FIELDS.filter(key => !["api_key_hash", "api_key_prefix", "revoked_at"].includes(key))) {
      if (body.account[field] !== existing[field]) throw Object.assign(new Error(), { status: 412 });
    }
    if (!body.resource.active && (body.account.api_key_hash === existing.api_key_hash || body.account.api_key_prefix === existing.api_key_prefix))
      throw Object.assign(new Error(), { status: 400 });
    if (body.resource.active && (body.account.api_key_hash !== existing.api_key_hash || body.account.api_key_prefix !== existing.api_key_prefix))
      throw Object.assign(new Error(), { status: 400 });
  }
  return existing;
}

function collaboratorStatements(callback, data) {
  if (typeof callback !== "function") throw new Error("Authority unavailable");
  const result = callback(data);
  if (!Array.isArray(result)) throw new Error("Atomic authority statements required");
  return result;
}

async function put(db, body, collaborators) {
  const { org_id: org, kind, resource: row, expected } = body;
  const old = await get(db, org, kind, row.id);
  if (expected === 0 && row.externalId) {
    const existing = await db.prepare("SELECT document FROM scim_resources WHERE org_id=? AND kind=? AND external_id=?")
      .bind(org, kind, row.externalId).first();
    if (existing) return reply({ resource: JSON.parse(existing.document), created: false });
  }
  if (expected !== 0 && (!old || version(old) !== expected)) return reply("scim_version_conflict", 412);
  if (kind === "Users") {
    const names = new Set([String(collaborators.adminUsername ?? "admin"), ...(collaborators.adminUsernames ?? [])]);
    if (names.has(row.userName)) return reply("scim_admin_denied", 400);
  }
  const priorAccount = await prepareAccount(db, body, old);
  const statements = resourceStatements(db, body);
  statements.push(...accountStatements(db, body, priorAccount));
  if (kind === "Users" && expected === 0) {
    statements.push(...collaboratorStatements(collaborators.principalStatements, { org_id: org, resource: row }));
  }
  if (kind === "Groups") {
    statements.push(...collaboratorStatements(collaborators.teamStatements, { org_id: org, resource: row, prior: old, deactivated: body.deactivate }));
    statements.push(db.prepare("DELETE FROM scim_group_members WHERE org_id=? AND group_id=?").bind(org, row.id));
    for (const member of row.members) {
      const user = await get(db, org, "Users", member.value);
      if (!user) return reply("scim_foreign_member", 400);
      statements.push(db.prepare(`INSERT INTO scim_group_members (org_id,group_id,user_id)
        SELECT ?,?,id FROM scim_resources WHERE org_id=? AND kind='Users' AND id=?`)
        .bind(org, row.id, org, member.value), casGuard(db, body));
    }
  }
  const now = new Date().toISOString();
  if (body.token_digest !== null) statements.push(db.prepare(`INSERT INTO scim_token_digests VALUES (?,?,?)
    ON CONFLICT(org_id) DO UPDATE SET digest_sha256=excluded.digest_sha256,updated_at=excluded.updated_at`)
    .bind(org, body.token_digest, now));
  statements.push(db.prepare("INSERT INTO scim_audit (org_id,kind,resource_id,revision,operation,at) VALUES (?,?,?,?,?,?)")
    .bind(org, kind, row.id, expected + 1, row.active === false || body.deactivate ? "deactivate" : expected === 0 ? "create" : "update", now));
  try {
    if (!await commitRevision(db, ["key_controls", "model_grants"], statements)) return reply("scim_revision_conflict", 412);
  } catch (error) {
    const message = String(error?.message ?? error);
    if (message.includes("scim_cas_confirmed")) return reply("scim_version_conflict", 412);
    if (/UNIQUE constraint/i.test(message)) {
      if (expected === 0 && row.externalId) {
        const existing = await db.prepare("SELECT document FROM scim_resources WHERE org_id=? AND kind=? AND external_id=?")
          .bind(org, kind, row.externalId).first();
        if (existing) return reply({ resource: JSON.parse(existing.document), created: false });
      }
      return reply("scim_uniqueness", 409);
    }
    throw error;
  }
  return reply({ resource: row, created: expected === 0 });
}

export async function handleScimStateRequest(request, env, collaborators = {}) {
  if (!scimEnabled(env)) return reply("not_found", 404);
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.pathname !== PATH || url.search || url.hash
    || url.username || url.password || request.method !== "POST") return reply("not_found", 404);
  let body;
  try {
    if (!/^application\/json(?:;|$)/i.test(request.headers.get("content-type") ?? "")) throw new Error();
    body = JSON.parse(await boundedBody(request, 131072));
    if (!validBody(body)) throw new Error();
  } catch { return reply("scim_invalid_request", 400); }
  try {
    if (!revisionSyncSettings(env).enabled) return reply("scim_security_sync_required", 503);
    const db = env.INTELLIGENCE_DB;
    await requireSchema(db);
    if (body.operation === "probe") return reply({ ready: true });
    if (body.operation === "get") return reply({ resource: await get(db, body.org_id, body.kind, body.id) });
    if (body.operation === "list") return await list(db, body);
    if (body.operation === "account") return reply({ account: await db.prepare(`SELECT ${USER_FIELDS.join(",")} FROM control_users WHERE username=?`)
      .bind(body.username).first() });
    return await put(db, body, { ...collaborators, adminUsername: String(env.ADMIN_USERNAME || "admin").trim(),
      adminUsernames: String(env.ADMIN_USERNAMES || "").split(",").map(name => name.trim()) });
  } catch (error) {
    const status = [400, 409, 412].includes(error?.status) ? error.status : 503;
    return reply(status === 503 ? "scim_storage_unavailable" : "scim_operation_rejected", status);
  }
}
