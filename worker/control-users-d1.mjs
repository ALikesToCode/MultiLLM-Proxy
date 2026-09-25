/**
 * Durable dashboard accounts (username, key hash and metadata) in D1, reachable only
 * through the Container's private outbound handler. Fixed statements, no client SQL.
 */
import { logFailure } from "./log.mjs";

export const USER_FIELDS = Object.freeze(["username", "api_key_hash", "api_key_prefix", "scopes", "is_admin",
  "created_at", "last_login", "last_used_at", "last_used_ip", "created_by", "rotated_at", "revoked_at"]);
const COLUMNS = USER_FIELDS.join(", ");
const MAX_BODY_BYTES = 8192;
const MAX_PAGE = 200;
const OPERATIONS = new Set(["list", "get", "by_prefix", "upsert", "delete", "touch"]);
const CONTROL = /[\x00-\x1f\x7f]/;
const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !CONTROL.test(value);
const optionalText = (value, maximum) => value === null || text(value, maximum);
const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Account storage operation failed" } }
  : value, { status, headers: { "cache-control": "no-store" } });
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));

export function validUser(user) {
  return user !== null && typeof user === "object" && !Array.isArray(user) && fields(user, USER_FIELDS)
    && text(user.username, 128) && text(user.api_key_hash, 512) && text(user.api_key_prefix, 64)
    && typeof user.scopes === "string" && user.scopes.length <= 512 && /^[A-Za-z0-9:_.,-]*$/.test(user.scopes)
    && (user.is_admin === 0 || user.is_admin === 1) && text(user.created_at, 64)
    && ["last_login", "last_used_at", "rotated_at", "revoked_at"].every(name => optionalText(user[name], 64))
    && optionalText(user.last_used_ip, 128) && optionalText(user.created_by, 128);
}

/**
 * Usernames the Worker's own configuration lets hold administration: ADMIN_USERNAME and
 * the comma-separated ADMIN_USERNAMES. The Container writes accounts, but it cannot grant
 * a durable admin account that the Worker and the edge would then honor.
 */
export function adminUsernames(env) {
  const names = [env.ADMIN_USERNAME ?? "admin", ...String(env.ADMIN_USERNAMES ?? "").split(",")];
  return new Set(names.map(name => String(name).trim()).filter(name => name && !CONTROL.test(name)));
}

export const grantsAdmin = user => user.is_admin === 1 || user.scopes.split(",").map(scope => scope.trim()).includes("admin");

// Reads are idempotent: retry once so a transient D1 error does not reject a valid key.
async function read(query) {
  try { return await query(); }
  catch (error) {
    logFailure("account_storage_retry", error);
    return query();
  }
}

function audit(db, operation, outcome, user) {
  return db.prepare(`INSERT INTO control_user_audit (at, operation, outcome, username, is_admin, scopes, api_key_prefix, revoked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(new Date().toISOString(), operation, outcome, user.username,
    user.is_admin ?? null, user.scopes ?? null, user.api_key_prefix ?? null, user.revoked_at ?? null);
}

/** Unrevoked accounts for a key prefix, shared by the Container RPC and the edge. */
export async function activeUsersByPrefix(db, prefix) {
  const { results } = await read(() => db.prepare(`SELECT ${COLUMNS} FROM control_users
    WHERE api_key_prefix=? AND revoked_at IS NULL ORDER BY username LIMIT ${MAX_PAGE}`).bind(prefix).all());
  return results;
}

export async function boundedBody(request, maxBytes = MAX_BODY_BYTES) {
  if (!request.body) throw new Error("Missing body");
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { void reader.cancel().catch(() => {}); throw new Error("Oversized body"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export async function handleControlUsersRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal"
    || url.pathname !== "/v1/users" || url.search || url.hash || url.username || url.password) return reply({ error: "not_found" }, 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return reply({ error: "invalid_request" }, 400);
  }
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) return reply({ error: "invalid_request" }, 400);
  if (!env.INTELLIGENCE_DB) return reply({ error: "storage_unavailable" }, 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request));
    if (!body || Array.isArray(body) || typeof body !== "object" || body.version !== 1) return reply({ error: "invalid_request" }, 400);
  } catch { return reply({ error: "invalid_request" }, 400); }
  const db = env.INTELLIGENCE_DB;
  try {
    switch (body.operation) {
      case "list": {
        if (!fields(body, ["version", "operation", "after", "limit"]) || !optionalText(body.after, 128)
          || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > MAX_PAGE) break;
        const statement = body.after === null
          ? db.prepare(`SELECT ${COLUMNS} FROM control_users ORDER BY username LIMIT ?`).bind(body.limit)
          : db.prepare(`SELECT ${COLUMNS} FROM control_users WHERE username > ? ORDER BY username LIMIT ?`).bind(body.after, body.limit);
        return reply({ version: 1, users: (await read(() => statement.all())).results });
      }
      case "get": {
        if (!fields(body, ["version", "operation", "username"]) || !text(body.username, 128)) break;
        const user = await read(() => db.prepare(`SELECT ${COLUMNS} FROM control_users WHERE username=?`).bind(body.username).first());
        return reply({ version: 1, user: user ?? null });
      }
      case "by_prefix": {
        if (!fields(body, ["version", "operation", "prefix"]) || !text(body.prefix, 64)) break;
        return reply({ version: 1, users: await activeUsersByPrefix(db, body.prefix) });
      }
      case "upsert": {
        if (!fields(body, ["version", "operation", "user"]) || !validUser(body.user)) break;
        const user = body.user;
        if (grantsAdmin(user) && !adminUsernames(env).has(user.username)) {
          logFailure("account_admin_refused", new Error("Administration is not configured for this username"));
          await audit(db, "upsert", "refused", user).run();
          return reply({ error: "admin_not_allowed" }, 403);
        }
        // The write and its audit row commit together, or neither does.
        await db.batch([db.prepare(`INSERT INTO control_users (${COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(username) DO UPDATE SET ${USER_FIELDS.slice(1).map(name => `${name}=excluded.${name}`).join(", ")}`)
          .bind(...USER_FIELDS.map(name => user[name])), audit(db, "upsert", "stored", user)]);
        return reply({ version: 1, stored: true });
      }
      case "delete": {
        if (!fields(body, ["version", "operation", "username"]) || !text(body.username, 128)) break;
        const [result] = await db.batch([db.prepare("DELETE FROM control_users WHERE username=?").bind(body.username),
          db.prepare(`INSERT INTO control_user_audit (at, operation, outcome, username)
            VALUES (?, 'delete', CASE WHEN changes() = 1 THEN 'deleted' ELSE 'missing' END, ?)`)
            .bind(new Date().toISOString(), body.username)]);
        return reply({ version: 1, deleted: result.meta.changes === 1 });
      }
      case "touch": {
        if (!fields(body, ["version", "operation", "username", "last_used_at", "last_used_ip"])
          || !text(body.username, 128) || !text(body.last_used_at, 64) || !optionalText(body.last_used_ip, 128)) break;
        const result = await db.prepare("UPDATE control_users SET last_used_at=?, last_used_ip=? WHERE username=?")
          .bind(body.last_used_at, body.last_used_ip, body.username).run();
        return reply({ version: 1, updated: result.meta.changes === 1 });
      }
      default:
        break;
    }
    return reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("account_storage_failed", error, { operation: OPERATIONS.has(body.operation) ? body.operation : "unknown" });
    return reply({ error: "storage_unavailable" }, 503);
  }
}
