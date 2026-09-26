/**
 * Durable dashboard accounts (username, key hash and metadata) in D1, reachable only
 * through the Container's private outbound handler. Fixed statements, no client SQL.
 */
import { logFailure } from "./log.mjs";
import { AUDIT_OPERATIONS, handleAuditOperation } from "./control-audit-d1.mjs";

export const USER_FIELDS = Object.freeze(["username", "api_key_hash", "api_key_prefix", "scopes", "is_admin",
  "created_at", "last_login", "last_used_at", "last_used_ip", "created_by", "rotated_at", "revoked_at",
  "daily_budget_usd", "monthly_budget_usd", "allowed_models", "allowed_ips", "expires_at"]);
// Migration 0007 added the per-key controls. Until it is applied, reads return the
// older columns with no controls, so deploying before migrating cannot lock keys out.
const CONTROL_FIELDS = USER_FIELDS.slice(12);
const LEGACY_FIELDS = USER_FIELDS.slice(0, 12);
const COLUMNS = USER_FIELDS.join(", ");
const missingColumn = error => /no such column|has no column named/i.test(String(error?.message ?? error));
const withoutControls = row => row && { ...row, ...Object.fromEntries(CONTROL_FIELDS.map(name => [name, null])) };
const MAX_BODY_BYTES = 8192;
const MAX_PAGE = 200;
const OPERATIONS = new Set(["list", "get", "by_prefix", "upsert", "delete", "touch"]);
const CONTROL = /[\x00-\x1f\x7f]/;
const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !CONTROL.test(value);
const optionalText = (value, maximum) => value === null || text(value, maximum);
const budget = value => value === null || (typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1_000_000_000);
// Comma-separated model patterns ("auto:*", "openai:gpt-4.1") and normalized CIDR ranges.
const MODEL_PATTERNS = /^[A-Za-z0-9._:/+@*-]+(?:,[A-Za-z0-9._:/+@*-]+)*$/;
const IP_RANGES = /^[0-9A-Fa-f.:]+\/\d{1,3}(?:,[0-9A-Fa-f.:]+\/\d{1,3})*$/;
const list = (value, pattern) => value === null || (typeof value === "string" && value.length <= 4096 && pattern.test(value));
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
    && optionalText(user.last_used_ip, 128) && optionalText(user.created_by, 128)
    && budget(user.daily_budget_usd) && budget(user.monthly_budget_usd)
    && list(user.allowed_models, MODEL_PATTERNS) && list(user.allowed_ips, IP_RANGES)
    && (user.expires_at === null || (text(user.expires_at, 64) && Number.isFinite(Date.parse(user.expires_at))));
}

// 4 or 16 bytes for an IPv4 or IPv6 address; an IPv4-mapped IPv6 address becomes IPv4.
function addressBytes(value) {
  if (typeof value !== "string" || !value || value.length > 64) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    const parts = value.split(".").map(Number);
    return parts.every(part => part <= 255) ? Uint8Array.from(parts) : null;
  }
  if (!/^[0-9A-Fa-f:.]+$/.test(value) || value.split("::").length > 2) return null;
  let address = value;
  const embedded = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (embedded) {
    const v4 = addressBytes(embedded[2]);
    if (!v4) return null;
    address = `${embedded[1]}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const [head, rest] = address.split("::");
  const groups = part => (part ? part.split(":") : []);
  const left = groups(head);
  const tail = rest === undefined ? [] : groups(rest);
  const missing = 8 - left.length - tail.length;
  if (rest === undefined ? missing !== 0 : missing < 1) return null;
  const words = [...left, ...Array(rest === undefined ? 0 : missing).fill("0"), ...tail];
  if (!words.every(word => /^[0-9A-Fa-f]{1,4}$/.test(word))) return null;
  const bytes = new Uint8Array(16);
  words.forEach((word, index) => {
    const number = parseInt(word, 16);
    bytes[index * 2] = number >> 8;
    bytes[index * 2 + 1] = number & 255;
  });
  const mapped = bytes.slice(0, 10).every(byte => byte === 0) && bytes[10] === 255 && bytes[11] === 255;
  return mapped ? bytes.slice(12) : bytes;
}

function inRange(address, range) {
  const [base, length] = range.split("/");
  const network = addressBytes(base);
  const bits = Number(length);
  if (!network || network.length !== address.length || bits > network.length * 8) return false;
  for (let bit = 0; bit < bits; bit += 1) {
    const mask = 0x80 >> (bit % 8);
    if ((network[bit >> 3] & mask) !== (address[bit >> 3] & mask)) return false;
  }
  return true;
}

/**
 * Whether an account's key may be used now from the client address: it has not expired
 * and, when the account lists address ranges, the address is inside one of them. The
 * Container applies the same rules to every API request it authenticates.
 */
export function keyControlsPermit(user, clientAddress, now = Date.now()) {
  if (user.expires_at !== null && user.expires_at !== undefined && !(Date.parse(user.expires_at) > now)) return false;
  if (user.allowed_ips === null || user.allowed_ips === undefined) return true;
  const address = addressBytes(clientAddress);
  return Boolean(address) && user.allowed_ips.split(",").some(range => inRange(address, range));
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
    if (missingColumn(error)) throw error;
    logFailure("account_storage_retry", error);
    return query();
  }
}

/** Run an account query with every column, or with the pre-0007 columns and no controls. */
async function readUsers(query) {
  try { return await read(() => query(COLUMNS)); }
  catch (error) {
    if (!missingColumn(error)) throw error;
    logFailure("account_controls_unmigrated", error);
    const rows = await read(() => query(LEGACY_FIELDS.join(", ")));
    return Array.isArray(rows) ? rows.map(withoutControls) : withoutControls(rows);
  }
}

function upsertStatement(db, user, fields) {
  return db.prepare(`INSERT INTO control_users (${fields.join(", ")}) VALUES (${fields.map(() => "?").join(", ")})
    ON CONFLICT(username) DO UPDATE SET ${fields.slice(1).map(name => `${name}=excluded.${name}`).join(", ")}`)
    .bind(...fields.map(name => user[name]));
}

function audit(db, operation, outcome, user) {
  return db.prepare(`INSERT INTO control_user_audit (at, operation, outcome, username, is_admin, scopes, api_key_prefix, revoked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(new Date().toISOString(), operation, outcome, user.username,
    user.is_admin ?? null, user.scopes ?? null, user.api_key_prefix ?? null, user.revoked_at ?? null);
}

/** Unrevoked accounts for a key prefix, shared by the Container RPC and the edge. */
export async function activeUsersByPrefix(db, prefix) {
  return readUsers(async columns => (await db.prepare(`SELECT ${columns} FROM control_users
    WHERE api_key_prefix=? AND revoked_at IS NULL ORDER BY username LIMIT ${MAX_PAGE}`).bind(prefix).all()).results);
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
    if (AUDIT_OPERATIONS.has(body.operation)) {
      const result = await handleAuditOperation(db, body);
      return result ? reply(result) : reply({ error: "invalid_request" }, 400);
    }
    switch (body.operation) {
      case "list": {
        if (!fields(body, ["version", "operation", "after", "limit"]) || !optionalText(body.after, 128)
          || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > MAX_PAGE) break;
        const users = await readUsers(async columns => (await (body.after === null
          ? db.prepare(`SELECT ${columns} FROM control_users ORDER BY username LIMIT ?`).bind(body.limit)
          : db.prepare(`SELECT ${columns} FROM control_users WHERE username > ? ORDER BY username LIMIT ?`).bind(body.after, body.limit)
        ).all()).results);
        return reply({ version: 1, users });
      }
      case "get": {
        if (!fields(body, ["version", "operation", "username"]) || !text(body.username, 128)) break;
        const user = await readUsers(columns => db.prepare(`SELECT ${columns} FROM control_users WHERE username=?`)
          .bind(body.username).first());
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
        try {
          await db.batch([upsertStatement(db, user, USER_FIELDS), audit(db, "upsert", "stored", user)]);
        } catch (error) {
          // Before migration 0007 an account without controls can still be stored; controls cannot.
          if (!missingColumn(error) || CONTROL_FIELDS.some(name => user[name] !== null)) throw error;
          await db.batch([upsertStatement(db, user, LEGACY_FIELDS), audit(db, "upsert", "stored", user)]);
        }
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
