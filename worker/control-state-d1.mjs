/**
 * Control-plane state that every Container instance shares and that outlives Container
 * restarts: request usage, login throttling, model overrides, free-route cooldowns,
 * workbench profiles and provider catalog snapshots. Reachable only through the
 * Container's private outbound handler at /v1/state/<domain>. Fixed statements, no
 * client SQL.
 */
import { boundedBody } from "./control-users-d1.mjs";
import { logFailure } from "./log.mjs";

const CONTROL = /[\x00-\x1f\x7f]/;
const HASH = /^[0-9a-f]{64}$/;
const HEX_ID = /^[0-9a-f]{32}$/;
const PROVIDER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const SCOPE = /^(?:provider|model):[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const TIMESTAMP = /^[0-9T:.+\-Z]{10,40}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_RATE_INCREMENTS = 12;
const MAX_RATE_READS = 16;
const FLUSH_RETENTION_SECONDS = 24 * 3600;
const MAX_OVERRIDES = 2000;
const MAX_COOLDOWNS = 1000;
const MAX_COOLDOWN_WRITES = 32;
const MAX_COOLDOWN_SECONDS = 7 * 24 * 3600;
const MAX_PROFILES = 50;
const MAX_REPORTS = 100;
const PROFILE_FIELDS = Object.freeze(["name", "kind", "provider", "model", "mode", "effort", "billing", "fallback", "memory", "recovery"]);
const MAX_CATALOG_PROVIDERS = 200;
const MAX_SNAPSHOT_CHARS = 240000;
// Each chunk is one bound value, far below D1's 100 KB statement and 2 MB row limits.
const SNAPSHOT_CHUNK_CHARS = 60000;

const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !CONTROL.test(value);
const integer = (value, minimum, maximum) => Number.isSafeInteger(value) && value >= minimum && value <= maximum;
const number = (value, minimum, maximum) => typeof value === "number" && Number.isFinite(value) && value >= minimum && value <= maximum;
const matches = (pattern, value) => typeof value === "string" && pattern.test(value);
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (body, names) => object(body) && Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));
const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Control state storage operation failed" } }
  : { version: 1, ...value }, { status, headers: { "cache-control": "no-store" } });

// Usage increments apply once per flush ID: a resent flush whose reply was lost adds nothing.
const RATE_UPSERT = `INSERT INTO control_rate_usage (identity, provider, span, bucket, instance, requests, tokens)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE NOT EXISTS (SELECT 1 FROM control_rate_flushes WHERE id = ?8)
  ON CONFLICT (identity, provider, span, bucket, instance) DO UPDATE SET
  requests = requests + excluded.requests, tokens = tokens + excluded.tokens`;
// Usage every other ledger recorded: this minute, the previous one, and the last 24 hour buckets.
const RATE_READ = `SELECT
  COALESCE(SUM(CASE WHEN span = 60 AND bucket = ?1 THEN requests END), 0) AS current_requests,
  COALESCE(SUM(CASE WHEN span = 60 AND bucket = ?1 THEN tokens END), 0) AS current_tokens,
  COALESCE(SUM(CASE WHEN span = 60 AND bucket = ?1 - 1 THEN requests END), 0) AS previous_requests,
  COALESCE(SUM(CASE WHEN span = 60 AND bucket = ?1 - 1 THEN tokens END), 0) AS previous_tokens,
  COALESCE(SUM(CASE WHEN span = 3600 THEN requests END), 0) AS day_requests
  FROM control_rate_usage WHERE identity = ?3 AND provider = ?4 AND instance != ?5
  AND ((span = 60 AND bucket >= ?1 - 1) OR (span = 3600 AND bucket > ?2 - 24))`;
const USAGE_FIELDS = ["current_requests", "current_tokens", "previous_requests", "previous_tokens", "day_requests"];

const rateKey = value => fields(value, ["identity", "provider"]) && matches(HASH, value.identity) && matches(PROVIDER, value.provider);
const increment = (value, minute) => fields(value, ["identity", "provider", "minute", "requests", "tokens"])
  && matches(HASH, value.identity) && matches(PROVIDER, value.provider) && integer(value.minute, minute - 1440, minute + 5)
  && integer(value.requests, 0, 1_000_000) && integer(value.tokens, 0, 1e12) && value.requests + value.tokens > 0;

async function limits(db, body) {
  const now = Date.now() / 1000;
  const minute = Math.floor(now / 60);
  const hour = Math.floor(now / 3600);
  if (body.operation !== "sync" || !fields(body, ["version", "operation", "instance", "flush_id", "increments", "read", "prune"])
    || !matches(HEX_ID, body.instance) || !(body.flush_id === null || matches(HEX_ID, body.flush_id))
    || !Array.isArray(body.increments) || body.increments.length > MAX_RATE_INCREMENTS
    || (body.increments.length > 0) !== (body.flush_id !== null) || !body.increments.every(item => increment(item, minute))
    || !Array.isArray(body.read) || body.read.length > MAX_RATE_READS || !body.read.every(rateKey)
    || typeof body.prune !== "boolean") return null;
  const statements = body.increments.flatMap(item => [[60, item.minute], [3600, Math.floor(item.minute / 60)]].map(([span, bucket]) =>
    db.prepare(RATE_UPSERT).bind(item.identity, item.provider, span, bucket, body.instance, item.requests, item.tokens, body.flush_id)));
  if (body.flush_id !== null) {
    statements.push(db.prepare("INSERT OR IGNORE INTO control_rate_flushes (id, at) VALUES (?, ?)").bind(body.flush_id, Math.floor(now)));
  }
  const firstRead = statements.length;
  for (const key of body.read) statements.push(db.prepare(RATE_READ).bind(minute, hour, key.identity, key.provider, body.instance));
  if (body.prune) {
    statements.push(db.prepare("DELETE FROM control_rate_usage WHERE span = 60 AND bucket < ?").bind(minute - 10),
      db.prepare("DELETE FROM control_rate_usage WHERE span = 3600 AND bucket < ?").bind(hour - 25),
      db.prepare("DELETE FROM control_rate_flushes WHERE at < ?").bind(Math.floor(now) - FLUSH_RETENTION_SECONDS));
  }
  // One transaction: the increments, the flush record and the reads commit or fail together.
  const results = statements.length ? await db.batch(statements) : [];
  return reply({ minute, usage: body.read.map((key, index) => {
    const row = results[firstRead + index].results[0] ?? {};
    return { identity: key.identity, provider: key.provider, ...Object.fromEntries(USAGE_FIELDS.map(name => [name, Number(row[name] ?? 0)])) };
  }) });
}

// Mirrors LoginAttemptService.record_failure in one atomic statement: a running lock is kept,
// a failure inside the window counts up, and the configured count starts a lockout.
const LOGIN_FAILURE = `INSERT INTO control_login_attempts (identity_hash, failures, window_started, locked_until, updated_at)
  VALUES (?1, 1, ?2, CASE WHEN ?3 <= 1 THEN ?2 + ?5 ELSE 0 END, ?2)
  ON CONFLICT(identity_hash) DO UPDATE SET
  failures = CASE WHEN locked_until > ?2 THEN failures WHEN ?2 - window_started < ?4 THEN failures + 1 ELSE 1 END,
  window_started = CASE WHEN locked_until > ?2 OR ?2 - window_started < ?4 THEN window_started ELSE ?2 END,
  locked_until = CASE WHEN locked_until > ?2 THEN locked_until
    WHEN (CASE WHEN ?2 - window_started < ?4 THEN failures + 1 ELSE 1 END) >= ?3 THEN ?2 + ?5 ELSE 0 END,
  updated_at = CASE WHEN locked_until > ?2 THEN updated_at ELSE ?2 END
  RETURNING failures, window_started, locked_until`;

async function login(db, body) {
  switch (body.operation) {
    case "check": {
      if (!fields(body, ["version", "operation", "identity"]) || !matches(HASH, body.identity)) return null;
      const state = await db.prepare("SELECT failures, window_started, locked_until FROM control_login_attempts WHERE identity_hash = ?")
        .bind(body.identity).first();
      return reply({ state: state ?? null });
    }
    case "failure": {
      if (!fields(body, ["version", "operation", "identity", "now", "max_attempts", "window_seconds", "lockout_seconds", "retention_seconds"])
        || !matches(HASH, body.identity) || !number(body.now, 0, 1e11) || !integer(body.max_attempts, 1, 100)
        || !integer(body.window_seconds, 1, 86400) || !integer(body.lockout_seconds, 1, 604800)
        || !integer(body.retention_seconds, 1, 1209600)) return null;
      const [recorded] = await db.batch([
        db.prepare(LOGIN_FAILURE).bind(body.identity, body.now, body.max_attempts, body.window_seconds, body.lockout_seconds),
        db.prepare("DELETE FROM control_login_attempts WHERE locked_until <= ?1 AND updated_at < ?1 - ?2").bind(body.now, body.retention_seconds),
      ]);
      return reply({ state: recorded.results[0] });
    }
    case "success": {
      if (!fields(body, ["version", "operation", "identity"]) || !matches(HASH, body.identity)) return null;
      const result = await db.prepare("DELETE FROM control_login_attempts WHERE identity_hash = ?").bind(body.identity).run();
      return reply({ deleted: result.meta.changes === 1 });
    }
    default:
      return null;
  }
}

async function models(db, body) {
  if (body.operation === "list" && fields(body, ["version", "operation"])) {
    const { results } = await db.prepare(`SELECT model_id, status FROM control_model_overrides ORDER BY model_id LIMIT ${MAX_OVERRIDES}`).all();
    return reply({ overrides: results });
  }
  if (body.operation === "put" && fields(body, ["version", "operation", "model_id", "status", "updated_at"])
    && matches(MODEL_ID, body.model_id) && body.model_id.includes(":")
    && ["available", "disabled"].includes(body.status) && matches(TIMESTAMP, body.updated_at)) {
    await db.prepare(`INSERT INTO control_model_overrides (model_id, status, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(model_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at`)
      .bind(body.model_id, body.status, body.updated_at).run();
    return reply({ stored: true });
  }
  return null;
}

async function quotas(db, body) {
  const now = Date.now() / 1000;
  if (body.operation === "list" && fields(body, ["version", "operation"])) {
    const { results } = await db.prepare(`SELECT scope, blocked_until FROM control_free_cooldowns WHERE blocked_until > ?
      ORDER BY blocked_until DESC LIMIT ${MAX_COOLDOWNS}`).bind(now).all();
    return reply({ cooldowns: results });
  }
  if (body.operation === "block" && fields(body, ["version", "operation", "cooldowns"]) && Array.isArray(body.cooldowns)
    && body.cooldowns.length > 0 && body.cooldowns.length <= MAX_COOLDOWN_WRITES
    && body.cooldowns.every(item => fields(item, ["scope", "blocked_until"]) && matches(SCOPE, item.scope)
      && number(item.blocked_until, 0, now + MAX_COOLDOWN_SECONDS + 3600))) {
    // A shorter cooldown never replaces a longer one another instance recorded.
    await db.batch([...body.cooldowns.map(item => db.prepare(`INSERT INTO control_free_cooldowns (scope, blocked_until) VALUES (?, ?)
      ON CONFLICT(scope) DO UPDATE SET blocked_until = MAX(blocked_until, excluded.blocked_until)`).bind(item.scope, item.blocked_until)),
    db.prepare("DELETE FROM control_free_cooldowns WHERE blocked_until < ?").bind(now - 3600)]);
    return reply({ stored: body.cooldowns.length });
  }
  return null;
}

const profileSettings = value => fields(value, PROFILE_FIELDS) && text(value.name, 64)
  && PROFILE_FIELDS.every(name => typeof value[name] === "string" && value[name].length <= 200 && !CONTROL.test(value[name]));
const measurements = value => Array.isArray(value) && value.length >= 2 && value.length <= 12
  && value.every(item => object(item) && Object.keys(item).length <= 16) && JSON.stringify(value).length <= 16384;

async function workbench(db, body) {
  switch (body.operation) {
    case "profiles": {
      if (!fields(body, ["version", "operation", "owner"]) || !text(body.owner, 128)) return null;
      const { results } = await db.prepare(`SELECT id, settings, created_at FROM control_connection_profiles WHERE owner = ?
        ORDER BY created_at DESC LIMIT ${MAX_PROFILES}`).bind(body.owner).all();
      return reply({ profiles: results.map(row => ({ id: row.id, created_at: row.created_at, settings: JSON.parse(row.settings) })) });
    }
    case "save_profile": {
      if (!fields(body, ["version", "operation", "owner", "id", "settings", "created_at"]) || !text(body.owner, 128)
        || !matches(HEX_ID, body.id) || !profileSettings(body.settings) || !number(body.created_at, 0, 1e11)) return null;
      // The limit check and the insert are one statement, so concurrent saves cannot pass it together.
      const result = await db.prepare(`INSERT INTO control_connection_profiles (id, owner, name, settings, created_at)
        SELECT ?1, ?2, ?3, ?4, ?5 WHERE (SELECT COUNT(*) FROM control_connection_profiles WHERE owner = ?2) < ${MAX_PROFILES}`)
        .bind(body.id, body.owner, body.settings.name, JSON.stringify(body.settings), body.created_at).run();
      return result.meta.changes === 1 ? reply({ stored: true }) : reply({ error: "limit_reached" }, 409);
    }
    case "reports": {
      if (!fields(body, ["version", "operation", "owner"]) || !text(body.owner, 128)) return null;
      const { results } = await db.prepare(`SELECT id, created_at, data FROM control_comparison_results WHERE owner = ?
        ORDER BY created_at DESC LIMIT ${MAX_REPORTS}`).bind(body.owner).all();
      return reply({ reports: results.map(row => ({ id: row.id, created_at: row.created_at, data: JSON.parse(row.data) })) });
    }
    case "save_report": {
      if (!fields(body, ["version", "operation", "owner", "id", "data", "created_at"]) || !text(body.owner, 128)
        || !matches(HEX_ID, body.id) || !measurements(body.data) || !number(body.created_at, 0, 1e11)) return null;
      const result = await db.prepare(`INSERT INTO control_comparison_results (id, owner, created_at, data)
        SELECT ?1, ?2, ?3, ?4 WHERE (SELECT COUNT(*) FROM control_comparison_results WHERE owner = ?2) < ${MAX_REPORTS}`)
        .bind(body.id, body.owner, body.created_at, JSON.stringify(body.data)).run();
      return result.meta.changes === 1 ? reply({ stored: true }) : reply({ error: "limit_reached" }, 409);
    }
    default:
      return null;
  }
}

async function catalog(db, body) {
  switch (body.operation) {
    case "list": {
      if (!fields(body, ["version", "operation"])) return null;
      const { results } = await db.prepare(`SELECT provider, MAX(updated_at) AS updated_at FROM control_provider_catalog
        GROUP BY provider ORDER BY provider LIMIT ${MAX_CATALOG_PROVIDERS}`).all();
      return reply({ snapshots: results });
    }
    case "get": {
      if (!fields(body, ["version", "operation", "provider"]) || !matches(PROVIDER, body.provider)) return null;
      const { results } = await db.prepare("SELECT chunk, data, updated_at FROM control_provider_catalog WHERE provider = ? ORDER BY chunk")
        .bind(body.provider).all();
      const complete = results.length > 0 && results.every((row, index) => row.chunk === index && row.updated_at === results[0].updated_at);
      return reply({ snapshot: complete
        ? { provider: body.provider, updated_at: results[0].updated_at, data: results.map(row => row.data).join("") } : null });
    }
    case "put": {
      if (!fields(body, ["version", "operation", "provider", "updated_at", "data"]) || !matches(PROVIDER, body.provider)
        || !matches(TIMESTAMP, body.updated_at) || typeof body.data !== "string" || body.data.length === 0 || body.data.length > MAX_SNAPSHOT_CHARS
        || body.data.length % 4 !== 0 || !matches(BASE64, body.data)) return null;
      const chunks = [];
      for (let offset = 0; offset < body.data.length; offset += SNAPSHOT_CHUNK_CHARS) {
        chunks.push(body.data.slice(offset, offset + SNAPSHOT_CHUNK_CHARS));
      }
      // The new snapshot replaces the previous one in a single transaction.
      await db.batch([db.prepare("DELETE FROM control_provider_catalog WHERE provider = ?").bind(body.provider),
        ...chunks.map((data, chunk) => db.prepare(`INSERT INTO control_provider_catalog (provider, chunk, data, updated_at)
          VALUES (?, ?, ?, ?)`).bind(body.provider, chunk, data, body.updated_at))]);
      return reply({ stored: true });
    }
    default:
      return null;
  }
}

const DOMAINS = Object.freeze({
  limits: { handle: limits, maxBytes: 16384, operations: ["sync"] },
  login: { handle: login, maxBytes: 4096, operations: ["check", "failure", "success"] },
  models: { handle: models, maxBytes: 4096, operations: ["list", "put"] },
  quotas: { handle: quotas, maxBytes: 16384, operations: ["list", "block"] },
  workbench: { handle: workbench, maxBytes: 32768, operations: ["profiles", "save_profile", "reports", "save_report"] },
  catalog: { handle: catalog, maxBytes: 262144, operations: ["list", "get", "put"] },
});

export async function handleControlStateRequest(request, env) {
  const url = new URL(request.url);
  const name = url.pathname.startsWith("/v1/state/") ? url.pathname.slice("/v1/state/".length) : "";
  const domain = Object.hasOwn(DOMAINS, name) ? DOMAINS[name] : null;
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal" || !domain
    || url.search || url.hash || url.username || url.password) return reply({ error: "not_found" }, 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return reply({ error: "invalid_request" }, 400);
  }
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > domain.maxBytes)) return reply({ error: "invalid_request" }, 400);
  if (!env.INTELLIGENCE_DB) return reply({ error: "storage_unavailable" }, 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request, domain.maxBytes));
    if (!object(body) || body.version !== 1) return reply({ error: "invalid_request" }, 400);
  } catch { return reply({ error: "invalid_request" }, 400); }
  try {
    return await domain.handle(env.INTELLIGENCE_DB, body) ?? reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("control_state_storage_failed", error, { domain: name,
      operation: domain.operations.includes(body.operation) ? body.operation : "unknown" });
    return reply({ error: "storage_unavailable" }, 503);
  }
}
