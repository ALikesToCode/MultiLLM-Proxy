/** Native gateway authentication, ticket admission and approved Realtime dispatch. */
import { Buffer } from "node:buffer";
import { createHash, scrypt, timingSafeEqual } from "node:crypto";
import { activeUsersByPrefix, boundedBody, keyControlsPermit, validUser } from "./control-users-d1.mjs";
import { lookupIntegrationPrincipal } from "./intelligence-auth-d1.mjs";
import { authStorageBackend } from "./container-env.mjs";
import { acquireAdmission, admissionSettings, principalHash } from "./admission-do.mjs";
import { nativeRevisionConsumer, tickNativeRevisionSync } from "./native-config-sync.mjs";
import { isRealtimeRequestPath } from "./api-paths.mjs";
import { bridgeRealtime, REALTIME_TTL_MS } from "./realtime-session.mjs";
import { createRealtimeMeter, realtimeCostPolicy, reserveRealtime, RealtimeError } from "./realtime-metering.mjs";

const MODEL = /^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,191}$/;
const HASH = /^scrypt:32768:8:1\$([A-Za-z0-9]{8,32})\$([a-f0-9]{128})$/;
const KEYS = Object.freeze({ openai: ["OPENAI_API_KEY"], opencode: ["OPENCODE_GO_API_KEY", "OPENCODE_API_KEY"],
  linkapi: ["LINKAPI_KEY", "LINKAPI_API_KEY"], "codex-easy": ["CODEX_EASY_API_KEY", "CODEX_API_KEY"],
  nanogpt: ["NANOGPT_API_KEY"], openrouter: ["OPENROUTER_API_KEY"], groq: ["GROQ_API_KEY"], xai: ["XAI_API_KEY"] });
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const digest = value => createHash("sha256").update(String(value)).digest("hex");
const same = (a, b) => Boolean(a && b) && timingSafeEqual(Buffer.from(digest(a), "hex"), Buffer.from(digest(b), "hex"));
const warned = new Set();
function warn(name) { if (!warned.has(name)) { warned.add(name); console.warn(`Invalid ${name}; Realtime disabled`); } }
const identifier = () => crypto.randomUUID().replaceAll("-", "");
let verifying = 0;

export function realtimeSettings(env = {}) {
  const flag = String(env.REALTIME_ENABLED ?? "").trim().toLowerCase();
  if (["", "false", "0", "off", "no"].includes(flag)) return { enabled: false };
  if (!["true", "1", "on", "yes"].includes(flag)) { warn("REALTIME_ENABLED"); return { enabled: false }; }
  try {
    const raw = String(env.REALTIME_PROVIDERS_JSON ?? "").trim(); if (raw.length > 65536) throw Error();
    const mapping = JSON.parse(raw || "{}");
    if (!object(mapping) || Object.keys(mapping).length > 256) throw Error();
    const providers = new Map();
    for (const [model, entry] of Object.entries(mapping)) {
      if (!MODEL.test(model) || !Object.hasOwn(KEYS, model.split(":", 1)[0]) || !object(entry)
        || Object.keys(entry).join() !== "url" || typeof entry.url !== "string" || entry.url.length > 2048) throw Error();
      const url = new URL(entry.url);
      if (url.protocol !== "wss:" || url.username || url.password || url.hash || url.port && url.port !== "443"
        || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(url.hostname) || !url.hostname.includes(".")
        || /^[0-9.]+$/.test(url.hostname) || /(?:^|\.)(?:localhost|local|internal)$/.test(url.hostname)
        || /[\x00-\x20\\]/.test(entry.url)
        || [...url.searchParams.keys()].some(name => /^(?:api[-_]?key|access[-_]?token|token|authorization|secret|key)$/i.test(name))) throw Error();
      providers.set(model, url.href);
    }
    return { enabled: true, providers };
  } catch { warn("REALTIME_PROVIDERS_JSON"); return { enabled: false }; }
}
function bearer(request) {
  const direct = request.headers.get("x-multillm-api-key")?.trim();
  return direct || /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "")?.[1].trim();
}
async function checkHash(key, hash) {
  const match = HASH.exec(hash ?? ""); if (!match) throw new RealtimeError("realtime_credential_unverifiable");
  if (verifying >= 2) throw new RealtimeError("realtime_auth_busy");
  verifying++;
  try {
    const derived = await new Promise((resolve, reject) => scrypt(key, match[1], 64,
      { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, value) => error ? reject(error) : resolve(value)));
    return timingSafeEqual(derived, Buffer.from(match[2], "hex"));
  } finally { verifying--; }
}
function modelGranted(patterns, model) {
  if (patterns == null || patterns === "") return true;
  if (typeof patterns !== "string") return false;
  return patterns.split(",").some(pattern => new RegExp("^" + pattern.toLowerCase().split("*")
    .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$").test(model.toLowerCase()));
}
function permit(principal, request, model, now) {
  if (!principal || principal.revoked_at || !keyControlsPermit(principal, request.headers.get("cf-connecting-ip"), now)) {
    throw new RealtimeError("invalid_api_key", 401);
  }
  if (!principal.scopes.includes("chat") || !principal.scopes.includes("audio") || !modelGranted(principal.allowed_models, model)) {
    throw new RealtimeError("model_not_granted", 403);
  }
  return principal;
}
function account(row) {
  if (!validUser(row)) throw new RealtimeError("realtime_auth_unavailable");
  return { ...row, owner: row.username, scopes: row.scopes.split(",").map(value => value.trim()),
    credential_kind: "account", credential_fingerprint: digest(row.api_key_hash) };
}
function bootstrap(env) {
  const owner = String(env.ADMIN_USERNAME ?? "admin").trim();
  if (!owner || owner.length > 128 || /[\x00-\x1f\x7f]/.test(owner)) throw new RealtimeError("realtime_auth_unavailable");
  return { owner, scopes: ["chat", "audio"], credential_kind: "bootstrap", credential_fingerprint: digest(env.ADMIN_API_KEY) };
}
function integration(row) {
  if (!row || !/^integration:[a-z][a-z0-9_-]{0,63}$/.test(row.id) || !Array.isArray(row.scopes)
    || !row.scopes.every(scope => typeof scope === "string") || !HASH.test(row.keyHash)
    || !Number.isSafeInteger(row.credentialVersion)) throw new RealtimeError("realtime_auth_unavailable");
  return { owner: row.id, scopes: row.scopes, revoked_at: row.revokedAt,
    credential_kind: "integration", credential_fingerprint: digest(row.keyHash) };
}
async function authenticate(request, env, model, now) {
  const key = bearer(request);
  if (!key || key.length > 1024) throw new RealtimeError("invalid_api_key", 401);
  if (key.startsWith("rt1.")) return consumeTicket(key, request, env, model, now);
  let principal;
  if (same(key, env.ADMIN_API_KEY)) principal = bootstrap(env);
  else if (/^mllm_intelligence_[A-Za-z0-9_-]{32,128}$/.test(key)) {
    const row = await lookupIntegrationPrincipal(env.INTELLIGENCE_DB, key.slice(0, "mllm_intelligence_".length + 16));
    if (!row || !await checkHash(key, row.keyHash)) throw new RealtimeError("invalid_api_key", 401);
    principal = integration(row);
  } else if (authStorageBackend(env) === "d1") {
    const rows = await activeUsersByPrefix(env.INTELLIGENCE_DB, `mllm_${key.slice(0, 8)}`, env);
    if (rows.length > 8) throw new RealtimeError("realtime_auth_busy");
    for (const row of rows) { if (!validUser(row)) throw new RealtimeError("realtime_auth_unavailable");
      if (await checkHash(key, row.api_key_hash)) { principal = account(row); break; } }
  }
  if (!principal) throw new RealtimeError("invalid_api_key", 401);
  principal.principal_hash = await principalHash(`realtime-key:${digest(key)}`);
  return permit(principal, request, model, now);
}
async function signingKey(env) {
  // Derive a domain-specific key from the existing gateway signing binding.
  if (!env.JWT_SECRET) throw new RealtimeError("realtime_tickets_unavailable");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(`multillm-realtime-ticket:v1:${env.JWT_SECRET}`),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function issueTicket(request, env, settings, now) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") throw new RealtimeError("invalid_request", 400);
  let body; try { body = JSON.parse(await boundedBody(request, 4096)); } catch { throw new RealtimeError("invalid_request", 400); }
  if (!object(body) || Object.keys(body).join() !== "model" || !settings.providers.has(body.model)) throw new RealtimeError("model_not_granted", 403);
  // A ticket cannot mint a second generation of tickets.
  if (bearer(request)?.startsWith("rt1.")) throw new RealtimeError("invalid_api_key", 401);
  const principal = await authenticate(request, env, body.model, now), key = await signingKey(env);
  const nonce = identifier(), expires = now + 60000;
  const result = await env.INTELLIGENCE_DB.prepare(`INSERT INTO realtime_tickets
    (nonce,principal_hash,owner,credential_kind,credential_fingerprint,model,expires_at)
    SELECT ?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM realtime_tickets WHERE principal_hash=? AND expires_at>? AND consumed_at IS NULL)<16`)
    .bind(nonce, principal.principal_hash, principal.owner, principal.credential_kind, principal.credential_fingerprint, body.model,
      expires, principal.principal_hash, now).run();
  if (result.meta.changes !== 1) throw new RealtimeError("realtime_ticket_limit", 429);
  const payload = `rt1.${nonce}.${expires}`;
  const signature = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))).toString("base64url");
  return Response.json({ value: `${payload}.${signature}`, expires_at: Math.floor(expires / 1000) }, { headers: { "cache-control": "no-store" } });
}
async function consumeTicket(ticket, request, env, model, now) {
  const match = /^(rt1\.([a-f0-9]{32})\.([0-9]{13}))\.([A-Za-z0-9_-]{43})$/.exec(ticket);
  if (!match || Number(match[3]) <= now || Number(match[3]) > now + 60000
    || Buffer.from(match[4], "base64url").toString("base64url") !== match[4]
    || !await crypto.subtle.verify("HMAC", await signingKey(env), Buffer.from(match[4], "base64url"), new TextEncoder().encode(match[1]))) {
    throw new RealtimeError("invalid_api_key", 401);
  }
  const row = await env.INTELLIGENCE_DB.prepare("SELECT * FROM realtime_tickets WHERE nonce=?").bind(match[2]).first();
  if (!row || row.model !== model || row.consumed_at !== null || row.expires_at !== Number(match[3])) throw new RealtimeError("invalid_api_key", 401);
  let principal;
  if (row.credential_kind === "bootstrap") principal = bootstrap(env);
  if (row.credential_kind === "account") {
    const user = await env.INTELLIGENCE_DB.prepare("SELECT * FROM control_users WHERE username=? AND revoked_at IS NULL").bind(row.owner).first();
    if (user) principal = account(user);
  }
  if (row.credential_kind === "integration") {
    const credential = await env.INTELLIGENCE_DB.prepare(`SELECT c.key_prefix FROM intelligence_credentials c
      JOIN intelligence_principals p ON p.id=c.principal_id AND p.version=c.version WHERE p.id=? AND p.revoked_at IS NULL`).bind(row.owner).first();
    if (credential) principal = integration(await lookupIntegrationPrincipal(env.INTELLIGENCE_DB, credential.key_prefix));
  }
  if (!principal || principal.owner !== row.owner || !same(principal.credential_fingerprint, row.credential_fingerprint)) throw new RealtimeError("invalid_api_key", 401);
  permit(principal, request, model, now);
  const consumed = await env.INTELLIGENCE_DB.prepare("UPDATE realtime_tickets SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL AND expires_at>?")
    .bind(now, match[2], now).run();
  if (consumed.meta.changes !== 1) throw new RealtimeError("invalid_api_key", 401);
  return { ...principal, principal_hash: row.principal_hash };
}
async function schemaReady(db) {
  if (!db) throw new RealtimeError("realtime_storage_unavailable");
  try {
    await db.prepare(`SELECT nonce,principal_hash,owner,credential_kind,credential_fingerprint,model,expires_at,consumed_at FROM realtime_tickets LIMIT 0`).all();
    await db.prepare(`SELECT id,principal_hash,owner,model,lease_id,created_at,expires_at,lease_until,state,
      input_text_tokens,input_audio_tokens,output_text_tokens,output_audio_tokens,cost_usd,closed_at FROM realtime_sessions LIMIT 0`).all();
    await db.prepare("SELECT id,state,revision FROM usage_reservations LIMIT 0").all();
    await db.prepare("SELECT id FROM usage_events LIMIT 0").all();
  } catch { throw new RealtimeError("realtime_schema_missing"); }
}
async function admitSession(env, principal, model, sessionId, now) {
  const result = await env.INTELLIGENCE_DB.prepare(`INSERT INTO realtime_sessions
    (id,principal_hash,owner,model,created_at,expires_at,lease_until,state)
    SELECT ?,?,?,?,?,?,?,'admitted' WHERE (SELECT COUNT(*) FROM realtime_sessions
      WHERE principal_hash=? AND state IN ('admitted','active') AND lease_until>?)<2`)
    .bind(sessionId, principal.principal_hash, principal.owner, model, now, now + REALTIME_TTL_MS, now + 30000, principal.principal_hash, now).run();
  if (result.meta.changes !== 1) throw new RealtimeError("realtime_session_limit", 429);
}
function upstreamHeaders(request, key) {
  const headers = new Headers({ Upgrade: "websocket", Authorization: `Bearer ${key}` });
  const beta = request.headers.get("openai-beta");
  if (beta === "realtime=v1") headers.set("OpenAI-Beta", beta);
  return headers;
}
async function openSession(request, env, ctx, settings, options) {
  const params = new URL(request.url).searchParams, model = params.get("model");
  const now = options.timers?.now?.() ?? Date.now();
  if (!model || !MODEL.test(model)) throw new RealtimeError("invalid_model", 400);
  const principal = await authenticate(request, env, model, now);
  if (!settings.providers.has(model)) throw new RealtimeError("model_not_granted", 403);
  if ([...params.keys()].some(name => name !== "model") || params.getAll("model").length !== 1) throw new RealtimeError("invalid_request", 400);
  const policy = realtimeCostPolicy(env, model), provider = model.split(":", 1)[0];
  const key = KEYS[provider].map(name => env[name]).find(value => typeof value === "string" && value.trim());
  if (!key) throw new RealtimeError("realtime_provider_unavailable");
  const admission = admissionSettings(env);
  if (!admission.enabled || !env.ADMISSION_COORDINATOR) throw new RealtimeError("realtime_admission_required");
  await schemaReady(env.INTELLIGENCE_DB);
  const sessionId = identifier(), controller = new AbortController();
  let lease, reservation, bridge, socket, server, admitted = false, handedOff = false;
  const abort = () => { controller.abort(); void bridge?.close(1008, true); };
  request.signal.addEventListener("abort", abort, { once: true });
  const setupTimeout = setTimeout(abort, 10000); setupTimeout.unref?.();
  const context = { principal: principal.owner, requestId: sessionId, provider, model: model.slice(provider.length + 1), endpoint: "/v1/realtime" };
  const finish = async (usage, code) => {
    try {
      const state = await reservation.finalize(usage, context, code === 1000 ? 200 : code === 1008 ? 499 : 502, ctx);
      await env.INTELLIGENCE_DB.prepare(`UPDATE realtime_sessions SET state=?,input_text_tokens=?,input_audio_tokens=?,
        output_text_tokens=?,output_audio_tokens=?,cost_usd=?,closed_at=? WHERE id=?`)
        .bind(state === "settled" ? "settled" : "unknown", usage.input_text_tokens, usage.input_audio_tokens,
          usage.output_text_tokens, usage.output_audio_tokens, usage.cost_usd, Date.now(), sessionId).run();
    } finally { request.signal.removeEventListener("abort", abort); }
  };
  try {
    await admitSession(env, principal, model, sessionId, now); admitted = true;
    lease = await acquireAdmission({ principal_hash: await principalHash(principal.owner), model_group: model,
      request_id: sessionId, deadline_ms: now + REALTIME_TTL_MS }, env, { onLost: abort });
    if (!lease) throw new RealtimeError("realtime_admission_required");
    reservation = await reserveRealtime(env, principal, policy, sessionId, now);
    if (request.signal.aborted || controller.signal.aborted) throw new RealtimeError("realtime_canceled", 499);
    await reservation.dispatch();
    if (request.signal.aborted || controller.signal.aborted) throw new RealtimeError("realtime_canceled", 499);
    const url = new URL(settings.providers.get(model)); url.protocol = "https:";
    handedOff = true;
    const response = await (options.dial ?? fetch)(url.href, { method: "GET", headers: upstreamHeaders(request, key),
      redirect: "manual", signal: controller.signal });
    socket = response.webSocket;
    if (response.status !== 101 || !socket) { void response.body?.cancel?.().catch(() => {}); throw new RealtimeError("realtime_upstream_error", 502); }
    if (request.signal.aborted || controller.signal.aborted) throw new RealtimeError("realtime_canceled", 499);
    lease.check();
    const pair = options.pair ? options.pair() : new WebSocketPair(); server = pair[1];
    await env.INTELLIGENCE_DB.prepare("UPDATE realtime_sessions SET state='active',lease_id=? WHERE id=?")
      .bind(lease.value.lease_id, sessionId).run();
    socket.accept(); server.accept();
    bridge = bridgeRealtime(server, socket, { meter: createRealtimeMeter(policy), finalize: finish, secret: key,
      signal: request.signal, timers: options.timers, lease,
      heartbeat: async () => { const timestamp = options.timers?.now?.() ?? Date.now();
        const result = await env.INTELLIGENCE_DB.prepare(`UPDATE realtime_sessions SET lease_until=? WHERE id=? AND state='active' AND lease_until>?`)
          .bind(Math.min(timestamp + 30000, now + REALTIME_TTL_MS), sessionId, timestamp).run();
        if (result.meta.changes !== 1) throw new RealtimeError("realtime_session_expired"); } });
    ctx?.waitUntil?.(bridge.done);
    return options.upgradeResponse ? options.upgradeResponse(pair[0]) : new Response(null, { status: 101, webSocket: pair[0] });
  } catch (error) {
    if (bridge) await bridge.close(1011, true);
    else {
      try { socket?.close(1011, "Realtime session closed"); server?.close(1011, "Realtime session closed"); } catch { /* Already closed. */ }
      try {
        if (reservation) await reservation.finalize({ input_tokens: null, output_tokens: null, cost_usd: null, cost_basis: null }, context, 502, ctx);
        if (admitted) await env.INTELLIGENCE_DB.prepare("UPDATE realtime_sessions SET state=?,closed_at=? WHERE id=?")
          .bind(handedOff ? "unknown" : "released", Date.now(), sessionId).run();
      } catch { console.warn("Realtime finalization unavailable; retain monetary hold"); }
      await lease?.release(); request.signal.removeEventListener("abort", abort);
    }
    throw error;
  } finally { clearTimeout(setupTimeout); }
}

/** Null is the untouched legacy path; enabled routes never fall through to Container. */
export async function handleRealtimeRequest(request, env, ctx, options = {}) {
  if (!isRealtimeRequestPath(new URL(request.url).pathname)) return null;
  const settings = realtimeSettings(env); if (!settings.enabled) return null;
  try {
    const url = new URL(request.url);
    if (url.pathname === "/v1/realtime" && (request.method !== "GET" || request.headers.get("upgrade")?.trim().toLowerCase() !== "websocket")) {
      throw new RealtimeError("websocket_upgrade_required", 426);
    }
    const rejection = nativeRevisionConsumer(env)?.requireFreshSecurity(); if (rejection) return rejection;
    tickNativeRevisionSync(env, ctx);
    if (url.pathname === "/v1/realtime/client_secrets" && request.method === "POST") {
      await schemaReady(env.INTELLIGENCE_DB);
      if (url.search) throw new RealtimeError("invalid_request", 400);
      return await issueTicket(request, env, settings, options.timers?.now?.() ?? Date.now());
    }
    if (url.pathname !== "/v1/realtime") throw new RealtimeError("not_found", 404);
    return await openSession(request, env, ctx, settings, options);
  } catch (error) {
    if (error instanceof RealtimeError || typeof error?.response === "function") return error.response();
    return new RealtimeError("realtime_unavailable").response();
  }
}
