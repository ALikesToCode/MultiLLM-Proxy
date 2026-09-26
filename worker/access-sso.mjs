/**
 * Cloudflare Access single sign-on for the dashboard. On the sign-in path only, the Worker
 * verifies the Access application token (RS256 against the team's published keys, then
 * issuer, audience and validity window) and hands the Container an identity assertion
 * signed with CF_ACCESS_PROOF_SECRET. Clients can never supply that assertion: every
 * inbound copy of the headers is removed from every request before it is forwarded.
 */
import { logFailure } from "./log.mjs";

export const ACCESS_LOGIN_PATH = "/login/access";
export const ACCESS_IDENTITY_HEADER = "x-multillm-access-identity";
export const ACCESS_PROOF_HEADER = "x-multillm-access-proof";
export const ACCESS_PROOF_CONTEXT = "multillm-access-identity-v1.";
const ACCESS_HEADER_PREFIX = "x-multillm-access-";
const ACCESS_JWT_HEADER = "cf-access-jwt-assertion";
const CLOCK_SKEW_SECONDS = 60;
const MAX_TOKEN_LENGTH = 16384;
const MAX_KEYS_BYTES = 65536;
const MAX_KEYS = 16;
// 2048-bit moduli and larger; base64url of 256 bytes is 342 characters.
const MIN_MODULUS_LENGTH = 342;
const KEYS_TTL_MS = 60 * 60 * 1000;
// Access keeps a rotated key valid for 7 days; a failing endpoint may serve cached keys for a day.
const KEYS_STALE_MS = 24 * 60 * 60 * 1000;
// An unknown key id refetches the keys at most this often, so forged ids cannot drive fetches.
const KEYS_REFRESH_INTERVAL_MS = 10 * 1000;
const KEYS_TIMEOUT_MS = 5000;
const MIN_SECRET_LENGTH = 32;
const CONTROL = /[\x00-\x1f\x7f]/;
const SEGMENT = /^[A-Za-z0-9_-]+$/;
const TEAM_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/;
const EMAIL = /^[^\s@\x00-\x1f\x7f]{1,64}@[^\s@\x00-\x1f\x7f]{1,253}$/;
const CLIENT_ADDRESS = /^[0-9A-Fa-f:.]{2,45}$/;
const encoder = new TextEncoder();
// Imported keys per team domain. CryptoKeys may be shared across requests; in-flight
// fetches are not, because Workers cannot await I/O started by another request.
const keyCache = new Map();
const warned = new Set();

function warnOnce(event, message) {
  if (warned.has(event)) return;
  warned.add(event);
  logFailure(event, new Error(message));
}

function normalizeTeamDomain(value) {
  let url;
  try { url = new URL(value.includes("://") ? value : `https://${value}`); } catch { return null; }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash
    || (url.pathname !== "/" && url.pathname !== "") || !TEAM_HOST.test(url.hostname)) return null;
  return url.origin;
}

/**
 * The Access settings, or null when single sign-on is off. It is on only when the team
 * domain, at least one application audience tag and a proof secret are all configured.
 */
export function accessSsoConfig(env = {}) {
  const team = typeof env.CF_ACCESS_TEAM_DOMAIN === "string" ? env.CF_ACCESS_TEAM_DOMAIN.trim() : "";
  const audiences = String(env.CF_ACCESS_AUD ?? "").split(",").map(value => value.trim()).filter(Boolean);
  if (!team && !audiences.length) return null;
  const secret = typeof env.CF_ACCESS_PROOF_SECRET === "string" ? env.CF_ACCESS_PROOF_SECRET : "";
  const teamDomain = normalizeTeamDomain(team);
  if (!teamDomain || !audiences.length || audiences.some(value => value.length > 256 || CONTROL.test(value))
    || secret.length < MIN_SECRET_LENGTH) {
    warnOnce("access_sso_misconfigured", "Set CF_ACCESS_TEAM_DOMAIN (https://<team>.cloudflareaccess.com), "
      + "CF_ACCESS_AUD and a CF_ACCESS_PROOF_SECRET of at least 32 characters");
    return null;
  }
  return { teamDomain, audiences, secret };
}

function base64UrlBytes(value) {
  if (!SEGMENT.test(value) || value.length % 4 === 1) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));
    return Uint8Array.from(binary, character => character.charCodeAt(0));
  } catch { return null; }
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeJsonObject(segment) {
  const bytes = base64UrlBytes(segment);
  if (!bytes) return null;
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch { return null; }
}

async function boundedText(response, maxBytes) {
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
    void response.body?.cancel().catch(() => {});
    throw new Error("Access keys response is too large");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      void reader.cancel().catch(() => {});
      throw new Error("Access keys response is too large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

async function fetchSigningKeys(teamDomain, fetchImpl) {
  const response = await fetchImpl(`${teamDomain}/cdn-cgi/access/certs`, {
    headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(KEYS_TIMEOUT_MS),
  });
  if (response.status !== 200) {
    void response.body?.cancel().catch(() => {});
    throw new Error(`Access keys answered HTTP ${response.status}`);
  }
  const document = JSON.parse(await boundedText(response, MAX_KEYS_BYTES));
  if (!document || !Array.isArray(document.keys)) throw new Error("Access keys response has no key set");
  const keys = new Map();
  for (const jwk of document.keys.slice(0, MAX_KEYS)) {
    if (!jwk || typeof jwk !== "object" || jwk.kty !== "RSA" || typeof jwk.kid !== "string" || !jwk.kid
      || jwk.kid.length > 256 || (jwk.alg !== undefined && jwk.alg !== "RS256") || (jwk.use !== undefined && jwk.use !== "sig")
      || typeof jwk.n !== "string" || jwk.n.length < MIN_MODULUS_LENGTH || typeof jwk.e !== "string") continue;
    try {
      keys.set(jwk.kid, await crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]));
    } catch { /* A key WebCrypto rejects is skipped. */ }
  }
  if (!keys.size) throw new Error("Access published no usable RS256 key");
  return keys;
}

class SigningKeysUnavailable extends Error {}

/**
 * The verification key for a key id. Keys are refreshed hourly and when an unknown id
 * appears (Access rotated its key), at most once per refresh interval. If the endpoint
 * fails, cached keys stay usable for a day.
 */
async function signingKey(config, kid, { now, fetchImpl }) {
  let entry = keyCache.get(config.teamDomain);
  if (!entry) {
    entry = { keys: null, fetchedAt: 0, attemptedAt: -Infinity };
    keyCache.set(config.teamDomain, entry);
  }
  const cached = entry.keys?.get(kid);
  if (cached && now - entry.fetchedAt < KEYS_TTL_MS) return cached;
  if (now - entry.attemptedAt >= KEYS_REFRESH_INTERVAL_MS) {
    entry.attemptedAt = now;
    try {
      entry.keys = await fetchSigningKeys(config.teamDomain, fetchImpl);
      entry.fetchedAt = now;
    } catch (error) {
      logFailure("access_keys_unavailable", error);
    }
  }
  if (!entry.keys || now - entry.fetchedAt >= KEYS_STALE_MS) throw new SigningKeysUnavailable();
  return entry.keys.get(kid) ?? null;
}

/** Forget cached signing keys (tests and key-compromise drills). */
export function resetAccessKeyCache() {
  keyCache.clear();
}

const failure = reason => ({ ok: false, reason });

/**
 * Verify a Cf-Access-Jwt-Assertion token. Only RS256 is accepted; the signature is checked
 * before any claim is trusted. Returns { ok: true, email, exp } or { ok: false, reason }.
 */
export async function verifyAccessJwt(token, config, { now = Date.now(), fetchImpl = fetch } = {}) {
  if (typeof token !== "string" || !token) return failure("missing");
  if (token.length > MAX_TOKEN_LENGTH) return failure("malformed");
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every(part => SEGMENT.test(part))) return failure("malformed");
  const header = decodeJsonObject(parts[0]);
  const payload = decodeJsonObject(parts[1]);
  if (!header || !payload) return failure("malformed");
  if (header.alg !== "RS256") return failure("algorithm");
  if (typeof header.kid !== "string" || !header.kid || header.kid.length > 256 || header.crit !== undefined
    || (header.typ !== undefined && header.typ !== "JWT")) return failure("malformed");
  let key;
  try { key = await signingKey(config, header.kid, { now, fetchImpl }); } catch { return failure("keys_unavailable"); }
  if (!key) return failure("unknown_key");
  const signature = base64UrlBytes(parts[2]);
  let valid = false;
  try {
    valid = Boolean(signature) && await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature,
      encoder.encode(`${parts[0]}.${parts[1]}`));
  } catch { valid = false; }
  if (!valid) return failure("signature");

  const seconds = Math.floor(now / 1000);
  if (payload.iss !== config.teamDomain) return failure("issuer");
  const audience = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
  if (!Array.isArray(audience) || !audience.some(value => typeof value === "string" && config.audiences.includes(value))) {
    return failure("audience");
  }
  if (!Number.isFinite(payload.exp) || seconds > payload.exp + CLOCK_SKEW_SECONDS) return failure("expired");
  for (const claim of ["nbf", "iat"]) {
    if (payload[claim] !== undefined && (!Number.isFinite(payload[claim]) || seconds + CLOCK_SKEW_SECONDS < payload[claim])) {
      return failure("not_yet_valid");
    }
  }
  if (payload.type !== undefined && payload.type !== "app") return failure("token_type");
  // Service tokens carry no email; only people sign in to the dashboard.
  const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
  if (!email || email.length > 254 || !EMAIL.test(email)) return failure("no_email");
  return { ok: true, email, exp: Math.floor(payload.exp) };
}

/** HMAC-SHA256 proof over the exact identity header value, base64url encoded. */
export async function accessIdentityProof(secret, identity) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(ACCESS_PROOF_CONTEXT + identity))));
}

/** Remove every client-supplied Access identity header and the raw Access token. */
export function stripAccessHeaders(headers) {
  for (const name of [...headers.keys()]) {
    if (name.startsWith(ACCESS_HEADER_PREFIX) || name === ACCESS_JWT_HEADER) headers.delete(name);
  }
  return headers;
}

/**
 * Prepare Container-bound headers: always strip client copies, then, on the sign-in path
 * with single sign-on configured, assert the verification result. The assertion binds the
 * method, path and issue time, and the Container accepts it only with a valid proof.
 */
export async function withAccessIdentity(request, env, headers, { now = Date.now(), fetchImpl = fetch } = {}) {
  const token = request.headers.get(ACCESS_JWT_HEADER);
  stripAccessHeaders(headers);
  const { pathname } = new URL(request.url);
  if (pathname !== ACCESS_LOGIN_PATH) return headers;
  const config = accessSsoConfig(env);
  if (!config) return headers;
  let result;
  try {
    result = token ? await verifyAccessJwt(token, config, { now, fetchImpl }) : failure("missing");
  } catch (error) {
    logFailure("access_verification_failed", error);
    result = failure("unavailable");
  }
  const client = request.headers.get("cf-connecting-ip");
  const claims = {
    v: 1, status: result.ok ? "verified" : "failed", method: request.method, path: pathname, iat: Math.floor(now / 1000),
    ...(result.ok ? { email: result.email, exp: result.exp } : { reason: result.reason }),
    ...(client && CLIENT_ADDRESS.test(client) ? { client } : {}),
  };
  const identity = base64Url(encoder.encode(JSON.stringify(claims)));
  headers.set(ACCESS_IDENTITY_HEADER, identity);
  headers.set(ACCESS_PROOF_HEADER, await accessIdentityProof(config.secret, identity));
  return headers;
}
