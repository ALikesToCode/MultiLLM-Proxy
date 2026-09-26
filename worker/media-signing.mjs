/**
 * The media signing key, shared with services/media_signing.py: HMAC-SHA256 of
 * "multillm-media-v1" under MEDIA_SIGNING_SECRET, or FLASK_SECRET_KEY when that is unset.
 * It signs expiring file links (checked here without waking the Container) and derives
 * each owner's webhook secret.
 */
import { Buffer } from "node:buffer";

export const MAX_LINK_TTL_SECONDS = 30 * 86400;
export const FILE_ID = /^m[a-z]_[A-Za-z0-9_-]{8,120}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();
const derivedKeys = new Map();

const hmacKey = raw => crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
const sign = async (key, message) => new Uint8Array(await crypto.subtle.sign("HMAC", key,
  typeof message === "string" ? encoder.encode(message) : message));

export function mediaSecret(env) {
  const secret = String(env?.MEDIA_SIGNING_SECRET || env?.FLASK_SECRET_KEY || "").trim();
  return secret || null;
}

async function mediaKey(secret) {
  let key = derivedKeys.get(secret);
  if (!key) {
    key = sign(await hmacKey(encoder.encode(secret)), "multillm-media-v1").then(hmacKey);
    if (derivedKeys.size >= 4) derivedKeys.clear();
    derivedKeys.set(secret, key);
  }
  return key;
}

export async function mediaMac(secret, label, message) {
  return sign(await mediaKey(secret), `${label}:${message}`);
}

function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

/** Whether a file link's expiry and signature are valid now. */
export async function verifyFileLink(secret, fileId, expires, signature, now = Date.now() / 1000) {
  if (!secret || !FILE_ID.test(fileId) || typeof expires !== "string" || !/^\d{1,12}$/.test(expires)
    || typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
  const expiry = Number(expires);
  if (expiry < now || expiry > now + MAX_LINK_TTL_SECONDS + 60) return false;
  const expected = await mediaMac(secret, "file", `${fileId}:${expires}`);
  return sameBytes(encoder.encode(Buffer.from(expected).toString("base64url")), encoder.encode(signature));
}

/** Standard Webhooks signature with the owner's secret: `v1,` + base64 HMAC of `id.timestamp.body`. */
export async function webhookSignature(secret, owner, messageId, timestamp, body) {
  const ownerKey = await hmacKey(await mediaMac(secret, "webhook", owner));
  return `v1,${Buffer.from(await sign(ownerKey, `${messageId}.${timestamp}.${body}`)).toString("base64")}`;
}
