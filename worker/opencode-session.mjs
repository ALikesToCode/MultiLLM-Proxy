import { withOpencodeSession } from "./client-headers.mjs";

export const MAX_SESSION_BODY_BYTES = 1024 * 1024;

function conversationAnchor(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  for (const value of [
    payload.session_id, payload.conversation_id,
    payload.metadata?.session_id, payload.metadata?.conversation_id,
    typeof payload.conversation === "object" ? payload.conversation?.id : payload.conversation,
  ]) {
    if (typeof value === "string" && value.trim()) return ["conversation", value];
  }
  let messages = payload.messages ?? payload.input;
  if (typeof messages === "string") messages = [{ role: "user", content: messages }];
  if (!Array.isArray(messages)) return null;
  const opening = [];
  for (const message of messages) {
    const { role, content } = message ?? {};
    if (!["system", "developer", "assistant", "user"].includes(role)) continue;
    if (!(typeof content === "string" || Array.isArray(content)) || !content.length) continue;
    opening.push([role, content]);
    if (role === "user") return ["opening", payload.system ?? null, payload.instructions ?? null, opening];
  }
  return null;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

async function boundedPayload(request) {
  const declaredLength = request.headers.get("Content-Length");
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
  // Unknown-length uploads must start streaming immediately, without a body probe.
  if (!request.body || !declaredLength || !/^\d+$/.test(declaredLength)
      || Number(declaredLength) > MAX_SESSION_BODY_BYTES || contentType !== "application/json") return null;
  const reader = request.clone().body.getReader();
  // Cloned streams can stall. Affinity discovery must not delay raw transport indefinitely.
  const timer = setTimeout(() => { void reader.cancel().catch(() => {}); }, 1000);
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_SESSION_BODY_BYTES) return null;
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => {});
  }
}

export async function withOpencodeRequestSession(request, source) {
  const headers = withOpencodeSession(source);
  if (headers.has("x-opencode-session")) return headers;
  const scope = headers.get("Authorization") || headers.get("X-Api-Key");
  let anchor = null;
  try {
    if (scope) anchor = canonical(conversationAnchor(await boundedPayload(request)));
  } catch {
    // Invalid or excessively nested input remains the provider's validation responsibility.
  }
  let session = `multillm_request_${crypto.randomUUID()}`;
  if (anchor !== null) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", encoder.encode(scope), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(JSON.stringify(anchor))));
    session = `multillm_v1_${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }
  headers.set("x-opencode-session", session);
  return headers;
}
