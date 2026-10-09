/** Request-local deterministic PII findings; no reversible state is persisted. */
import { scanPayload, scanText } from "./secret-scan.mjs";

export const PREFIX = "__MLPII_";
export const TOKEN = /__MLPII_[0-9a-f]{64}__/g;
const MAX_INPUT_BYTES = 1024 * 1024, MAX_VALUES = 512;
const encoder = new TextEncoder();
const warned = new Set();
const EMAIL = /(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}(?![A-Za-z0-9.-])/g;
const NUMBER = /(?<![A-Za-z0-9+])\+?[0-9](?:[0-9 ()-]{0,30}[0-9])?(?![0-9]|[ ()-]{1,4}[0-9])/g;

export class PIIRedactionError extends Error {
  constructor(message = "Required PII transformation failed before provider dispatch") {
    super(message); this.name = "PIIRedactionError";
  }
}

function warnOnce(name) {
  if (!warned.has(name)) { warned.add(name); console.warn(`Invalid PII configuration for ${name}; redaction disabled`); }
}

export function resolvePIIPolicy(env = {}, { route = "", keyScope = "" } = {}) {
  const flag = String(env.PII_REDACTION_ENABLED ?? "").trim().toLowerCase();
  if (["", "false", "0", "no", "off"].includes(flag)) return null;
  if (!["true", "1", "yes", "on"].includes(flag)) { warnOnce("PII_REDACTION_ENABLED"); return null; }
  try {
    const raw = String(env.PII_REDACTION_POLICY_JSON ?? "").trim() || "{}";
    if (encoder.encode(raw).length > 65536) throw new Error();
    const policy = JSON.parse(raw);
    if (!policy || typeof policy !== "object" || Array.isArray(policy) ||
      Object.keys(policy).some(key => !["routes", "keys", "detectors", "mode"].includes(key))) throw new Error();
    for (const name of ["routes", "keys", "detectors"]) {
      const items = policy[name] ?? [];
      if (!Array.isArray(items) || items.length > 512 || items.some(item => typeof item !== "string" || !item.length || item.length > 256)) throw new Error();
    }
    if ((policy.detectors ?? []).some(name => !["email", "phone", "card"].includes(name))) throw new Error();
    const mode = policy.mode ?? "required";
    if (!["required", "best_effort"].includes(mode)) throw new Error();
    if (!(policy.routes ?? []).includes(route) && (!keyScope || !(policy.keys ?? []).includes(keyScope))) return null;
    return policy.detectors?.length ? { detectors: policy.detectors, mode } : null;
  } catch { warnOnce("PII_REDACTION_POLICY_JSON"); return null; }
}

function luhn(digits) {
  let total = 0;
  [...digits].reverse().forEach((char, index) => {
    const value = Number(char) * (index % 2 ? 2 : 1);
    total += value > 9 ? value - 9 : value;
  });
  return total % 10 === 0 && new Set(digits).size > 1;
}

function findings(text, detectors) {
  const protectedSpans = scanText(text), found = [];
  if (detectors.includes("email")) for (const match of text.matchAll(EMAIL)) found.push([match.index, match.index + match[0].length]);
  if (detectors.includes("phone") || detectors.includes("card")) {
    for (const match of text.matchAll(NUMBER)) {
      const value = match[0], digits = value.replace(/[^0-9]/g, "");
      const card = digits.length >= 13 && digits.length <= 19 && luhn(digits);
      const phone = digits.length >= 10 && digits.length <= 15 && (value.startsWith("+") || /[ ()-]/.test(value));
      if (detectors.includes("card") && card || detectors.includes("phone") && phone)
        found.push([match.index, match.index + value.length]);
    }
  }
  found.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  let end = -1;
  return found.filter(([start, stop]) => {
    if (start < end || protectedSpans.some(span => start < span.end && stop > span.start)) return false;
    end = stop; return true;
  });
}

export class PIIContext {
  constructor() {
    this.secret = crypto.getRandomValues(new Uint8Array(32));
    this.values = new Map(); this.closed = false;
  }
  async issue(value) {
    if (this.closed) throw new PIIRedactionError("PII request context is closed");
    const key = await crypto.subtle.importKey("raw", this.secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
    if (this.closed) throw new PIIRedactionError("PII request context is closed");
    const token = PREFIX + [...signature].map(byte => byte.toString(16).padStart(2, "0")).join("") + "__";
    if (this.values.has(token) && this.values.get(token) !== value) throw new PIIRedactionError("PII placeholder collision");
    if (!this.values.has(token) && this.values.size >= MAX_VALUES) throw new PIIRedactionError("PII request exceeds the value limit");
    this.values.set(token, value); return token;
  }
  restore(text) { return text.replace(TOKEN, token => this.values.get(token) ?? token); }
  close() { this.values.clear(); this.secret.fill(0); this.closed = true; }
}

async function redactTree(value, context, detectors, depth = 0, counter = { nodes: 0 }, field = "") {
  counter.nodes += 1;
  if (depth > 32 || counter.nodes > 32768) throw new PIIRedactionError("PII document exceeds the structure limit");
  if (typeof value === "string") {
    if (scanPayload({ [field]: value }).types.secret_field) return value;
    const parts = []; let end = 0;
    for (const [start, stop] of findings(value, detectors)) {
      parts.push(value.slice(end, start), await context.issue(value.slice(start, stop))); end = stop;
    }
    return parts.join("") + value.slice(end);
  }
  if (Array.isArray(value)) {
    const result = [];
    for (const item of value) result.push(await redactTree(item, context, detectors, depth + 1, counter, field));
    return result;
  }
  if (value && typeof value === "object") {
    const result = [];
    for (const [key, item] of Object.entries(value)) result.push([key, await redactTree(item, context, detectors, depth + 1, counter, key)]);
    return Object.fromEntries(result);
  }
  return value;
}

export async function preparePayload(payload, env = {}, { route = "", keyScope = "", raw = false, firewall } = {}) {
  const policy = raw ? null : resolvePIIPolicy(env, { route, keyScope });
  if (!policy) return { payload, context: null, skipped: false };
  const checked = firewall ? await firewall(payload) : payload;
  let context;
  try {
    if (encoder.encode(JSON.stringify(checked)).length > MAX_INPUT_BYTES) throw new PIIRedactionError("PII request exceeds the input limit");
    context = new PIIContext();
    const updated = await redactTree(checked, context, policy.detectors);
    if (!context.values.size) { context.close(); return { payload: checked, context: null, skipped: false }; }
    return { payload: updated, context, skipped: false };
  } catch {
    context?.close();
    if (policy.mode === "best_effort") return { payload: checked, context: null, skipped: true };
    throw new PIIRedactionError();
  }
}

/** Inspect before paging or persistence; the reversible map remains transport-local. */
export async function roleplayPIIRetention(payload, env, keyScope, retention, onDecision = () => {}) {
  const prepared = await preparePayload(payload, env, { route: "/v1/roleplay/chat/completions", keyScope });
  const redacted = Boolean(prepared.context);
  prepared.context?.close();
  onDecision({ redacted, skipped: prepared.skipped, cacheable: !redacted, replayable: !redacted });
  return redacted ? Object.freeze({ enabled: true, mode: "zero" }) : retention;
}
