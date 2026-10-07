/** Provider dispatch policy. Audit failures never change the upstream request. */
import { redactPayload, scanText } from "./secret-scan.mjs";

export const SECRET_SCAN_HEADER = "X-MultiLLM-Secret-Scan";
const blockedResponses = new WeakSet();
export const isSecretScanBlock = response => blockedResponses.has(response);
const MODES = new Set(["off", "observe", "redact", "block"]);
const MAX_BUFFER_BYTES = 32 * 1024 * 1024;
const READ_TIMEOUT_MS = 1000;

export function secretScanMode(env = {}, principal = {}, knowledge = false) {
  let mode = MODES.has(principal?.secret_scan_mode) ? principal.secret_scan_mode : String(env.SECRET_SCAN_DEFAULT ?? "redact").trim().toLowerCase();
  if (!MODES.has(mode)) mode = "redact";
  return knowledge && mode !== "off" ? "block" : mode;
}

function safeLabel(value, fallback) {
  return typeof value === "string" && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value)
    && !scanText(value).length ? value : fallback;
}

async function record(env, report, { principal, route, provider, mode, action }) {
  if (!env.INTELLIGENCE_DB) return;
  try {
    const detail = JSON.stringify({ kind: "secret_scan", mode, action, provider: safeLabel(provider, null), types: report.types });
    let timer;
    const write = env.INTELLIGENCE_DB.prepare("INSERT INTO control_audit_events (at, actor, action, outcome, target, detail) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(new Date().toISOString(), safeLabel(principal?.id ?? principal?.username, null), "setting_change",
        action === "blocked" ? "refused" : "succeeded", safeLabel(route, "redacted_route"), detail).run();
    try { await Promise.race([write, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("audit_timeout")), 1000);
    })]); } finally { clearTimeout(timer); }
  } catch { console.warn("secret_scan_audit_unavailable"); }
}

export async function protectPayload(value, env = {}, { principal = {}, route = "background", provider = null, knowledge = false } = {}) {
  const mode = secretScanMode(env, principal, knowledge);
  let updated, report;
  try { [updated, report] = redactPayload(value, { mode }); }
  catch { console.warn("secret_scan_unavailable"); return { value, report: null, mode }; }
  if (!report.high && !report.heuristic) return { value: updated, report, mode };
  const action = mode === "block" && report.high ? "blocked" : mode === "redact" && report.high ? "redacted" : "observed";
  await record(env, report, { principal, route, provider, mode, action });
  const header = `redacted=${action === "redacted" ? report.high : 0}; observed=${report.heuristic + (action === "observed" ? report.high : 0)}`;
  const blocked = action === "blocked" ? Response.json({ error: { code: "secret_detected",
    message: "High-confidence secrets detected in outbound content", types: report.types,
    high: report.high, heuristic: report.heuristic } }, { status: 422 }) : null;
  if (blocked) blockedResponses.add(blocked);
  return { value: updated, report, mode, action, header, blocked };
}

async function boundedBody(request) {
  const reader = request.clone().body.getReader();
  const chunks = [];
  let length = 0, timer;
  try {
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("scan_timeout")), READ_TIMEOUT_MS); });
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BUFFER_BYTES) throw new Error("scan_body_limit");
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => {});
  }
}

const utf8 = new TextEncoder();
const latinBytes = text => Uint8Array.from(text, char => char.charCodeAt(0));
function latinText(bytes) {
  const parts = [];
  for (let offset = 0; offset < bytes.length; offset += 8192) parts.push(String.fromCharCode(...bytes.subarray(offset, offset + 8192)));
  return parts.join("");
}

function multipart(bytes, contentType) {
  const boundary = /boundary=(?:"([^"\r\n]{1,200})"|([^;\s]{1,200}))/i.exec(contentType);
  if (!boundary) throw new Error("invalid_boundary");
  const marker = `--${boundary[1] ?? boundary[2]}`;
  const text = latinText(bytes), parts = [];
  let position = 0;
  for (let count = 0; count < 257; count += 1) {
    const next = text.indexOf(marker, position);
    if (next < 0) break;
    parts.push(text.slice(position, next)); position = next + marker.length;
  }
  parts.push(text.slice(position));
  const fields = {};
  for (let index = 0; index < Math.min(parts.length, 256); index += 1) {
    const part = parts[index], split = part.indexOf("\r\n\r\n"), head = part.slice(0, split);
    const name = /name="([^"\r\n]{1,128})"/.exec(head);
    if (split < 0 || head.length > 8192 || /filename=/i.test(head) || !name) continue;
    fields[index] = { [name[1]]: new TextDecoder().decode(latinBytes(part.slice(split + 4).replace(/\r\n$/, ""))) };
  }
  return [fields, updated => {
    for (const [index, values] of Object.entries(updated)) if (JSON.stringify(values) !== JSON.stringify(fields[index])) {
      const head = parts[index].split("\r\n\r\n", 1)[0];
      parts[index] = head + "\r\n\r\n" + latinText(utf8.encode(Object.values(values)[0])) + "\r\n";
    }
    return latinBytes(parts.join(marker));
  }];
}

export async function firewallFetch(request, env, options = {}, fetchImpl = fetch) {
  if (!request.body || secretScanMode(env, options.principal) === "off") return fetchImpl(request);
  let protectedRequest = request, decision;
  try {
    const bytes = await boundedBody(request);
    const type = request.headers.get("content-type") ?? "";
    let value, rebuild;
    if (/^multipart\/form-data/i.test(type)) [value, rebuild] = multipart(bytes, type);
    else if (/^application\/x-www-form-urlencoded/i.test(type)) {
      const pairs = [];
      for (const [key, text] of new URLSearchParams(new TextDecoder().decode(bytes))) {
        if (pairs.length >= 256) throw new Error("scan_form_limit");
        pairs.push({ [key]: text });
      }
      value = pairs;
      rebuild = updated => new URLSearchParams(updated.flatMap(part => Object.entries(part))).toString();
    } else {
      try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); rebuild = updated => JSON.stringify(updated); }
      catch {
        value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        rebuild = updated => updated;
      }
    }
    decision = await protectPayload(value, env, options);
    options.onDecision?.(decision);
    if (decision.blocked) return decision.blocked;
    if (decision.value !== value) {
      const headers = new Headers(request.headers);
      headers.delete("content-length");
      protectedRequest = new Request(request, { headers, body: rebuild(decision.value), duplex: "half" });
    }
  } catch { console.warn("secret_scan_body_unavailable"); }
  const upstream = await fetchImpl(protectedRequest);
  if (!decision?.header || !upstream.ok) return upstream;
  const response = new Response(upstream.body, upstream);
  response.headers.set(SECRET_SCAN_HEADER, decision.header);
  return response;
}
