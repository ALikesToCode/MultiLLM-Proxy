/** Content-free, best-effort collector delivery. No generation transport is retried. */
export const MAX_QUEUE = 1000;
export const BATCH_SIZE = 50;
export const TIMEOUT_MS = 2000;
export const RETRIES = 2;
let warned = false;
const exporters = new WeakMap();
const kinds = new Set(["chat", "responses", "embeddings", "images", "audio", "proxy", "shadow", "canary", "roleplay"]);
const outcomes = new Set(["success", "unknown", "upstream_error", "transport_error", "canceled"]);
const bases = new Set(["usage", "estimate", "cache"]);
const provenanceValues = new Set(["provider", "request_estimate", "cache", "measured", "estimated", "unknown"]);
const text = value => typeof value === "string" && value.length > 0 && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value) ? value : null;
const number = value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER ? value : null;
const tokens = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const hex = bytes => [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, "0")).join("");
const digest = async value => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));

function origin(value, originOnly = false) {
  if (typeof value !== "string" || value.length > 2048 || /[\s\x00-\x1f\x7f\\]/.test(value) || value.includes("?") || value.includes("#")) throw new Error("Invalid destination");
  const url = new URL(value);
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || originOnly && url.pathname !== "/") throw new Error("Invalid destination");
  return url.origin;
}

export function destinations(raw) {
  if (raw === undefined || raw === null || raw === "" || typeof raw === "string" && !raw.trim()) return [];
  try {
    if (typeof raw !== "string" || raw.length > 32768) throw new Error("Invalid configuration");
    const values = JSON.parse(raw), result = [];
    if (!Array.isArray(values) || values.length > 8) throw new Error("Invalid exporters");
    for (const value of values) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || Object.keys(value).sort().join(",") !== "allowed_origins,credential_env,endpoint,type"
        || !["langfuse", "helicone"].includes(value.type) || typeof value.credential_env !== "string"
        || !/^[A-Z][A-Z0-9_]{0,99}_EXPORT_CREDENTIAL$/.test(value.credential_env)
        || !Array.isArray(value.allowed_origins) || value.allowed_origins.length < 1 || value.allowed_origins.length > 16) throw new Error("Invalid exporter");
      const allowed = value.allowed_origins.map(item => origin(item, true));
      if (!allowed.includes(origin(value.endpoint))) throw new Error("Destination not allowed");
      const target = Object.freeze({ type: value.type, endpoint: value.endpoint, credential_env: value.credential_env });
      if (result.some(item => JSON.stringify(item) === JSON.stringify(target))) throw new Error("Duplicate exporter");
      result.push(target);
    }
    return result;
  } catch {
    if (!warned) { warned = true; console.warn("Invalid OBSERVABILITY_EXPORTERS_JSON; exports disabled"); }
    return [];
  }
}

function timestamp(value) {
  if (typeof value !== "string" || value.length > 40 || !value.endsWith("Z")) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

function observation(record, owner) {
  const requestId = text(record.request_id), principal = text(record.principal);
  if (!requestId || !principal || !["worker", "flask"].includes(owner)) return null;
  const status = tokens(record.status), validStatus = status >= 100 && status <= 599 ? status : null;
  const basis = bases.has(record.cost_basis) ? record.cost_basis : null;
  const usageBasis = provenanceValues.has(record.usage_basis) ? record.usage_basis
    : basis === "estimate" ? "estimated" : basis === "usage" ? "provider" : "unknown";
  const outcome = outcomes.has(record.outcome) ? record.outcome : validStatus >= 400 ? "upstream_error" : "unknown";
  const end = timestamp(record.at), latency = number(record.latency_ms);
  const start = end !== null && latency !== null && latency <= 86_400_000 ? new Date(Date.parse(end) - latency) : null;
  return { request_id: requestId, correlation_id: text(record.trace_id), principal, origin: owner,
    model: text(record.selected_model), kind: kinds.has(record.kind) ? record.kind : "proxy", status: validStatus,
    error: ["upstream_error", "transport_error", "canceled"].includes(outcome) ? outcome : null, outcome,
    start_time: start && Number.isFinite(start.getTime()) ? start.toISOString() : null, end_time: end,
    latency_ms: latency, ttft_ms: number(record.ttft_ms),
    usage: { input_tokens: tokens(record.input_tokens), output_tokens: tokens(record.output_tokens), basis: usageBasis },
    cost: { usd: number(record.cost_usd), basis },
    provenance: Array.isArray(record.provenance) ? record.provenance.slice(0, 16).filter(item => provenanceValues.has(item)) : [usageBasis] };
}

async function payloads(target, records) {
  const batch = await Promise.all(records.map(async record => {
    const item = { ...record, principal: `principal:${await digest(record.principal)}` };
    const id = await digest(JSON.stringify([item.origin, item.request_id, item.kind]));
    return { item, id };
  }));
  if (target.type === "langfuse") return [{ batch: batch.map(({ item, id }) => ({ id, type: "generation-create", timestamp: item.end_time,
    body: { id, traceId: item.correlation_id ?? item.request_id, name: `multillm.${item.kind}`, model: item.model,
      startTime: item.start_time, endTime: item.end_time, usage: { input: item.usage.input_tokens, output: item.usage.output_tokens, unit: "TOKENS" }, metadata: item },
  })) }];
  const timing = value => value === null ? null : { seconds: Math.floor(Date.parse(value) / 1000), milliseconds: Date.parse(value) % 1000 };
  return batch.map(({ item, id }) => ({ providerRequest: { url: "https://multillm.invalid", json: { model: item.model },
    meta: { "Helicone-Request-Id": id, "Helicone-User-Id": item.principal, "Helicone-Property-observation": JSON.stringify(item) } },
    providerResponse: { status: item.status, headers: {}, json: { usage: { prompt_tokens: item.usage.input_tokens, completion_tokens: item.usage.output_tokens } } },
    timing: { startTime: timing(item.start_time), endTime: timing(item.end_time) } }));
}

async function receipt(response, payload, signal) {
  const count = payload.batch?.length ?? 1;
  if (signal.aborted) { void response.body?.cancel().catch(() => {}); return 0; }
  if (response.status !== 207) {
    void response.body?.cancel().catch(() => {});
    return response.status >= 200 && response.status < 300 ? count : 0;
  }
  if (!payload.batch || !response.body) return 0;
  const reader = response.body.getReader(), chunks = [];
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", abort, { once: true });
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 32768) { void reader.cancel().catch(() => {}); return 0; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const result = JSON.parse(new TextDecoder().decode(bytes));
    if (!Array.isArray(result.successes) || !Array.isArray(result.errors)) return 0;
    const successes = new Set(result.successes.map(item => item?.id)), errors = new Set(result.errors.map(item => item?.id));
    return payload.batch.filter(item => successes.has(item.id) && !errors.has(item.id)).length;
  } catch { return 0; }
  finally { signal.removeEventListener("abort", abort); reader.releaseLock(); }
}

async function send(transport, target, body, headers) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(async () => {
        const response = await transport(target.endpoint, { method: "POST", headers, body: JSON.stringify(body), redirect: "error", signal: controller.signal });
        return { code: response.status, acknowledged: await receipt(response, body, controller.signal) };
      }),
      new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error("Collector timeout")); }, TIMEOUT_MS); }),
    ]);
  } finally { clearTimeout(timer); }
}

const emptyStats = () => ({ acknowledged: 0, failed: 0, attempts: 0, delivery_status: "idle" });

export class ObservabilityExporter {
  constructor(env, options = {}) {
    this.env = env;
    this.transport = options.transport ?? ((...args) => fetch(...args));
    this.targets = destinations(env.OBSERVABILITY_EXPORTERS_JSON);
    this.queue = [];
    this.seen = new Set();
    this.accepted = 0;
    this.dropped = 0;
    this.stats = new Map(this.targets.map(target => [target, emptyStats()]));
    this.delivery = null;
  }

  submit(record, { owner = "worker" } = {}) {
    if (!this.targets.length) return false;
    const item = observation(record, owner);
    if (!item) { this.dropped++; return false; }
    const identity = JSON.stringify([owner, item.request_id, item.kind]);
    if (this.seen.has(identity)) return false;
    if (this.queue.length >= MAX_QUEUE) { this.dropped++; return false; }
    this.seen.add(identity);
    if (this.seen.size > MAX_QUEUE) this.seen.delete(this.seen.values().next().value);
    this.queue.push(item); this.accepted++;
    return true;
  }

  async deliver(target, batch) {
    const stats = this.stats.get(target), credential = this.env[target.credential_env];
    if (typeof credential !== "string" || !credential || credential.length > 8192 || /[\x00-\x1f\x7f]/.test(credential)) {
      stats.failed += batch.length; stats.delivery_status = "credential_unavailable"; return;
    }
    const encoded = target.type === "langfuse" ? btoa(String.fromCharCode(...new TextEncoder().encode(credential))) : null;
    const headers = { "Content-Type": "application/json", Authorization: target.type === "langfuse" ? `Basic ${encoded}` : `Bearer ${credential}` };
    for (const payload of await payloads(target, batch)) {
      const count = target.type === "langfuse" ? batch.length : 1;
      let acknowledged = 0;
      for (let attempt = 0; attempt <= RETRIES; attempt++) {
        stats.attempts++;
        try {
          const response = await send(this.transport, target, payload, headers), code = response.code;
          acknowledged = response.acknowledged;
          if (acknowledged || code !== 429 && code < 500) break;
        } catch { /* Collector failures never affect serving or another destination. */ }
      }
      stats.acknowledged += acknowledged; stats.failed += count - acknowledged;
      stats.delivery_status = acknowledged === count ? "acknowledged" : acknowledged ? "partial" : "failed";
    }
  }

  exportOnce() {
    if (this.delivery) return this.delivery.then(() => this.exportOnce());
    const batch = this.queue.splice(0, BATCH_SIZE);
    if (!batch.length) return Promise.resolve(0);
    this.delivery = (async () => {
      for (const target of this.targets) {
        try { await this.deliver(target, batch); }
        catch { const stats = this.stats.get(target); stats.failed += batch.length; stats.delivery_status = "failed"; }
      }
      return batch.length;
    })().finally(() => { this.delivery = null; });
    return this.delivery;
  }

  async flush() {
    // Work remains bounded even if traffic continues to refill the queue.
    let drained = 0;
    while (drained < MAX_QUEUE) {
      const count = await this.exportOnce();
      if (!count) break;
      drained += count;
    }
    return drained;
  }

  status() {
    return { accepted: this.accepted, dropped: this.dropped, queued: this.queue.length,
      exporters: this.targets.map(target => ({ type: target.type, credential_env: target.credential_env, ...this.stats.get(target) })) };
  }
}

export function getObservabilityExporter(env) {
  if (!exporters.has(env)) exporters.set(env, new ObservabilityExporter(env));
  return exporters.get(env);
}

export function observabilityEnabled(env) { return getObservabilityExporter(env).targets.length > 0; }

/** Explicit transport injection for tests and static runtime collaborators. */
export function setObservabilityExporter(env, exporter) { exporters.set(env, exporter); }

export function submitNativeObservation(env, record, ctx) {
  try {
    const exporter = getObservabilityExporter(env);
    const accepted = exporter.submit(record);
    if ((accepted || exporter.queue.length) && ctx?.waitUntil) ctx.waitUntil(Promise.resolve().then(() => exporter.flush()));
    return accepted;
  } catch { console.warn("Observability submission failed"); return false; }
}

/** Native finalizer interface; forwarded Container records must never call it. */
export function submitNativeEvent(env, event, ctx) {
  const model = event.model ? `${event.provider}:${event.model}` : null;
  const endpoint = typeof event.endpoint === "string" ? event.endpoint : "";
  const kind = endpoint.endsWith("/responses") ? "responses" : endpoint.endsWith("/embeddings") ? "embeddings"
    : endpoint.endsWith("/images/generations") ? "images" : "chat";
  return submitNativeObservation(env, { at: new Date().toISOString(), principal: event.principal,
    kind: event.kind ?? kind, selected_model: model, status: event.status, latency_ms: event.duration_ms,
    input_tokens: event.input_tokens, output_tokens: event.output_tokens, cost_usd: event.cost_usd,
    cost_basis: event.cost_basis, request_id: event.requestId, trace_id: event.trace_id,
    ttft_ms: event.ttft_ms, outcome: event.outcome, usage_basis: event.usage_basis, provenance: event.provenance }, ctx);
}

export function createNativeObservabilityHook(env, ctx) {
  return { enabled: observabilityEnabled, finalize: event => submitNativeEvent(env, event, ctx) };
}
