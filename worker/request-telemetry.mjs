/** Bounded, byte-preserving native response observation. No payload leaves this module. */
import { escapeLabel, PROMETHEUS_CONTENT_TYPE } from "./prometheus.mjs";

export const PARSER_LIMIT = 64 * 1024;
const decoder = new TextDecoder();
const providers = new Set(["codex-easy", "linkapi", "opencode", "kimi-code"]);
const outcomes = new Set(["success", "unknown", "upstream_error", "transport_error", "canceled"]);
const totals = new Map();
const component = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const millis = value => Math.min(86_400_000, Math.max(0, Math.round(value)));

export function createUsageObserver(sse = false, onToken = () => {}) {
  let carry = new Uint8Array(), data = [], dataBytes = 0, oversized = false, eventOversized = false;
  let usage = { input_tokens: null, output_tokens: null }, completed = false, failed = false;
  const consume = text => {
    if (text.trim() === "[DONE]") { completed = true; return; }
    let value;
    try { value = JSON.parse(text); } catch { return; }
    if (!value || typeof value !== "object") return;
    const observed = value.usage ?? value.response?.usage ?? value.message?.usage;
    if (observed && typeof observed === "object") {
      const input = component(observed.prompt_tokens ?? observed.input_tokens);
      const output = component(observed.completion_tokens ?? observed.output_tokens);
      if (input !== null) usage.input_tokens = input;
      if (output !== null) usage.output_tokens = output;
    }
    const choices = Array.isArray(value.choices) ? value.choices : [];
    if (value.error || value.type === "error" || value.type === "response.failed") failed = true;
    if (value.type === "message_stop" || value.type === "response.completed"
      || choices.some(choice => choice?.finish_reason != null)) completed = true;
    if (choices.some(choice => choice?.delta?.content || choice?.delta?.reasoning_content || choice?.delta?.tool_calls?.length)
      || value.delta?.text || value.delta?.thinking || value.type === "response.output_text.delta"
      || value.type === "response.function_call_arguments.delta") onToken();
  };
  const line = () => {
    const text = oversized ? "" : decoder.decode(carry).replace(/\r$/, "");
    carry = new Uint8Array();
    if (oversized) eventOversized = true;
    oversized = false;
    if (text === "") {
      if (!eventOversized && data.length) consume(data.join("\n"));
      data = []; dataBytes = 0; eventOversized = false;
    } else if (text.startsWith("data:")) {
      const part = text.slice(5).replace(/^ /, "");
      const size = new TextEncoder().encode(part).length + 1;
      if (dataBytes + size > PARSER_LIMIT) { data = []; dataBytes = 0; eventOversized = true; }
      else if (!eventOversized) { data.push(part); dataBytes += size; }
    }
  };
  const append = bytes => {
    if (oversized) return;
    if (carry.length + dataBytes + bytes.length > PARSER_LIMIT) {
      carry = new Uint8Array(); oversized = true; return;
    }
    const next = new Uint8Array(carry.length + bytes.length);
    next.set(carry); next.set(bytes, carry.length); carry = next;
  };
  return {
    get carryBytes() { return carry.length + dataBytes; },
    feed(bytes) {
      if (!sse) { append(bytes); return; }
      let start = 0, end;
      while ((end = bytes.indexOf(10, start)) !== -1) {
        append(bytes.subarray(start, end)); line(); start = end + 1;
      }
      append(bytes.subarray(start));
    },
    finish() {
      if (sse) { if (carry.length || oversized) line(); if (!eventOversized && data.length) consume(data.join("\n")); }
      else if (!oversized) { consume(decoder.decode(carry)); completed = true; }
      carry = new Uint8Array(); data = []; dataBytes = 0;
      return { usage: { ...usage }, completed, failed };
    },
  };
}

function priceUsage(env, provider, model, usage, known) {
  if (!known || !model) return null;
  let table;
  const raw = env.MODEL_PRICING_USD_PER_MILLION;
  if (typeof raw !== "string" || raw.length > PARSER_LIMIT) return null;
  try { table = JSON.parse(raw); } catch { return null; }
  const name = (model.includes(":") ? model : `${provider}:${model}`).toLowerCase();
  const price = table?.[name] ?? table?.[`${provider}:*`] ?? table?.["*"];
  if (!price || typeof price !== "object") return null;
  const flatOnly = Object.hasOwn(price, "request") && !["input", "output", "input_cost_per_million", "output_cost_per_million"].some(k => Object.hasOwn(price, k));
  const rate = value => typeof value === "number" || typeof value === "string" && value.trim()
    ? Number(value) : NaN;
  const input = flatOnly ? 0 : rate(price.input ?? price.input_cost_per_million);
  const output = flatOnly ? 0 : rate(price.output ?? price.output_cost_per_million);
  const request = Object.hasOwn(price, "request") ? rate(price.request) : 0;
  if (![input, output, request].every(n => Number.isFinite(n) && n >= 0)) return null;
  const cost = (usage.input_tokens * input + usage.output_tokens * output) / 1_000_000 + request;
  return Number.isFinite(cost) && cost <= 1_000_000 ? cost : null;
}

function countEvent(event) {
  if (!providers.has(event.provider) || !outcomes.has(event.outcome)) return;
  const key = `${event.provider}:${event.outcome}`;
  const item = totals.get(key) ?? { provider: event.provider, outcome: event.outcome, requests: 0,
    duration: 0, ttft: 0, firstTokens: 0, measured: 0, priced: 0 };
  item.requests++; item.duration += event.duration_ms / 1000;
  if (event.ttft_ms !== null) { item.ttft += event.ttft_ms / 1000; item.firstTokens++; }
  if (event.usage_basis === "measured") item.measured++;
  if (event.cost_usd !== null) item.priced++;
  totals.set(key, item);
}

export function renderNativeMetrics() {
  const families = [
    ["requests_total", "Finalized native attempts in this isolate.", "requests"],
    ["duration_seconds_total", "Total native attempt duration in this isolate.", "duration"],
    ["ttft_seconds_total", "Total observed first-token time in this isolate.", "ttft"],
    ["first_token_observations_total", "Attempts with a first-token observation.", "firstTokens"],
    ["measured_usage_total", "Attempts with complete measured token counts.", "measured"],
    ["priced_requests_total", "Attempts with known configured cost.", "priced"],
  ];
  return families.map(([suffix, help, field]) => {
    const name = `multillm_native_${suffix}`;
    return `# HELP ${name} ${help}\n# TYPE ${name} counter\n` + [...totals.values()]
      .map(item => `${name}{provider="${escapeLabel(item.provider)}",outcome="${item.outcome}"} ${item[field]}\n`).join("");
  }).join("");
}

export async function appendNativeMetrics(response) {
  if (response.status !== 200 || !response.headers.get("content-type")?.includes("text/plain")) return response;
  const suffix = new TextEncoder().encode(`\n${renderNativeMetrics()}`);
  const reader = response.body?.getReader(); let appended = false;
  const body = new ReadableStream({
    async pull(controller) {
      if (reader) {
        const result = await reader.read();
        if (!result.done) { controller.enqueue(result.value); return; }
      }
      if (!appended) { appended = true; controller.enqueue(suffix); }
      controller.close();
    }, cancel(reason) { return reader?.cancel(reason); },
  }, { highWaterMark: 0 });
  const headers = new Headers(response.headers); headers.delete("content-length");
  headers.set("content-type", PROMETHEUS_CONTENT_TYPE);
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}

function finalEvent(response, context, options, parsed, reason, duration, ttft) {
  const usage = { ...parsed.usage };
  const hasProviderUsage = usage.input_tokens !== null || usage.output_tokens !== null;
  let estimated = false;
  for (const key of ["input_tokens", "output_tokens"]) {
    const estimate = component(options.usageEstimate?.[key]);
    if (usage[key] === null && estimate !== null) { usage[key] = estimate; estimated = true; }
  }
  const known = usage.input_tokens !== null && usage.output_tokens !== null;
  const outcome = reason ?? options.outcome ?? (response.status >= 400 || parsed.failed ? "upstream_error"
    : parsed.completed && known && hasProviderUsage ? "success" : "unknown");
  const basis = outcome === "success" && known ? estimated ? "estimated" : "measured" : "unknown";
  const cost = priceUsage(options.env ?? {}, context.provider, context.model, usage, known && outcome === "success");
  const status = outcome === "canceled" ? 499 : outcome === "transport_error" ? 502
    : outcome === "unknown" && response.status < 400 ? 520
    : outcome === "upstream_error" && response.status < 400 ? 502 : response.status;
  const cohort = options.canary ?? context.canary;
  const canary = cohort && ["baseline", "candidate"].includes(cohort.cohort) && ["shadow", "live"].includes(cohort.mode)
    ? { cohort: cohort.cohort, mode: cohort.mode } : null;
  const { canary: _unverifiedCohort, ...metadata } = context;
  return { ...metadata, ...(canary ? { canary } : {}), status, outcome, duration_ms: duration, ttft_ms: ttft, ...usage,
    usage_basis: basis, cost_usd: cost, cost_basis: cost === null ? null : estimated ? "estimate" : "usage" };
}

export async function observeNativeResponse(response, context, options = {}) {
  const clock = options.clock ?? (() => performance.now());
  let ttft = null, finalization;
  const started = context.startedAt ?? clock();
  const sse = response.headers.get("content-type")?.includes("text/event-stream") ?? false;
  const observer = createUsageObserver(sse, () => { ttft ??= millis(clock() - started); });
  const finish = reason => finalization ??= Promise.resolve().then(async () => {
    options.signal?.removeEventListener("abort", abort);
    const parsed = observer.finish();
    const observed = finalEvent(response, context, options, parsed, reason, millis(clock() - started), ttft);
    const event = options.classifyEvent ? options.classifyEvent(observed) : observed;
    if (options.metrics !== false) countEvent(event);
    try { await options.finalize?.(event); } catch { console.error(JSON.stringify({ event: "native_metrics_finalize_failed" })); }
  });
  const reader = response.body?.getReader(); let controllerRef;
  const abort = () => {
    void finish("canceled");
    void reader?.cancel().catch(() => {});
    controllerRef?.error(new DOMException("The operation was aborted", "AbortError"));
  };
  if (!reader) { await finish(); return response; }
  const body = new ReadableStream({
    start(controller) { controllerRef = controller; },
    async pull(controller) {
      try {
        const result = await reader.read();
        if (result.done) { await finish(); controller.close(); return; }
        observer.feed(result.value); controller.enqueue(result.value);
      } catch (error) { await finish(options.signal?.aborted ? "canceled" : "transport_error"); controller.error(error); }
    },
    async cancel(reason) { await finish("canceled"); await reader.cancel(reason); },
  }, { highWaterMark: 0 });
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) abort();
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}
