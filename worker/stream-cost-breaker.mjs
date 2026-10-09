/** Opt-in stream cost enforcement for native Worker responses. */
const CAP = "max_stream_cost_microusd";
export const STREAM_CAP_FIELD = CAP;
const MAX_CAP = 1_000_000_000_000;
const LIMIT = 65536;
const encoder = new TextEncoder();
const warned = new Set();
export function streamCostEnabled(env) {
  const flag = String(env?.STREAM_COST_BREAKER_ENABLED ?? "").trim().toLowerCase();
  if (["", "false", "0", "no", "off"].includes(flag)) return false;
  if (["true", "1", "yes", "on"].includes(flag)) return true;
  if (!warned.has("flag")) {
    warned.add("flag");
    console.warn("Invalid STREAM_COST_BREAKER_ENABLED; stream cost breaker disabled");
  }
  return false;
}
export const validStreamCap = cap => cap === null || (Number.isSafeInteger(cap) && cap >= 0 && cap <= MAX_CAP);
function failure(code, status = 503) {
  const error = new Error("Stream cost enforcement could not admit this request");
  error.code = code; error.status = status;
  return error;
}
// Decimal rates stay rational until the final micro-USD ceiling.
function decimal(value) {
  if (!["number", "string"].includes(typeof value)) throw failure("stream_cost_unpriced");
  const text = String(value), match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/i.exec(text);
  if (!match || text.length > 64) throw failure("stream_cost_unpriced");
  const exponent = Number(match[3] ?? 0) - (match[2]?.length ?? 0);
  if (Math.abs(exponent) > 30) throw failure("stream_cost_unpriced");
  const n = BigInt(match[1] + (match[2] ?? ""));
  return exponent >= 0 ? { n: n * 10n ** BigInt(exponent), d: 1n } : { n, d: 10n ** BigInt(-exponent) };
}
const add = (a, b) => ({ n: a.n * b.d + b.n * a.d, d: a.d * b.d });
const mul = (a, n) => ({ n: a.n * BigInt(n), d: a.d });
const greater = (a, b) => a.n * b.d > b.n * a.d;
const zero = { n: 0n, d: 1n };
function priceFor(env, model) {
  let table, metadata;
  try {
    table = JSON.parse(env.MODEL_PRICING_USD_PER_MILLION || "{}");
    metadata = JSON.parse(env.PROMPT_CACHE_PRICE_METADATA_JSON || "{}");
  } catch { throw failure("stream_cost_unpriced"); }
  if (!table || Array.isArray(table) || typeof table !== "object") throw failure("stream_cost_unpriced");
  table = Object.fromEntries(Object.entries(table).map(([key, value]) => [key.trim().toLowerCase(), value]));
  model = model.trim().toLowerCase();
  const provider = model.includes(":") ? model.split(":")[0] : "";
  const entry = [model, provider ? provider + ":*" : "", "*"].map(key => table[key]).find(v => v && typeof v === "object" && !Array.isArray(v));
  if (!entry) throw failure("stream_cost_unpriced");
  const names = ["input", "cache_read", "cache_write", "output"];
  const flatOnly = "request" in entry && !names.some(name => name in entry) && !("input_cost_per_million" in entry) && !("output_cost_per_million" in entry);
  const aliases = { input: "input_cost_per_million", output: "output_cost_per_million" };
  const supplement = metadata?.[model] ?? {};
  const rates = names.map(name => decimal(flatOnly ? 0 : entry[name] ?? entry[aliases[name]] ?? supplement[name]));
  const bound = rates.slice(0, 3).reduce((a, b) => greater(a, b) ? a : b);
  return { model, rates, bound, flat: mul(decimal(entry.request ?? 0), 1_000_000) };
}
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
function observation(value) {
  const native = value.usage ? value : value.response?.usage ? value.response : value.message?.usage ? value.message : null;
  if (!native?.usage || typeof native.usage !== "object") return null;
  const usage = native.usage;
  const anthropic = native.type === "message" || Boolean(value.message) || String(value.type ?? "").startsWith("message_")
    || "cache_read_input_tokens" in usage || "cache_creation_input_tokens" in usage;
  const raw = count(usage.prompt_tokens ?? usage.input_tokens);
  const details = usage.prompt_tokens_details ?? usage.input_tokens_details ?? {};
  return {
    raw, read: count(anthropic ? usage.cache_read_input_tokens : details.cached_tokens),
    write: count(anthropic ? usage.cache_creation_input_tokens : details.cache_write_tokens ?? (raw !== null ? 0 : null)),
    output: count(usage.completion_tokens ?? usage.output_tokens),
    source: anthropic ? "anthropic" : raw !== null || Object.keys(details).length ? "openai" : "unknown",
  };
}
function merge(old, next) {
  if (!old) return next;
  return { raw: next.raw ?? old.raw, read: next.read ?? old.read,
    write: next.source !== "unknown" ? next.write ?? old.write : old.write,
    output: next.output ?? old.output, source: next.source === "unknown" ? old.source : next.source };
}
function buckets(usage) {
  if (!usage) return [null, null, null, null];
  const ordinary = usage.source === "anthropic" ? usage.raw :
    usage.raw !== null && usage.read !== null && usage.write !== null ? count(usage.raw - usage.read - usage.write) : null;
  return [ordinary, usage.read, usage.write, usage.output];
}
function strings(value) {
  if (typeof value === "string") return encoder.encode(value).byteLength;
  if (Array.isArray(value)) return value.reduce((sum, v) => sum + strings(v), 0);
  if (value && typeof value === "object") return Object.values(value).reduce((sum, v) => sum + strings(v), 0);
  return 0;
}
function outputBytes(value) {
  if (Array.isArray(value.choices)) return value.choices.reduce((sum, c) => sum + strings(c?.delta ?? {}), 0);
  return strings(value.delta);
}
function terminal(value) {
  return ["message_stop", "response.completed", "response.failed", "response.incomplete"].includes(value.type)
    || (Array.isArray(value.choices) && value.choices.some(c => c?.finish_reason != null));
}
class StreamCostState {
  constructor(cap, prices, input, protocol) {
    this.cap = cap; this.prices = prices; this.input = input; this.protocol = protocol;
    this.runningMicrousd = 0; this.basis = "conservative_estimate"; this.exceeded = false;
    this.terminal = false; this.usage = null; this.finalUsage = null; this.output = 0; this.outputAtMeasurement = 0;
    this.cost();
  }
  cost() {
    const amounts = buckets(this.usage), additional = this.output - this.outputAtMeasurement;
    let measured = this.usage !== null && additional === 0;
    const costs = this.prices.map(price => {
      let result = price.flat;
      if (amounts.every((amount, i) => amount !== null || price.rates[i].n === 0n)) {
        amounts.forEach((amount, i) => { result = add(result, mul(price.rates[i], amount ?? 0)); });
        return add(result, mul(price.rates[3], additional));
      }
      measured = false;
      const knownInput = amounts.slice(0, 3).reduce((sum, n) => sum + (n ?? 0), 0);
      result = add(result, mul(price.bound, Math.max(this.input, knownInput)));
      return add(result, mul(price.rates[3], Math.max((this.usage?.output ?? 0) + additional, this.output)));
    });
    const maximum = costs.reduce((a, b) => greater(a, b) ? a : b);
    this.runningMicrousd = Number((maximum.n + maximum.d - 1n) / maximum.d);
    this.basis = measured ? "measured" : "conservative_estimate";
  }
  observe(bytes) {
    let data, value;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      data = text.split(/\r\n|\r|\n/).filter(line => line.startsWith("data:")).map(line => line.slice(5).replace(/^ +/, "")).join("\n");
      if (!data) return true;
      if (data === "[DONE]") {
        this.terminal = true;
        if (this.basis === "measured") this.finalUsage = this.usage;
        return true;
      }
      value = JSON.parse(data);
      if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("Invalid frame");
    } catch { this.exceeded = true; return false; }
    this.output += outputBytes(value);
    const found = observation(value);
    if (found) {
      this.usage = merge(this.usage, found);
      if (found.output !== null) this.outputAtMeasurement = this.output;
    }
    this.cost();
    if (terminal(value)) this.terminal = true;
    if (this.terminal && this.basis === "measured") this.finalUsage = this.usage;
    else if (this.basis !== "measured") this.finalUsage = null;
    if (this.runningMicrousd > this.cap) { this.exceeded = true; return false; }
    return true;
  }
  errorFrame() {
    const error = { code: "stream_cost_cap_exceeded", type: "stream_cost_cap_exceeded",
      message: "The stream cost cap was exceeded.", cost_basis: this.basis };
    let value = { error }, prefix = "";
    if (this.protocol === "anthropic") { value = { type: "error", error }; prefix = "event: error\n"; }
    if (this.protocol === "responses") {
      value = { type: "response.failed", response: { object: "response", status: "failed", error } };
      prefix = "event: response.failed\n";
    }
    return encoder.encode(prefix + "data: " + JSON.stringify(value) + "\n\n");
  }
}
export function prepareStreamCostBreaker(env, user, models, inputTokens, protocol = "chat") {
  const cap = user?.[CAP];
  if (!streamCostEnabled(env) || cap == null) return null;
  if (!validStreamCap(cap)) throw failure("stream_cost_storage_unavailable");
  if (!models.length || count(inputTokens) === null) throw failure("stream_cost_unpriced");
  const state = new StreamCostState(cap, models.map(model => priceFor(env, model)), inputTokens, protocol);
  if (state.runningMicrousd > cap) throw failure("stream_cost_cap_exceeded", 429);
  return state;
}
function frameEnd(bytes) {
  for (let i = 0; i < bytes.length - 1; i++) {
    if ((bytes[i] === 10 && bytes[i + 1] === 10) || (bytes[i] === 13 && bytes[i + 1] === 13)) return i + 2;
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) return i + 4;
  }
  return 0;
}
/** onFinal receives content-free state; retain the hold when finalUsage is null. */
export function wrapStreamCost(stream, state, { abort, onFinal } = {}) {
  if (!state) return stream;
  const reader = stream.getReader();
  let pending = new Uint8Array(), trailer = [], trailerSize = 0, closed = false, finalized = false;
  const finalize = async () => {
    if (finalized) return;
    finalized = true;
    try { await onFinal?.(state); } catch { console.warn("Stream cost finalization failed"); }
  };
  const close = async reason => {
    if (closed) return;
    closed = true;
    try { await abort?.(); } catch { console.warn("Stream cost abort failed"); }
    try { await reader.cancel(reason); } catch { console.warn("Stream cost cleanup failed"); }
    finally { reader.releaseLock(); await finalize(); }
  };
  return new ReadableStream({
    async pull(controller) {
      try {
        while (!closed) {
          const end = frameEnd(pending);
          if (end) {
            const frame = pending.slice(0, end); pending = pending.slice(end);
            if (end > LIMIT || !state.observe(frame)) {
              state.exceeded = true;
              if (end > LIMIT || state.runningMicrousd <= state.cap) state.finalUsage = null;
              pending = new Uint8Array();
              await close("stream_cost_cap_exceeded"); controller.enqueue(state.errorFrame()); controller.close(); return;
            }
            if (state.terminal) {
              trailer.push(frame); trailerSize += frame.length;
              if (trailerSize > LIMIT) {
                state.exceeded = true; state.finalUsage = null;
                await close("stream_cost_cap_exceeded"); controller.enqueue(state.errorFrame()); controller.close(); return;
              }
              continue;
            }
            controller.enqueue(frame); return;
          }
          if (pending.length > LIMIT) {
            state.exceeded = true; state.finalUsage = null;
            await close("stream_cost_cap_exceeded"); controller.enqueue(state.errorFrame()); controller.close(); return;
          }
          const { value, done } = await reader.read();
          if (done) {
            closed = true; reader.releaseLock();
            if (pending.length) { state.exceeded = true; state.finalUsage = null; controller.enqueue(state.errorFrame()); }
            if (!pending.length) for (const frame of trailer) controller.enqueue(frame);
            trailer = []; await finalize(); controller.close(); return;
          }
          const next = new Uint8Array(pending.length + value.byteLength);
          next.set(pending); next.set(value, pending.length); pending = next;
        }
      } catch {
        state.finalUsage = null;
        await close("interrupted");
        controller.error(failure("stream_cost_interrupted", 502));
      }
    },
    async cancel() { state.finalUsage = null; await close("cancelled"); },
  }, { highWaterMark: 0 });
}
