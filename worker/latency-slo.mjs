/** Bounded measured latency admission. Candidate eligibility remains the caller's authority. */
const WINDOW_MS = 900000, MAX_SAMPLES = 1000, MAX_OUTPUT = 131072;
const IDENTIFIER = /^[A-Za-z0-9._:/@+-]{1,256}$/;
const warned = new Set();
const integer = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;
const number = (value, min = 0, max = 1e13) => typeof value === "number" && Number.isFinite(value) && value >= min && value <= max;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);

function warnOnce(name, warn) {
  if (!warned.has(name)) { warned.add(name); warn(`Invalid ${name}; latency SLO admission disabled`); }
}

function uniqueJSON(raw) {
  const value = JSON.parse(raw), stack = [];
  // JSON.parse validates syntax; this pass rejects duplicate object keys before normalization.
  for (const token of raw.match(/"(?:\\.|[^"\\])*"|[{}\[\]:,]/g) ?? []) {
    if (token === "{" || token === "[") stack.push({ object: token === "{", keys: new Set(), key: token === "{" });
    else if (token === "}" || token === "]") stack.pop();
    else if (token === ",") { if (stack.at(-1)?.object) stack.at(-1).key = true; }
    else if (token === ":") { if (stack.at(-1)) stack.at(-1).key = false; }
    else if (token.startsWith('"') && stack.at(-1)?.object && stack.at(-1).key) {
      const key = JSON.parse(token), current = stack.at(-1);
      if (current.keys.has(key)) throw new Error("Duplicate policy key");
      current.keys.add(key); current.key = false;
    }
  }
  return value;
}

function parsePolicy(raw) {
  if (new TextEncoder().encode(raw).length > 32768) throw new Error("Policy too large");
  const config = uniqueJSON(raw);
  if (!object(config) || Object.keys(config).some(key => !["routes", "keys"].includes(key))) throw new Error("Invalid policy");
  const rules = {};
  for (const scope of ["routes", "keys"]) {
    const entries = Object.hasOwn(config, scope) ? config[scope] : {};
    if (!object(entries) || Object.keys(entries).length > 128) throw new Error("Invalid scope");
    rules[scope] = new Map();
    for (const [name, rule] of Object.entries(entries)) {
      if (!IDENTIFIER.test(name) || !object(rule) || Object.keys(rule).some(key => !["deadline_ms", "require_coverage"].includes(key))
          || !integer(rule.deadline_ms, 1, 300000) || "require_coverage" in rule && typeof rule.require_coverage !== "boolean") throw new Error("Invalid rule");
      rules[scope].set(name, { deadline_ms: rule.deadline_ms, require_coverage: rule.require_coverage ?? false });
    }
  }
  return rules;
}

function settingsObject(mode = "off", minSamples = 20, maxModels = 128, rules = {}) {
  return { mode, minSamples, maxModels, ruleFor({ route = "", keyId = "", model = "" } = {}) {
    const selected = [rules.routes?.get(route), rules.routes?.get(model), rules.keys?.get(keyId)].filter(Boolean);
    return selected.length ? { deadline_ms: Math.min(...selected.map(rule => rule.deadline_ms)),
      require_coverage: selected.some(rule => rule.require_coverage) } : null;
  } };
}

export function latencySLOSettings(env = {}, warn = text => console.warn(text)) {
  const mode = String(env.LATENCY_SLO_MODE ?? "").trim().toLowerCase() || "off";
  if (mode === "off") return settingsObject();
  if (!["reject", "reroute"].includes(mode)) { warnOnce("LATENCY_SLO_MODE", warn); return settingsObject(); }
  const limits = [];
  for (const [name, fallback, maximum] of [["LATENCY_SLO_MIN_SAMPLES", 20, 1000], ["LATENCY_SLO_MAX_MODELS", 128, 512]]) {
    const raw = String(env[name] ?? "").trim() || String(fallback);
    if (!/^[0-9]{1,4}$/.test(raw) || !integer(Number(raw), 1, maximum)) { warnOnce(name, warn); return settingsObject(); }
    limits.push(Number(raw));
  }
  try { return settingsObject(mode, ...limits, parsePolicy(String(env.LATENCY_SLO_POLICY_JSON ?? "").trim() || "{}")); }
  catch { warnOnce("LATENCY_SLO_POLICY_JSON", warn); return settingsObject(); }
}

export function requestedOutput(payload, fallback = 1024) {
  const values = ["max_tokens", "max_completion_tokens"].filter(name => Object.hasOwn(payload, name)).map(name => payload[name]);
  if (!values.length) values.push(fallback);
  return values.every(value => integer(value, 1, MAX_OUTPUT)) ? Math.min(...values) : null;
}

export class ObservationWindow {
  constructor({ maxModels = 128 } = {}) {
    if (!integer(maxModels, 1, 512)) throw new Error("Invalid model cap");
    this.maxModels = maxModels; this.models = new Map();
  }
  record(model, { ttft_ms, tokens_per_second, now = Date.now(), maxModels = this.maxModels }) {
    if (typeof model !== "string" || !IDENTIFIER.test(model) || !number(now)
        || !number(ttft_ms, 0, 3600000) || !number(tokens_per_second, 1e-9, 1000000) || !integer(maxModels, 1, 512)) return false;
    for (const [name, samples] of this.models) {
      const recent = samples.filter(sample => sample[0] >= now - WINDOW_MS);
      if (recent.length) this.models.set(name, recent); else this.models.delete(name);
    }
    const samples = this.models.get(model) ?? [];
    samples.push([now, ttft_ms, tokens_per_second]);
    if (samples.length > MAX_SAMPLES) samples.splice(0, samples.length - MAX_SAMPLES);
    this.models.delete(model); this.models.set(model, samples);
    while (this.models.size > maxModels) this.models.delete(this.models.keys().next().value);
    return true;
  }
  predict(model, outputTokens, { minSamples = 20, now = Date.now() } = {}) {
    const samples = this.models.get(model) ?? [], recent = samples.filter(sample => now - sample[0] >= 0 && now - sample[0] <= WINDOW_MS);
    const age = samples.length ? Math.max(0, Math.round(now - Math.max(...samples.map(sample => sample[0])))) : null;
    const prediction = { status: "prediction_unknown", predicted_ms: null, samples: recent.length,
      min_samples: minSamples, coverage: Math.min(1, recent.length / minSamples), observation_age_ms: age,
      window_ms: WINDOW_MS, output_tokens: outputTokens };
    if (recent.length >= minSamples && integer(outputTokens, 1, MAX_OUTPUT)) {
      const times = recent.map(([, ttft, rate]) => ttft + outputTokens * 1000 / rate).sort((a, b) => a - b);
      prediction.status = "prediction_known"; prediction.predicted_ms = Math.ceil(times[Math.ceil(.95 * times.length) - 1]);
    }
    return prediction;
  }
}

export const observations = new ObservationWindow();

export class LatencySLOError extends Error {
  constructor(code, prediction) {
    super(code === "latency_slo_unavailable" ? "Recent latency coverage is unavailable" : "Predicted completion exceeds the latency deadline");
    this.code = code; this.prediction = prediction;
  }
  response() { return Response.json({ error: { code: this.code, message: this.message, retryable: false, prediction: this.prediction } },
    { status: 503, headers: { "Cache-Control": "no-store" } }); }
}

export function admitCandidates(candidates, { settings, rule, outputTokens, auto, observations: store = observations, now = Date.now() }) {
  if (settings.mode === "off" || !rule) return { candidates, action: "pass", prediction: null };
  const primary = candidates[0] ?? {}, prediction = store.predict(primary.model, outputTokens, { minSamples: settings.minSamples, now });
  if (prediction.status === "prediction_unknown") {
    if (rule.require_coverage) throw new LatencySLOError("latency_slo_unavailable", prediction);
    return { candidates, action: "pass", prediction };
  }
  if (prediction.predicted_ms <= rule.deadline_ms) return { candidates, action: "pass", prediction };
  if (settings.mode === "reroute" && auto && integer(primary.quality_tier, 0, 100)) {
    const safe = candidates.slice(1).filter(candidate => {
      if (!integer(candidate.quality_tier, 0, 100) || candidate.quality_tier !== primary.quality_tier) return false;
      const predicted = store.predict(candidate.model, outputTokens, { minSamples: settings.minSamples, now });
      return predicted.status === "prediction_known" && predicted.predicted_ms <= rule.deadline_ms;
    });
    if (safe.length) return { candidates: safe, action: "reroute", prediction: store.predict(safe[0].model, outputTokens, { minSamples: settings.minSamples, now }) };
  }
  throw new LatencySLOError("latency_slo_predicted_miss", prediction);
}

async function boundedPayload(request) {
  if (!request.body) return null;
  const reader = request.clone().body.getReader(), parts = []; let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > 1048576) return null;
      parts.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    const payload = JSON.parse(new TextDecoder().decode(bytes));
    return object(payload) ? payload : null;
  } catch { return null; }
  finally { void reader.cancel().catch(() => {}); }
}

export async function prepareLatencySLO(request, env, authority = {}) {
  const settings = latencySLOSettings(env);
  if (settings.mode === "off" || authority.authenticated !== true || authority.passthrough) return null;
  const route = authority.route ?? new URL(request.url).pathname;
  const rule = settings.ruleFor({ route, keyId: authority.keyId, model: authority.routeId });
  if (!rule) return null;
  authority.deadline?.check();
  const payload = authority.payload ?? await boundedPayload(request);
  if (!payload) return null;
  const model = authority.model ?? payload.model;
  if (typeof model !== "string" || !IDENTIFIER.test(model)) return null;
  const auto = model.startsWith("auto:"), candidates = auto ? authority.candidates ?? [] : [{ model }];
  const remaining = authority.deadline?.remainingMs();
  const effective = remaining === undefined ? rule : { ...rule, deadline_ms: Math.min(rule.deadline_ms, remaining) };
  try {
    return admitCandidates(candidates, { settings, rule: effective, outputTokens: requestedOutput(payload), auto,
      observations: authority.observations ?? observations, now: authority.now ?? Date.now() });
  } catch (error) {
    if (!(error instanceof LatencySLOError)) throw error;
    return { response: error.response(), action: "reject", prediction: error.prediction };
  }
}

export function recordLatencyObservation(event, env, { observations: store = observations, now = Date.now() } = {}) {
  const settings = latencySLOSettings(env);
  if (settings.mode === "off" || event.outcome !== "success" || event.usage_basis !== "measured"
      || event.cost_basis === "cache" || event.cacheServed || !integer(event.output_tokens, 1, 2147483647)
      || !number(event.ttft_ms, 0, 3600000) || !number(event.duration_ms) || event.duration_ms <= event.ttft_ms
      || typeof event.provider !== "string" || typeof event.model !== "string") return false;
  const model = event.model.startsWith(event.provider + ":") ? event.model : `${event.provider}:${event.model}`;
  return store.record(model, { ttft_ms: event.ttft_ms, tokens_per_second: event.output_tokens * 1000 / (event.duration_ms - event.ttft_ms),
    now, maxModels: settings.maxModels });
}
