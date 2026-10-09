import assert from "node:assert/strict";
import test from "node:test";
import { ObservationWindow, latencySLOSettings, requestedOutput, admitCandidates,
  LatencySLOError, prepareLatencySLO, recordLatencyObservation } from "../worker/latency-slo.mjs";

const now = 1800000000000, a = "openai:slow", b = "openai:fast", c = "openai:other";
const env = (mode = "reject", required = false, changes = {}) => ({ LATENCY_SLO_MODE: mode,
  LATENCY_SLO_POLICY_JSON: JSON.stringify({ routes: { "/v1/chat/completions": { deadline_ms: 5000, require_coverage: required } } }), ...changes });
const choices = [{ model: a, quality_tier: 1 }, { model: b, quality_tier: 1 }, { model: c, quality_tier: 2 }];
function measured(store, model = a, rate = 10, count = 20, at = now) {
  for (let i = 0; i < count; i++) store.record(model, { ttft_ms: 1000, tokens_per_second: rate, now: at });
}
function decision(store, candidates = choices, mode = "reject", required = false, auto = true, outputTokens = 100) {
  const settings = latencySLOSettings(env(mode, required));
  return admitCandidates(candidates, { settings, rule: settings.ruleFor({ route: "/v1/chat/completions" }), observations: store, now, auto, outputTokens });
}

test("sparse, expired, unpaired and zero rate are unknown", () => {
  const store = new ObservationWindow(); measured(store, a, 10, 19);
  store.record(a, { ttft_ms: null, tokens_per_second: 10, now });
  store.record(a, { ttft_ms: 10, tokens_per_second: 0, now });
  assert.equal(store.predict(a, 100, { minSamples: 20, now }).samples, 19);
  assert.equal(store.predict(a, 100, { minSamples: 20, now }).coverage, .95);
  assert.equal(store.predict(a, 100, { minSamples: 20, now: now + 900001 }).samples, 0);
  assert.equal(decision(store).prediction.status, "prediction_unknown");
  assert.throws(() => decision(store, choices, "reject", true), error => error.code === "latency_slo_unavailable");
});

test("empirical p95 uses measured pairs and bounded requested output", () => {
  const store = new ObservationWindow();
  for (let i = 0; i < 18; i++) store.record(a, { ttft_ms: 100, tokens_per_second: 100, now });
  store.record(a, { ttft_ms: 2000, tokens_per_second: 100, now });
  store.record(a, { ttft_ms: 9000, tokens_per_second: 100, now });
  assert.equal(store.predict(a, 100, { minSamples: 20, now }).predicted_ms, 3000);
  assert.equal(store.predict(a, 1000, { minSamples: 20, now }).predicted_ms, 12000);
  assert.equal(requestedOutput({}), 1024);
  assert.equal(requestedOutput({ max_tokens: 100, max_completion_tokens: 50 }), 50);
  for (const value of [true, 0, -1, "100", 131073]) assert.equal(requestedOutput({ max_tokens: value }), null);
});

test("observation and model bounds", () => {
  const store = new ObservationWindow({ maxModels: 2 }); measured(store, a, 10, 1100);
  assert.equal(store.predict(a, 100, { minSamples: 20, now }).samples, 1000);
  measured(store, b); measured(store, c);
  assert.equal(store.models.size, 2);
  assert.equal(store.predict(a, 100, { minSamples: 20, now }).samples, 0);
});

test("reroute selects only supplied same-tier safe candidates and preserves explicit model", () => {
  const store = new ObservationWindow(); measured(store); measured(store, b, 100); measured(store, c, 100);
  const before = structuredClone(choices);
  assert.deepEqual(decision(store, choices, "reroute").candidates, [choices[1]]);
  assert.deepEqual(choices, before);
  assert.throws(() => decision(store, [choices[0], choices[2]], "reroute"), LatencySLOError);
  assert.throws(() => decision(store, choices, "reroute", false, false), error => error.code === "latency_slo_predicted_miss");
  assert.equal(decision(store, choices, "reject", false, true, 10).action, "pass");
});

test("invalid configuration disables once with no setting values", () => {
  const warnings = [];
  for (const changes of [{ LATENCY_SLO_MODE: "private-invalid" }, { LATENCY_SLO_MIN_SAMPLES: "0" },
    { LATENCY_SLO_MAX_MODELS: "513" }, { LATENCY_SLO_POLICY_JSON: "[]" },
    { LATENCY_SLO_POLICY_JSON: '{"routes":{"x":{"deadline_ms":true}}}' },
    { LATENCY_SLO_POLICY_JSON: '{"routes":{"x":{"deadline_ms":10,"extra":1}}}' }]) {
    for (let i = 0; i < 2; i++) assert.equal(latencySLOSettings(env("reject", false, changes), text => warnings.push(text)).mode, "off");
  }
  assert.equal(warnings.length, 4);
  assert.ok(!warnings.join().includes("private-invalid"));
});

test("tightest route and verified key opt-in; empty means defaults", () => {
  assert.equal(latencySLOSettings({ LATENCY_SLO_MODE: "", LATENCY_SLO_MIN_SAMPLES: "" }).mode, "off");
  const settings = latencySLOSettings(env("reject", false, { LATENCY_SLO_POLICY_JSON: JSON.stringify({
    routes: { "auto:test": { deadline_ms: 5000 } }, keys: { caller: { deadline_ms: 1000, require_coverage: true } } }) }));
  assert.deepEqual(settings.ruleFor({ route: "auto:test", keyId: "caller" }), { deadline_ms: 1000, require_coverage: true });
  assert.equal(settings.ruleFor({ route: "other" }), null);
});

test("native callback rejects before handoff, reports coverage and never rewrites request", async () => {
  const store = new ObservationWindow(); measured(store);
  const request = new Request("https://example.invalid/v1/chat/completions", { method: "POST", body: JSON.stringify({ model: a, max_tokens: 100 }) });
  let handoffs = 0;
  const decision = await prepareLatencySLO(request, env(), { authenticated: true, model: a, keyId: "caller", observations: store, now });
  if (!decision.response) handoffs++;
  assert.equal(handoffs, 0);
  assert.equal(decision.response.status, 503);
  const payload = await decision.response.json();
  assert.equal(payload.error.code, "latency_slo_predicted_miss");
  assert.equal(payload.error.prediction.observation_age_ms, 0);
  assert.equal(await request.text(), JSON.stringify({ model: a, max_tokens: 100 }));
});

test("off, unverified authority and passthrough do not read request or call collaborators", async () => {
  const request = { clone() { throw new Error("must not read"); } };
  assert.equal(await prepareLatencySLO(request, env("off"), { authenticated: true }), null);
  assert.equal(await prepareLatencySLO(request, env(), { authenticated: false }), null);
  assert.equal(await prepareLatencySLO(request, env(), { authenticated: true, passthrough: true }), null);
});

test("native observation adapter requires measured completed non-cache output", () => {
  const store = new ObservationWindow();
  const event = { provider: "openai", model: "slow", ttft_ms: 1000, duration_ms: 2000,
    output_tokens: 100, outcome: "success", usage_basis: "measured", cost_basis: "usage" };
  assert.equal(recordLatencyObservation(event, env("off"), { observations: store, now }), false);
  for (const changes of [{ usage_basis: "estimated" }, { outcome: "unknown" }, { cost_basis: "cache" }, { output_tokens: null }]) {
    assert.equal(recordLatencyObservation({ ...event, ...changes }, env(), { observations: store, now }), false);
  }
  for (let i = 0; i < 20; i++) assert.equal(recordLatencyObservation(event, env(), { observations: store, now }), true);
  assert.equal(store.predict(a, 100, { minSamples: 20, now }).predicted_ms, 2000);
});

test("duplicate, null and invalid policy scopes disable admission", () => {
  for (const policy of ['{"routes":{},"routes":{}}', '{"routes":null}', '{"keys":[]}',
    '{"routes":{"x":{"deadline_ms":10,"deadline_ms":20}}}', '{"routes":{"x":{"deadline_ms":10,"require_coverage":null}}}']) {
    assert.equal(latencySLOSettings(env("reject", false, { LATENCY_SLO_POLICY_JSON: policy }), () => {}).mode, "off");
  }
});

test("remaining generation deadline is checked and never extended", async () => {
  const store = new ObservationWindow(); measured(store, a, 100);
  const request = new Request("https://example.invalid/v1/chat/completions", { method: "POST", body: JSON.stringify({ model: a, max_tokens: 100 }) });
  let checked = 0;
  const deadline = { check() { checked++; }, remainingMs() { return 500; } };
  const result = await prepareLatencySLO(request, env(), { authenticated: true, model: a, observations: store, now, deadline });
  assert.equal(result.response.status, 503); assert.equal(checked, 1); assert.equal(deadline.remainingMs(), 500);
  const expired = new Error("generation_deadline_exceeded");
  await assert.rejects(() => prepareLatencySLO(request, env(), { authenticated: true, model: a, deadline: { check() { throw expired; } } }), error => error === expired);
});

test("unmatched policy and malformed payload preserve ordinary validation", async () => {
  const request = new Request("https://example.invalid/v1/messages", { method: "POST", body: "invalid" });
  assert.equal(await prepareLatencySLO(request, env(), { authenticated: true }), null);
  const invalid = new Request("https://example.invalid/v1/chat/completions", { method: "POST", body: "invalid" });
  assert.equal(await prepareLatencySLO(invalid, env(), { authenticated: true }), null);
});
