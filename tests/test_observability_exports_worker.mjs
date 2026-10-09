import assert from "node:assert/strict";
import test from "node:test";
import { ObservabilityExporter, setObservabilityExporter, createNativeObservabilityHook } from "../worker/observability-export.mjs";
import { handleUsageLedgerRequest, recordNativeUsage } from "../worker/usage-ledger-d1.mjs";

const settings = (...types) => ({ OBSERVABILITY_EXPORTERS_JSON: JSON.stringify(types.map(type => ({
  type, endpoint: `https://${type}.example/ingest`, allowed_origins: [`https://${type}.example`], credential_env: `TEST_${type.toUpperCase()}_EXPORT_CREDENTIAL`,
}))), TEST_LANGFUSE_EXPORT_CREDENTIAL: "public:synthetic-secret", TEST_HELICONE_EXPORT_CREDENTIAL: "synthetic-secret" });
const record = (extra = {}) => ({ request_id: "req-1", trace_id: "a".repeat(32), principal: "private-user",
  selected_model: "openai:test", kind: "chat", status: 200, at: "2026-10-09T00:00:00.000Z", latency_ms: 10,
  input_tokens: 0, output_tokens: null, cost_usd: null, cost_basis: null,
  prompt: "private-prompt", response: "private-output", tools: ["private-tool"], headers: { authorization: "private-key" }, key_prefix: "private-prefix", ...extra });
const collector = (calls, status = 200) => async (url, options) => { calls.push({ url, options, body: JSON.parse(options.body) }); return new Response("{}", { status }); };

test("defaults and malformed configuration never call transport", async () => {
  const logs = [], original = console.warn; console.warn = message => logs.push(message);
  try {
    for (const raw of [undefined, "", "[]", "private-invalid", "{}", '[{"type":"unknown"}]']) {
      const calls = [], exporter = new ObservabilityExporter({ OBSERVABILITY_EXPORTERS_JSON: raw }, { transport: collector(calls) });
      assert.equal(exporter.submit(record()), false); assert.equal(exporter.submit(record()), false);
      assert.equal(await exporter.flush(), 0); assert.equal(calls.length, 0);
    }
    assert.equal(logs.length, 1); assert.ok(!logs.join("").includes("private-invalid"));
  } finally { console.warn = original; }
});

test("destination allowlists and credential names reject unsafe configuration", () => {
  for (const change of [{ endpoint: "http://helicone.example/log" }, { endpoint: "https://other.example/log" },
    { endpoint: "https://secret@helicone.example/log" }, { endpoint: "https://helicone.example/log?key=secret" },
    { endpoint: "https://helicone.example/log#secret" }, { api_key: "secret" }, { credential_env: "secret!" }, { credential_env: "GEMINI_API_KEY" },
    { allowed_origins: ["https://helicone.example/path"] }]) {
    const env = settings("helicone"), config = JSON.parse(env.OBSERVABILITY_EXPORTERS_JSON);
    Object.assign(config[0], change); env.OBSERVABILITY_EXPORTERS_JSON = JSON.stringify(config);
    assert.equal(new ObservabilityExporter(env).submit(record()), false);
  }
});

test("adapter schemas preserve nulls, strip content, and expose only credential references", async () => {
  const calls = [], exporter = new ObservabilityExporter(settings("langfuse", "helicone"), { transport: collector(calls) });
  assert.equal(exporter.submit(record()), true); assert.equal(calls.length, 0);
  assert.equal(exporter.status().exporters[0].acknowledged, 0);
  assert.equal(await exporter.flush(), 1);
  const event = calls[0].body.batch[0]; assert.equal(event.type, "generation-create");
  assert.deepEqual(event.body.usage, { input: 0, output: null, unit: "TOKENS" });
  assert.deepEqual(event.body.metadata.cost, { usd: null, basis: null });
  assert.match(event.body.metadata.principal, /^principal:[0-9a-f]{64}$/);
  assert.equal(calls[1].body.providerResponse.json.usage.completion_tokens, null);
  assert.deepEqual(calls[1].body.providerRequest.json, { model: "openai:test" });
  assert.deepEqual(calls[1].body.timing, { startTime: { seconds: 1791503999, milliseconds: 990 }, endTime: { seconds: 1791504000, milliseconds: 0 } });
  for (const call of calls) {
    assert.equal(call.options.redirect, "error"); assert.ok(call.options.signal);
    for (const value of ["private-user", "private-prompt", "private-output", "private-tool", "private-key", "private-prefix"]) assert.ok(!JSON.stringify(call.body).includes(value));
  }
  assert.ok(!JSON.stringify(exporter.status()).includes("synthetic-secret"));
  assert.deepEqual(exporter.status().exporters.map(item => item.acknowledged), [1, 1]);
});

test("overflow, bounded batches, deduplication and separate experiment costs", async () => {
  const calls = [], exporter = new ObservabilityExporter(settings("langfuse"), { transport: collector(calls) });
  for (let index = 0; index < 1000; index++) assert.equal(exporter.submit(record({ request_id: `req-${index}` })), true);
  assert.equal(exporter.submit(record({ request_id: "overflow" })), false);
  assert.equal(exporter.status().dropped, 1); assert.equal(exporter.status().queued, 1000);
  assert.equal(exporter.submit(record({ request_id: "req-1" })), false);
  assert.equal(await exporter.exportOnce(), 50); assert.equal(calls[0].body.batch.length, 50);
  for (const [kind, cost] of [["shadow", .1], ["canary", .2]]) assert.equal(exporter.submit(record({ request_id: "same", kind, cost_usd: cost, cost_basis: "usage" })), true);
  await exporter.flush();
  const observations = calls.flatMap(call => call.body.batch.map(event => event.body.metadata));
  assert.deepEqual(observations.slice(-2).map(item => [item.kind, item.cost.usd]), [["shadow", .1], ["canary", .2]]);
});

test("timeouts and retries are bounded and failures are isolated", async () => {
  const calls = [], logs = [], original = console.warn;
  console.warn = value => logs.push(value);
  const exporter = new ObservabilityExporter(settings("langfuse", "helicone"), {
    transport: async (url, options) => { calls.push({ url, options }); if (url.includes("langfuse")) throw new Error("private-secret"); return new Response("{}"); },
  });
  try {
    exporter.submit(record()); await exporter.flush();
    assert.equal(calls.length, 4); assert.equal(exporter.status().exporters[0].failed, 1);
    assert.equal(exporter.status().exporters[1].acknowledged, 1); assert.ok(!logs.join("").includes("private-secret"));
    assert.equal(new Set(calls.slice(0, 3).map(call => JSON.parse(call.options.body).batch[0].id)).size, 1);
    const hanging = new ObservabilityExporter(settings("helicone"), { transport: () => new Promise(() => {}) });
    hanging.submit(record()); const start = performance.now(); await hanging.flush();
    assert.ok(performance.now() - start >= 5900 && performance.now() - start < 8000);
    assert.equal(hanging.status().exporters[0].attempts, 3);
  } finally { console.warn = original; }
});

test("redirects, authentication failures and partial receipts are not retried or acknowledged", async () => {
  for (const status of [301, 400, 401, 207]) {
    const calls = [], exporter = new ObservabilityExporter(settings("langfuse"), { transport: collector(calls, status) });
    exporter.submit(record()); await exporter.flush();
    assert.equal(calls.length, 1); assert.equal(exporter.status().exporters[0].failed, 1);
  }
});

test("native exports once without waiting; forwarded ledger flushes do not export", async () => {
  const calls = [], pending = [], rows = [];
  const env = { ...settings("helicone"), INTELLIGENCE_DB: {
    prepare(sql) { return { bind(...values) { return { sql, values }; } }; },
    async batch(statements) { rows.push(...JSON.parse(statements[1].values[0])); return [{ meta: { changes: 1 } }]; },
  } };
  const exporter = new ObservabilityExporter(env, { transport: collector(calls) }); setObservabilityExporter(env, exporter);
  const event = { provider: "openai", model: "test", principal: "edge:trusted", requestId: crypto.randomUUID(),
    endpoint: "/v1/chat/completions", status: 200, duration_ms: 10, input_tokens: 0, output_tokens: null, cost_usd: null, cost_basis: null };
  await recordNativeUsage(env, event); await recordNativeUsage(env, event);
  assert.equal(exporter.status().accepted, 1); assert.equal(calls.length, 0);
  const forwarded = { ...rows[0], request_id: "flask-request" }; delete forwarded.bucket;
  const response = await handleUsageLedgerRequest(new Request("http://intelligence.internal/v1/usage", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "record", batch: "a".repeat(32), rows: [forwarded] }),
  }), env);
  assert.deepEqual(await response.json(), { version: 1, recorded: 1, duplicate: false });
  assert.equal(exporter.status().accepted, 1);
  await recordNativeUsage(env, { ...event, requestId: crypto.randomUUID() }, { waitUntil(promise) { pending.push(promise); } });
  await Promise.all(pending); assert.equal(calls.length, 2);
});

test("exports work without D1 and concurrent flushes deliver each queue item once", async () => {
  const calls = [], env = settings("helicone"), exporter = new ObservabilityExporter(env, { transport: collector(calls) });
  setObservabilityExporter(env, exporter);
  const original = console.error; console.error = () => {};
  try {
    await recordNativeUsage(env, { provider: "openai", model: "test", principal: "edge:trusted", requestId: crypto.randomUUID(),
      endpoint: "/v1/chat/completions", status: 200, duration_ms: 10, input_tokens: null, output_tokens: null, cost_usd: null, cost_basis: null });
    await Promise.all([exporter.flush(), exporter.flush()]); assert.equal(calls.length, 1);
  } finally { console.error = original; }
});

test("partial Langfuse receipts acknowledge only matching successful event IDs", async () => {
  const exporter = new ObservabilityExporter(settings("langfuse"), { transport: async (url, options) => {
    const [first, second] = JSON.parse(options.body).batch;
    return Response.json({ successes: [{ id: first.id }, { id: "foreign" }], errors: [{ id: second.id }] }, { status: 207 });
  } });
  exporter.submit(record()); exporter.submit(record({ request_id: "req-2" })); await exporter.flush();
  const stats = exporter.status().exporters[0];
  assert.deepEqual([stats.acknowledged, stats.failed, stats.attempts, stats.delivery_status], [1, 1, 1, "partial"]);
});

test("slow partial response bodies share the delivery timeout", async () => {
  const exporter = new ObservabilityExporter(settings("langfuse"), { transport: async () =>
    new Response(new ReadableStream({ pull() {} }), { status: 207 }) });
  exporter.submit(record()); const start = performance.now(); await exporter.flush();
  assert.ok(performance.now() - start >= 5900 && performance.now() - start < 8000);
  assert.equal(exporter.status().exporters[0].failed, 1);
});

test("static native finalizer exports independently of metrics or storage", async () => {
  const calls = [], pending = [], env = settings("helicone");
  const exporter = new ObservabilityExporter(env, { transport: collector(calls) }); setObservabilityExporter(env, exporter);
  const hook = createNativeObservabilityHook(env, { waitUntil(promise) { pending.push(promise); } });
  assert.equal(hook.enabled(env), true);
  const event = { provider: "openai", model: "test", principal: "edge:trusted", requestId: "native-only",
    kind: "shadow", endpoint: "/v1/chat/completions", status: 200, duration_ms: 10, cost_usd: .01, cost_basis: "usage", input_tokens: 1, output_tokens: 0 };
  assert.equal(hook.finalize(event), true); assert.equal(hook.finalize(event), false);
  await Promise.all(pending); assert.equal(calls.length, 1);
  const observed = JSON.parse(calls[0].body.providerRequest.meta["Helicone-Property-observation"]);
  assert.equal(observed.kind, "shadow"); assert.equal(observed.cost.usd, .01);
});
