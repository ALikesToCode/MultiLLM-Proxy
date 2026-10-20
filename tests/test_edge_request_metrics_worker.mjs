import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { recordNativeUsage } from "../worker/usage-ledger-d1.mjs";
import { createGatewayLifecycle } from "../worker/gateway-lifecycle.mjs";
import { createUsageObserver, observeNativeResponse, renderNativeMetrics } from "../worker/request-telemetry.mjs";
import { nativeGenerationFetch, withForwardedCorrelation, withNativeMetrics } from "../worker/gateway-extensions.mjs";

// Keep the shared loader untouched; register the owned import in this test's copy.
const helperUrl = new URL("./helpers/load_cloudflare_worker.mjs", import.meta.url);
const helper = (await readFile(helperUrl, "utf8"))
  .replaceAll("import.meta.url", JSON.stringify(helperUrl.href))
  .replace("const patchedSource = source", `const patchedSource = source.replace('from "./worker/gateway-extensions.mjs";', 'from "${new URL("../worker/gateway-extensions.mjs", import.meta.url)}";')`);
const registeredHelperUrl = `data:text/javascript;base64,${Buffer.from(helper).toString("base64")}`;
const worker = (await (await import(registeredHelperUrl)).loadWorkerModule()).default;
const encoder = new TextEncoder();
const chunks = values => new ReadableStream({ start(c) { for (const value of values) c.enqueue(encoder.encode(value)); c.close(); } });
function fixture() {
  const rows = [], pending = [];
  const env = { NATIVE_EDGE_METRICS_ENABLED: "true", ADMIN_API_KEY: "synthetic-admin", ADMIN_USERNAME: "test-owner",
    CODEX_EASY_API_KEY: "synthetic-upstream", INTELLIGENCE_DB: {
      prepare(sql) { return { bind(...values) { return { sql, values }; } }; },
      async batch(statements) { rows.push(...JSON.parse(statements[1].values[0])); return [{ meta: { changes: 1 } }]; },
    } };
  return { env, rows, ctx: { waitUntil(p) { pending.push(p); } }, async flush() { await Promise.all(pending); } };
}
const req = (path = "/codex-easy/v1/chat/completions", token = "synthetic-admin", signal) => new Request(`https://gateway.example${path}`, {
  method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "x-multillm-principal": "spoofed", "x-request-id": "spoofed" },
  body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "private-prompt" }] }), signal,
});
async function upstream(response, run) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => response;
  try { return await run(); } finally { globalThis.fetch = original; }
}

test("default and empty settings preserve native bytes, headers and storage", async () => {
  for (const setting of [undefined, "", "false"]) {
    const f = fixture(); f.env.NATIVE_EDGE_METRICS_ENABLED = setting;
    const raw = '{"usage":{"prompt_tokens":2,"completion_tokens":0},"choices":[]}';
    const response = await upstream(new Response(raw, { headers: { "content-type": "application/json" } }), () => worker.fetch(req(), f.env, f.ctx));
    assert.equal(await response.text(), raw); await f.flush(); assert.equal(f.rows.length, 0);
    const headers = new Headers({ "x-request-id": "client" });
    withForwardedCorrelation(headers, f.env); assert.equal(headers.get("x-request-id"), "client");
  }
});

test("registered native success stores opaque authorized identity and exact bytes", async () => {
  const f = fixture(); f.env.MODEL_PRICING_USD_PER_MILLION = '{"codex-easy:test-model":{"input":1,"output":2}}';
  const raw = '{"model":"untrusted-model","usage":{"prompt_tokens":4,"completion_tokens":0},"choices":[]}';
  const response = await upstream(new Response(raw, { headers: { "content-type": "application/json" } }), () => worker.fetch(req(), f.env, f.ctx));
  assert.equal(await response.text(), raw); await f.flush();
  assert.equal(f.rows.length, 1); const row = f.rows[0];
  assert.match(row.principal, /^edge:[0-9a-f]{64}$/); assert.notEqual(row.request_id, "spoofed");
  assert.equal(row.selected_model, "codex-easy:test-model"); assert.equal(row.key_prefix, null);
  assert.deepEqual([row.input_tokens, row.output_tokens, row.cost_usd, row.cost_basis], [4, 0, 0.000004, "usage"]);
  assert.ok(!JSON.stringify(row).includes("private-prompt"));
});

test("unauthenticated spoof creates no native row", async () => {
  const f = fixture(); const response = await worker.fetch(req(undefined, "wrong"), f.env, f.ctx);
  assert.equal(response.status, 401); await f.flush(); assert.equal(f.rows.length, 0);
});

test("split SSE usage preserves bytes and finalizes exactly once", async () => {
  const values = ['data: {"choices":[{"delta":{"content":"private-output"}}]}\r\n\r\n', 'data: {"usage":{"prompt_to', 'kens":7}}\n\n', 'data: {"usage":{"completion_tokens":3}}\n\ndata: [DONE]\n\n'];
  const events = [], f = fixture();
  const response = await observeNativeResponse(new Response(chunks(values), { headers: { "content-type": "text/event-stream" } }), {
    provider: "codex-easy", model: "test-model", principal: "edge:trusted", requestId: "req-test", endpoint: "/codex-easy/v1/chat/completions", startedAt: 0,
  }, { clock: () => 12, finalize: event => events.push(event) });
  assert.equal(await response.text(), values.join("")); assert.equal(events.length, 1);
  assert.deepEqual([events[0].input_tokens, events[0].output_tokens, events[0].usage_basis, events[0].outcome, events[0].ttft_ms], [7, 3, "measured", "success", 12]);
});

test("parser carry stays at most 64 KiB and recovers after oversized lines", () => {
  const parser = createUsageObserver(true);
  parser.feed(encoder.encode('data: ' + 'x'.repeat(200000))); assert.ok(parser.carryBytes <= 65536);
  parser.feed(encoder.encode('\n\ndata: {"usage":{"input_tokens":0,"output_tokens":2}}\n\ndata: [DONE]\n\n'));
  assert.deepEqual(parser.finish().usage, { input_tokens: 0, output_tokens: 2 });
});

test("partial usage, missing usage, stream error and cancellation remain unknown", async () => {
  for (const raw of ['data: {"usage":{"input_tokens":2}}\n\ndata: [DONE]\n\n', 'data: [DONE]\n\n', 'data: {"error":{"message":"private-error"}}\n\n']) {
    const events = [];
    const response = await observeNativeResponse(new Response(raw, { headers: { "content-type": "text/event-stream" } }), { provider: "linkapi", principal: "edge:trusted", startedAt: 0 }, { finalize: e => events.push(e), clock: () => 5 });
    await response.text(); assert.equal(events.length, 1); assert.notEqual(events[0].outcome, "success"); assert.equal(events[0].cost_usd, null);
  }
  const events = []; let canceled = 0;
  const response = await observeNativeResponse(new Response(new ReadableStream({ pull(c) { c.enqueue(encoder.encode('data: {}\n\n')); }, cancel() { canceled++; } }), { headers: { "content-type": "text/event-stream" } }), { provider: "linkapi", principal: "edge:trusted", startedAt: 0 }, { finalize: e => events.push(e) });
  const reader = response.body.getReader(); await reader.read(); await reader.cancel("private-reason");
  assert.equal(canceled, 1); assert.equal(events.length, 1); assert.equal(events[0].outcome, "canceled"); assert.equal(events[0].status, 499);
});

test("lifecycle is ordered, static and finalize is idempotent under concurrency", async () => {
  const seen = []; const lifecycle = createGatewayLifecycle([{ authorize: () => seen.push("authorize"), admit: () => seen.push("admit"), before_dispatch: () => seen.push("before_dispatch"), observe: () => seen.push("observe"), finalize: () => seen.push("finalize") }]);
  await lifecycle.authorize({}); await lifecycle.admit({}); await lifecycle.before_dispatch({}); await lifecycle.observe({});
  await Promise.all([lifecycle.finalize({}), lifecycle.finalize({})]);
  assert.deepEqual(seen, ["authorize", "admit", "before_dispatch", "observe", "finalize"]);
});

test("forwarded Container traffic gets trusted correlation and only its own ledger row", async () => {
  const f = fixture(); let calls = 0;
  f.env.MULTILLM_PROXY_CONTAINER = { getByName() { return { async fetch(request) {
    calls++; assert.notEqual(request.headers.get("x-request-id"), "spoofed"); assert.equal(request.headers.get("x-multillm-principal"), null);
    f.rows.push({ owner: "flask" }); return new Response("unchanged");
  } }; } };
  const response = await worker.fetch(req("/kimi-code/v1/chat/completions"), { ...f.env, KIMI_CODE_API_KEY: "synthetic-kimi" }, f.ctx);
  assert.equal(await response.text(), "unchanged"); await f.flush(); assert.equal(calls, 1); assert.deepEqual(f.rows, [{ owner: "flask" }]);
});

test("W5 registered private Prometheus endpoint appends bounded content-free metrics", async () => {
  const f = fixture();
  f.env.PROMETHEUS_ENABLED = "true";
  f.env.MULTILLM_PROXY_CONTAINER = { getByName() { return { fetch: async () => new Response("# upstream metrics\n", { headers: { "content-type": "text/plain; version=0.0.4; charset=utf-8" } }) }; } };
  const response = await worker.fetch(new Request("https://gateway.example/v1/metrics/prometheus"), f.env, f.ctx);
  const body = await response.text(); assert.match(body, /multillm_native_requests_total/);
  for (const privateValue of ["private-prompt", "private-output", "test-owner", "test-model", "synthetic-admin"]) assert.ok(!body.includes(privateValue));
  const denied = await withNativeMetrics(new Response("denied", { status: 401 }), f.env); assert.equal(await denied.text(), "denied");
  assert.ok(Buffer.byteLength(renderNativeMetrics()) < 16384);
});


test("semantic SSE errors are ledger errors even with upstream HTTP 200", async () => {
  const events = [];
  const response = await observeNativeResponse(new Response('data: {"error":{"message":"private"}}\n\n', { headers: { "content-type": "text/event-stream" } }), { startedAt: 0, provider: "opencode" }, { finalize: event => events.push(event) });
  assert.equal(response.status, 200); await response.text();
  assert.equal(events[0].outcome, "upstream_error"); assert.equal(events[0].status, 502);
});

test("registered Link and OpenCode native paths observe errors without changing them", async () => {
  for (const path of ["/linkapi/v1/chat/completions", "/opencode/v1/chat/completions"]) {
    const f = fixture(); f.env.LINKAPI_KEY = "synthetic-link"; f.env.OPENCODE_GO_API_KEY = "synthetic-open"; f.env.OPENCODE_EDGE_FETCH = "true";
    const raw = '{"error":{"message":"provider error"}}';
    const response = await upstream(new Response(raw, { status: 429, headers: { "content-type": "application/json", "retry-after": "3" } }), () => worker.fetch(req(path), f.env, f.ctx));
    assert.equal(response.status, 429); assert.equal(await response.text(), raw); await f.flush();
    assert.equal(f.rows.length, 1); assert.equal(f.rows[0].status, 429); assert.equal(f.rows[0].cost_usd, null);
  }
});

test("injected named hooks see only metadata and stay dormant while disabled", async () => {
  for (const enabled of ["false", "true"]) {
    const f = fixture(); f.env.NATIVE_EDGE_METRICS_ENABLED = enabled; const seen = [];
    const hooks = Object.fromEntries(["authorize", "admit", "before_dispatch", "observe", "finalize"].map(name => [name, context => {
      assert.ok(!JSON.stringify(context).includes("private-prompt")); seen.push(name);
    }]));
    const response = await nativeGenerationFetch(req(), f.env, f.ctx, { route: "/codex-easy/v1/chat/completions", principal: { id: "trusted" }, provider: "codex-easy" }, async () => new Response('{"usage":{"input_tokens":0,"output_tokens":0}}'), [hooks]);
    await response.text(); await f.flush();
    assert.deepEqual(seen, enabled === "false" ? [] : ["authorize", "admit", "before_dispatch", "observe", "finalize"]);
  }
});

test("upstream exceptions, body failures and abort finalize once without hiding errors", async () => {
  const f = fixture();
  const authority = { route: "/codex-easy/v1/chat/completions", provider: "codex-easy", principal: { id: "trusted" } };
  await assert.rejects(nativeGenerationFetch(req(), f.env, f.ctx, authority, async () => { throw new Error("transport failed"); }), /transport failed/);
  await f.flush(); assert.equal(f.rows.length, 1); assert.equal(f.rows[0].status, 502);
  const events = [];
  const failed = await observeNativeResponse(new Response(new ReadableStream({ pull(controller) { controller.error(new Error("body failed")); } })), { provider: "codex-easy" }, { finalize: event => events.push(event) });
  await assert.rejects(failed.text(), /body failed/); assert.equal(events.length, 1); assert.equal(events[0].outcome, "transport_error");
  const abortEvents = [], abort = new AbortController();
  const hanging = await observeNativeResponse(new Response(new ReadableStream({ pull() {} })), { provider: "linkapi" }, { signal: abort.signal, finalize: event => abortEvents.push(event) });
  const reading = hanging.text(); abort.abort(); await assert.rejects(reading, { name: "AbortError" });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(abortEvents.length, 1); assert.equal(abortEvents[0].usage_basis, "unknown");
});

test("simultaneous native requests each write exactly one independent row", async () => {
  const f = fixture(); const authority = { route: "/codex-easy/v1/chat/completions", provider: "codex-easy", principal: { id: "trusted" } };
  await Promise.all(Array.from({ length: 8 }, async () => {
    const response = await nativeGenerationFetch(req(), f.env, f.ctx, authority, async () => new Response('{"usage":{"input_tokens":1,"output_tokens":1}}'));
    await response.text();
  }));
  await f.flush(); assert.equal(f.rows.length, 8); assert.equal(new Set(f.rows.map(row => row.request_id)).size, 8);
});

test("malformed flag warns once without its value, and storage failures preserve response", async () => {
  const original = console.error, logs = []; console.error = value => logs.push(value);
  try {
    const f = fixture(); f.env.NATIVE_EDGE_METRICS_ENABLED = "private-invalid";
    for (let i = 0; i < 2; i++) {
      const response = await nativeGenerationFetch(req(), f.env, f.ctx, { provider: "linkapi" }, async () => new Response("unchanged"));
      assert.equal(await response.text(), "unchanged");
    }
    assert.equal(logs.length, 1); assert.ok(!logs.join("").includes("private-invalid"));
    f.env.NATIVE_EDGE_METRICS_ENABLED = "true";
    f.env.INTELLIGENCE_DB.batch = async () => { throw new Error("private database detail"); };
    const raw = '{"usage":{"input_tokens":1,"output_tokens":1}}';
    const response = await upstream(new Response(raw), () => worker.fetch(req(), f.env, f.ctx));
    assert.equal(await response.text(), raw); await f.flush();
    assert.ok(logs.some(value => value.includes("native_usage_storage_failed"))); assert.ok(!logs.join("").includes("private database detail"));
  } finally { console.error = original; }
});


test("explicit estimate collaborator retains measured zero and marks estimated coverage", async () => {
  const events = [];
  const response = await observeNativeResponse(new Response('{"usage":{"input_tokens":0}}'), { provider: "linkapi", model: "test-model" }, {
    usageEstimate: { input_tokens: 99, output_tokens: 2 }, env: { MODEL_PRICING_USD_PER_MILLION: '{"linkapi:test-model":{"input":1,"output":1}}' }, finalize: event => events.push(event),
  });
  await response.text(); assert.equal(events[0].input_tokens, 0); assert.equal(events[0].output_tokens, 2);
  assert.equal(events[0].usage_basis, "estimated"); assert.equal(events[0].cost_basis, "estimate");
  const unknown = [];
  const missing = await observeNativeResponse(new Response('{}'), { provider: "linkapi" }, { usageEstimate: { input_tokens: 2, output_tokens: 2 }, finalize: event => unknown.push(event) });
  await missing.text(); assert.equal(unknown[0].outcome, "unknown"); assert.equal(unknown[0].usage_basis, "unknown");
});

test("multiline UTF-8 SSE and large JSON keep bounds and original bytes", async () => {
  const parser = createUsageObserver(true), raw = 'data: {"usage":\r\ndata: {"input_tokens":0,"output_tokens":0}}\r\n\r\ndata: [DONE]\r\n\r\n';
  const bytes = encoder.encode(raw); for (const byte of bytes) { parser.feed(new Uint8Array([byte])); assert.ok(parser.carryBytes <= 65536); }
  assert.deepEqual(parser.finish().usage, { input_tokens: 0, output_tokens: 0 });
  const events = [], big = JSON.stringify({ output: "漢".repeat(40000), usage: { input_tokens: 2, output_tokens: 3 } });
  const response = await observeNativeResponse(new Response(big), { provider: "linkapi" }, { finalize: event => events.push(event) });
  assert.equal(await response.text(), big); assert.equal(events[0].usage_basis, "unknown"); assert.equal(events[0].cost_usd, null);
});

test("all finalizers run once even if a collaborator fails", async () => {
  let calls = 0;
  const lifecycle = createGatewayLifecycle([{ finalize() { throw new Error("hook failed"); } }, { finalize() { calls++; } }]);
  await assert.rejects(lifecycle.finalize({}), /hook failed/); await assert.rejects(lifecycle.finalize({}), /hook failed/);
  assert.equal(calls, 1);
});

test("native ledger statements preserve nullable usage and batch idempotency in SQLite", async () => {
  const statements = [];
  const env = { INTELLIGENCE_DB: {
    prepare(sql) { return { bind(...values) { return { sql, values }; } }; },
    async batch(batch) { statements.push(...batch); return [{ meta: { changes: 1 } }]; },
  } };
  const event = { provider: "codex-easy", model: "test-model", principal: "edge:trusted", endpoint: "/codex-easy/v1/chat/completions",
    status: 520, duration_ms: 9, input_tokens: 0, output_tokens: null, cost_usd: null, cost_basis: null, requestId: crypto.randomUUID() };
  await recordNativeUsage(env, event); await recordNativeUsage(env, event);
  const schema = (await Promise.all(["0003_control_users.sql", "0007_usage_ledger.sql"].map(name =>
    readFile(new URL(`../intelligence-migrations/${name}`, import.meta.url), "utf8")))).join("\n");
  const code = `import json,sqlite3,sys
payload=json.loads(sys.argv[1])
db=sqlite3.connect(":memory:")
db.executescript(payload["schema"])
for statement in payload["statements"]:
    db.execute(statement["sql"],statement["values"])
print(json.dumps({"events":db.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0],"usage":db.execute("SELECT input_tokens,output_tokens,cost_usd FROM usage_events").fetchone(),"daily":db.execute("SELECT requests,errors,priced_requests FROM usage_daily").fetchone()}))`;
  const result = await new Promise((resolve, reject) => {
    const child = spawn("python3",
      ["-I", "-c", code, JSON.stringify({ schema, statements })], {
        cwd: new URL("../", import.meta.url), stdio: ["ignore", "pipe", "pipe"], timeout: 10000,
      });
    let stdout = "", stderr = "";
    child.stdout.on("data", value => { stdout += value; });
    child.stderr.on("data", value => { stderr += value; });
    child.on("error", reject);
    child.on("close", status => resolve({ status, stdout, stderr }));
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.deepEqual(JSON.parse(result.stdout), { events: 1, usage: [0, null, null], daily: [1, 1, 0] });
});

test("malformed optional provider fields never change native bytes or error semantics", async () => {
  for (const choices of [{}, [null], "invalid"]) {
    const raw = JSON.stringify({ usage: { input_tokens: 1, output_tokens: 0 }, choices });
    const response = await observeNativeResponse(new Response(raw), { provider: "linkapi" });
    assert.equal(await response.text(), raw);
  }
});

// Run unchanged existing tests with the same in-memory import registration when requested.
if (process.env.W18_EXISTING_REGRESSIONS === "true") {
  for (const name of ["test_cloudflare_worker.mjs", "test_prometheus_worker.mjs", "test_opencode_reasoning_worker.mjs",
    "test_opencode_thinking_worker.mjs", "test_sse_heartbeat_worker.mjs"]) {
    const url = new URL(`./${name}`, import.meta.url);
    const source = (await readFile(url, "utf8")).replaceAll("import.meta.url", JSON.stringify(url.href))
      .replace(/from\s+"(\.\.?\/[^"\n]+)"/g, (_, path) => `from "${path === "./helpers/load_cloudflare_worker.mjs"
        ? registeredHelperUrl : new URL(path, url).href}"`);
    await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
  }
}
