import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { nativeGenerationFetch, forwardedGenerationHeaders, nativeGenerationSetup, generationErrorResponse } from "../worker/gateway-extensions.mjs";
import { runScheduledMaintenance, scheduledMaintenanceEnabled, collectAlertAggregates } from "../worker/scheduled-maintenance.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { handleAlertState, normalizeAlertRules } from "../worker/alert-delivery.mjs";
import { retentionRequestId } from "../worker/retention-policy.mjs";
import { generationDeadlineHook } from "../worker/generation-deadline.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const authority = { route: "/openai/v1/chat/completions", provider: "openai", principal: { id: "admin" } };
const completed = JSON.stringify({ choices: [{ message: { content: "fixture" }, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 2 } });
const request = (headers = {}, payload = {}, signal) => new Request("https://provider.invalid/v1/chat/completions", {
  method: "POST", headers: { "content-type": "application/json", ...headers }, signal,
  body: JSON.stringify({ model: "test", temperature: 0, messages: [{ role: "user", content: "private prompt" }], ...payload }),
});
const response = () => new Response(completed, { headers: { "content-type": "application/json" } });
const flags = { GENERATION_CACHE_BACKEND: "d1-r2", GENERATION_CACHE_SHARED_ENABLED: "true",
  USAGE_RESERVATIONS_ENABLED: "true", GATEWAY_ALERTS_ENABLED: "true", GENERATION_DEADLINE_MAX_MS: "300000" };
function fixture(t, extra = {}) {
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  for (const name of ["0003_control_users.sql", "0007_usage_ledger.sql", "0019_generation_cache.sql", "0020_usage_reservations.sql", "0022_gateway_alerts.sql"]) {
    sql.exec(readFileSync(new URL(`../intelligence-migrations/${name}`, import.meta.url), "utf8"));
  }
  const operations = [];
  const db = { prepare(query) {
    let values = [];
    const run = () => {
      operations.push(query);
      const numbered = /\?[1-9]/.test(query);
      const statement = sql.prepare(query.replace(/\?(\d+)/g, (_, n) => `$v${n}`));
      const args = numbered ? [Object.fromEntries(values.map((v, i) => [`v${i + 1}`, v]))] : values;
      const rows = statement.columns().length ? statement.all(...args) : (statement.run(...args), []);
      return { success: true, results: rows.map(r => ({ ...r })), meta: { changes: sql.prepare("SELECT changes() AS n").get().n } };
    };
    const statement = { bind(...args) { values = args; return statement; }, async all() { return run(); },
      async run() { return run(); }, async first() { return run().results[0] ?? null; } };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const results = []; for (const s of statements) results.push(await s.all()); sql.exec("COMMIT"); return results; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const objects = new Map();
  const bucket = { async put(key, value, options) { objects.set(key, { value, customMetadata: options.customMetadata }); },
    async get(key) { const item = objects.get(key); return item ? { size: item.value.length, arrayBuffer: async () => item.value } : null; },
    async delete(key) { objects.delete(key); }, async list() { return { objects: [], truncated: false }; } };
  const env = { ...flags, ADMIN_API_KEY: "synthetic-key", MODEL_PRICING_USD_PER_MILLION: '{"openai:test":{"input":1,"output":2}}',
    INTELLIGENCE_DB: db, multillm_media: bucket, ...extra };
  const budgetAuthority = { ...authority, principal: { id: "admin", daily_budget_usd: 1, monthly_budget_usd: 10 } };
  return { env, sql, operations, objects, authority: budgetAuthority };
}
const reservations = f => f.sql.prepare("SELECT state, basis, charged_units, input_tokens, output_tokens FROM usage_reservations").all();

test("all flags off leave native bytes, outbound headers and storage unchanged", async () => {
  let submitted;
  const req = request({ "x-extra": "fixture" });
  const res = await nativeGenerationFetch(req, {}, {}, authority, r => { submitted = r; return response(); });
  assert.equal(await res.text(), completed); assert.deepEqual([...submitted.headers], [...req.headers]);
  assert.deepEqual([...forwardedGenerationHeaders(req, {})], [...req.headers]);
  const touched = { INTELLIGENCE_DB: { prepare() { throw Error("disabled storage"); } } };
  assert.deepEqual(await runScheduledMaintenance(touched), { cache_batches: 0, alerts: null });
  assert.equal(scheduledMaintenanceEnabled(touched), false);
  assert.equal(scheduledMaintenanceEnabled({ GENERATION_CACHE_BACKEND: "d1-r2", GENERATION_CACHE_SHARED_ENABLED: "true" }), true);
  assert.equal(scheduledMaintenanceEnabled({ GATEWAY_ALERTS_ENABLED: "true" }), true);
  for (const path of ["/v1/state/alerts", "/v1/reservations", "/v1/managed-state/reservations", "/v1/managed-state/tool-grants"]) {
    assert.equal((await handleIntelligenceOutbound(new Request(`http://intelligence.internal${path}`, { method: "POST" }), touched)).status, 404);
  }
});

test("forwarding strips spoofed budgets and adds the remaining time", () => {
  const req = request({ "X-MultiLLM-Deadline-Ms": "1000", "X-MultiLLM-Internal-Deadline-Ms": "1" });
  const headers = forwardedGenerationHeaders(req, {});
  assert.equal(headers.get("X-MultiLLM-Deadline-Ms"), "1000");
  assert.ok(Number(headers.get("X-MultiLLM-Internal-Deadline-Ms")) <= 1000);
  assert.equal(forwardedGenerationHeaders(request({ "X-MultiLLM-Internal-Deadline-Ms": "1" }), {}).has("X-MultiLLM-Internal-Deadline-Ms"), false);
});

test("deadline covers asynchronous native setup before provider submission", async () => {
  let calls = 0;
  const hooks = [{ enabled: () => true, authorize: () => new Promise(() => {}) }];
  const res = await nativeGenerationFetch(request({ "X-MultiLLM-Deadline-Ms": "15" }), {}, {}, authority,
    () => { calls++; return response(); }, hooks);
  assert.equal(res.status, 504); assert.equal((await res.json()).error.code, "generation_deadline_exceeded"); assert.equal(calls, 0);
});

test("deadline after stream commitment emits a protocol error without DONE", async () => {
  const req = request({ "X-MultiLLM-Deadline-Ms": "100" }, { stream: true });
  let now = 0, reads = 0;
  const hook = generationDeadlineHook(req, {}, { now: () => now });
  const stream = new ReadableStream({ pull(controller) {
    if (++reads === 1) controller.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{"content":"fixture"}}]}\n\n'));
    else { now = 101; controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n")); }
  } }, { highWaterMark: 0 });
  const res = await nativeGenerationFetch(req, {}, {}, { ...authority, deadlineHook: hook },
    () => new Response(stream, { headers: { "content-type": "text/event-stream" } }));
  const text = await res.text(); assert.match(text, /generation_deadline_exceeded/); assert.doesNotMatch(text, /\[DONE\]/);
});

test("scheduled cleanup carries the cursor but stops at three batches", async () => {
  const calls = [];
  const result = await runScheduledMaintenance({ GENERATION_CACHE_BACKEND: "d1-r2", GENERATION_CACHE_SHARED_ENABLED: "true" }, {
    cleanup: async (env, options) => { calls.push(options); return { cursor: `page-${calls.length}` }; },
  });
  assert.equal(result.cache_batches, 3); assert.deepEqual(calls, [{ limit: 100, cursor: undefined }, { limit: 100, cursor: "page-1" }, { limit: 100, cursor: "page-2" }]);
});

test("one scheduled failure does not suppress alert delivery", async () => {
  let deliveries = 0;
  const result = await runScheduledMaintenance(flags, { cleanup: async () => { throw Error("storage"); },
    deliver: async (env, options) => { deliveries++; assert.equal(typeof options.collect, "function"); assert.equal(typeof options.transport, "function"); return { attempted: 0 }; } });
  assert.equal(deliveries, 1); assert.equal(result.cache_batches, 0);
});

test("reservations alone settle measured flat finalization and preserve bytes", async t => {
  const f = fixture(t, { GENERATION_CACHE_SHARED_ENABLED: "false", GATEWAY_ALERTS_ENABLED: "false" });
  const res = await nativeGenerationFetch(request(), f.env, {}, f.authority, response);
  assert.equal(reservations(f)[0].state, "dispatched"); assert.equal(await res.text(), completed);
  assert.equal(reservations(f)[0].state, "settled"); assert.equal(reservations(f)[0].charged_units, 70000);
});

test("all flags on cache hit releases a reservation and makes no provider call", async t => {
  const f = fixture(t); let calls = 0;
  const fetcher = () => { calls++; return response(); };
  for (let i = 0; i < 2; i++) {
    const res = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on", "X-MultiLLM-Deadline-Ms": "1000" }), f.env, {}, f.authority, fetcher);
    assert.equal(await res.text(), completed);
    assert.equal(res.headers.get("X-MultiLLM-Cache"), i ? "hit" : "miss");
  }
  assert.equal(calls, 1); assert.deepEqual(reservations(f).map(r => [r.state, r.basis]), [["settled", "provider"], ["settled", "released"]]);
});

test("all flags on deadline after handoff retains unknown hold and bypasses cache", async t => {
  const f = fixture(t);
  const res = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on", "X-MultiLLM-Deadline-Ms": "20" }), f.env, {}, f.authority, () => new Promise(() => {}));
  assert.equal(res.status, 504); await res.text();
  assert.equal(reservations(f)[0].state, "unknown"); assert.equal(f.objects.size, 0);
});

test("registered native routes retain transformed upstream URLs under a deadline", async () => {
  const { default: worker } = await loadWorkerModule();
  const env = { ADMIN_API_KEY: "synthetic-key", CODEX_EASY_API_KEY: "synthetic-upstream", LINKAPI_KEY: "synthetic-upstream",
    OPENCODE_GO_API_KEY: "synthetic-upstream", OPENCODE_EDGE_FETCH: "true" };
  const original = globalThis.fetch, outbound = [];
  globalThis.fetch = async req => { outbound.push(req); return response(); };
  try {
    for (const provider of ["codex-easy", "linkapi", "opencode"]) {
      const req = new Request(`https://gateway.example/${provider}/v1/chat/completions`, {
        method: "POST", headers: { authorization: "Bearer synthetic-key", "content-type": "application/json", "X-MultiLLM-Deadline-Ms": "1000" },
        body: JSON.stringify({ model: "test", messages: [] }),
      });
      const res = await worker.fetch(req, env, { waitUntil() {} });
      assert.equal(res.status, 200); assert.equal(await res.text(), completed);
      assert.notEqual(new URL(outbound.at(-1).url).hostname, "gateway.example");
      assert.equal(outbound.at(-1).headers.has("X-MultiLLM-Deadline-Ms"), false);
    }
  } finally { globalThis.fetch = original; }
});

test("registered forwarding does not acquire native reservations or admission", async () => {
  const { default: worker } = await loadWorkerModule(); let forwarded;
  const env = { ...flags, ADMISSION_ENABLED: "true", INTELLIGENCE_DB: { prepare() { assert.fail("forwarded native storage"); } },
    MULTILLM_PROXY_CONTAINER: { getByName: () => ({ async fetch(req) { forwarded = req; return response(); } }) } };
  const res = await worker.fetch(new Request("https://gateway.example/v1/chat/completions", {
    method: "POST", body: "{}", headers: { "X-MultiLLM-Deadline-Ms": "1000", "X-MultiLLM-Internal-Deadline-Ms": "1" },
  }), env, { waitUntil() {} });
  assert.equal(await res.text(), completed);
  assert.equal(forwarded.headers.get("X-MultiLLM-Deadline-Ms"), "1000");
  assert.ok(Number(forwarded.headers.get("X-MultiLLM-Internal-Deadline-Ms")) > 1);
});

test("all flags on enforce admission before lookup, hold before dispatch and settlement last", async t => {
  const f = fixture(t, { ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
  const order = [];
  f.env.ADMISSION_COORDINATOR = { getByName: () => ({ async fetch(req) {
    const body = await req.json(); order.push(body.operation);
    return Response.json({ version: 1, ...(body.operation === "release" ? { released: true }
      : { lease: { lease_id: "a".repeat(32), expires_at: Math.min(Date.now() + 29000, body.deadline_ms) } }) });
  } }) };
  const base = f.env.INTELLIGENCE_DB.prepare;
  f.env.INTELLIGENCE_DB.prepare = query => {
    if (query.startsWith("SELECT * FROM generation_cache")) order.push("cache");
    if (query.includes("INSERT INTO usage_reservations")) order.push("reserve");
    return base(query);
  };
  const res = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on", "X-MultiLLM-Deadline-Ms": "1000" }), f.env, {}, f.authority, req => {
    order.push("dispatch"); assert.equal(reservations(f)[0].state, "dispatched"); assert.equal(req.signal.aborted, false); return response();
  });
  assert.equal(await res.text(), completed);
  assert.ok(order.indexOf("acquire") < order.indexOf("reserve"));
  assert.ok(order.indexOf("cache") < order.indexOf("reserve"));
  assert.ok(order.indexOf("reserve") < order.indexOf("dispatch"));
  assert.equal(order.at(-1), "release"); assert.equal(reservations(f)[0].state, "settled");
});

test("all flags on pre-handoff expiry releases the hold and suppresses dispatch", async t => {
  const f = fixture(t); let calls = 0, now = 0;
  const req = request({ "X-MultiLLM-Deadline-Ms": "100", "X-MultiLLM-Cache": "on" });
  const hook = generationDeadlineHook(req, f.env, { now: () => now });
  const res = await nativeGenerationFetch(req, f.env, {}, { ...f.authority, deadlineHook: hook }, () => { calls++; return response(); },
    [{ enabled: () => true, before_dispatch() { now = 101; } }]);
  assert.equal(res.status, 504); assert.equal(calls, 0); assert.equal(reservations(f)[0].basis, "released"); assert.equal(f.objects.size, 0);
});

test("cancellation after handoff keeps the hold and nullable counters", async t => {
  const f = fixture(t), controller = new AbortController();
  const res = await nativeGenerationFetch(request({}, {}, controller.signal), f.env, {}, f.authority,
    () => new Response(new ReadableStream({ pull() {} })));
  controller.abort(); await assert.rejects(res.text(), { name: "AbortError" });
  await new Promise(resolve => setImmediate(resolve));
  const row = reservations(f)[0]; assert.equal(row.state, "unknown"); assert.equal(row.input_tokens, null); assert.equal(row.output_tokens, null);
});

test("missing usage and error responses never become native shared cache successes", async t => {
  const f = fixture(t);
  for (const res of [Response.json({ choices: [{ message: { content: "fixture" }, finish_reason: "stop" }] }),
    Response.json({ error: { code: "output_schema_violation" } }, { status: 502 })]) {
    const actual = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on" }), f.env, {}, f.authority, () => res);
    await actual.text(); assert.equal(f.objects.size, 0);
  }
  assert.deepEqual(reservations(f).map(r => r.state), ["unknown", "unknown"]);
});

test("unpriced eligible candidates and absent reservation tables fail before handoff", async t => {
  const f = fixture(t); let calls = 0;
  const res = await nativeGenerationFetch(request(), f.env, {}, { ...f.authority, eligibleModels: ["test", "unpriced"] },
    () => { calls++; return response(); });
  assert.equal(res.status, 503); assert.equal((await res.json()).error.code, "unpriced_reservation"); assert.equal(calls, 0);
  const unavailable = { ...f.env, INTELLIGENCE_DB: { prepare() { throw Error("private detail"); } } };
  const failed = await nativeGenerationFetch(request(), unavailable, {}, f.authority, () => { calls++; return response(); });
  assert.equal(failed.status, 503); assert.doesNotMatch(await failed.text(), /private detail/); assert.equal(calls, 0);
});

test("registered native bootstrap metadata applies monetary limits and seeds legacy spend", async t => {
  const f = fixture(t, { GENERATION_CACHE_SHARED_ENABLED: "false" });
  f.sql.exec("INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at,daily_budget_usd) VALUES ('admin','synthetic','fixture','',1,'2026-10-09',1)");
  const identity = `edge:${await retentionRequestId("native-admin:admin")}`, day = new Date().toISOString().slice(0, 10);
  f.sql.prepare("INSERT INTO usage_daily(day,principal,model,cost_usd) VALUES (?,?,?,?)").run(day, identity, "openai:test", 0.25);
  const res = await nativeGenerationFetch(request(), f.env, {}, authority, response); await res.text();
  assert.equal(reservations(f)[0].state, "settled");
  assert.equal(f.sql.prepare("SELECT baseline_units FROM usage_reservation_budgets WHERE period=?").get(day).baseline_units, 2500000000);
});

test("alert collector returns only UTC ledger aggregates; Flask owns provider observations", async t => {
  const f = fixture(t);
  f.sql.exec("INSERT INTO usage_daily(day,principal,model,requests,cost_usd,priced_requests) VALUES ('2026-10-09','fixture','test',4,9,3)");
  const rules = await normalizeAlertRules([{ kind: "spend", period: "day", budget_usd: 1 },
    { kind: "unknown_price", period: "month" }, { kind: "provider_health", provider: "openai" }]);
  const rows = await collectAlertAggregates(f.env, rules, new Date("2026-10-09T12:00:00Z"));
  assert.deepEqual(rows.map(r => [r.value, r.basis, r.window]), [[9, "gateway_cost_estimate", "2026-10-09"], [25, "unknown_price_coverage", "2026-10"]]);
  assert.ok(rows.every(r => Object.keys(r).sort().join() === "basis,rule_id,value,window"));
  assert.doesNotMatch(JSON.stringify(rows), /fixture|prompt|content|recipient/);
});

test("scheduled alert transport rejects redirects and sends bounded content-free observations", async t => {
  const f = fixture(t, { GENERATION_CACHE_SHARED_ENABLED: "false", GATEWAY_ALERT_WEBHOOK_ALLOWLIST: '["https://hooks.example"]' });
  f.sql.exec(`INSERT INTO usage_daily(day,principal,model,requests,cost_usd,priced_requests) VALUES ('${new Date().toISOString().slice(0, 10)}','fixture','test',1,10,1)`);
  const configured = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/state/alerts", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "configure", revision: 0,
      configuration: { destination: "https://hooks.example/private-recipient", rules: [{ kind: "spend", period: "day", budget_usd: 1 }] } }),
  }), f.env);
  assert.equal(configured.status, 200);
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = async (url, options) => {
    calls++; assert.equal(options.redirect, "error"); assert.ok(options.signal instanceof AbortSignal);
    assert.ok(new TextEncoder().encode(options.body).length <= 8192); assert.doesNotMatch(options.body, /fixture|prompt|content|recipient/);
    return new Response(null, { status: 302, headers: { location: "https://other.example" } });
  };
  try { const result = await runScheduledMaintenance(f.env); assert.ok(result.alerts.attempted <= 10); assert.equal(result.alerts.delivered, 0); }
  finally { globalThis.fetch = original; }
  assert.equal(calls, 2);
  assert.ok(f.sql.prepare("SELECT error_code FROM gateway_alert_events").all().every(r => r.error_code === "delivery_failed"));
});

test("private alerts and reservations fail closed on missing schema without exposing details", async () => {
  const env = { ...flags, INTELLIGENCE_DB: { prepare() { throw Error("private schema detail"); }, batch() {} } };
  for (const [path, body, code] of [["/v1/state/alerts", { operation: "get" }, "gateway_alert_storage_unavailable"],
    ["/v1/reservations", { operation: "summary", principal: "fixture" }, "usage_reservations_unavailable"]]) {
    const res = await handleIntelligenceOutbound(new Request(`http://intelligence.internal${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
    }), env);
    assert.equal(res.status, 503); assert.equal((await res.json()).error.code, code);
  }
});

test("zero retention with all flags on stores no shared response", async t => {
  const f = fixture(t, { CONTENT_RETENTION_ENABLED: "true" });
  const res = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on", "X-MultiLLM-Retention": "zero" }), f.env, {}, f.authority, response);
  assert.equal(await res.text(), completed); assert.equal(f.objects.size, 0);
});

test("zero-cost cache hit does not require a current provider price", async t => {
  const f = fixture(t); let calls = 0;
  const fetcher = () => { calls++; return response(); };
  const first = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on" }), f.env, {}, f.authority, fetcher); await first.text();
  f.env.MODEL_PRICING_USD_PER_MILLION = "{}";
  const hit = await nativeGenerationFetch(request({ "X-MultiLLM-Cache": "on" }), f.env, {}, f.authority, fetcher);
  assert.equal(await hit.text(), completed); assert.equal(calls, 1); assert.equal(reservations(f)[1].basis, "released");
});

test("conflicting output limits reserve the largest eligible exposure", async t => {
  const f = fixture(t, { GENERATION_CACHE_SHARED_ENABLED: "false" });
  const req = request({}, { max_tokens: 1, max_completion_tokens: 100 });
  const size = new TextEncoder().encode(await req.clone().text()).length;
  const res = await nativeGenerationFetch(req, f.env, {}, f.authority, response);
  const hold = f.sql.prepare("SELECT amount_units FROM usage_reservations").get();
  assert.ok(hold.amount_units >= (size + 200) * 10000); await res.text();
});

test("Gemini native budgets use the URL model and retain unclassified usage", async t => {
  const f = fixture(t, { GENERATION_CACHE_SHARED_ENABLED: "false", MODEL_PRICING_USD_PER_MILLION: '{"linkapi:test":{"input":1,"output":2}}' });
  const req = new Request("https://provider.invalid/v1beta/models/test:generateContent", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ contents: [], generationConfig: { maxOutputTokens: 10 } }),
  });
  const res = await nativeGenerationFetch(req, f.env, {}, { ...f.authority, provider: "linkapi", route: "/linkapi/v1beta/models/test:generateContent" },
    () => Response.json({ candidates: [{ content: { parts: [{ text: "fixture" }] }, finishReason: "STOP" }], usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 2 } }));
  assert.equal(res.status, 200); await res.text();
  assert.equal(reservations(f)[0].state, "unknown"); assert.equal(reservations(f)[0].input_tokens, null);
});

test("stale security rejects before parsing a native deadline or starting setup", () => {
  assert.throws(() => nativeGenerationSetup(request({ "X-MultiLLM-Deadline-Ms": "invalid" }), { CONFIG_REVISION_SYNC_ENABLED: "true" }), error => {
    assert.equal(generationErrorResponse(error)?.status, 503); return true;
  });
});

test("registered OpenCode normalization preserves a deadline stream error without DONE", async () => {
  const { default: worker } = await loadWorkerModule();
  const env = { ADMIN_API_KEY: "synthetic-key", OPENCODE_GO_API_KEY: "synthetic-upstream", OPENCODE_EDGE_FETCH: "true" };
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    let sent = false;
    return new Response(new ReadableStream({ pull(controller) {
      if (!sent) { sent = true; controller.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{"content":"fixture"}}]}\n\n')); }
    } }, { highWaterMark: 0 }), { headers: { "content-type": "text/event-stream" } });
  };
  try {
    const res = await worker.fetch(new Request("https://gateway.example/opencode/v1/chat/completions", {
      method: "POST", headers: { authorization: "Bearer synthetic-key", "content-type": "application/json", "X-MultiLLM-Deadline-Ms": "100" },
      body: JSON.stringify({ model: "test", messages: [], stream: true }),
    }), env, { waitUntil() {} });
    assert.equal(res.status, 200); const text = await res.text();
    assert.match(text, /generation_deadline_exceeded/); assert.doesNotMatch(text, /\[DONE\]/);
  } finally { globalThis.fetch = original; }
});
