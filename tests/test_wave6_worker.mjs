import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { nativeGenerationFetch, withForwardedCorrelation } from "../worker/gateway-extensions.mjs";
import { ObservationWindow } from "../worker/latency-slo.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { DatabaseSync } from "node:sqlite";
import { handleReservationsRequest } from "../worker/reservations-d1.mjs";
import { activeUsersByPrefix } from "../worker/control-users-d1.mjs";
import { renderNativeMetrics } from "../worker/request-telemetry.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const route = "/codex-easy/v1/chat/completions", now = Date.now();
const auth = { authenticated: true, route, provider: "codex-easy", keyId: "admin", principal: { id: "admin" } };
const payload = { model: "m", messages: [{ role: "user", content: "fixture" }], max_tokens: 100 };
const request = (changes = {}, headers = {}) => new Request("https://provider.invalid/v1/chat/completions", {
  method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ ...payload, ...changes }) });
const complete = text => Response.json({ choices: [{ message: { content: text }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 2 } });
const encoder = new TextEncoder();
const frame = value => "data: " + JSON.stringify(value) + "\n\n";
const delta = text => frame({ choices: [{ delta: { content: text } }] });
function source(chunks) {
  let cancels = 0;
  return { response: new Response(new ReadableStream({ pull(c) { chunks.length ? c.enqueue(encoder.encode(chunks.shift())) : c.close(); },
    cancel() { cancels++; } }, { highWaterMark: 0 }), { headers: { "content-type": "text/event-stream" } }), cancels: () => cancels };
}
const slo = (mode = "reject") => ({ LATENCY_SLO_MODE: mode, LATENCY_SLO_MIN_SAMPLES: "1",
  LATENCY_SLO_POLICY_JSON: JSON.stringify({ keys: { admin: { deadline_ms: 1000, require_coverage: true } } }) });
const cost = { STREAM_COST_BREAKER_ENABLED: "true", MODEL_PRICING_USD_PER_MILLION:
  JSON.stringify({ "codex-easy:m": { input: 0, cache_read: 0, cache_write: 0, output: 1 } }) };
const canary = mode => ({ CONTEXT_CANARY_MODE: mode, CONTEXT_CANARY_POLICY_JSON: JSON.stringify({ routes: [route] }) });
function admission() {
  return { ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}',
    ADMISSION_COORDINATOR: { getByName() { return { async fetch(req) {
      const body = await req.json();
      return Response.json({ version: 1, ...(body.operation === "acquire" ? {
        lease: { lease_id: "a".repeat(32), expires_at: Math.min(Date.now() + 1000, body.deadline_ms) } } : { released: true }) });
    } }; } } };
}
const events = list => [{ enabled: () => true, finalize: event => list.push(event) }];
const privateRequest = (path, body, headers = {}) => new Request("http://intelligence.internal" + path, {
  method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

test("disabled native streaming and nonstream bodies, headers and account reads stay unchanged", async () => {
  for (const streaming of [false, true]) {
    const upstream = streaming ? source([delta("ok"), "data: [DONE]\n\n"]).response : complete("ok");
    const expected = await upstream.clone().text(), headers = [...upstream.headers];
    const res = await nativeGenerationFetch(request({ stream: streaming }), { INTELLIGENCE_DB: { prepare() { assert.fail("storage"); } } }, {}, auth,
      async req => { assert.deepEqual(await req.json(), { ...payload, stream: streaming }); return upstream; });
    assert.equal(await res.text(), expected); assert.deepEqual([...res.headers], headers);
  }
  let query;
  await activeUsersByPrefix({ prepare(sql) { query = sql; return { bind() { return this; }, all() { return { results: [] }; } }; } }, "fixture", {});
  assert.doesNotMatch(query, /max_stream_cost/);
  const headers = new Headers({ "x-request-id": "fixture" });
  assert.equal(withForwardedCorrelation(headers, { ...slo(), ...cost, ...canary("block") }), headers);
  assert.deepEqual([...headers], [["x-request-id", "fixture"]]);
  for (const path of ["/v1/state/learned-cooldown", "/v1/managed-state/usage-receipts"])
    assert.equal((await handleIntelligenceOutbound(privateRequest(path, {}), {})).status, 404);
});

test("latency rejection runs before admission, cache, reservation, canary and dispatch", async () => {
  const store = new ObservationWindow(); store.record("codex-easy:m", { ttft_ms: 500, tokens_per_second: 1, now });
  const env = { ...slo(), ...cost, ...canary("block"), USAGE_RESERVATIONS_ENABLED: "true", ADMISSION_ENABLED: "true",
    GENERATION_CACHE_SHARED_ENABLED: "true", GENERATION_CACHE_BACKEND: "d1-r2", SEMANTIC_CACHE_ENABLED: "true",
    INTELLIGENCE_DB: { prepare() { assert.fail("storage before rejection"); } },
    ADMISSION_COORDINATOR: { getByName() { assert.fail("admission before rejection"); } } };
  const response = await nativeGenerationFetch(request(), env, {}, { ...auth, observations: store, now }, () => assert.fail("upstream"));
  assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "latency_slo_predicted_miss");
});

test("latency reroute dispatch receives only the approved eligible same-tier candidates", async () => {
  const store = new ObservationWindow(), candidates = [{ model: "codex-easy:slow", quality_tier: 1 },
    { model: "codex-easy:m", quality_tier: 1 }, { model: "codex-easy:other", quality_tier: 2 }];
  for (const [model, speed] of [["slow", 1], ["m", 1000], ["other", 1000]])
    store.record("codex-easy:" + model, { ttft_ms: 10, tokens_per_second: speed, now });
  const response = await nativeGenerationFetch(request({ model: "auto:fast" }), slo("reroute"), {},
    { ...auth, candidates, eligibleModels: candidates.map(c => c.model), observations: store, now }, async (req, _env, authority) => {
      assert.deepEqual(authority.candidates, [candidates[1]]); assert.deepEqual(authority.eligibleModels, ["codex-easy:m"]);
      assert.equal((await req.json()).model, "codex-easy:m"); return complete("ok");
    });
  assert.equal(response.status, 200); await response.text(); assert.equal(candidates.length, 3);
});

test("capped native streams reject missing pricing before upstream", async () => {
  const response = await nativeGenerationFetch(request({ stream: true }), { STREAM_COST_BREAKER_ENABLED: "true" }, {},
    { ...auth, principal: { id: "admin", max_stream_cost_microusd: 10 } }, () => assert.fail("upstream"));
  assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "stream_cost_unpriced");
});

test("a capped oversized streaming payload cannot bypass preflight inspection", async () => {
  const req = request({ stream: true, messages: [{ role: "user", content: "x".repeat(65536) }] });
  const response = await nativeGenerationFetch(req, { ...cost, INTELLIGENCE_DB: { prepare(sql) {
    assert.match(sql, /SELECT max_stream_cost_microusd/);
    return { bind() { return this; }, first() { return { max_stream_cost_microusd: 10 }; } };
  } } }, {}, auth, () => assert.fail("upstream before bounded capped preflight"));
  assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "stream_cost_unpriced");
});

test("stream cost stop delivers one error and one cancel and retains ambiguous accounting", async () => {
  const upstream = source([delta("four"), delta("too-much"), "data: [DONE]\n\n"]), seen = [];
  const response = await nativeGenerationFetch(request({ stream: true }), cost, {},
    { ...auth, principal: { id: "admin", max_stream_cost_microusd: 4 } }, () => upstream.response, events(seen));
  const text = await response.text();
  assert.equal((text.match(/"code":"stream_cost_cap_exceeded"/g) ?? []).length, 1);
  assert.doesNotMatch(text, /too-much|\[DONE\]/); assert.equal(upstream.cancels(), 1);
  assert.equal(seen.length, 1); assert.equal(seen[0].outcome, "canceled"); assert.equal(seen[0].cancellationOutcome.ambiguous, true);
});

test("cost policy leaves nonstream malformed payloads alone and classifies stopped metrics before counting", async () => {
  const malformed = new Request("https://provider.invalid/v1/chat/completions", { method: "POST", body: "fixture-invalid" });
  const passthrough = await nativeGenerationFetch(malformed, cost, {}, auth, async req => {
    assert.equal(await req.text(), "fixture-invalid"); return complete("ok");
  });
  assert.equal(passthrough.status, 200); await passthrough.text();
  const count = () => Number(renderNativeMetrics().match(/multillm_native_requests_total\{provider="codex-easy",outcome="canceled"\} (\d+)/)?.[1] ?? 0);
  const before = count(), original = console.error; console.error = () => {};
  try {
    const response = await nativeGenerationFetch(request({ stream: true }), { ...cost, NATIVE_EDGE_METRICS_ENABLED: "true" }, {},
      { ...auth, principal: { id: "admin", max_stream_cost_microusd: 4 } }, () => source([delta("too-much"), "data: [DONE]\n\n"]).response);
    await response.text(); assert.equal(count(), before + 1);
  } finally { console.error = original; }
});

for (const mode of ["log", "block"]) test("native canary " + mode + " scans before accounting and bypasses all shared caches", async () => {
  const seen = [], warnings = [], original = console.warn; let marker;
  console.warn = value => warnings.push(value);
  try {
    const response = await nativeGenerationFetch(request({ temperature: 0 }, { "X-MultiLLM-Cache": "on" }), {
      ...canary(mode), GENERATION_CACHE_SHARED_ENABLED: "true", GENERATION_CACHE_BACKEND: "d1-r2", SEMANTIC_CACHE_ENABLED: "true",
      INTELLIGENCE_DB: { prepare() { assert.fail("cache storage"); } } }, {}, auth, async req => {
        const body = await req.json(); marker = body.messages[0].content.match(/marker: ([a-f0-9]{32})/)[1];
        return complete("before " + marker + " after");
      }, events(seen));
    const text = await response.text(); assert.equal(response.status, mode === "block" ? 502 : 200);
    assert.doesNotMatch(text, new RegExp(marker)); assert.equal(warnings.length, 1);
    assert.ok(!JSON.stringify(seen).includes(marker)); assert.ok(!warnings.join().includes(marker));
    assert.equal(seen.length, 1); if (mode === "block") assert.equal(seen[0].cancellationOutcome.ambiguous, true);
  } finally { console.warn = original; }
});

test("all native flags preserve one late canary error, one cancel, no terminal or successful latency sample", async () => {
  const store = new ObservationWindow(); store.record("codex-easy:m", { ttft_ms: 1, tokens_per_second: 1000, now });
  let upstream, marker; const seen = [], warnings = [], original = console.warn; console.warn = value => warnings.push(value);
  try {
    const response = await nativeGenerationFetch(request({ stream: true }), { ...slo(), ...cost, ...canary("block") }, {},
      { ...auth, observations: store, now, principal: { id: "admin", max_stream_cost_microusd: 10 } }, async req => {
        marker = (await req.json()).messages[0].content.match(/marker: ([a-f0-9]{32})/)[1];
        upstream = source([delta("safe"), delta(marker), "data: [DONE]\n\n"]); return upstream.response;
      }, events(seen));
    const text = await response.text(); assert.equal((text.match(/"code":/g) ?? []).length, 1);
    assert.match(text, /context_canary_leak/); assert.doesNotMatch(text, /\[DONE\]/); assert.ok(!text.includes(marker));
    assert.equal(upstream.cancels(), 1); assert.equal(seen.length, 1); assert.notEqual(seen[0].outcome, "success");
    assert.equal(store.models.get("codex-easy:m").length, 1);
  } finally { console.warn = original; }
});

for (const streaming of [false, "early", "late"]) test("canary block survives active deadline and admission wrappers " + streaming, async () => {
  let upstream; const seen = [], original = console.warn; console.warn = () => {};
  try {
    const response = await nativeGenerationFetch(request({ stream: Boolean(streaming) }, { "X-MultiLLM-Deadline-Ms": "5000" }),
      { ...canary("block"), ...admission() }, {}, auth, async req => {
        const marker = (await req.json()).messages[0].content.match(/marker: ([a-f0-9]{32})/)[1];
        upstream = streaming ? source([...(streaming === "late" ? [delta("safe")] : []), delta(marker), "data: [DONE]\n\n"]) : { response: complete(marker) };
        return upstream.response;
      }, events(seen));
    const text = await response.text(); assert.match(text, /context_canary_leak/); assert.doesNotMatch(text, /\[DONE\]/);
    assert.equal((text.match(/"code":/g) ?? []).length, 1); assert.equal(seen.length, 1);
    if (streaming) assert.equal(upstream.cancels(), 1);
  } finally { console.warn = original; }
});

test("private learned cooldown dispatch supports get and put with bounded off-first gating", async () => {
  const path = "/v1/state/learned-cooldown", body = { version: 1, operation: "get", bucket_digest: "a".repeat(64), credential_digest: "b".repeat(64), now: 100 };
  const db = { prepare() { return { bind() { return this; }, first() { return null; } }; }, async batch() { return [{}, { meta: { changes: 1 } }]; } };
  const response = await handleIntelligenceOutbound(privateRequest(path, body), { LEARNED_COOLDOWN_MODE: "apply", INTELLIGENCE_DB: db });
  assert.equal(response.status, 200); assert.equal((await response.json()).entry, null);
  const entry = { credential_digest: body.credential_digest, lower_seconds: 1, upper_seconds: 10, trial_seconds: 1, samples: 0,
    consistent: 0, steps: 0, confident: false, last_kind: "none", last_throttle: null, last_observed: 100,
    floor_until: 0, created_at: 100, expires_at: 100 + 7 * 24 * 3600, revision: 1 };
  const put = await handleIntelligenceOutbound(privateRequest(path, { ...body, operation: "put", expected_revision: 0, entry }),
    { LEARNED_COOLDOWN_MODE: "shadow", INTELLIGENCE_DB: db });
  assert.equal(put.status, 200); assert.equal((await put.json()).stored, true);
  assert.equal((await handleIntelligenceOutbound(privateRequest(path, {}, { "content-length": "4097" }),
    { LEARNED_COOLDOWN_MODE: "apply", INTELLIGENCE_DB: db })).status, 400);
  assert.equal((await handleIntelligenceOutbound(new Request("http://intelligence.internal" + path, { method: "POST", body: "invalid" }), {})).status, 404);
});

test("hub dispatches realtime before generation setup and retains metering and Flask receipt forwarding", async () => {
  const source = await readFile(new URL("../cloudflare-worker.mjs", import.meta.url), "utf8");
  const fetchBody = source.slice(source.indexOf("const realtimeResponse = await handleRealtimeRequest"));
  assert.ok(fetchBody.indexOf("handleDirectKimiCodeRequest") > 0);
  assert.ok(!source.includes("handleUsageReceiptRequest"));
  const metering = await readFile(new URL("../worker/realtime-metering.mjs", import.meta.url), "utf8");
  assert.match(metering, /recordNativeUsage/);
});

test("registered direct routes authenticate before canary inspection and forwarded paths retain Flask ownership", async () => {
  const { default: worker } = await loadWorkerModule();
  const env = { ADMIN_API_KEY: "synthetic-key", CODEX_EASY_API_KEY: "synthetic-upstream", LINKAPI_KEY: "synthetic-upstream",
    OPENCODE_GO_API_KEY: "synthetic-upstream", OPENCODE_EDGE_FETCH: "true",
    CONTEXT_CANARY_MODE: "block", CONTEXT_CANARY_POLICY_JSON: JSON.stringify({ routes:
      ["codex-easy", "linkapi", "opencode"].map(provider => `/${provider}/v1/chat/completions`) }) };
  const originalFetch = globalThis.fetch, originalWarn = console.warn; let calls = 0;
  console.warn = () => {};
  globalThis.fetch = async req => {
    calls++; const body = await req.json();
    const marker = body.messages[0].content.match(/marker: ([a-f0-9]{32})/)[1]; return complete(marker);
  };
  try {
    for (const provider of ["codex-easy", "linkapi", "opencode"]) {
      const req = token => new Request(`https://gateway.example/${provider}/v1/chat/completions`, {
        method: "POST", headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify(payload) });
      assert.equal((await worker.fetch(req("wrong"), env, {})).status, 401);
      const response = await worker.fetch(req("synthetic-key"), env, {});
      assert.equal(response.status, 502); assert.match(await response.text(), /context_canary_leak/);
    }
    assert.equal(calls, 3);
    for (const path of ["/v1/chat/completions", "/v1/usage/receipts"]) {
      let forwarded;
      const res = await worker.fetch(new Request("https://gateway.example" + path, { method: "POST", body: JSON.stringify(payload) }), {
        ...slo(), ...cost, ...canary("block"), USAGE_RECEIPTS_ENABLED: "true",
        INTELLIGENCE_DB: { prepare() { assert.fail("native policy on Flask path"); } },
        MULTILLM_PROXY_CONTAINER: { getByName: () => ({ async fetch(req) { forwarded = req; return new Response("flask"); } }) },
      }, {});
      assert.equal(await res.text(), "flask"); assert.deepEqual(await forwarded.json(), payload);
    }
  } finally { globalThis.fetch = originalFetch; console.warn = originalWarn; }
});

function sqliteDatabase(sql, observe = () => {}) {
  return { prepare(query) {
    observe(query);
    let args = [];
    return { bind(...values) { args = values; return this; }, first() { return sql.prepare(query).get(...args) ?? null; },
      all() { const stmt = sql.prepare(query); return stmt.columns().length ? { success: true, results: stmt.all(...args), meta: { changes: 0 } }
        : { success: true, results: [], meta: { changes: Number(stmt.run(...args).changes) } }; } };
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const results = statements.map(statement => statement.all()); sql.exec("COMMIT"); return results; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
}

test("combined policies meter before settlement and retain a hold when the cost stop wins", async t => {
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  for (const file of ["0003_control_users.sql", "0007_usage_ledger.sql", "0020_usage_reservations.sql"])
    sql.exec(await readFile(new URL("../intelligence-migrations/" + file, import.meta.url), "utf8"));
  const order = [], seen = [], store = new ObservationWindow();
  store.record("codex-easy:m", { ttft_ms: 1, tokens_per_second: 1000, now });
  const env = { ...slo(), ...cost, ...canary("block"), ...admission(), USAGE_RESERVATIONS_ENABLED: "true",
    NATIVE_EDGE_METRICS_ENABLED: "true", LEARNED_COOLDOWN_MODE: "apply", USAGE_RECEIPTS_ENABLED: "true",
    GENERATION_CACHE_SHARED_ENABLED: "true", GENERATION_CACHE_BACKEND: "d1-r2", SEMANTIC_CACHE_ENABLED: "true",
    INTELLIGENCE_DB: sqliteDatabase(sql, query => order.push(query)) };
  const upstream = source([delta("too-much"), "data: [DONE]\n\n"]), original = console.warn; console.warn = () => {};
  try {
    const response = await nativeGenerationFetch(request({ stream: true }, { "X-MultiLLM-Deadline-Ms": "5000" }), env, {},
      { ...auth, observations: store, now, principal: { id: "admin", daily_budget_usd: 1, monthly_budget_usd: 10,
        max_stream_cost_microusd: 4 } }, () => upstream.response, events(seen));
    assert.equal(response.status, 200);
    const text = await response.text(); assert.match(text, /stream_cost_cap_exceeded/); assert.doesNotMatch(text, /\[DONE\]/);
    assert.equal((text.match(/"code":/g) ?? []).length, 1); assert.equal(upstream.cancels(), 1);
    assert.equal(seen.length, 1); assert.equal(seen[0].cancellationOutcome.ambiguous, true);
    assert.equal(sql.prepare("SELECT state FROM usage_reservations").get().state, "unknown");
    assert.equal(sql.prepare("SELECT status FROM usage_events").get().status, 499);
    const usage = order.findIndex(query => query.includes("INSERT INTO usage_events"));
    const settlement = order.findLastIndex(query => query.includes("UPDATE usage_reservations"));
    assert.ok(usage >= 0 && usage < settlement);
    assert.ok(!order.some(query => /learned_cooldown|generation_cache/.test(query)));
    assert.equal(store.models.get("codex-easy:m").length, 1);
  } finally { console.warn = original; }
});

test("reconciliation appends one immutable content-free receipt after commit and failure preserves the response", async t => {
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  for (const file of ["0020_usage_reservations.sql", "0032_usage_receipts.sql"])
    sql.exec(await readFile(new URL("../intelligence-migrations/" + file, import.meta.url), "utf8"));
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const signing = Buffer.from(await crypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
  const publicKey = Buffer.from(await crypto.subtle.exportKey("raw", keys.publicKey)).toString("base64");
  sql.prepare("INSERT INTO usage_receipt_keys VALUES (?, ?, 1)").run("fixture", publicKey);
  const env = { USAGE_RESERVATIONS_ENABLED: "true", USAGE_RECEIPTS_ENABLED: "true", USAGE_RECEIPTS_KEY_ID: "fixture",
    USAGE_RECEIPTS_SIGNING_KEY_REF: "TEST_RECEIPT_SIGNER", TEST_RECEIPT_SIGNER: signing, INTELLIGENCE_DB: sqliteDatabase(sql) };
  const id = n => n.toString(16).padStart(32, "0");
  const call = (body, settings = env) => handleReservationsRequest(privateRequest("/v1/reservations", { version: 1, ...body }), settings);
  const setup = async n => {
    await call({ operation: "reserve", id: id(n), principal: "alice", estimate_usd: 0.1, daily_budget_usd: 100,
      monthly_budget_usd: null, day_spent_usd: 0, month_spent_usd: 0 });
    await call({ operation: "transition", id: id(n), transition_id: id(n + 1), revision: 0, state: "dispatched" });
    await call({ operation: "transition", id: id(n), transition_id: id(n + 2), revision: 1, state: "unknown" });
    return { operation: "transition", id: id(n), transition_id: id(n + 3), revision: 2, state: "reconciled",
      cost_usd: 0.08, basis: "provider", settlement_id: id(n + 4), admin: true, reason: "reviewed", evidence: "provider:fixture" };
  };
  const body = await setup(1), applied = await call(body);
  assert.equal(applied.status, 200); assert.equal((await applied.json()).applied, true);
  assert.equal((await (await call(body)).json()).applied, false);
  const rows = sql.prepare("SELECT * FROM usage_receipts").all(); assert.equal(rows.length, 1);
  assert.equal(rows[0].event_id, body.transition_id);
  assert.doesNotMatch(JSON.stringify(rows), /provider:fixture|reviewed|annotation|marker/);
  const next = await setup(10), warnings = [], original = console.warn; console.warn = value => warnings.push(value);
  try {
    const response = await call(next, { ...env, USAGE_RECEIPTS_KEY_ID: "unavailable" });
    assert.equal(response.status, 200); assert.equal((await response.json()).applied, true); assert.equal(warnings.length, 1);
  } finally { console.warn = original; }
  assert.equal(sql.prepare("SELECT state FROM usage_reservations WHERE id=?").get(id(10)).state, "reconciled");
  const disabled = await setup(20); assert.equal((await call(disabled, { ...env, USAGE_RECEIPTS_ENABLED: "" })).status, 200);
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM usage_receipts").get().n, 1);
});
