import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFile, readdir } from "node:fs/promises";
import { scryptSync } from "node:crypto";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { handleRealtimeRequest, realtimeSettings } from "../worker/realtime.mjs";
import { bridgeRealtime } from "../worker/realtime-session.mjs";
import { createRealtimeMeter, realtimeCostPolicy } from "../worker/realtime-metering.mjs";

const worker = (await loadWorkerModule()).default;
const model = "openai:realtime-test";
const prices = { input_text: 1, output_text: 2, input_audio: 3, output_audio: 4, provider_session_limit_usd: 0.1 };
const enabled = { REALTIME_ENABLED: "true", ADMIN_API_KEY: "synthetic-gateway",
  JWT_SECRET: "synthetic-ticket-signing",
  OPENAI_API_KEY: "synthetic-provider", REALTIME_SESSION_CAP_USD: "0.2", REALTIME_DAILY_BUDGET_USD: "1",
  REALTIME_PROVIDERS_JSON: JSON.stringify({ [model]: { url: "wss://approved.example/v1/realtime?model=realtime-test" } }),
  REALTIME_PRICING_JSON: JSON.stringify({ [model]: prices }), ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":2}' };
const request = (extra = {}) => new Request(`https://gateway.example/v1/realtime?model=${model}`, {
  headers: { upgrade: "websocket", authorization: "Bearer synthetic-gateway", ...extra } });
class Socket {
  listeners = {}; sent = []; closes = []; accepted = false;
  accept() { this.accepted = true; }
  addEventListener(name, fn) { (this.listeners[name] ??= []).push(fn); }
  removeEventListener(name, fn) { this.listeners[name] = (this.listeners[name] ?? []).filter(item => item !== fn); }
  send(data) { this.sent.push(data); }
  close(code, reason) { this.closes.push([code, reason]); }
  emit(name, event = {}) { for (const fn of [...(this.listeners[name] ?? [])]) fn(event); }
}
function clock() {
  let now = Date.now(), next = 0; const jobs = new Map();
  return { now: () => now, setTimeout(fn, delay) { jobs.set(++next, { at: now + delay, fn }); return next; },
    clearTimeout(id) { jobs.delete(id); }, async advance(ms) { now += ms;
      for (const [id, job] of [...jobs]) if (job.at <= now) { jobs.delete(id); job.fn(); }
      await new Promise(resolve => setImmediate(resolve)); } };
}
async function fixture(t) {
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  const directory = new URL("../intelligence-migrations/", import.meta.url);
  for (const file of (await readdir(directory)).filter(name => name.endsWith(".sql")).sort()) sql.exec(await readFile(new URL(file, directory), "utf8"));
  const db = { prepare(query) { const values = []; return { bind(...args) { values.push(...args); return this; },
    async first() { return sql.prepare(query).get(...values) ?? null; },
    async all() { return { results: sql.prepare(query).all(...values), success: true }; },
    async run() { const meta = sql.prepare(query).run(...values); return { success: true, meta: { changes: Number(meta.changes) } }; },
    execute() { const stmt = sql.prepare(query); if (stmt.columns().length) return { success: true, results: stmt.all(...values), meta: { changes: 0 } };
      return { success: true, results: [], meta: { changes: Number(stmt.run(...values).changes) } }; } }; },
    async batch(statements) { sql.exec("BEGIN"); try { const results = statements.map(stmt => stmt.execute()); sql.exec("COMMIT"); return results; }
      catch (error) { sql.exec("ROLLBACK"); throw error; } } };
  const server = new Socket(), client = new Socket(), upstream = new Socket(), timers = clock(), pending = [], leases = [];
  const env = { ...enabled, INTELLIGENCE_DB: db, ADMISSION_COORDINATOR: { getByName() { return { async fetch(req) {
    const value = await req.json(); leases.push(value);
    return Response.json({ version: 1, ...(value.operation === "release" ? { released: true }
      : { lease: { lease_id: "a".repeat(32), expires_at: Math.min(Date.now() + 25000, value.deadline_ms) } }) }); } }; } } };
  let calls = 0; const options = { timers, pair: () => ({ 0: client, 1: server }),
    upgradeResponse: socket => ({ status: 101, webSocket: socket }), async dial(url, init) { calls++;
      assert.equal(url, "https://approved.example/v1/realtime?model=realtime-test");
      assert.equal(init.headers.get("authorization"), "Bearer synthetic-provider");
      assert.equal(init.headers.get("x-attacker"), null); return { status: 101, webSocket: upstream }; } };
  const ctx = { waitUntil(promise) { pending.push(promise); } };
  return { sql, db, env, options, ctx, server, upstream, client, timers, leases, calls: () => calls,
    async flush() { await Promise.all(pending); } };
}
const done = (id = "r1") => JSON.stringify({ type: "response.done", response: { id, status: "completed", usage: {
  input_tokens: 3, output_tokens: 2, input_token_details: { text_tokens: 1, audio_tokens: 2, cached_tokens: 0 },
  output_token_details: { text_tokens: 1, audio_tokens: 1 } } } });

test("disabled, empty and malformed flags preserve registered Container bytes and headers", async () => {
  for (const flag of [undefined, "", "false", "garbage"]) {
    let calls = 0; const env = { REALTIME_ENABLED: flag, MULTILLM_PROXY_CONTAINER: { getByName() { return {
      async fetch(req) { calls++; assert.equal(req.headers.get("upgrade"), "websocket");
        return new Response("unchanged 雪", { status: 418, headers: { "x-original": "yes" } }); } }; } } };
    const response = await worker.fetch(request(), env, {});
    assert.equal(response.status, 418); assert.equal(response.headers.get("x-original"), "yes");
    assert.equal(await response.text(), "unchanged 雪"); assert.equal(calls, 1);
    assert.equal(await handleRealtimeRequest(request(), env), null);
  }
});
test("invalid mappings disable once without logging values", () => {
  const old = console.warn, messages = []; console.warn = message => messages.push(message);
  try { for (const url of ["https://approved.example", "wss://user:password@approved.example", "wss://127.0.0.1/x", "wss://approved.example/#x", "wss://approved.example/?api_key=private"]) {
    const env = { ...enabled, REALTIME_PROVIDERS_JSON: JSON.stringify({ [model]: { url } }) };
    assert.equal(realtimeSettings(env).enabled, false); assert.equal(realtimeSettings(env).enabled, false);
  } } finally { console.warn = old; }
  assert.equal(messages.length, 1); assert.ok(!messages.join().includes("password"));
});
test("registered enabled errors never wake Container", async () => {
  const env = { ...enabled, MULTILLM_PROXY_CONTAINER: { getByName() { throw Error("Container woke"); } } };
  for (const [req, expected] of [[request({ upgrade: "" }), 426], [request({ authorization: "" }), 401],
    [new Request("https://gateway.example/v1/realtime?model=openai:unmapped", { headers: { upgrade: "websocket", authorization: "Bearer synthetic-gateway" } }), 403]]) {
    const response = await worker.fetch(req, env, {}); assert.equal(response.status, expected); assert.ok((await response.json()).error.code);
  }
});
test("missing session migration, prices, cap or admission fail before dialing", async t => {
  const f = await fixture(t); f.sql.exec("DROP TABLE realtime_sessions");
  assert.equal((await handleRealtimeRequest(request(), f.env, f.ctx, f.options)).status, 503); assert.equal(f.calls(), 0);
  for (const changes of [{ REALTIME_PRICING_JSON: "{}" }, { REALTIME_SESSION_CAP_USD: "" }, { ADMISSION_ENABLED: "false" }]) {
    const response = await handleRealtimeRequest(request(), { ...f.env, ...changes }, f.ctx, f.options);
    assert.equal(response.status, 503); assert.equal(f.calls(), 0);
  }
});
test("policy requires known audio/text prices and an enforceable upstream ceiling", () => {
  assert.equal(realtimeCostPolicy(enabled, model).cap, 0.2);
  for (const changes of [{ input_audio: null }, { provider_session_limit_usd: null }, { provider_session_limit_usd: 1 }]) {
    assert.throws(() => realtimeCostPolicy({ ...enabled, REALTIME_PRICING_JSON: JSON.stringify({ [model]: { ...prices, ...changes } }) }, model));
  }
});
test("approved sockets preserve JSON/binary, lease lifetime, measured usage and content-free ledger", async t => {
  const f = await fixture(t);
  const response = await handleRealtimeRequest(request({ "x-attacker": "bad", "openai-beta": "realtime=v1" }), f.env, f.ctx, f.options);
  assert.equal(response.status, 101); assert.equal(f.calls(), 1); assert.equal(f.leases.length, 1);
  f.server.emit("message", { data: '{"type":"conversation.item.create","content":"private prompt"}' });
  const binary = new Uint8Array([1, 2]).buffer; f.upstream.emit("message", { data: binary });
  assert.equal(f.upstream.sent[0], '{"type":"conversation.item.create","content":"private prompt"}'); assert.equal(f.server.sent[0], binary);
  f.upstream.emit("message", { data: done() }); f.server.emit("close", { code: 1000 }); await f.flush();
  assert.equal(f.leases.at(-1).operation, "release"); assert.equal(f.upstream.closes.length, 1);
  const row = f.sql.prepare("SELECT * FROM usage_events").get();
  assert.deepEqual([row.input_tokens, row.output_tokens, row.cost_usd, row.cost_basis], [3, 2, 0.000013, "usage"]);
  assert.equal(f.sql.prepare("SELECT state FROM usage_reservations").get().state, "settled");
  assert.ok(!JSON.stringify(f.sql.prepare("SELECT * FROM realtime_sessions").all()).includes("private prompt"));
});
test("single-use tickets expire and cannot switch models or bypass rotated credentials", async t => {
  const f = await fixture(t), issue = () => handleRealtimeRequest(new Request("https://gateway.example/v1/realtime/client_secrets", {
    method: "POST", headers: { authorization: "Bearer synthetic-gateway", "content-type": "application/json" }, body: JSON.stringify({ model }) }), f.env, f.ctx, f.options);
  const issued = await issue(), payload = await issued.json(); assert.equal(issued.status, 200);
  assert.ok(!JSON.stringify(payload).includes("synthetic-provider"));
  const ticketReq = token => request({ authorization: `Bearer ${token}` });
  assert.equal((await handleRealtimeRequest(ticketReq(payload.value), f.env, f.ctx, f.options)).status, 101);
  assert.equal((await handleRealtimeRequest(ticketReq(payload.value), f.env, f.ctx, f.options)).status, 401);
  f.server.emit("close", { code: 1000 }); await f.flush();
  const rotated = await (await issue()).json();
  assert.equal((await handleRealtimeRequest(ticketReq(rotated.value), { ...f.env, ADMIN_API_KEY: "synthetic-rotated" }, f.ctx, f.options)).status, 401);
  const otherModel = new Request(`https://gateway.example/v1/realtime?model=openai:other`, { headers: { upgrade: "websocket", authorization: `Bearer ${rotated.value}` } });
  assert.equal((await handleRealtimeRequest(otherModel, f.env, f.ctx, f.options)).status, 401);
  const tampered = rotated.value.slice(0, -1) + (rotated.value.endsWith("A") ? "B" : "A");
  assert.equal((await handleRealtimeRequest(ticketReq(tampered), f.env, f.ctx, f.options)).status, 401);
  const expired = await (await issue()).json(); await f.timers.advance(60001);
  assert.equal((await handleRealtimeRequest(ticketReq(expired.value), f.env, f.ctx, f.options)).status, 401);
});
test("D1 admission enforces two sessions per key across parallel requests", async t => {
  const f = await fixture(t);
  const results = await Promise.all(Array.from({ length: 3 }, () => handleRealtimeRequest(request(), f.env, f.ctx,
    { ...f.options, pair: () => ({ 0: new Socket(), 1: new Socket() }), dial: async () => ({ status: 101, webSocket: new Socket() }) })));
  assert.deepEqual(results.map(r => r.status).sort(), [101, 101, 429]);
  await f.timers.advance(900001); await f.flush();
});
test("upstream real errors precede 1011; uncertain usage retains a distinct hold", async t => {
  const f = await fixture(t); await handleRealtimeRequest(request(), f.env, f.ctx, f.options);
  const error = '{"type":"error","error":{"code":"upstream_limit","message":"real error"}}';
  f.upstream.emit("message", { data: error }); f.upstream.emit("error"); f.server.emit("close"); await f.flush();
  assert.equal(f.server.sent[0], error); assert.equal(f.server.closes[0][0], 1011); assert.equal(f.upstream.closes.length, 1);
  assert.equal(f.sql.prepare("SELECT state FROM usage_reservations").get().state, "unknown");
  assert.equal(f.sql.prepare("SELECT cost_usd FROM usage_events").get().cost_usd, null);
});
test("frame, idle, TTL, request abort and send failures couple closure exactly once", async () => {
  for (const mode of ["frame", "idle", "ttl", "abort", "send"]) {
    const client = new Socket(), upstream = new Socket(), timers = clock(), controller = new AbortController(); let finalized = 0;
    const bridge = bridgeRealtime(client, upstream, { timers, signal: controller.signal, meter: createRealtimeMeter({ ...prices, cap: 0.2 }),
      finalize: async () => { finalized++; } });
    if (mode === "frame") client.emit("message", { data: "雪".repeat(400000) });
    if (mode === "idle") await timers.advance(30000);
    if (mode === "ttl") { for (let i = 0; i < 30; i++) { await timers.advance(29999); client.emit("message", { data: "{}" }); } await timers.advance(31); }
    if (mode === "abort") controller.abort();
    if (mode === "send") { upstream.send = () => { throw Error("private failure"); }; client.emit("message", { data: "{}" }); }
    await bridge.done; assert.equal(finalized, 1); assert.equal(client.closes.length, 1); assert.equal(upstream.closes.length, 1);
    assert.equal(client.closes[0][0], mode === "send" ? 1011 : 1008);
  }
});
test("usage dedupe, partial, in-flight and cap overflow never invent a final bill", () => {
  const meter = createRealtimeMeter({ ...prices, cap: 0.2 }); meter.observe(done()); meter.observe(done());
  assert.equal(meter.finish().cost_usd, 0.000013);
  meter.observe('{"type":"response.created","response":{"id":"r2"}}'); assert.equal(meter.finish().cost_usd, null);
  const unknown = createRealtimeMeter({ ...prices, cap: 0.2 }); unknown.observe('{"type":"response.done","response":{"id":"r","usage":{"input_tokens":1}}}');
  assert.equal(unknown.finish().cost_usd, null);
  const overflow = createRealtimeMeter({ ...prices, cap: 0.000001 }); assert.equal(overflow.observe(done()), "policy"); assert.equal(overflow.finish().cost_usd, null);
  const cached = createRealtimeMeter({ ...prices, cap: 0.2 });
  const event = JSON.parse(done()); event.response.usage.input_token_details.cached_tokens = 1;
  cached.observe(JSON.stringify(event)); assert.equal(cached.finish().cost_usd, null);
});

test("dashboard key model grants, scopes, expiry and tickets use current D1 authority", async t => {
  const f = await fixture(t), key = "synthetic-account-key", salt = "syntheticsalt";
  const hash = `scrypt:32768:8:1$${salt}$${scryptSync(key, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex")}`;
  f.env.AUTH_STORAGE_BACKEND = "d1";
  f.sql.prepare(`INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at,allowed_models)
    VALUES (?,?,?,?,0,?,?)`).run("fixture-user", hash, `mllm_${key.slice(0, 8)}`, "chat,audio", new Date().toISOString(), "openai:other");
  assert.equal((await handleRealtimeRequest(request({ authorization: `Bearer ${key}` }), f.env, f.ctx, f.options)).status, 403);
  f.sql.prepare("UPDATE control_users SET allowed_models='OPENAI:realtime-*',scopes='chat' WHERE username='fixture-user'").run();
  assert.equal((await handleRealtimeRequest(request({ authorization: `Bearer ${key}` }), f.env, f.ctx, f.options)).status, 403);
  f.sql.prepare("UPDATE control_users SET scopes='chat,audio',expires_at='2000-01-01T00:00:00Z' WHERE username='fixture-user'").run();
  assert.equal((await handleRealtimeRequest(request({ authorization: `Bearer ${key}` }), f.env, f.ctx, f.options)).status, 401);
  f.sql.prepare("UPDATE control_users SET expires_at=NULL WHERE username='fixture-user'").run();
  assert.equal((await handleRealtimeRequest(request({ authorization: `Bearer ${key}` }), f.env, f.ctx, f.options)).status, 101);
  f.server.emit("close", { code: 1000 }); await f.flush(); assert.equal(f.calls(), 1);
});
test("provider-key echoes close 1008 without transmitting bytes or escaped JSON", async () => {
  for (const data of ['{"key":"synthetic-provider"}', '{"key":"synthetic-\\u0070rovider"}', new TextEncoder().encode("synthetic-provider").buffer]) {
    const client = new Socket(), upstream = new Socket();
    const bridge = bridgeRealtime(client, upstream, { secret: "synthetic-provider", meter: createRealtimeMeter({ ...prices, cap: 0.2 }), finalize: async () => {} });
    upstream.emit("message", { data }); await bridge.done;
    assert.equal(client.sent.length, 0); assert.equal(client.closes[0][0], 1008);
  }
});
test("redirects and handshake failures are not followed and retain ambiguous holds", async t => {
  const f = await fixture(t);
  const result = await handleRealtimeRequest(request(), f.env, f.ctx, { ...f.options, dial: async (url, init) => {
    assert.equal(init.redirect, "manual"); return new Response("private upstream", { status: 302, headers: { location: "https://attacker.example" } }); } });
  assert.equal(result.status, 502); assert.equal(f.leases.at(-1).operation, "release");
  assert.equal(f.sql.prepare("SELECT state FROM usage_reservations").get().state, "unknown");
  assert.ok(!JSON.stringify(await result.json()).includes("private upstream"));
});

test("registered successful socket route never wakes Container or forwards caller headers", async t => {
  const f = await fixture(t), BaseResponse = globalThis.Response, previousFetch = globalThis.fetch, previousPair = globalThis.WebSocketPair;
  globalThis.Response = class extends BaseResponse { constructor(body, init) {
    if (init?.status === 101) return { status: 101, webSocket: init.webSocket };
    super(body, init);
  } };
  globalThis.WebSocketPair = class { constructor() { return { 0: f.client, 1: f.server }; } };
  globalThis.fetch = async (url, init) => { assert.equal(url, "https://approved.example/v1/realtime?model=realtime-test");
    assert.deepEqual([...init.headers.keys()].sort(), ["authorization", "openai-beta", "upgrade"]);
    assert.equal(init.headers.get("authorization"), "Bearer synthetic-provider"); return { status: 101, webSocket: f.upstream }; };
  try {
    const response = await worker.fetch(request({ "x-attacker": "bad", "openai-beta": "realtime=v1" }), {
      ...f.env, MULTILLM_PROXY_CONTAINER: { getByName() { throw Error("Container woke"); } } }, f.ctx);
    assert.equal(response.status, 101); assert.equal(response.webSocket, f.client);
    f.upstream.emit("message", { data: done() }); f.server.emit("close", { code: 1000 }); await f.flush();
  } finally { globalThis.Response = BaseResponse; globalThis.fetch = previousFetch; globalThis.WebSocketPair = previousPair; }
});
test("additive session migration preserves prior rows and can be applied again", async t => {
  const f = await fixture(t);
  f.sql.prepare("INSERT INTO realtime_sessions(id,principal_hash,owner,model,created_at,expires_at,lease_until,state) VALUES (?,?,?,?,0,1,1,'unknown')")
    .run("old-row", "opaque-key", "old-owner", model);
  f.sql.exec(await readFile(new URL("../intelligence-migrations/0029_realtime_sessions.sql", import.meta.url), "utf8"));
  assert.equal(f.sql.prepare("SELECT state FROM realtime_sessions WHERE id='old-row'").get().state, "unknown");
  assert.equal(f.sql.prepare("SELECT name FROM sqlite_master WHERE name='usage_reservations'").get().name, "usage_reservations");
});
test("late input, transcription and canceled responses retain holds", () => {
  for (const mode of ["input", "transcription", "canceled"]) {
    const meter = createRealtimeMeter({ ...prices, cap: 0.2 }); meter.observe(done());
    if (mode === "input") meter.noteInput('{"type":"input_audio_buffer.append","audio":"opaque"}');
    if (mode === "transcription") meter.observe('{"type":"conversation.item.input_audio_transcription.completed"}');
    if (mode === "canceled") { const value = JSON.parse(done("r2")); value.response.status = "cancelled"; meter.observe(JSON.stringify(value)); }
    assert.equal(meter.finish().cost_usd, null);
  }
});
test("output from a later incomplete response never settles prior usage as the final bill", () => {
  const meter = createRealtimeMeter({ ...prices, cap: 0.2 }); meter.observe(done());
  meter.observe('{"type":"response.output_audio.delta","response_id":"r2","delta":"opaque"}');
  assert.equal(meter.finish().cost_usd, null);
  meter.observe(done("r2")); assert.equal(meter.finish().cost_usd, 0.000026);
});
test("missing lease, storage failure and budget exhaustion never dial", async t => {
  const f = await fixture(t);
  for (const env of [{ ...f.env, ADMISSION_LIMITS_JSON: "{}" }, { ...f.env, REALTIME_DAILY_BUDGET_USD: "0.01" },
    { ...f.env, INTELLIGENCE_DB: { prepare() { throw Error("private storage details"); } } }]) {
    const response = await handleRealtimeRequest(request(), env, f.ctx, f.options);
    assert.ok([429, 503].includes(response.status)); assert.equal(f.calls(), 0);
    assert.ok(!JSON.stringify(await response.json()).includes("private storage details"));
  }
});
