import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { GenerationCacheD1, cleanupGenerationCache, CACHE_PREFIX } from "../worker/generation-cache-d1.mjs";
import { generationCacheSettings, exactCacheIdentity, eligibleRequest, prepareNativeCache } from "../worker/exact-generation-cache.mjs";
import { completeCacheBody } from "../worker/generation-cache-d1.mjs";
import { nativeGenerationFetch } from "../worker/gateway-extensions.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { handleControlStateRequest } from "../worker/control-state-d1.mjs";

const MIGRATION = "0019_generation_cache.sql";
function database() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL(`../intelligence-migrations/${MIGRATION}`, import.meta.url), "utf8"));
  const execute = (sql, args) => {
    const numbered = /\?[1-9]/.test(sql);
    const statement = db.prepare(sql.replace(/\?(\d+)/g, (_, number) => `$v${number}`));
    const rows = numbered ? statement.all(Object.fromEntries(args.map((value, index) => [`v${index + 1}`, value]))) : statement.all(...args);
    return {results: rows.map(row => ({...row})), meta: {changes: db.prepare("SELECT changes() AS n").get().n}};
  };
  return { prepare(sql) { return { sql, args: [], bind(...args) {this.args = args; return this;},
    async first() {return execute(sql, this.args).results[0] ?? null;},
    async all() {return execute(sql, this.args);}, async run() {return execute(sql, this.args);} }; },
    async batch(items) {
      db.exec("BEGIN IMMEDIATE");
      try {const result = items.map(item => execute(item.sql, item.args)); db.exec("COMMIT"); return result;}
      catch (error) {db.exec("ROLLBACK"); throw error;}
    } };
}
function bucket() {
  const rows = new Map(); let writes = 0;
  return { rows, get writes() { return writes; }, async put(key, value, options) {
    writes++; rows.set(key, { value: new Uint8Array(value), customMetadata: options.customMetadata });
  }, async get(key) { const row = rows.get(key); return row ? { size: row.value.length,
    async arrayBuffer() { return row.value.slice().buffer; } } : null; },
  async delete(key) { rows.delete(key); }, async list() { return { objects: [...rows].map(([key, row]) => ({key, customMetadata: row.customMetadata})), truncated: false }; } };
}
const enabled = { GENERATION_CACHE_BACKEND: "d1-r2", GENERATION_CACHE_SHARED_ENABLED: "true", ADMIN_USERNAME: "test", ADMIN_API_KEY: "synthetic" };
const payload = { model: "fixture-model", temperature: 0, messages: [{ role: "user", content: "hello" }] };
const body = JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 1 } });
const metadata = { content_type: "application/json", headers: {}, provider: "fixture", model: "fixture-model" };
const identity = { principal_hash: "a".repeat(64), cache_key: "b".repeat(64), policy_hash: "c".repeat(64), model: "fixture-model" };
function request(changes = {}, headers = {}) { return new Request("https://provider.invalid/v1/chat/completions", {
  method: "POST", headers: { "content-type": "application/json", "X-MultiLLM-Cache": "on", ...headers }, body: JSON.stringify({ ...payload, ...changes }) }); }
const authority = { route: "/fixture/v1/chat/completions", provider: "fixture", principal: { id: "test" } };

// SQLite executes the actual fixed statements, including transaction bounds, without a Worker daemon.
test("D1 and R2 share exact entries across instances with TTL and dangling-pointer misses", async () => {
  const env = { ...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket() }; let now = 1000;
  const one = new GenerationCacheD1(env, { clock: () => now });
  const two = new GenerationCacheD1(env, { clock: () => now });
  assert.equal(await one.put(identity, new TextEncoder().encode(body), metadata), true);
  assert.equal(new TextDecoder().decode((await two.get(identity)).body), body);
  assert.equal(await two.get({ ...identity, principal_hash: "d".repeat(64) }), null);
  assert.equal(await two.get({ ...identity, policy_hash: "d".repeat(64) }), null);
  assert.equal(await two.get({ ...identity, model: "other" }), null);
  now += 1; assert.equal(await two.get(identity, { maxAge: 0 }), null);
  const stored = [...env.multillm_media.rows][0]; env.multillm_media.rows.delete(stored[0]);
  assert.equal(await two.get(identity), null); env.multillm_media.rows.set(...stored);
  now = 1300; assert.equal(await two.get(identity), null);
  env.multillm_media.rows.set("unrelated", { value: new Uint8Array(), customMetadata: { expires_at: "0" } });
  await cleanupGenerationCache(env, { now, limit: 100 });
  assert.equal(env.multillm_media.rows.has("unrelated"), true);
  assert.equal([...env.multillm_media.rows.keys()].some(key => key.startsWith(CACHE_PREFIX)), false);
});

test("transaction limits reject over-budget writes and preserve other principals", async () => {
  const env = { ...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket() };
  const store = new GenerationCacheD1(env);
  const size = new TextEncoder().encode(body).length;
  const now = Date.now() / 1000;
  await env.INTELLIGENCE_DB.batch(Array.from({length: 512}, (_, index) => env.INTELLIGENCE_DB.prepare(
    "INSERT INTO generation_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(identity.principal_hash, index.toString(16).padStart(64, "0"), identity.policy_hash,
    identity.model, now, now + 300, CACHE_PREFIX + "fixture", size, "d".repeat(64), JSON.stringify(metadata))));
  assert.equal(await store.put(identity, new TextEncoder().encode(body), metadata), false);
  assert.equal(await store.put({ ...identity, principal_hash: "d".repeat(64) }, new TextEncoder().encode(body), metadata), true);
  assert.equal(await store.put(identity, new Uint8Array(1024 * 1024 + 1), metadata), false);
  await env.INTELLIGENCE_DB.prepare("DELETE FROM generation_cache WHERE principal_hash = ?").bind(identity.principal_hash).run();
  await env.INTELLIGENCE_DB.batch(Array.from({length: 16}, (_, index) => env.INTELLIGENCE_DB.prepare(
    "INSERT INTO generation_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(identity.principal_hash, index.toString(16).padStart(64, "0"), identity.policy_hash,
    identity.model, now, now + 300, CACHE_PREFIX + "fixture", 1024 * 1024, "d".repeat(64), JSON.stringify(metadata))));
  assert.equal(await store.put(identity, new TextEncoder().encode(body), metadata), false);
});

test("native registered lifecycle replays exact bytes without dispatch and finalizes cache accounting", async () => {
  const env = { ...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket() }; const events = [];
  const hooks = [{ enabled: () => true, finalize: event => events.push(event) }]; let calls = 0;
  const fetcher = async () => { calls++; return new Response(body, { headers: {"content-type": "application/json"} }); };
  const first = await nativeGenerationFetch(request(), env, null, authority, fetcher, hooks); assert.equal(await first.text(), body);
  const hit = await nativeGenerationFetch(request(), {...env}, null, authority, fetcher, hooks); assert.equal(await hit.text(), body);
  assert.equal(calls, 1); assert.equal(hit.headers.get("X-MultiLLM-Cache"), "hit");
  assert.equal(hit.headers.get("X-MultiLLM-Cache-Backend"), "d1-r2");
  assert.equal(events.at(-1).usage_basis, "cache-served"); assert.equal(events.at(-1).provider_calls, 0);
  assert.equal(events.at(-1).cost_basis, "cache"); assert.equal(events.at(-1).cost_usd, 0);
  assert.equal(JSON.parse(body).usage.prompt_tokens, 3);
});

test("native retention streams tools errors and partial results bypass before storage", async () => {
  let touched = 0;
  const env = { ...enabled, CONTENT_RETENTION_ENABLED: "true", INTELLIGENCE_DB: {prepare() {touched++; throw Error();}}, multillm_media: bucket() };
  for (const [changes, headers] of [[{}, {"X-MultiLLM-Retention": "zero"}], [{stream: true}, {}], [{tools: [{type: "function"}]}, {}], [{temperature: 1}, {}]]) {
    const result = await nativeGenerationFetch(request(changes, headers), env, null, authority,
      async () => new Response(body, {headers: {"content-type": "application/json"}}));
    await result.text();
  }
  assert.equal(touched, 0); assert.equal(env.multillm_media.writes, 0);
  const valid = { ...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket() };
  for (const response of [new Response(body, {status: 500}), new Response(body.replace('"stop"', '"length"'), {headers: {"content-type": "application/json"}}),
    new Response('{"choices":[{"message":{"tool_calls":[{}]},"finish_reason":"stop"}]}', {headers: {"content-type": "application/json"}})]) {
    await (await nativeGenerationFetch(request(), valid, null, authority, async () => response)).text();
  }
  assert.equal(valid.multillm_media.writes, 0);
});

test("private dispatch is default off, validates inputs and returns sanitized 503 for missing schema", async () => {
  const rpc = value => new Request("http://intelligence.internal/v1/state/generation-cache", {method: "POST",
    headers: {"content-type": "application/json"}, body: JSON.stringify({version: 1, operation: "get", ...identity, max_age: null, ...value})});
  assert.equal((await handleControlStateRequest(rpc(), {})).status, 404);
  const broken = { ...enabled, INTELLIGENCE_DB: { prepare() {throw Error("private storage detail");}}, multillm_media: bucket() };
  const failed = await handleControlStateRequest(rpc(), broken); assert.equal(failed.status, 503);
  assert.doesNotMatch(await failed.text(), /private storage detail/);
  assert.equal((await handleControlStateRequest(rpc({principal_hash: "invalid"}), broken)).status, 400);
  const env = { ...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket() };
  const saved = await handleControlStateRequest(rpc({operation: "put", max_age: undefined, body: Buffer.from(body).toString("base64"), metadata}), env);
  assert.equal(saved.status, 200); assert.equal((await saved.json()).stored, true);
  const hit = await handleControlStateRequest(rpc(), env); assert.equal(Buffer.from((await hit.json()).entry.body, "base64").toString(), body);
  let calls = 0;
  const result = await nativeGenerationFetch(request(), broken, null, authority, async () => {calls++; return new Response(body);});
  assert.equal(await result.text(), body); assert.equal(calls, 1);
});

test("empty malformed default settings preserve raw native response and do not inspect cache", async () => {
  for (const changes of [{}, {GENERATION_CACHE_BACKEND: "", GENERATION_CACHE_SHARED_ENABLED: ""},
    {...enabled, GENERATION_CACHE_SHARED_ENABLED: "bad"}, {...enabled, GENERATION_CACHE_BACKEND: "bad"}]) {
    const env = {...changes, INTELLIGENCE_DB: {prepare() {assert.fail("cache inspected");}}};
    const raw = new Response("unchanged", {headers: {"x-fixture": "original"}});
    const result = await nativeGenerationFetch(request(), env, null, authority, async () => raw);
    assert.equal(await result.text(), "unchanged"); assert.equal(result.headers.get("x-fixture"), "original");
    assert.equal(result.headers.get("X-MultiLLM-Cache"), null);
  }
  assert.equal(generationCacheSettings(enabled).enabled, true);
});

test("native canonical identity isolates principal policy endpoint and model", async () => {
  const context = {retentionPolicy: {mode: "inherit", enabled: false}};
  const one = await exactCacheIdentity(request(), enabled, authority, context);
  assert.equal(one.cache_key, (await exactCacheIdentity(request(), enabled, authority, context)).cache_key);
  for (const [req, env, auth] of [[request({model: "other"}), enabled, authority], [request(), {...enabled, SECRET_SCAN_DEFAULT: "block"}, authority],
    [request(), {...enabled, ADMIN_API_KEY: "other-synthetic"}, authority], [request(), enabled, {...authority, principal: {id: "other"}}]]) {
    assert.notDeepEqual(await exactCacheIdentity(req, env, auth, context), one);
  }
});


test("authorized hub routes expose provenance and a bad key cannot read an entry", async () => {
  const worker = (await loadWorkerModule()).default;
  const env = {...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket(), CODEX_EASY_API_KEY: "synthetic-upstream"};
  let calls = 0; const original = globalThis.fetch;
  globalThis.fetch = async () => {calls++; return new Response(body, {headers: {"content-type": "application/json"}});};
  const source = (token = env.ADMIN_API_KEY) => new Request("https://gateway.example/codex-easy/v1/chat/completions", {
    method: "POST", headers: {Authorization: `Bearer ${token}`, "content-type": "application/json", "X-MultiLLM-Cache": "on"}, body: JSON.stringify(payload)});
  try {
    const first = await worker.fetch(source(), env); assert.equal(await first.text(), body);
    assert.equal(first.headers.get("X-MultiLLM-Cache"), "miss");
    const hit = await worker.fetch(source(), env); assert.equal(await hit.text(), body);
    assert.equal(hit.headers.get("X-MultiLLM-Cache"), "hit"); assert.equal(hit.headers.get("X-MultiLLM-Provider-Calls"), "0");
    assert.equal((await worker.fetch(source("wrong"), env)).status, 401); assert.equal(calls, 1);
  } finally {globalThis.fetch = original;}
});

test("concurrent writes respect capacity and corrupt R2 bytes never replay", async () => {
  const env = {...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket()}; const store = new GenerationCacheD1(env);
  await Promise.all(Array.from({length: 20}, (_, index) => store.put({...identity, cache_key: index.toString(16).padStart(64, "0")}, new TextEncoder().encode(body), metadata)));
  assert.equal((await env.INTELLIGENCE_DB.prepare("SELECT COUNT(*) AS n FROM generation_cache").first()).n, 20);
  await store.put(identity, new TextEncoder().encode(body), metadata);
  const row = await env.INTELLIGENCE_DB.prepare("SELECT body_pointer FROM generation_cache WHERE cache_key=?").bind(identity.cache_key).first();
  const saved = env.multillm_media.rows.get(row.body_pointer); saved.value[0] ^= 1;
  assert.equal(await store.get(identity), null);
});

test("native cancellation and refresh never replay or authorize another dispatch", async () => {
  const env = {...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket()}; let calls = 0;
  const fetcher = async () => {calls++; return new Response(body, {headers: {"content-type": "application/json"}});};
  await (await nativeGenerationFetch(request(), env, null, authority, fetcher)).text();
  await (await nativeGenerationFetch(request({}, {"Cache-Control": "no-cache"}), env, null, authority, fetcher)).text();
  assert.equal(calls, 2);
  const controller = new AbortController(); controller.abort();
  const canceled = new Request(request(), {signal: controller.signal});
  await assert.rejects(nativeGenerationFetch(canceled, env, null, authority, fetcher)); assert.equal(calls, 2);
});

test("ambiguous upstream credentials and malformed tools never enter the cache", async () => {
  const context = {retentionPolicy: {mode: "inherit", enabled: false}};
  for (const header of ["x-multillm-api-key", "x-opencode-session", "x-grok-conv-id"]) {
    assert.equal(await exactCacheIdentity(request({}, {[header]: "synthetic"}), enabled, authority, context), null);
  }
  for (const tools of [{type: "function"}, "invalid", false]) {
    assert.equal(eligibleRequest({...payload, tools}), false);
  }
  assert.equal(completeCacheBody(new TextEncoder().encode(JSON.stringify({choices: [{finish_reason: "stop", message: {tool_calls: {id: "tool"}}}]}))), false);
});

test("stalled lookup falls through and a changed policy cannot replay a stored entry", async () => {
  const context = {retentionPolicy: {mode: "inherit", enabled: false}, cacheRevisions: {security: 1}};
  const stuck = {...enabled, INTELLIGENCE_DB: {prepare() {return {bind() {return this;}, first() {return new Promise(() => {});}};}}};
  const started = performance.now();
  assert.equal(await (await prepareNativeCache(request(), stuck, authority, context)).lookup(), null);
  assert.ok(performance.now() - started < 4000);
  const env = {...enabled, INTELLIGENCE_DB: database(), multillm_media: bucket()};
  const original = await exactCacheIdentity(request(), env, authority, context);
  await new GenerationCacheD1(env).put(original, new TextEncoder().encode(body), metadata);
  const cache = await prepareNativeCache(request(), env, authority, context);
  const get = env.multillm_media.get;
  env.multillm_media.get = async key => {context.cacheRevisions.security++; return get(key);};
  assert.equal(await cache.lookup(), null);
});
