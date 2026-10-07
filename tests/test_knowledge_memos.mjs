import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoStore, memoQueryNorm, memoSecretQuery, quantizeEmbedding, embeddingCosine, MEMO_SHARD_LIMIT, MEMO_TOTAL_LIMIT } from "../worker/knowledge/memo-store.mjs";
import { createArtifact } from "../worker/knowledge/evidence.mjs";
import { memoSession } from "../worker/knowledge/memos.mjs";
import { retrieveKnowledge } from "../worker/knowledge/retrieval.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
import { defaultPolicy, validatePolicy, withProviderDefaults } from "../worker/knowledge/policy.mjs";
import { fixture, principal, manager, request } from "./knowledge_fixture.mjs";

function store(t, limits = {}) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const storage = {
    sql: { exec: (sql, ...args) => db.prepare(sql).all(...args) },
    transactionSync(callback) {
      db.exec("BEGIN");
      try { const result = callback(); db.exec("COMMIT"); return result; }
      catch (error) { db.exec("ROLLBACK"); throw error; }
    },
  };
  const memos = new MemoStore(storage, limits);
  return { memos: { call: async (...args) => memos.call(...args) }, db, local: memos };
}

async function setup(t) {
  const f = await fixture();
  const s = store(t);
  const artifact = await f.published();
  const query = request({ version: "3.1.3" });
  let embeddings = 0;
  const options = { corpus: f.corpus, retrieve: f.retrieve, cache: null, memos: s.memos,
    embed: async () => { embeddings++; return [1, 0, 0]; } };
  const run = (q = query, extra = {}, identity = principal) => retrieveKnowledge(f.env, f.authority, identity, q, { ...options, ...extra });
  return { ...f, ...s, artifact, query, options, run, embeddings: () => embeddings };
}

function record(id, product = "flask", time = "2026-10-07T00:00:00Z") {
  const citation = { artifact_id: "a".repeat(64), content_hash: "b".repeat(64), expires_at: "2026-10-09T00:00:00Z" };
  return { id: id.toString(16).padStart(64, "0"), created_at: time, last_hit_at: time, hits: 0,
    key: { product, version: "", repository: "" }, query: `limits ${id}`, query_norm: `limits ${id}`, mode: "smart", token_budget: 6000,
    embedding: quantizeEmbedding([1, 0, 0]), citations: [citation], bundle: { status: "ok", token_count: 300, excerpts: [citation] } };
}

test("memo normalization and Int8 embeddings preserve cosine and reject invalid vectors", () => {
  assert.equal(memoQueryNorm("  LIMITS   configured?!  "), "limits configured");
  const q = quantizeEmbedding([0.25, -0.5, 1]);
  assert.equal(q.scale, 1 / 127);
  assert.deepEqual(q.values, [32, -63, 127]);
  assert.ok(embeddingCosine(q.values, q.values) > 0.999);
  for (const vector of [[], [0, 0], [NaN], [Infinity], ["1"], Array(1025).fill(1)]) assert.equal(quantizeEmbedding(vector), null);
});

test("exact memo serves across principals and unrelated generation changes without providers or embedding", async t => {
  const f = await setup(t);
  const first = await f.run();
  assert.equal(first.status, "ok");
  assert.equal((await f.memos.call("stats")).totals.count, 1);
  await f.authority.call("source.create", { product: "react", url: "https://react.dev/reference" });
  const calls = [];
  const authority = { call: (operation, payload) => { calls.push(operation); return f.authority.call(operation, payload); } };
  const hit = await retrieveKnowledge(f.env, authority, { ...principal, id: "another-reader" },
    request({ ...f.query, query: "HOW ARE request size limits configured!!!" }), f.options);
  assert.equal(hit.path, "memo");
  assert.equal(hit.memo.kind, "exact");
  assert.equal(hit.memo.similarity, 1);
  assert.equal(hit.memo.matched_query, undefined);
  assert.equal(hit.memo.age_seconds, 0);
  assert.deepEqual(hit.usage, []);
  assert.equal(f.embeddings(), 1);
  assert.equal(f.counts.searches, 1);
  assert.equal(f.counts.providers, 0);
  assert.deepEqual(calls, ["catalogue.state", "memos.validate"]);
  assert.equal((await f.memos.call("stats")).totals.hits, 1);
  assert.ok(Date.parse(hit.served_at) >= Date.parse(first.served_at));
  const saved = f.local.find({ request: f.query, kind: "exact" }).record;
  assert.equal(saved.bundle.usage, undefined);
  assert.equal(saved.bundle.served_at, undefined);
});

async function liveSetup(t) {
  const f = await fixture();
  const { memos, local } = store(t);
  const query = request({ version: "3.1.3" });
  const options = { corpus: f.corpus, retrieve: f.retrieve, cache: null, memos, embed: async () => [1, 0, 0] };
  const run = () => retrieveKnowledge(f.env, f.authority, principal, query, options);
  return { ...f, memos, local, query, run };
}

test("live-only answers are memoized and served before their source publishes", async t => {
  const f = await liveSetup(t);
  const first = await f.run();
  assert.equal(first.path, "live");
  assert.equal(first.status, "ok");
  const artifact = await f.authority.call("artifact.get", { id: first.excerpts[0].artifact_id });
  assert.equal(artifact.status, "live");
  assert.equal((await f.storage.get(`source:${artifact.source_id}`)).current_artifact, null);
  assert.equal((await f.memos.call("stats")).totals.count, 1);
  const hit = await f.run();
  assert.equal(hit.path, "memo");
  assert.equal(hit.memo.kind, "exact");
  assert.equal(f.counts.providers, 1);
});

test("publishing a memo's live backing preserves it; a later published revision invalidates it", async t => {
  const f = await liveSetup(t);
  const first = await f.run();
  const old = await f.authority.call("artifact.get", { id: first.excerpts[0].artifact_id });
  const publish = async artifact => {
    const job = await f.authority.call("job.enqueue", { source_id: artifact.source_id });
    await f.authority.call("job.publish", { id: job.id, artifact_id: artifact.id, item_id: "fixture-item", index_key: artifact.index_key });
  };
  await publish(old);
  assert.equal((await f.run()).path, "memo");
  const replacement = await createArtifact({ ...f.source, origin_checked: true }, `${f.text} New limits.`, "firecrawl");
  await f.authority.call("artifact.save", { artifact: replacement });
  await publish(replacement);
  assert.equal((await f.authority.call("memos.validate", {
    citations: f.local.find({ request: f.query, kind: "exact" }).record.citations, policy_revision: f.policy.revision,
  })).valid, false);
  let deleted = false;
  const call = f.memos.call;
  f.memos.call = (...args) => { if (args[0] === "delete") deleted = true; return call(...args); };
  assert.notEqual((await f.run()).path, "memo");
  assert.equal(deleted, true);
});

test("expired live backing is rejected both when writing and when serving a memo", async t => {
  const f = await liveSetup(t);
  const first = await f.run();
  const id = first.excerpts[0].artifact_id;
  const artifact = await f.authority.call("artifact.get", { id });
  await f.storage.put(`artifact:${id}`, { ...artifact, expires_at: new Date(Date.now() - 1000).toISOString() });
  const session = memoSession(f.env, f.authority, f.query, f.policy, { memos: f.memos }, performance.now(), []);
  assert.deepEqual(await session.lookup(), {});
  assert.equal((await f.memos.call("stats")).totals.count, 0);
  await session.write(first, false);
  assert.equal((await f.memos.call("stats")).totals.count, 0);
});

test("semantic on serves a rephrased query; observe reports a candidate and performs normal retrieval", async t => {
  const f = await setup(t);
  await f.run();
  const rephrased = request({ ...f.query, query: "Where can I set Flask request limits?" });
  const observed = await f.run(rephrased);
  assert.equal(observed.path, "index");
  assert.equal(observed.memo, undefined);
  assert.equal(observed.index_diagnostics.memo_candidate.matched_query, f.query.query);
  assert.equal(observed.index_diagnostics.memo_candidate.similarity, 1);
  assert.equal(f.counts.searches, 2);
  f.policy.memo_semantic = "on";
  await f.storage.put("policy", f.policy);
  const hit = await f.run(request({ ...f.query, query: "Explain configuring request limits in Flask." }));
  assert.equal(hit.path, "memo");
  assert.equal(hit.memo.kind, "semantic");
  assert.equal(hit.memo.similarity, 1);
  assert.ok(hit.memo.matched_query);
  assert.equal(f.counts.searches, 2);
  assert.equal(hit.usage.length, 1);
  assert.equal(hit.usage[0].provider, "workers_ai");
  assert.equal(hit.usage[0].bound_units, 0);
});

test("semantic off and below-threshold embeddings never serve or observe", async t => {
  const f = await setup(t);
  await f.run();
  const q = request({ ...f.query, query: "Other limits question" });
  const result = await f.run(q, { embed: async () => [0, 1, 0] });
  assert.notEqual(result.path, "memo");
  assert.equal(result.index_diagnostics.memo_candidate, undefined);
  f.policy.memo_semantic = "off";
  await f.storage.put("policy", f.policy);
  const count = f.embeddings();
  const disabled = await f.run(request({ ...f.query, query: "Yet another question" }));
  assert.notEqual(disabled.path, "memo");
  assert.equal(f.embeddings(), count);
});

test("memo matches require identical product, version, repository and mode, and a fitting token count", async t => {
  const f = await setup(t);
  f.policy.memo_semantic = "on";
  await f.storage.put("policy", f.policy);
  await f.run();
  for (const changes of [{ product: "django" }, { version: "4.0" }, { repository: "pallets/flask" }, { mode: "deep" }]) {
    const result = await f.run(request({ ...f.query, ...changes }));
    assert.notEqual(result.path, "memo", JSON.stringify(changes));
    assert.equal(result.memo, undefined);
  }
  const saved = f.local.find({ request: f.query, kind: "exact" }).record;
  saved.bundle.token_count = 500;
  f.local.put(saved);
  assert.equal(f.local.find({ kind: "exact", request: request({ ...f.query, token_budget: 256 }) }), null);
  assert.equal(f.local.find({ kind: "semantic", request: request({ ...f.query, token_budget: 256 }), embedding: quantizeEmbedding([1, 0, 0]), similarity: 0.92 }), null);
});

for (const reason of ["hash", "superseded", "expired", "missing", "ttl", "source_disabled", "provider_disabled", "host_revoked"]) {
  test(`invalid ${reason} memo is deleted and retrieval continues`, async t => {
    const f = await setup(t);
    await f.run();
    const saved = f.local.find({ request: f.query, kind: "exact" }).record;
    const key = `artifact:${f.artifact.id}`;
    const artifact = await f.storage.get(key);
    if (reason === "hash") await f.storage.put(key, { ...artifact, content_hash: "c".repeat(64) });
    if (reason === "missing") await f.storage.delete(key);
    if (reason === "expired") await f.storage.put(key, { ...artifact, expires_at: new Date(Date.now() - 1000).toISOString() });
    if (["superseded", "source_disabled"].includes(reason)) {
      const source = await f.storage.get(`source:${f.source.id}`);
      await f.storage.put(`source:${source.id}`, reason === "superseded" ? { ...source, current_artifact: "c".repeat(64) } : { ...source, enabled: false });
    }
    if (reason === "ttl") { saved.created_at = new Date(Date.now() - 73 * 3600000).toISOString(); f.local.put(saved); }
    if (reason === "provider_disabled") { f.policy.providers.firecrawl.enabled = false; await f.storage.put("policy", f.policy); }
    if (reason === "host_revoked") { f.policy.allowed_hosts = ["react.dev"]; await f.storage.put("policy", f.policy); }
    const deleted = [];
    const memos = { call: (operation, payload) => {
      if (operation === "delete") deleted.push(payload.id);
      return f.memos.call(operation, payload);
    } };
    const result = await f.run(f.query, { memos });
    assert.notEqual(result.path, "memo");
    assert.ok(deleted.includes(saved.id), "the invalid record is deleted before a replacement can be written");
  });
}

test("fresh bypasses memo lookup, exact off skips exact, and both off disables storage", async t => {
  const f = await setup(t);
  await f.run();
  let finds = 0;
  const memos = { call: (op, payload) => { if (op === "find") finds++; return f.memos.call(op, payload); } };
  const fresh = await f.run(request({ ...f.query, freshness: "fresh" }), { memos });
  assert.notEqual(fresh.path, "memo");
  assert.equal(finds, 0);
  f.policy.memo_exact = "off";
  await f.storage.put("policy", f.policy);
  const observed = await f.run();
  assert.notEqual(observed.path, "memo");
  assert.ok(observed.index_diagnostics.memo_candidate);
  f.policy.memo_semantic = "off";
  await f.storage.put("policy", f.policy);
  await f.memos.call("purge", { all: true });
  await f.run();
  assert.equal((await f.memos.call("stats")).totals.count, 0);
});

test("failures, partial failure gaps and unverified provider-only responses are never memoized", async t => {
  const f = await setup(t);
  const bad = async () => { throw Object.assign(new Error("synthetic failure"), { code: "provider_timeout" }); };
  const partial = await f.run(request({ ...f.query, mode: "deep" }), { retrieve: bad });
  assert.equal(partial.status, "partial");
  assert.ok(partial.excerpts.length);
  assert.equal((await f.memos.call("stats")).totals.count, 0);
  const empty = await fixture();
  await assert.rejects(retrieveKnowledge(empty.env, empty.authority, principal, f.query,
    { corpus: empty.corpus, memos: f.memos, retrieve: bad, cache: null }));
  assert.equal((await f.memos.call("stats")).totals.count, 0);
  const session = memoSession(f.env, f.authority, f.query, f.policy, f.options, performance.now(), []);
  await session.write({ status: "partial", excerpts: [], provider_context: [{ text: "Unverified" }] }, false);
  assert.equal((await f.memos.call("stats")).totals.count, 0);
});

test("partial coverage notes without failures can be memoized", async t => {
  const f = await setup(t);
  const result = await f.run(request({ ...f.query, mode: "deep" }), { retrieve: async () => ({ observations: [], warnings: ["coverage_limited"] }) });
  assert.equal(result.status, "partial");
  assert.ok(result.excerpts.length);
  assert.equal((await f.memos.call("stats")).totals.count, 1);
});

test("secret-shaped queries bypass memo reads, embeddings and writes", async t => {
  const f = await setup(t);
  const prefixes = ["s" + "k-", "AI" + "za", "gh" + "p_", "xo" + "xb-", "-----BEGIN " + "PRIVATE KEY-----", "-----BEGIN " + "RSA PRIVATE KEY-----"];
  for (const prefix of prefixes) {
    const query = `Explain ${prefix}synthetic-example`;
    assert.equal(memoSecretQuery(query), true);
    await f.run(request({ ...f.query, query }));
  }
  assert.equal(f.embeddings(), 0);
  assert.equal((await f.memos.call("stats")).totals.count, 0);
});

test("embedding or memo backend errors degrade to ordinary retrieval", async t => {
  const f = await setup(t);
  const failedEmbedding = await f.run(f.query, { embed: async () => { throw new Error("synthetic embedding failure"); } });
  assert.equal(failedEmbedding.status, "ok");
  assert.equal((await f.memos.call("stats")).totals.count, 1, "exact memo survives without a vector");
  const backend = { call: async () => { throw new Error("synthetic store failure"); } };
  const failedStore = await f.run(f.query, { memos: backend });
  assert.equal(failedStore.status, "ok");
  assert.notEqual(failedStore.path, "memo");
});

test("Workers AI binding receives bge-m3 request and storage uses waitUntil", async t => {
  const f = await setup(t);
  let called;
  f.env.KNOWLEDGE_SEARCH_AI = { run: async (...args) => { called = args; return { data: [[0.5, 1, -1]] }; } };
  const tasks = [];
  await f.run(f.query, { embed: undefined, waitUntil: promise => tasks.push(promise) });
  await Promise.all(tasks);
  assert.deepEqual(called, ["@cf/baai/bge-m3", { text: [f.query.query] }]);
  assert.equal(tasks.length, 2);
  assert.equal((await f.memos.call("stats")).totals.count, 1);
});

test("SQLite bounds evict least recently hit within products and globally; purge clears lazy vectors", t => {
  assert.equal(MEMO_SHARD_LIMIT, 2000);
  assert.equal(MEMO_TOTAL_LIMIT, 20000);
  const { local } = store(t, { shardLimit: 2, totalLimit: 3 });
  for (const id of [1, 2]) local.put(record(id));
  local.hit(record(1).id, Date.parse("2026-10-07T01:00:00Z"));
  local.put(record(3, "flask", "2026-10-07T00:02:00Z"));
  assert.equal(local.rows("SELECT id FROM memos WHERE id = ?", record(2).id).length, 0);
  local.put(record(4, "react", "2026-10-07T00:03:00Z"));
  local.put(record(5, "django", "2026-10-07T00:04:00Z"));
  assert.equal(local.rows("SELECT id FROM memos WHERE id = ?", record(3).id).length, 0);
  assert.equal(local.stats().totals.count, 3);
  assert.equal(local.stats().totals.hits, 1);
  local.find({ kind: "semantic", request: request(), embedding: quantizeEmbedding([1, 0, 0]), similarity: 0.92 });
  assert.ok(local.vectors);
  assert.deepEqual(local.purge({ product: "FLASK" }), { purged: 1 });
  assert.equal(local.vectors, null);
  assert.deepEqual(local.purge({ all: true }), { purged: 2 });
  assert.equal(local.stats().totals.count, 0);
  for (const payload of [{}, { all: false }, { all: true, product: "flask" }, { all: "true" }, { other: true }]) assert.throws(() => local.purge(payload));
});

test("oversized or malformed memo records are rejected at the store boundary", t => {
  const { local } = store(t);
  const oversized = record(1);
  oversized.bundle.padding = "x".repeat(256 * 1024);
  assert.throws(() => local.put(oversized), { code: "invalid_memo" });
  const invalid = record(2);
  invalid.embedding.values = [300];
  assert.throws(() => local.put(invalid), { code: "invalid_memo" });
  invalid.embedding = null;
  invalid.citations = [];
  assert.throws(() => local.put(invalid), { code: "invalid_memo" });
  assert.equal(local.stats().totals.count, 0);
  assert.throws(() => local.find({ kind: "semantic", request: request(), embedding: quantizeEmbedding([1, 0, 0]), similarity: NaN }), { code: "invalid_memo" });
});

test("memo management service is strictly manage-scoped and validates purge contracts", async t => {
  const f = await setup(t);
  await f.run();
  const submit = (operation, payload, identity = manager) => dispatchKnowledge(f.env,
    { version: 1, operation, payload, principal: identity }, { authority: f.authority, memos: f.memos });
  for (const op of ["memos.stats", "memos.purge"]) await assert.rejects(submit(op, {}, principal), { code: "insufficient_scope" });
  assert.equal((await submit("memos.stats", {})).totals.count, 1);
  await assert.rejects(submit("memos.stats", { all: true }), { code: "invalid_request" });
  await assert.rejects(submit("memos.purge", {}), { code: "invalid_request" });
  assert.deepEqual(await submit("memos.purge", { product: "flask" }), { purged: 1 });
  assert.equal((await submit("memos.stats", {})).totals.count, 0);
});

test("memo policy defaults migrate old stored policy and enforce documented limits", () => {
  const { revision, ...policy } = defaultPolicy();
  const body = { ...policy, expected_revision: revision };
  for (const values of [{ memo_exact: true }, { memo_semantic: "always" }, { memo_similarity: 0.84 }, { memo_similarity: 1 }, { memo_similarity: NaN }, { memo_similarity: true }, { memo_ttl_hours: 0 }, { memo_ttl_hours: 721 }, { memo_ttl_hours: 1.5 }]) {
    assert.throws(() => validatePolicy({ ...body, ...values }));
  }
  for (const [similarity, hours] of [[0.85, 1], [0.99, 720]]) assert.equal(validatePolicy({ ...body, memo_similarity: similarity, memo_ttl_hours: hours }).memo_ttl_hours, hours);
  for (const name of ["memo_exact", "memo_semantic", "memo_similarity", "memo_ttl_hours"]) delete policy[name];
  assert.equal(withProviderDefaults(policy).memo_semantic, "observe");
  assert.equal(validatePolicy({ ...policy, expected_revision: revision }).memo_exact, "on");
});

test("real KnowledgeMemos SQLite Durable Object survives restart with hit counts and vectors", async t => {
  const bundled = await build({ stdin: { resolveDir: process.cwd(), contents: `
    export { KnowledgeMemos } from './worker/knowledge/index.mjs';
    export default { fetch(request, env) { return env.MEMOS.get(env.MEMOS.idFromName('personal')).fetch(request); } };
  ` }, bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], write: false });
  const directory = await mkdtemp(join(tmpdir(), "knowledge-memos-"));
  const create = () => new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, compatibilityDate: "2026-07-28",
    script: bundled.outputFiles[0].text, resourcePersistencePath: directory, durableObjects: { MEMOS: { className: "KnowledgeMemos", useSQLite: true } } }));
  let mf = create();
  t.after(async () => { await mf.dispose(); await rm(directory, { recursive: true, force: true }); });
  const call = async (operation, payload = {}) => {
    const response = await mf.dispatchFetch("http://memos.internal/dispatch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ operation, payload }) });
    assert.equal(response.status, 200);
    return (await response.json()).result;
  };
  const memo = record(1);
  await call("put", { record: memo });
  await Promise.all(Array.from({ length: 10 }, () => call("hit", { id: memo.id })));
  await mf.dispose();
  mf = create();
  assert.equal((await call("stats")).totals.hits, 10);
  const match = await call("find", { request: request({ query: "rephrase", mode: "smart" }), kind: "semantic", embedding: quantizeEmbedding([1, 0, 0]), similarity: 0.92 });
  assert.equal(match.record.id, memo.id);
  assert.equal(match.record.hits, 10);
  assert.deepEqual(await call("purge", { all: true }), { purged: 1 });
});

test("slow optional memo stages are bounded and do not fail successful retrieval", async t => {
  const f = await setup(t);
  const slow = { call: () => new Promise(() => {}) };
  const result = await f.run(f.query, { memos: slow, memoBudgetMs: 10 });
  assert.equal(result.status, "ok");
  assert.notEqual(result.path, "memo");
  const session = memoSession(f.env, f.authority, f.query, f.policy,
    { ...f.options, memoWriteDeadlineAt: performance.now() - 1 }, performance.now(), []);
  await session.write(result, false);
  assert.equal((await f.memos.call("stats")).totals.count, 0);
  f.env.KNOWLEDGE_MEMOS = { idFromName: () => { throw new Error("synthetic binding fault"); } };
  const unavailable = await f.run(f.query, { memos: undefined });
  assert.equal(unavailable.status, "ok");
});
