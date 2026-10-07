import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import { MemoStore } from "../worker/knowledge/memo-store.mjs";
import { memoSession } from "../worker/knowledge/memos.mjs";
import { retrieveKnowledge } from "../worker/knowledge/retrieval.mjs";
import { fixture, principal, request } from "./knowledge_fixture.mjs";

const never = () => new Promise(() => {});
function gate() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function setup(t) {
  const f = await fixture();
  await f.published();
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const local = new MemoStore({
    sql: { exec: (sql, ...args) => db.prepare(sql).all(...args) },
    transactionSync(callback) {
      db.exec("BEGIN");
      try { const result = callback(); db.exec("COMMIT"); return result; }
      catch (error) { db.exec("ROLLBACK"); throw error; }
    },
  });
  const memos = { call: async (...args) => local.call(...args) };
  const tasks = [];
  const query = request({ version: "3.1.3" });
  const options = { corpus: f.corpus, retrieve: f.retrieve, memos, embed: async () => [1, 0, 0],
    cache: null, waitUntil: promise => tasks.push(promise) };
  const run = (q = query, extra = {}) => retrieveKnowledge(f.env, f.authority, principal, q, { ...options, ...extra });
  const first = await run(query, { waitUntil: undefined });
  const drain = () => Promise.all(tasks.splice(0));
  t.after(drain);
  return { ...f, memos, local, query, run, options, tasks, first, drain };
}

for (const stage of ["validation", "embedding", "put"]) {
  test(`waitUntil moves the whole memo write off the response path: slow ${stage}`, async t => {
    const f = await setup(t);
    const blocked = gate();
    const order = [];
    const authority = { call: async (...args) => {
      if (args[0] === "memos.validate") { order.push("validation"); if (stage === "validation") await blocked.promise; }
      return f.authority.call(...args);
    } };
    const memos = { call: async (...args) => {
      order.push(args[0]);
      if (args[0] === "put" && stage === "put") await blocked.promise;
      return f.memos.call(...args);
    } };
    const usage = [];
    const session = memoSession(f.env, authority, f.query, f.policy, { ...f.options, memos,
      embed: async () => { order.push("embedding"); if (stage === "embedding") await blocked.promise; return [1, 0, 0]; },
    }, performance.now(), usage);
    const started = performance.now();
    await session.write(f.first, false);
    assert.ok(performance.now() - started < 100, "write returns without waiting for any I/O stage");
    assert.equal(f.tasks.length, 1);
    assert.equal(order.includes("put"), false);
    blocked.resolve();
    await f.drain();
    assert.deepEqual(order, ["validation", "embedding", "put"]);
    assert.equal(usage[0].bound_units, 0);
    assert.equal(usage[0].outcome, "completed");
  });
}

test("without waitUntil the entire write is awaited", async t => {
  const f = await setup(t);
  const blocked = gate();
  let stored = false, returned = false;
  const session = memoSession(f.env, f.authority, f.query, f.policy, { ...f.options, waitUntil: undefined,
    memos: { call: async (...args) => { await blocked.promise; stored = true; return f.memos.call(...args); } },
  }, performance.now(), []);
  const write = session.write(f.first, false).then(() => { returned = true; });
  await delay(20);
  assert.equal(returned, false);
  blocked.resolve();
  await write;
  assert.equal(stored, true);
});

for (const stage of ["embedding", "store", "validation"]) {
  test(`observe runs beside retrieval and ignores a late ${stage} result`, async t => {
    const f = await setup(t);
    const blocked = gate();
    const order = [];
    const corpus = { ...f.corpus, search: async (...args) => { order.push("retrieval"); return f.corpus.search(...args); } };
    const memos = { call: async (...args) => {
      if (args[0] === "find" && args[1].kind === "semantic") {
        order.push("match");
        if (stage === "store") await blocked.promise;
      }
      return f.memos.call(...args);
    } };
    const authority = { call: async (...args) => {
      if (args[0] === "memos.validate" && stage === "validation") await blocked.promise;
      return f.authority.call(...args);
    } };
    const query = request({ ...f.query, query: "Where do request size limits belong?" });
    const started = performance.now();
    const result = await retrieveKnowledge(f.env, authority, principal, query, { ...f.options, corpus, memos,
      embed: async () => { order.push("embedding"); if (stage === "embedding") await blocked.promise; return [1, 0, 0]; },
    });
    assert.ok(performance.now() - started < 100, "observation must not delay the answer");
    assert.equal(result.path, "index");
    assert.equal(result.index_diagnostics.memo_candidate, undefined);
    assert.ok(order.includes("retrieval"));
    assert.ok(order.indexOf("embedding") < order.indexOf("retrieval"));
    const before = structuredClone(result);
    blocked.resolve();
    await f.drain();
    assert.deepEqual(result, before, "late memo work cannot mutate the returned response or usage");
    assert.equal(f.local.stats().totals.hits, 0);
  });
}

for (const embeddingMs of [20, 450]) {
  test(`observe attaches a candidate completed during retrieval after ${embeddingMs} ms`, async t => {
    const f = await setup(t);
    let embedding = false;
    const result = await f.run(request({ ...f.query, query: "Where do request size limits belong?" }), {
      embed: async () => { await delay(embeddingMs); embedding = true; return [1, 0, 0]; },
      corpus: { ...f.corpus, search: async (...args) => { assert.equal(embedding, false); await delay(embeddingMs + 30); return f.corpus.search(...args); } },
    });
    assert.equal(result.path, "index");
    assert.equal(result.index_diagnostics.memo_candidate.matched_query, f.query.query);
    assert.equal(f.local.stats().totals.hits, 0);
    await f.drain();
  });
}

test("a candidate finishing after assembly is ignored even when a foreground write is awaited", async t => {
  const f = await setup(t);
  const result = await f.run(request({ ...f.query, query: "Where do request size limits belong?" }), {
    embed: async () => { await delay(40); return [1, 0, 0]; }, waitUntil: undefined,
  });
  assert.equal(result.index_diagnostics.memo_candidate, undefined);
});

for (const stage of ["store", "validation", "hit"]) {
  test(`exact lookup bounds slow ${stage} to 300 ms and returns normal evidence`, async t => {
    const f = await setup(t);
    f.policy.memo_semantic = "off";
    await f.storage.put("policy", f.policy);
    const authority = { call: (...args) => args[0] === "memos.validate" && stage === "validation"
      ? never() : f.authority.call(...args) };
    const memos = { call: (...args) => args[0] === "find" && stage === "store" || args[0] === "hit" && stage === "hit"
      ? never() : f.memos.call(...args) };
    const started = performance.now();
    const result = await retrieveKnowledge(f.env, authority, principal, f.query, { ...f.options, memos });
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 270 && elapsed < 650, `300 ms bound, measured ${elapsed}`);
    assert.equal(result.status, "ok");
    assert.equal(result.path, "index");
    await f.drain();
  });
}

for (const stage of ["embedding", "match", "combined", "validation"]) {
  test(`semantic on bounds slow ${stage} to 400 ms total and misses safely`, async t => {
    const f = await setup(t);
    f.policy.memo_exact = "off";
    f.policy.memo_semantic = "on";
    await f.storage.put("policy", f.policy);
    const authority = { call: (...args) => args[0] === "memos.validate" && stage === "validation"
      ? never() : f.authority.call(...args) };
    const finds = [];
    const memos = { call: async (...args) => {
      if (args[0] === "find") {
        finds.push(args[1].kind);
        if (stage === "match") return never();
        if (stage === "combined") await delay(250);
      }
      return f.memos.call(...args);
    } };
    const embed = async () => {
      if (stage === "embedding") return never();
      if (stage === "combined") await delay(250);
      return [1, 0, 0];
    };
    const started = performance.now();
    const result = await retrieveKnowledge(f.env, authority, principal, f.query, { ...f.options, memos, embed });
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 370 && elapsed < 700, `400 ms total bound, measured ${elapsed}`);
    assert.equal(result.status, "ok");
    assert.equal(result.path, "index");
    if (stage === "embedding") assert.deepEqual(finds, [], "no late match after an embedding timeout");
    const before = structuredClone(result);
    await f.drain();
    assert.deepEqual(result, before);
    if (stage === "embedding") assert.deepEqual(finds, []);
  });
}

for (const fault of ["embed", "store", "authority", "waitUntil"]) {
  test(`a failing optional ${fault} path never fails or delays an answer`, async t => {
    const f = await setup(t);
    const fail = () => { throw new Error("synthetic optional memo failure"); };
    const authority = fault === "authority" ? { call: (...args) => args[0] === "memos.validate" ? fail() : f.authority.call(...args) } : f.authority;
    const started = performance.now();
    const result = await retrieveKnowledge(f.env, authority, principal,
      request({ ...f.query, query: "Another way to configure limits?" }), { ...f.options,
        ...(fault === "embed" ? { embed: fail } : {}),
        ...(fault === "store" ? { memos: { call: fail } } : {}),
        ...(fault === "waitUntil" ? { waitUntil: fail } : {}),
      });
    assert.ok(performance.now() - started < 100);
    assert.equal(result.status, "ok");
    assert.equal(result.path, "index");
    await f.drain();
  });
}

test("background memo validation can finish after the response's request signal is aborted", async t => {
  const f = await setup(t);
  const blocked = gate();
  const controller = new AbortController();
  const authority = { call: async (...args) => {
    if (args[0] === "memos.validate") await blocked.promise;
    return f.authority.call(...args);
  } };
  const query = request({ ...f.query, query: "How do request limits handle file sizes?", freshness: "fresh" });
  const result = await retrieveKnowledge(f.env, authority, principal, query, { ...f.options, signal: controller.signal });
  assert.equal(result.status, "ok");
  controller.abort();
  blocked.resolve();
  await f.drain();
  assert.ok(f.local.find({ request: query, kind: "exact" }));
});

test("write validation and embedding share one total deadline and never put after timeout", async t => {
  const f = await setup(t);
  let puts = 0;
  const session = memoSession(f.env, { call: async (...args) => {
    await delay(30);
    return f.authority.call(...args);
  } }, f.query, f.policy, { ...f.options, memoBudgetMs: 50, waitUntil: undefined,
    embed: async () => { await delay(30); return [1, 0, 0]; },
    memos: { call: (...args) => { if (args[0] === "put") puts++; return f.memos.call(...args); } },
  }, performance.now(), []);
  const started = performance.now();
  await session.write(f.first, false);
  assert.ok(performance.now() - started < 100);
  await delay(40);
  assert.equal(puts, 0);
});
