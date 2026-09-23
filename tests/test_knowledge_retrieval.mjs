import assert from "node:assert/strict";
import test from "node:test";
import { retrieveKnowledge } from "../worker/knowledge/retrieval.mjs";
import { fixture, principal, request } from "./knowledge_fixture.mjs";

const run = (f, query = request(), extra = {}) => retrieveKnowledge(f.env, f.authority, principal, query,
  { corpus: f.corpus, cache: f.cache, retrieve: f.retrieve, ...extra });

test("indexed citations match retained bytes and cache saves subsequent provider calls", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const query = request({ version: "3.1.3" });
  const result = await run(f, query);
  assert.equal(result.path, "index");
  assert.equal(result.status, "ok");
  assert.equal(result.excerpts[0].artifact_id, artifact.id);
  assert.equal(result.excerpts[0].target_match, "exact");
  assert.equal(result.excerpts[0].locator.end_byte, Buffer.byteLength(f.text));
  assert.equal(f.counts.providers, 0);
  const cached = await run(f, query);
  assert.equal(cached.path, "cache");
  assert.deepEqual(cached.usage, []);
  assert.deepEqual(cached.providers_used, []);
  assert.equal(f.counts.searches, 1);
  await retrieveKnowledge(f.env, f.authority, { ...principal, id: "different-reader" }, query,
    { corpus: f.corpus, cache: f.cache, retrieve: f.retrieve });
  assert.equal(f.counts.searches, 2, "cache entries are principal-scoped");
});

test("cache reads fail closed when policy or sources are revoked during lookup", async () => {
  for (const revokePolicy of [false, true]) {
    const f = await fixture();
    await f.published();
    await run(f);
    const match = f.cache.match.bind(f.cache);
    f.cache.match = async key => {
      const result = await match(key);
      if (revokePolicy) {
        const { revision, ...policy } = f.policy;
        await f.authority.call("policy.update", { ...policy, expected_revision: revision, enabled: false });
      } else {
        await f.authority.call("source.update", { id: f.source.id, expected_revision: 1, enabled: false });
      }
      return result;
    };
    await assert.rejects(run(f), { code: revokePolicy ? "policy_changed" : "corpus_changed" });
  }
});

test("source disable during a snapshot read removes the excerpt before return", async () => {
  const f = await fixture();
  await f.published();
  f.corpus.getSnapshot = async () => {
    await f.authority.call("source.update", { id: f.source.id, expected_revision: 1, enabled: false });
    return f.text;
  };
  const result = await run(f);
  assert.equal(result.status, "insufficient_evidence");
  assert.deepEqual(result.excerpts, []);
});

test("live acquisition retains source provenance, warnings and configured usage bounds", async () => {
  const f = await fixture();
  const retrieve = f.retrieve;
  f.retrieve = async (...args) => ({ ...await retrieve(...args), warnings: ["exa_content_truncated"] });
  const result = await run(f, request({ version: "3.1.3", token_budget: 256 }));
  assert.equal(result.path, "live");
  assert.equal(result.status, "partial");
  assert.equal(result.excerpts[0].version.basis, "versioned_source_url");
  assert.equal(result.gaps[0].code, "exa_content_truncated");
  assert.ok(result.excerpts[0].checked_at);
  assert.ok(result.token_count <= 256);
  const artifact = await f.authority.call("artifact.get", { id: result.excerpts[0].artifact_id });
  assert.equal(f.snapshots.get(artifact.id), f.text);
  const usage = (await f.authority.call("snapshot")).usage;
  assert.equal(usage.find(item => item.provider === "exa").confirmed, 1);
  assert.equal(usage.find(item => item.provider === "ai_search").confirmed, 1);
});

test("requested versions and incidental URL segments never prove a discovered product version", async () => {
  const f = await fixture();
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => ({
    observations: [{ kind: "source_excerpt", provider, url: "https://github.com/unrelated/project/blob/main/examples/3.1.3/", text: f.text }],
    warnings: [],
  }));
  const result = await run(f, request({ version: "3.1.3" }));
  assert.equal(result.status, "insufficient_evidence");
  assert.equal(result.excerpts.length, 0);
  assert.equal(result.related_evidence.length, 1);
  assert.equal(result.related_evidence[0].version.kind, "unknown");
  assert.ok(result.gaps.some(item => item.code === "version_not_verified"));
});

test("available primary text takes priority over a discovery for the same source", async () => {
  const f = await fixture();
  f.env.CONTEXT7_API_KEY = "synthetic-test-key";
  f.policy.providers.context7 = { ...f.policy.providers.exa };
  await f.storage.put("policy", f.policy);
  const calls = [];
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    calls.push(provider);
    if (provider === "firecrawl") throw new Error("unavailable");
    return { observations: [{ provider, url: f.source.url,
      kind: provider === "context7" ? "discovery" : "source_excerpt", text: provider === "exa" ? f.text : "" }], warnings: [] };
  });
  const result = await run(f, request({ mode: "smart" }));
  assert.equal(result.excerpts.length, 1);
  assert.equal(result.excerpts[0].provider, "exa");
  assert.deepEqual(calls.sort(), ["context7", "exa"]);
});

test("identical text reacquired by an enabled provider has independent immutable provenance", async () => {
  const f = await fixture();
  const original = await f.published();
  f.policy.providers.firecrawl.enabled = false;
  await f.storage.put("policy", f.policy);
  const scheduled = [];
  const result = await run(f, request({ version: "3.1.3" }), { schedule: async (...args) => scheduled.push(args) });
  assert.equal(result.excerpts.length, 1);
  assert.equal(result.excerpts[0].provider, "exa");
  assert.notEqual(result.excerpts[0].artifact_id, original.id);
  assert.equal(result.excerpts[0].content_hash, original.content_hash);
  assert.equal((await f.authority.call("artifact.get", { id: original.id })).provider, "firecrawl");
  assert.equal(scheduled[0][2], result.excerpts[0].artifact_id, "background indexing reuses this retained acquisition");
});

test("fresh requests reject unverified cache-age evidence from both the index and live providers", async () => {
  const f = await fixture();
  await f.published({ fresh: false });
  const retrieve = f.retrieve;
  f.retrieve = async (...args) => {
    const result = await retrieve(...args);
    result.observations[0].freshness = "cached_or_unknown";
    return result;
  };
  const result = await run(f, request({ freshness: "fresh" }));
  assert.equal(result.status, "insufficient_evidence");
  assert.equal(result.excerpts.length, 0);
  assert.ok(result.gaps.some(item => item.code === "freshness_unverified"));
});

test("invented index text is rejected and cannot become a citation", async () => {
  const f = await fixture();
  await f.published();
  f.rows[0].text = "Invented content absent from the retained source.";
  f.retrieve = async () => ({ observations: [], warnings: [] });
  const result = await run(f);
  assert.equal(result.status, "insufficient_evidence");
  assert.equal(result.excerpts.length, 0);
  assert.ok(result.gaps.some(item => item.code === "invalid_source_span"));
});

test("failed providers differ from successful empty results and preserve uncertain usage", async () => {
  const f = await fixture();
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "failed", async () => { throw new Error("transport failed"); });
  await assert.rejects(run(f), { code: "retrieval_failed", status: 502 });
  assert.equal((await f.authority.call("snapshot")).usage.find(item => item.provider === "exa").unknown, 1);
  f.retrieve = async () => ({ observations: [], warnings: [] });
  assert.equal((await run(f)).status, "insufficient_evidence");
  f.policy.enabled = false;
  await f.storage.put("policy", f.policy);
  await assert.rejects(run(f), { code: "knowledge_disabled" });
});

test("deadline bounds catalogue, cache, storage and pre-dispatch provider waits", async () => {
  for (const stage of ["catalogue", "cache", "snapshot", "provider"]) {
    const f = await fixture();
    if (stage !== "provider") await f.published();
    const never = () => new Promise(() => {});
    if (stage === "catalogue") f.authority = { call: never };
    if (stage === "cache") f.cache.match = never;
    if (stage === "snapshot") f.corpus.getSnapshot = never;
    if (stage === "provider") f.retrieve = never;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20);
    try { await assert.rejects(run(f, request(), { signal: controller.signal }), { code: "retrieval_deadline", status: 504 }); }
    finally { clearTimeout(timer); }
    assert.equal(f.counts.writes, 0);
  }
});

test("a cancelled reservation wait never dispatches late provider work", async () => {
  const f = await fixture();
  const call = f.authority.call.bind(f.authority);
  let release;
  const ready = new Promise(resolve => { release = resolve; });
  f.authority.call = async (operation, payload) => {
    if (operation === "reserve") await ready;
    return call(operation, payload);
  };
  const controller = new AbortController();
  const result = run(f, request(), { signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(result, { code: "retrieval_deadline" });
  release();
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(f.counts.providers, 0);
  assert.equal(f.counts.writes, 0);
});
