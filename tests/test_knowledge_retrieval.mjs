import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { retrieveKnowledge } from "../worker/knowledge/retrieval.mjs";
import { retrieve } from "../worker/knowledge/providers/index.mjs";
import { createArtifact } from "../worker/knowledge/evidence.mjs";
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

test("indexed chunks of one document share a catalogue lookup and snapshot read", async () => {
  const f = await fixture();
  const artifact = await f.published();
  for (let index = 0; index < 4; index += 1) f.rows.push({ ...f.rows[0], score: 0.8 - index / 10 });
  const calls = { lookups: 0, snapshots: 0 };
  const authority = { call: async (operation, payload) => {
    if (operation === "artifact.for_key") calls.lookups += 1;
    return f.authority.call(operation, payload);
  } };
  f.corpus.getSnapshot = async (item) => {
    calls.snapshots += 1;
    return f.snapshots.get(item.id) ?? null;
  };
  const result = await retrieveKnowledge(f.env, authority, principal, request({ version: "3.1.3" }),
    { corpus: f.corpus, cache: f.cache, retrieve: f.retrieve });
  assert.equal(result.status, "ok");
  assert.equal(result.excerpts[0].artifact_id, artifact.id);
  assert.deepEqual([calls.lookups, calls.snapshots], [1, 1]);
});

test("indexed rows resolve concurrently and keep evidence from rows before a failure", async () => {
  const f = await fixture();
  const first = await f.published();
  f.rows.push({ text: f.text, index_key: "missing-key", score: 0.4 });
  let inflight = 0;
  let overlapped = false;
  const authority = { call: async (operation, payload) => {
    if (operation !== "artifact.for_key") return f.authority.call(operation, payload);
    inflight += 1;
    overlapped ||= inflight > 1;
    await new Promise(resolve => setTimeout(resolve, 5));
    inflight -= 1;
    if (payload.key === "missing-key") throw Object.assign(new Error("catalogue"), { code: "storage_unavailable" });
    return f.authority.call(operation, payload);
  } };
  const result = await retrieveKnowledge(f.env, authority, principal, request({ version: "3.1.3", mode: "economy" }),
    { corpus: f.corpus, cache: f.cache, retrieve: f.retrieve });
  assert.equal(overlapped, true);
  assert.ok(result.excerpts.some(item => item.artifact_id === first.id));
  assert.ok(result.gaps.some(gap => gap.code === "storage_unavailable"));
});

test("versioned queries cite only the current revision of a refreshed source", async () => {
  const f = await fixture();
  const stale = await f.published();
  const revised = "# Request size limits\n\nFlask 3.1.3 documents the revised request limit.";
  const current = await createArtifact({ ...f.source, origin_checked: true }, revised, "firecrawl");
  f.snapshots.set(current.id, revised);
  await f.authority.call("artifact.save", { artifact: current });
  const job = await f.authority.call("job.enqueue", { source_id: f.source.id });
  await f.authority.call("job.publish", { id: job.id, artifact_id: current.id, item_id: "fixture-item-2", index_key: current.index_key });
  f.rows.push({ text: revised, index_key: current.index_key, score: 0.5 });
  const result = await run(f, request({ version: "3.1.3" }));
  assert.deepEqual(result.excerpts.map(item => item.artifact_id), [current.id]);
  assert.ok(![...result.excerpts, ...result.related_evidence].some(item => item.artifact_id === stale.id),
    "the higher-ranked stale revision is not evidence");
});

test("artifact admission applies the current retention policy", async () => {
  const f = await fixture();
  const artifact = await createArtifact({ ...f.source, origin_checked: true }, f.text, "firecrawl");
  f.policy.providers.firecrawl.retention_allowed = false;
  await f.storage.put("policy", f.policy);
  await assert.rejects(f.authority.call("artifact.save", { artifact }), { code: "provider_disabled" });
  f.policy.providers.firecrawl.retention_allowed = true;
  f.policy.allowed_hosts = ["react.dev"];
  await f.storage.put("policy", f.policy);
  await assert.rejects(f.authority.call("artifact.save", { artifact }), { code: "source_not_allowed" });
});

test("saving clamps expiry to the current retention duration", async () => {
  const f = await fixture();
  const artifact = await createArtifact({ ...f.source, origin_checked: true }, f.text, "firecrawl");
  f.policy.retention_hours = 1;
  await f.storage.put("policy", f.policy);
  const saved = await f.authority.call("artifact.save", { artifact });
  assert.equal(Date.parse(saved.expires_at), Date.parse(artifact.fetched_at) + 3600000);
  assert.equal((await f.authority.call("artifact.save", { artifact })).expires_at, saved.expires_at, "a refresh cannot extend it either");
});

test("revoking a host during a live snapshot write removes only bytes that write created", async () => {
  for (const created of [true, false]) {
    const f = await fixture();
    const discarded = [];
    f.corpus.putSnapshot = async (artifact, value) => {
      f.snapshots.set(artifact.id, value);
      const { revision, ...policy } = f.policy;
      await f.authority.call("policy.update", { ...policy, expected_revision: revision, allowed_hosts: ["react.dev"] });
      return { key: artifact.snapshot_key, created };
    };
    f.corpus.discardSnapshot = async artifact => { discarded.push(artifact.id); f.snapshots.delete(artifact.id); };
    await assert.rejects(run(f), { code: "policy_changed" });
    assert.equal(discarded.length, created ? 1 : 0);
    assert.equal(f.snapshots.size, created ? 0 : 1);
  }
});

test("a failed indexing schedule is not cached as a complete answer", async () => {
  const f = await fixture();
  const query = request({ version: "3.1.3" });
  const first = await run(f, query, { schedule: async () => { throw new Error("workflow unavailable"); } });
  assert.equal(first.status, "partial");
  assert.ok(first.gaps.some(gap => gap.code === "indexing_not_scheduled"));
  const scheduled = [];
  const retried = await run(f, query, { schedule: async (...args) => scheduled.push(args) });
  assert.notEqual(retried.path, "cache");
  assert.equal(scheduled.length, 1, "the next request retries indexing");
});

test("stable provider coverage notes are cached but provider failures are not", async () => {
  const f = await fixture();
  const retrieve = f.retrieve;
  f.retrieve = async (...args) => ({ ...await retrieve(...args), warnings: ["derived_context_requires_source_verification"] });
  const query = request({ version: "3.1.3" });
  const first = await run(f, query);
  assert.equal(first.status, "partial");
  const providers = f.counts.providers;
  const cached = await run(f, query);
  assert.equal(cached.path, "cache");
  assert.deepEqual(cached.gaps.map(gap => gap.code), ["derived_context_requires_source_verification"]);
  assert.equal(f.counts.providers, providers);

  const g = await fixture();
  let calls = 0;
  g.retrieve = async (provider, intent, context) => {
    calls += 1;
    if (calls === 1) throw Object.assign(new Error("upstream"), { code: "upstream_unavailable" });
    return retrieve.call(null, provider, intent, context);
  };
  g.env.CONTEXT7_API_KEY = "synthetic-test-key";
  g.policy.providers.context7 = { ...g.policy.providers.exa };
  await g.storage.put("policy", g.policy);
  const smart = request({ version: "3.1.3", mode: "smart" });
  const failed = await run(g, smart);
  assert.ok(failed.gaps.some(gap => gap.code === "upstream_unavailable"));
  assert.notEqual((await run(g, smart)).path, "cache", "a failed provider is retried");
});

test("unchanged sources reuse retained snapshots and skip re-indexing a published revision", async () => {
  const f = await fixture();
  const query = request({ version: "3.1.3", freshness: "fresh" });
  const scheduled = [];
  const schedule = async (...args) => { scheduled.push(args); };
  const first = await run(f, query, { schedule });
  assert.equal(f.counts.writes, 1);
  assert.equal(first.usage.filter(item => item.operation_id.includes("snapshot")).length, 1);
  assert.equal(scheduled.length, 1);
  const [sourceId, , artifactId] = scheduled[0];
  const artifact = await f.authority.call("artifact.get", { id: artifactId });
  const job = await f.authority.call("job.enqueue", { source_id: sourceId, artifact_id: artifactId });
  await f.authority.call("job.publish", { id: job.id, artifact_id: artifactId, item_id: "fixture-item", index_key: artifact.index_key });
  const second = await run(f, query, { schedule });
  assert.equal(second.excerpts[0].artifact_id, artifactId);
  assert.equal(f.counts.writes, 1, "the retained snapshot is not written again");
  assert.equal(second.usage.filter(item => item.operation_id.includes("snapshot")).length, 0);
  assert.equal(scheduled.length, 1, "a published revision is not submitted for indexing again");
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
    if (revokePolicy) {
      await assert.rejects(run(f), { code: "policy_changed" });
      continue;
    }
    // The stale entry is skipped and the answer is validated against the current corpus.
    const result = await run(f);
    assert.notEqual(result.path, "cache");
    assert.deepEqual(result.excerpts, []);
    assert.equal(result.status, "insufficient_evidence");
  }
});

test("parallel queries that discover sources neither fail nor skip the cache", async () => {
  const f = await fixture();
  const { revision, ...policy } = f.policy;
  await f.authority.call("policy.update", { ...policy, allowed_hosts: ["*"], expected_revision: revision });
  let lookups = 0;
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    const topic = intent.query.match(/topic (\d)/)[1];
    lookups += 1;
    await delay(5);
    return { observations: [{ kind: "source_excerpt", provider, url: `https://docs-${topic}.example-public-docs.dev/guide/`,
      text: `${f.text} Topic ${topic}.`, freshness: "live" }], warnings: [] };
  });
  const queries = [1, 2, 3].map(topic => request({ query: `How are request size limits configured for topic ${topic}?` }));
  const results = await Promise.all(queries.map(query => run(f, query)));
  assert.deepEqual(results.map(result => result.path), ["live", "live", "live"]);
  assert.ok(results.every(result => result.excerpts.length === 1 && result.excerpts[0].source_review === "unreviewed"));
  const again = await Promise.all(queries.map(query => run(f, query)));
  assert.deepEqual(again.map(result => result.path), ["cache", "cache", "cache"], "each discovering answer is cached");
  assert.equal(lookups, 3);
});

test("publication during final validation is revalidated instead of failing a paid query", async () => {
  const f = await fixture();
  const call = f.authority.call.bind(f.authority);
  const operations = [];
  let publications = 1;
  let registered = 0;
  f.authority.call = async (operation, payload) => {
    operations.push(operation);
    const result = await call(operation, payload);
    if (operation === "artifact.get" && publications > 0) {
      publications -= 1;
      await call("source.create", { url: `https://react.dev/learn/${registered++}`, product: "react" });
    }
    return result;
  };
  const result = await run(f);
  assert.equal(result.excerpts.length, 1);
  assert.equal(result.excerpts[0].source_review, "reviewed");
  assert.equal(f.counts.providers, 1, "the paid lookup is not repeated");
  assert.ok(!operations.includes("snapshot"), "queries read the lightweight catalogue state");
  assert.notEqual((await run(f)).path, "cache", "an answer from an older corpus is not cached");
  publications = Infinity;
  await assert.rejects(run(f, request({ query: "Which limits apply to uploaded files?" })), { code: "corpus_changed", status: 409 });
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

test("live retrieval uses numbered Exa credentials after the primary account is exhausted", async () => {
  const f = await fixture();
  f.env.EXA_API_KEY_1 = "synthetic-next";
  const keys = [];
  f.retrieve = (provider, intent, context) => {
    return retrieve(provider, intent, { ...context, fetchImpl: async (_url, options) => {
      keys.push(options.headers["x-api-key"]);
      if (keys.length === 1) return Response.json({ error: "Insufficient credits" }, { status: 402 });
      return Response.json({ results: [{ id: f.source.url, url: f.source.url, text: f.text }] });
    } });
  };
  const result = await run(f, request({ version: "3.1.3" }));
  assert.equal(result.path, "live");
  assert.equal(result.excerpts[0].text, f.text);
  assert.deepEqual(keys, ["synthetic-test-key", "synthetic-next"]);
  assert.equal(Object.keys((await f.storage.get("credentials:exa")).blocked).length, 1);
  assert.equal((await f.authority.call("snapshot")).usage.find(row => row.provider === "exa").confirmed, 1);
});

test("exhausted live key pools return an actionable quota error without consuming allowance", async () => {
  const f = await fixture();
  f.env.EXA_API_KEY_1 = "synthetic-next";
  let calls = 0;
  f.retrieve = (provider, intent, context) => retrieve(provider, intent, { ...context, fetchImpl: async () => {
    calls++;
    return Response.json({ error: "Insufficient credits" }, { status: 402 });
  } });
  await assert.rejects(run(f), { code: "provider_keys_exhausted", status: 429 });
  assert.equal(calls, 2);
  assert.equal((await f.authority.call("snapshot")).usage.find(row => row.provider === "exa").total, 0);
});

test("refused sources do not use the live retention slots", async () => {
  const f = await fixture();
  const base = "https://flask.palletsprojects.com/en/3.1.x/";
  for (const name of ["a", "b", "c"]) {
    const source = await f.authority.call("source.create", { url: `${base}${name}/`, product: "flask" });
    await f.authority.call("source.update", { id: source.id, expected_revision: source.revision, enabled: false });
  }
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => ({
    observations: ["a", "b", "c", "d"].map(name => ({ kind: "source_excerpt", provider, url: `${base}${name}/`, text: f.text, freshness: "live" })),
    warnings: [],
  }));
  const result = await run(f);
  assert.deepEqual(result.excerpts.map(item => item.url), [`${base}d/`]);
});

test("a failed acquisition does not block the next discovered source", async () => {
  const f = await fixture();
  f.env.CONTEXT7_API_KEY = "synthetic-test-key";
  f.policy.providers.context7 = { ...f.policy.providers.exa };
  await f.storage.put("policy", f.policy);
  const base = "https://flask.palletsprojects.com/en/3.1.x/";
  const acquired = [];
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    if (provider === "context7") {
      return { observations: ["broken", "working"].map(name => ({ kind: "discovery", provider, url: `${base}${name}/` })), warnings: [] };
    }
    if (!intent.source_url) return { observations: [], warnings: [] };
    acquired.push(intent.source_url);
    if (intent.source_url.endsWith("broken/")) throw new Error("acquisition failed");
    return { observations: [{ kind: "source_excerpt", provider, url: intent.source_url, text: f.text, freshness: "live" }], warnings: [] };
  });
  const result = await run(f, request({ mode: "smart" }));
  assert.deepEqual(acquired, [`${base}broken/`, `${base}working/`], "each attempt reserves its own operation");
  assert.deepEqual(result.excerpts.map(item => item.url), [`${base}working/`]);
});

test("economy mode never adds an acquisition provider beyond its one provider", async () => {
  const f = await fixture();
  Object.assign(f.env, { CONTEXT7_API_KEY: "synthetic-test-key", FIRECRAWL_API_KEY: "synthetic-test-key" });
  f.policy.providers.context7 = { ...f.policy.providers.exa };
  f.policy.providers.exa.enabled = false;
  await f.storage.put("policy", f.policy);
  const calls = [];
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    calls.push(provider);
    return { observations: [{ kind: "discovery", provider, url: f.source.url }], warnings: [] };
  });
  const result = await run(f, request({ mode: "economy" }));
  assert.deepEqual(calls, ["context7"]);
  assert.deepEqual(result.providers_used, ["context7"]);
  assert.equal(result.discoveries[0].url, f.source.url);
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

test("smart retrieval asks every eligible provider and keeps their context out of excerpts", async () => {
  const f = await fixture();
  for (const id of ["context7", "mintlify", "deepwiki"]) f.policy.providers[id] = { ...f.policy.providers.exa };
  await f.storage.put("policy", f.policy);
  f.env.CONTEXT7_API_KEY = "synthetic-test-key";
  const asked = [];
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    asked.push(provider);
    if (provider === "exa") return { observations: [{ kind: "source_excerpt", provider, url: f.source.url, text: f.text, freshness: "live" }], warnings: [] };
    const kind = provider === "context7" ? "provider_documentation" : "derived_context";
    return { observations: [{ kind, provider, url: `https://${provider}.example.com/answer`, title: `${provider} answer`, text: `${provider} says limits are configurable.` }],
      warnings: [] };
  });
  const result = await run(f, request({ version: "3.1.3", mode: "smart", repository: "pallets/flask" }));
  assert.deepEqual([...asked].sort(), ["context7", "deepwiki", "exa", "mintlify"]);
  assert.deepEqual(result.provider_context.map(item => item.provider).sort(), ["context7", "deepwiki", "mintlify"]);
  assert.ok(result.provider_context.every(item => item.verification === "provider_generated_unverified"));
  assert.ok(result.excerpts.every(item => item.provider === "exa"), "provider answers never become excerpts");
  assert.ok(result.token_count <= 6000);
});

test("a provider that misses its budget becomes a gap instead of failing the answer", async () => {
  const f = await fixture();
  f.policy.providers.mintlify = { ...f.policy.providers.exa };
  await f.storage.put("policy", f.policy);
  f.retrieve = async (provider, intent, { invoke, signal }) => invoke(provider, "lookup", async () => {
    if (provider === "mintlify") {
      // Model pending I/O: AbortSignal.timeout alone does not keep Node 22 alive.
      await delay(1000, undefined, { signal });
    }
    return { observations: [{ kind: "source_excerpt", provider, url: f.source.url, text: f.text, freshness: "live" }], warnings: [] };
  });
  const result = await run(f, request({ version: "3.1.3", mode: "smart" }), { providerBudgetMs: 30 });
  assert.equal(result.excerpts[0].provider, "exa");
  assert.ok(result.gaps.some(gap => gap.code === "provider_timeout"));
  assert.equal(result.status, "partial");
});

test("an any-public-host policy admits every public source but never private names", async () => {
  const f = await fixture();
  const { revision, ...policy } = f.policy;
  await f.authority.call("policy.update", { ...policy, allowed_hosts: ["*"], expected_revision: revision });
  const url = "https://docs.example-public-docs.dev/guide/";
  f.retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    assert.deepEqual(intent.allowed_hosts, ["*"]);
    return { observations: [{ kind: "source_excerpt", provider, url, text: f.text, freshness: "live" },
      { kind: "source_excerpt", provider, url: "https://intranet.local/secret", text: f.text, freshness: "live" }], warnings: [] };
  });
  const result = await run(f, request({ mode: "smart" }));
  assert.deepEqual(result.excerpts.map(item => item.url), [url]);
  await assert.rejects(f.authority.call("policy.update", { ...policy, allowed_hosts: ["*", "localhost"], expected_revision: revision + 1 }),
    { code: "invalid_policy" });
});
