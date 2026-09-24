import assert from "node:assert/strict";
import test from "node:test";
import { KnowledgeAuthority } from "../worker/knowledge/authority.mjs";
import { defaultPolicy } from "../worker/knowledge/policy.mjs";
import { metered } from "../worker/knowledge/operations.mjs";
import { retrieve } from "../worker/knowledge/providers/index.mjs";
import { runIngestion } from "../worker/knowledge/ingestion.mjs";

class Storage {
  constructor() { this.values = new Map(); }
  async get(key) { return structuredClone(this.values.get(key)); }
  async put(key, value) { this.values.set(key, structuredClone(value)); }
  async delete(key) { this.values.delete(key); }
  async list({ prefix }) { return new Map([...this.values].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => [key, structuredClone(value)])); }
  transaction(callback) { return callback(this); }
}

function workflow() {
  const values = new Map();
  return {
    calls: [], sleeps: [],
    async do(name, options, operation) {
      this.calls.push({ name, options });
      if (values.has(name)) return structuredClone(values.get(name));
      const result = await operation();
      assert.ok(JSON.stringify(result).length < 2000, "Workflow persists references rather than source bodies");
      values.set(name, structuredClone(result));
      return result;
    },
    async sleep(name, duration) { this.sleeps.push({ name, duration }); },
  };
}

async function fixture() {
  const storage = new Storage();
  let now = Date.parse("2026-09-23T00:00:00Z");
  const authority = new KnowledgeAuthority(storage, () => now);
  const policy = defaultPolicy();
  policy.enabled = true;
  for (const name of ["firecrawl", "ai_search"]) Object.assign(policy.providers[name], {
    enabled: true, limit: 100, background_limit: 100, hard_limit_confirmed: true, retention_allowed: true,
  });
  await storage.put("policy", policy);
  const source = await authority.call("source.create", {
    url: "https://flask.palletsprojects.com/en/3.1.3/limits/", product: "flask", version: "3.1.3", provider: "firecrawl",
  });
  const job = await authority.call("job.enqueue", { source_id: source.id });
  const text = "# Request limits\n\nFlask limits apply to café and 東京 requests.";
  const counts = { acquire: 0, write: 0, upload: 0, verify: 0 };
  const snapshots = new Map();
  const items = new Map();
  const corpus = {
    async putSnapshot(artifact, content) { counts.write += 1; snapshots.set(artifact.id, content); },
    async getSnapshot(artifact) { return snapshots.get(artifact.id) ?? null; },
    async reconcileRevision(artifact) { return items.get(artifact.index_key) ?? null; },
    async uploadRevision(artifact) {
      counts.upload += 1;
      const item = { id: "indexed-item", key: artifact.index_key, status: "completed" };
      items.set(artifact.index_key, item);
      return item;
    },
    async verifySearchable() { counts.verify += 1; return true; },
  };
  const retrieve = async (provider, intent, { invoke }) => invoke(provider, "source", async () => {
    counts.acquire += 1;
    assert.equal(intent.source_url, source.url);
    assert.equal(intent.freshness, "fresh");
    assert.ok(intent.allowed_hosts.includes("flask.palletsprojects.com"));
    return { observations: [{ kind: "source_excerpt", url: source.url, text, provider, freshness: "live" }], warnings: [] };
  });
  const deps = { authority, corpus, retrieve, metered, now: () => now };
  return {
    storage, authority, source, job, text, counts, snapshots, items, corpus, deps,
    advance() { now += 3600000; },
    run(step = workflow(), id = job.id) { return runIngestion({}, step, id, deps); },
  };
}

test("source ingestion reserves each external stage, persists references and publishes verified evidence", async () => {
  const f = await fixture();
  const step = workflow();
  const result = await f.run(step);
  assert.equal(result.status, "completed");
  assert.deepEqual(f.counts, { acquire: 1, write: 1, upload: 1, verify: 1 });
  for (const name of ["acquire-source", "submit-index-revision"]) {
    assert.equal(step.calls.find(call => call.name === name).options.retries.limit, 0);
  }
  const state = await f.authority.call("job.get", { id: f.job.id });
  assert.equal(state.source.current_artifact, result.artifact_id);
  assert.equal(state.artifact.version.kind, "exact");
  const usage = (await f.authority.call("snapshot")).usage;
  assert.equal(usage.find(value => value.provider === "firecrawl").confirmed, 1);
  assert.equal(usage.find(value => value.provider === "ai_search").confirmed, 2);
  const restarted = new KnowledgeAuthority(f.storage);
  assert.equal((await restarted.call("job.get", { id: f.job.id })).job.status, "completed");
  await f.run();
  assert.equal(f.counts.upload, 1);
});

test("the Firecrawl adapter carries a forced live acquisition through ingestion", async () => {
  const f = await fixture();
  let calls = 0;
  f.deps.retrieve = (provider, intent, context) => retrieve(provider, intent, {
    ...context, env: { FIRECRAWL_API_KEY: "synthetic-test-key" },
    fetchImpl: async (url, options) => {
      calls += 1;
      assert.equal(url, "https://api.firecrawl.dev/v2/scrape");
      const request = JSON.parse(options.body);
      assert.equal(request.url, f.source.url);
      assert.equal(request.maxAge, 0);
      return Response.json({ success: true, data: {
        markdown: f.text, metadata: { sourceURL: f.source.url, statusCode: 200 },
      } });
    },
  });
  const result = await f.run();
  assert.equal(result.status, "completed");
  assert.equal(calls, 1);
  const { artifact } = await f.authority.call("job.get", { id: f.job.id });
  assert.ok(artifact.checked_at);
});

test("a trailing-slash redirect still ingests the registered Firecrawl source", async () => {
  const f = await fixture();
  f.deps.retrieve = (provider, intent, context) => retrieve(provider, intent, {
    ...context, env: { FIRECRAWL_API_KEY: "synthetic-test-key" },
    fetchImpl: async () => Response.json({ success: true, data: { markdown: f.text,
      metadata: { sourceURL: f.source.url, url: f.source.url.replace(/\/$/, ""), statusCode: 200 } } }),
  });
  const result = await f.run();
  assert.equal(result.status, "completed");
  assert.equal((await f.authority.call("job.get", { id: f.job.id })).artifact.canonical_url, f.source.url);
});

test("indexing continues with the next Firecrawl key after a definitive credit rejection", async () => {
  const f = await fixture();
  const keys = [];
  f.deps.retrieve = (provider, intent, context) => {
    assert.equal(context.authority, f.authority);
    return retrieve(provider, intent, {
      ...context, env: { FIRECRAWL_API_KEY: "synthetic-empty", FIRECRAWL_API_KEY_1: "synthetic-next" },
      fetchImpl: async (_url, options) => {
        keys.push(options.headers.Authorization);
        if (keys.length === 1) return Response.json({ success: false, error: "Insufficient credits" }, { status: 402 });
        assert.equal(JSON.parse(options.body).maxAge, 0);
        return Response.json({ success: true, data: { markdown: f.text, metadata: { sourceURL: f.source.url, statusCode: 200 } } });
      },
    });
  };
  const result = await f.run();
  assert.equal(result.status, "completed");
  assert.deepEqual(keys, ["Bearer synthetic-empty", "Bearer synthetic-next"]);
  const usage = (await f.authority.call("snapshot")).usage.find(row => row.provider === "firecrawl");
  assert.equal(usage.confirmed, 1);
  assert.equal(usage.unknown, 0);
  assert.equal(f.counts.upload, 1);
  assert.equal((await f.authority.call("job.get", { id: f.job.id })).source.current_artifact, result.artifact_id);
});

test("an exhausted key pool fails the job so a later refresh can acquire again", async () => {
  const f = await fixture();
  const available = f.deps.retrieve;
  f.deps.retrieve = (provider, intent, context) => retrieve(provider, intent, {
    ...context, env: { FIRECRAWL_API_KEY: "synthetic-empty", FIRECRAWL_API_KEY_1: "synthetic-next" },
    fetchImpl: async () => Response.json({ success: false, error: "Insufficient credits" }, { status: 402 }),
  });
  const result = await f.run();
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "provider_keys_exhausted");
  assert.equal((await f.authority.call("snapshot")).usage.find(row => row.provider === "firecrawl").total, 0);
  const next = await f.authority.call("job.enqueue", { source_id: f.source.id });
  assert.notEqual(next.id, f.job.id, "a refused job no longer blocks refreshes");
  f.deps.retrieve = available;
  assert.equal((await f.run(workflow(), next.id)).status, "completed");
});

test("revoking retention during the snapshot write fails the job and discards its bytes", async () => {
  const f = await fixture();
  const discarded = [];
  f.corpus.putSnapshot = async (artifact, content) => {
    f.counts.write += 1;
    f.snapshots.set(artifact.id, content);
    const policy = await f.storage.get("policy");
    policy.providers.firecrawl.retention_allowed = false;
    await f.storage.put("policy", policy);
    return { key: artifact.snapshot_key, created: true };
  };
  f.corpus.discardSnapshot = async artifact => { discarded.push(artifact.id); f.snapshots.delete(artifact.id); };
  const result = await f.run();
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "provider_disabled");
  assert.equal(discarded.length, 1);
  assert.equal(f.snapshots.size, 0);
  assert.equal(f.counts.upload, 0);
});

test("derived answers and source URL substitution cannot become snapshots", async () => {
  for (const observation of [
    { kind: "derived_context", text: "An answer", url: "https://flask.palletsprojects.com/en/3.1.3/limits/" },
    { kind: "source_excerpt", text: "Other content", url: "https://flask.palletsprojects.com/en/3.0/limits/" },
  ]) {
    const f = await fixture();
    f.deps.retrieve = async () => ({ observations: [observation] });
    assert.equal((await f.run()).status, "failed");
    assert.equal(f.counts.write, 0);
    assert.equal(f.counts.upload, 0);
  }
});

test("cached or uncertain provider acquisition does not claim an origin freshness check", async () => {
  const f = await fixture();
  const retrieve = f.deps.retrieve;
  f.deps.retrieve = async (...args) => {
    const result = await retrieve(...args);
    delete result.observations[0].freshness;
    return result;
  };
  const result = await f.run();
  assert.equal(result.status, "completed");
  const state = await f.authority.call("job.get", { id: f.job.id });
  assert.equal(state.artifact.checked_at, null);
  assert.equal(state.source.last_checked_at, null);
});

test("a lost upload acknowledgement is reconciled without replay and retains the unknown charge", async () => {
  const f = await fixture();
  const upload = f.corpus.uploadRevision;
  f.corpus.uploadRevision = async artifact => { await upload(artifact); throw new Error("lost acknowledgement"); };
  assert.equal((await f.run()).status, "completed");
  const usage = (await f.authority.call("snapshot")).usage.find(value => value.provider === "ai_search");
  assert.equal(usage.unknown, 1);
  assert.equal(usage.confirmed, 1);
  await f.run();
  assert.equal(f.counts.upload, 1);
});

test("unresolved uploads remain unknown through bounded polls and process replacement", async () => {
  const f = await fixture();
  f.corpus.uploadRevision = async () => { f.counts.upload += 1; throw new Error("timeout"); };
  const step = workflow();
  assert.equal((await f.run(step)).status, "unknown");
  assert.equal(step.sleeps.length, 5);
  f.deps.authority = new KnowledgeAuthority(f.storage);
  assert.equal((await f.run()).status, "unknown");
  assert.equal(f.counts.acquire, 1);
  assert.equal(f.counts.upload, 1);
});

test("cancelling uncertain work cannot authorize another upload of the same immutable revision", async () => {
  const f = await fixture();
  f.corpus.uploadRevision = async () => { f.counts.upload += 1; throw new Error("timeout"); };
  assert.equal((await f.run()).status, "unknown");
  await f.authority.call("job.cancel", { id: f.job.id });
  const next = await f.authority.call("job.enqueue", { source_id: f.source.id });
  assert.notEqual(next.id, f.job.id);
  const result = await f.run(workflow(), next.id);
  assert.equal(result.status, "unknown");
  assert.equal(result.reason, "operation_already_submitted");
  assert.equal(f.counts.acquire, 2);
  assert.equal(f.counts.upload, 1);
  const usage = (await f.authority.call("snapshot")).usage.find(value => value.provider === "ai_search");
  assert.equal(usage.unknown, 1);
});

test("same-content refresh reuses immutable storage and the published index revision", async () => {
  const f = await fixture();
  const first = await f.run();
  const before = await f.authority.call("artifact.get", { id: first.artifact_id });
  f.advance();
  const next = await f.authority.call("job.enqueue", { source_id: f.source.id });
  const refreshed = await f.run(workflow(), next.id);
  assert.equal(refreshed.status, "completed");
  assert.equal(refreshed.artifact_id, first.artifact_id);
  assert.deepEqual(f.counts, { acquire: 2, write: 1, upload: 1, verify: 2 });
  const after = await f.authority.call("artifact.get", { id: first.artifact_id });
  assert.equal(after.fetched_at, before.fetched_at);
  assert.ok(after.checked_at > before.checked_at);
});

test("cached refresh preserves the last proven origin-check timestamp without advancing it", async () => {
  const f = await fixture();
  const first = await f.run();
  const before = await f.authority.call("artifact.get", { id: first.artifact_id });
  f.advance();
  const retrieve = f.deps.retrieve;
  f.deps.retrieve = async (...args) => {
    const result = await retrieve(...args);
    result.observations[0].freshness = "cached_or_unknown";
    return result;
  };
  const next = await f.authority.call("job.enqueue", { source_id: f.source.id });
  assert.equal((await f.run(workflow(), next.id)).status, "completed");
  const after = await f.authority.call("job.get", { id: next.id });
  assert.equal(after.artifact.checked_at, before.checked_at);
  assert.equal(after.source.last_checked_at, before.checked_at);
});

test("cancellation during acquisition prevents storage and publication", async () => {
  const f = await fixture();
  const retrieve = f.deps.retrieve;
  f.deps.retrieve = async (...args) => {
    const result = await retrieve(...args);
    await f.authority.call("job.cancel", { id: f.job.id });
    return result;
  };
  assert.equal((await f.run()).status, "cancelled");
  assert.equal(f.counts.write, 0);
  assert.equal(f.counts.upload, 0);
});

test("cancellation while indexing stops subsequent readiness work", async () => {
  const f = await fixture();
  const upload = f.corpus.uploadRevision;
  f.corpus.uploadRevision = async artifact => {
    const item = await upload(artifact);
    item.status = "running";
    return item;
  };
  const step = workflow();
  step.sleep = async () => f.authority.call("job.cancel", { id: f.job.id });
  assert.equal((await f.run(step)).status, "cancelled");
  assert.equal(f.counts.verify, 0);
  assert.equal((await f.authority.call("job.get", { id: f.job.id })).source.current_artifact, null);
});

test("disabling a source while verifying its index prevents late publication", async () => {
  const f = await fixture();
  f.corpus.verifySearchable = async () => {
    await f.authority.call("source.update", { id: f.source.id, expected_revision: 1, enabled: false });
    return true;
  };
  const result = await f.run();
  assert.equal(result.status, "cancelled");
  assert.equal(result.reason, "source_disabled");
  assert.equal((await f.authority.call("job.get", { id: f.job.id })).source.current_artifact, null);
});

test("metadata failures after an ambiguous upload retain pending work and its allowance", async () => {
  const f = await fixture();
  const reconcile = f.corpus.reconcileRevision;
  f.corpus.reconcileRevision = async (...args) => {
    if (f.counts.upload > 0) throw new Error("metadata unavailable");
    return reconcile(...args);
  };
  f.corpus.uploadRevision = async () => { f.counts.upload += 1; throw new Error("timeout"); };
  assert.equal((await f.run()).status, "unknown");
  assert.equal((await f.run()).status, "unknown");
  assert.equal(f.counts.upload, 1);
  const usage = (await f.authority.call("snapshot")).usage.find(value => value.provider === "ai_search");
  assert.equal(usage.unknown, 1);
});

test("an acquisition interrupted before a snapshot never dispatches again", async () => {
  const f = await fixture();
  await f.authority.call("job.update", { id: f.job.id, status: "acquiring" });
  const result = await f.run();
  assert.equal(result.status, "unknown");
  assert.equal(result.reason, "acquisition_outcome_unknown");
  assert.equal(f.counts.acquire, 0);
});

test("a lost snapshot acknowledgement recovers its saved manifest and bytes without replaying acquisition", async () => {
  const f = await fixture();
  const write = f.corpus.putSnapshot;
  f.corpus.putSnapshot = async (...args) => { await write(...args); throw new Error("lost R2 acknowledgement"); };
  const pending = await f.run();
  assert.equal(pending.status, "unknown");
  assert.equal(pending.reason, "snapshot_outcome_unknown");
  assert.ok(pending.artifact_id);
  assert.equal((await f.run()).status, "completed");
  assert.deepEqual(f.counts, { acquire: 1, write: 1, upload: 1, verify: 1 });
  const usage = (await f.authority.call("snapshot")).usage.find(value => value.provider === "ai_search");
  assert.equal(usage.unknown, 1);
});

test("a missing uncertain snapshot remains visible without another R2 write or provider call", async () => {
  const f = await fixture();
  f.corpus.putSnapshot = async () => { f.counts.write += 1; throw new Error("R2 timeout"); };
  assert.equal((await f.run()).status, "unknown");
  const repeated = await f.run();
  assert.equal(repeated.status, "unknown");
  assert.equal(repeated.reason, "snapshot_outcome_unknown");
  assert.deepEqual(f.counts, { acquire: 1, write: 1, upload: 0, verify: 0 });
});

test("refused storage allowance prevents both snapshot writes and indexing", async () => {
  const f = await fixture();
  const policy = await f.storage.get("policy");
  policy.providers.ai_search.background_limit = 0;
  await f.storage.put("policy", policy);
  const result = await f.run();
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "allowance_exhausted");
  assert.equal(f.counts.write, 0);
  assert.equal(f.counts.upload, 0);
});

test("completed index items with unverifiable chunks stay pending and processing failures are visible", async () => {
  const f = await fixture();
  f.corpus.verifySearchable = async () => false;
  assert.equal((await f.run()).status, "pending_index");
  assert.equal((await f.authority.call("job.get", { id: f.job.id })).source.current_artifact, null);
  for (const item of f.items.values()) item.status = "error";
  const result = await f.run();
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "index_processing_failed");
  assert.equal(f.counts.upload, 1);
});
