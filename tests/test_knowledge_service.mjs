import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { dispatchKnowledge, maintainKnowledge, scheduleSource } from "../worker/knowledge/service.mjs";
import { KnowledgeAuthority } from "../worker/knowledge/authority.mjs";
import { createArtifact } from "../worker/knowledge/evidence.mjs";
import { handleKnowledgeOutbound } from "../worker/knowledge-outbound.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { fixture, manager, principal } from "./knowledge_fixture.mjs";

const envelope = (operation, payload = {}, identity = manager) => ({ version: 1, operation, principal: identity, payload });
const submit = (f, operation, payload, identity) => dispatchKnowledge(f.env, envelope(operation, payload, identity),
  { authority: f.authority, corpus: f.corpus, cache: f.cache, retrieve: f.retrieve });

test("private dispatcher enforces read/manage capabilities and strict operation envelopes", async () => {
  const f = await fixture();
  await assert.rejects(submit(f, "status", {}, principal), { code: "insufficient_scope" });
  await assert.rejects(submit(f, "context", { query: "limits" }, { ...manager, scopes: ["knowledge:manage"] }), { code: "insufficient_scope" });
  await assert.rejects(dispatchKnowledge(f.env, { ...envelope("status"), user: "forged" }), { code: "invalid_request" });
  await assert.rejects(dispatchKnowledge(f.env, envelope("not-an-operation")), { code: "unknown_operation" });
  const result = await submit(f, "status");
  assert.equal(result.ready, false);
  assert.ok(result.setup.some(item => !item.configured));
  assert.ok(result.providers.every(item => item.connectivity === "not_checked"));
  assert.ok(!JSON.stringify(result).includes("synthetic-test-key"));
});

test("readiness reports distinct numbered key counts without exposing secrets or fingerprints", async () => {
  const f = await fixture();
  Object.assign(f.env, { CONTEXT7_API_KEY_1: "synthetic-context-one", CONTEXT7_API_KEY_7: "synthetic-context-seven",
    FIRECRAWL_API_KEY_2: "synthetic-firecrawl", FIRECRAWL_API_KEY_3: "synthetic-firecrawl", EXA_API_KEY_1: " " });
  const result = await submit(f, "status");
  for (const [id, count] of [["context7", 2], ["firecrawl", 1], ["alexandria", 1], ["exa", 1]]) {
    const provider = result.providers.find(row => row.id === id);
    assert.equal(provider.configured, true);
    assert.equal(provider.configured_key_count, count);
  }
  assert.ok(!JSON.stringify(result).includes("synthetic"));
  await assert.rejects(submit(f, "credentials.select", {}), { code: "unknown_operation" });
});

test("saving sources has no implicit paid work; refresh is idempotent and resumes pending reconciliation", async () => {
  const f = await fixture();
  let created = 0;
  let restarted = 0;
  let workflowStatus = "running";
  const ids = new Set();
  f.env.KNOWLEDGE_INGESTION = {
    async createBatch(batch) {
      if (ids.has(batch[0].id)) return [];
      ids.add(batch[0].id); created++;
      return [{ id: batch[0].id }];
    },
    async get(id) {
      assert.ok(ids.has(id));
      return { status: async () => ({ status: workflowStatus }), restart: async () => { restarted++; } };
    },
  };
  const saved = await submit(f, "sources.create", { url: "https://react.dev/reference", product: "react" });
  assert.equal(saved.job, null);
  assert.equal(created, 0);
  const first = await scheduleSource(f.env, f.authority, saved.source.id);
  const second = await scheduleSource(f.env, f.authority, saved.source.id);
  assert.equal(first.id, second.id);
  assert.equal(created, 1);
  assert.equal(restarted, 0);
  await f.authority.call("job.update", { id: first.id, status: "pending_index" });
  workflowStatus = "complete";
  const resumed = await scheduleSource(f.env, f.authority, saved.source.id);
  assert.equal(resumed.id, first.id);
  assert.equal(restarted, 1);
});

test("unconfirmed Workflow creation reuses its durable job and cancellation survives control-plane failure", async () => {
  const f = await fixture();
  const attempted = [];
  f.env.KNOWLEDGE_INGESTION = {
    async createBatch(batch) { attempted.push(batch[0].id); throw new Error("lost acknowledgement"); },
    async get() { throw new Error("unavailable"); },
  };
  for (let i = 0; i < 2; i++) await assert.rejects(scheduleSource(f.env, f.authority, f.source.id), { code: "schedule_unconfirmed" });
  assert.equal(attempted[0], attempted[1]);
  const cancelled = await submit(f, "jobs.cancel", { id: attempted[0] });
  assert.equal(cancelled.job.status, "cancelled");
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(scheduleSource(f.env, f.authority, f.source.id, controller.signal), { code: "retrieval_deadline" });
  assert.equal(attempted.length, 2);
});

test("maintenance re-polls stuck index jobs in bounded rotation without new uploads", async () => {
  const f = await fixture();
  let now = Date.parse("2026-09-24T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  const jobs = [];
  for (let i = 0; i < 7; i++) {
    const source = await authority.call("source.discover", { url: `https://flask.palletsprojects.com/en/3.1.3/page-${i}/`, product: "flask", provider: "exa" });
    const artifact = await authority.call("artifact.save", { artifact: await createArtifact({ ...source, origin_checked: true }, `${f.text} ${i}`, "exa", now) });
    const job = await authority.call("job.enqueue", { source_id: source.id, artifact_id: artifact.id });
    jobs.push((await authority.call("job.update", { id: job.id, status: i % 2 ? "unknown" : "pending_index" })).job ?? job);
  }
  const stuck = new Set(jobs.map(job => job.id));
  const restarted = [];
  f.env.KNOWLEDGE_INGESTION = {
    async createBatch() { return []; },
    async get(id) { return { status: async () => ({ status: "complete" }), restart: async () => { if (stuck.has(id)) restarted.push(id); } }; },
  };
  const corpus = { async removeArtifact() {} };
  await maintainKnowledge(f.env, { authority, corpus });
  assert.deepEqual(restarted, [], "recently updated jobs are still being verified by their Workflow");
  now += 11 * 60000;
  await maintainKnowledge(f.env, { authority, corpus });
  await maintainKnowledge(f.env, { authority, corpus });
  const ids = jobs.map(job => job.id).sort();
  assert.equal(restarted.length, 10);
  assert.deepEqual([...new Set(restarted)].sort(), ids, "every stuck job is reached across runs");
  const reserved = [...(await f.storage.list({ prefix: "reservation:" })).values()];
  assert.ok(reserved.every(item => !stuck.has(item.job_id)), "reconciliation spends no allowance");
});

test("jobs that can never reconcile end as failed and stop blocking refreshes", async () => {
  const f = await fixture();
  f.policy.providers.firecrawl.background_limit = 0;
  await f.storage.put("policy", f.policy);
  let now = Date.parse("2026-09-24T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  const lost = await authority.call("job.enqueue", { source_id: f.source.id });
  await authority.call("job.update", { id: lost.id, status: "unknown", reason: "acquisition_outcome_unknown" });
  const source = await authority.call("source.discover", { url: "https://flask.palletsprojects.com/en/3.1.3/upload/", product: "flask", provider: "exa" });
  const artifact = await authority.call("artifact.save", { artifact: await createArtifact({ ...source, origin_checked: true }, f.text, "exa", now) });
  const upload = await authority.call("job.enqueue", { source_id: source.id, artifact_id: artifact.id });
  await authority.call("job.update", { id: upload.id, status: "unknown", reason: "upload_outcome_unknown" });
  const restarted = [];
  f.env.KNOWLEDGE_INGESTION = {
    async createBatch() { return []; },
    async get(id) { return { status: async () => ({ status: "errored" }), restart: async () => { restarted.push(id); } }; },
  };
  const corpus = { async removeArtifact() {} };
  now += 11 * 60000;
  await maintainKnowledge(f.env, { authority, corpus });
  assert.deepEqual(restarted, [upload.id]);
  let state = await authority.call("job.get", { id: lost.id });
  assert.deepEqual([state.job.status, state.job.reason], ["failed", "acquisition_outcome_unknown"]);
  assert.notEqual((await authority.call("job.enqueue", { source_id: f.source.id })).id, lost.id, "the source can refresh again");
  for (let run = 0; run < 24; run++) {
    now += 3600000;
    await maintainKnowledge(f.env, { authority, corpus });
  }
  state = await authority.call("job.get", { id: upload.id });
  assert.deepEqual([state.job.status, state.job.reason], ["failed", "reconcile_exhausted"]);
  assert.equal(restarted.filter(id => id === upload.id).length, 24, "each unresolved upload is re-polled for a day");
  const status = await submit(f, "status");
  assert.equal(status.job_counts.failed, 2);
  assert.ok(status.jobs.some(job => job.id === upload.id && job.reason === "reconcile_exhausted"));
});

test("maintenance rotates eligible due sources so failed scheduling cannot starve later work", async () => {
  const f = await fixture();
  f.policy.providers.firecrawl.enabled = false;
  await f.storage.put("policy", f.policy);
  for (let i = 0; i < 12; i++) await f.authority.call("source.create", {
    url: `https://react.dev/docs/${i}`, product: "react", provider: i < 5 ? "firecrawl" : "exa",
  });
  const first = await f.authority.call("sources.due");
  const second = await f.authority.call("sources.due");
  assert.equal(first.length, 5);
  assert.ok([...first, ...second].every(item => item.provider === "exa"));
  assert.equal(new Set([...first, ...second].map(item => item.id)).size, 7);
});

test("terminal jobs make room for new work and expire after thirty days", async () => {
  const f = await fixture();
  let now = Date.parse("2026-09-23T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  for (let i = 0; i < 1000; i++) {
    const stamp = new Date(now - (1000 - i) * 60000).toISOString();
    await f.storage.put(`job:old-${i}`, { id: `old-${i}`, source_id: f.source.id, fence: 0, status: i % 2 ? "completed" : "failed",
      reason: null, artifact_id: null, item_id: null, index_key: null, created_at: stamp, updated_at: stamp });
  }
  const job = await authority.call("job.enqueue", { source_id: f.source.id });
  const jobs = [...(await f.storage.list({ prefix: "job:" })).keys()];
  assert.equal(jobs.length, 1000);
  assert.ok(!jobs.includes("job:old-0"), "the oldest terminal job made room");
  now += 31 * 24 * 3600000;
  await authority.call("maintenance");
  assert.deepEqual([...(await f.storage.list({ prefix: "job:" })).keys()], [`job:${job.id}`], "active work is never pruned");
});

test("read-query discoveries use their own pool and never refresh on a schedule", async () => {
  const f = await fixture();
  const discover = i => f.authority.call("source.discover", { url: `https://react.dev/learn/${i}`, product: "react", provider: "exa" });
  const discovered = [];
  for (let i = 0; i < 200; i++) discovered.push(await discover(i));
  const retained = await createArtifact({ ...discovered[0], origin_checked: true }, f.text, "exa");
  await f.authority.call("artifact.save", { artifact: retained });
  assert.ok((await f.authority.call("sources.due")).every(source => source.identity_confirmed));
  const newest = await discover(200);
  let ids = new Set((await f.authority.call("snapshot")).sources.map(source => source.id));
  assert.ok(ids.has(newest.id) && ids.has(discovered[0].id), "a discovery with a retained revision is kept");
  assert.ok(!ids.has(discovered[1].id), "the oldest idle discovery made room");
  for (let i = 0; i < 199; i++) await f.authority.call("source.create", { url: `https://react.dev/reference/${i}`, product: "react" });
  await assert.rejects(f.authority.call("source.create", { url: "https://react.dev/blog", product: "react" }), { code: "source_limit" });
  ids = new Set((await f.authority.call("snapshot")).sources.map(source => source.id));
  assert.equal(ids.size, 400, "200 registered and 200 discovered sources");
});

test("registering a discovered source promotes it with the operator settings", async () => {
  const f = await fixture();
  const url = "https://flask.palletsprojects.com/en/3.1.3/config/";
  const found = await f.authority.call("source.discover", { url, product: "flask", version: "3.1.3", provider: "exa", title: "Discovered" });
  assert.equal(found.identity_confirmed, false);
  const registered = await f.authority.call("source.create", { url, product: "flask", version: "3.1.3", provider: "firecrawl",
    pinned: true, refresh_hours: 48, title: "Configuration" });
  assert.equal(registered.id, found.id);
  assert.equal(registered.identity_confirmed, true);
  assert.deepEqual([registered.provider, registered.pinned, registered.refresh_hours, registered.title], ["firecrawl", true, 48, "Configuration"]);
  assert.equal(registered.revision, found.revision + 1);
  await assert.rejects(f.authority.call("source.update", { id: found.id, expected_revision: found.revision, enabled: false }),
    { code: "source_conflict" });
  assert.deepEqual(await f.authority.call("source.create", { url, product: "flask", version: "3.1.3" }), registered,
    "registering a confirmed source again changes nothing");
  assert.ok((await f.authority.call("sources.due")).some(source => source.id === registered.id));
});

test("retention cleanup runs while Knowledge is disabled and rotates past failing revisions", async () => {
  const f = await fixture();
  let now = Date.parse("2026-09-23T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  const artifacts = [];
  for (let i = 0; i < 12; i++) {
    const artifact = await createArtifact({ ...f.source, origin_checked: true }, `${f.text} ${i}`, "firecrawl", now);
    await authority.call("artifact.save", { artifact });
    artifacts.push(artifact);
  }
  const ids = artifacts.map(artifact => artifact.id).sort();
  Object.assign(f.policy, { enabled: false });
  f.policy.providers.ai_search.enabled = false;
  await f.storage.put("policy", f.policy);
  now += 169 * 3600000;
  const failing = new Set(ids.slice(0, 10));
  const removed = [];
  const corpus = { async removeArtifact(artifact) {
    if (failing.has(artifact.id)) throw new Error("index outage");
    removed.push(artifact.id);
  } };
  await maintainKnowledge(f.env, { authority, corpus });
  assert.deepEqual(removed, []);
  await maintainKnowledge(f.env, { authority, corpus });
  assert.deepEqual(removed, ids.slice(10), "later revisions are reached despite repeated failures");
  for (const id of ids.slice(10)) assert.equal(await authority.call("artifact.get", { id }), null);
  assert.equal((await authority.call("artifact.get", { id: ids[0] })).status, "expiring");
});

test("expiring a revision retires jobs that still wait on it", async () => {
  const f = await fixture();
  let now = Date.parse("2026-09-23T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  const created = await createArtifact({ ...f.source, origin_checked: true }, f.text, "firecrawl", now);
  const artifact = await authority.call("artifact.save", { artifact: created });
  const job = await authority.call("job.enqueue", { source_id: f.source.id, artifact_id: artifact.id });
  await authority.call("job.update", { id: job.id, status: "pending_index" });
  now += 169 * 3600000;
  await authority.call("artifact.expiration_claim", { id: artifact.id, expires_at: artifact.expires_at });
  await authority.call("artifact.expire", { id: artifact.id, expires_at: artifact.expires_at });
  const retired = (await authority.call("job.get", { id: job.id })).job;
  assert.deepEqual([retired.status, retired.reason], ["cancelled", "artifact_expired"]);
  assert.notEqual((await authority.call("job.enqueue", { source_id: f.source.id })).id, job.id, "a refresh starts a new job");
});

test("live acquisitions can be indexed without paying to acquire the source again", async () => {
  const f = await fixture();
  const artifact = await f.published();
  f.policy.providers.firecrawl.background_limit = 0;
  await f.storage.put("policy", f.policy);
  f.env.KNOWLEDGE_INGESTION = { createBatch: async batch => batch };
  const job = await scheduleSource(f.env, f.authority, f.source.id, undefined, artifact.id);
  assert.equal(job.status, "snapshot");
  assert.equal(job.artifact_id, artifact.id);
  await assert.rejects(scheduleSource(f.env, f.authority, f.source.id), { code: "background_disabled" });
});

test("artifact reads preserve source identity and fail if permission changes during the read", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const result = await submit(f, "artifact", { id: artifact.id }, principal);
  assert.equal(result.text, f.text);
  assert.equal(result.artifact.content_hash, artifact.content_hash);
  f.corpus.getSnapshot = async () => {
    await f.authority.call("source.update", { id: f.source.id, expected_revision: 1, enabled: false });
    return f.text;
  };
  await assert.rejects(submit(f, "artifact", { id: artifact.id }, principal), { code: "artifact_unavailable", status: 409 });
});

test("Container outbound forwarding accepts only its fixed private target and strips credentials", async () => {
  const requests = [];
  const env = { KNOWLEDGE_SERVICE: { async fetch(url, options) {
    requests.push({ url, options });
    return Response.json({ version: 1, result: { ready: false } });
  } } };
  const body = JSON.stringify(envelope("status"));
  const options = { method: "POST", headers: { "content-type": "application/json", "authorization": "Bearer synthetic" }, body };
  const result = await handleKnowledgeOutbound(new Request("http://knowledge.internal/v1/dispatch", options), env);
  assert.equal(result.status, 200);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].options.headers, { "content-type": "application/json" });
  for (const target of ["http://knowledge.internal/other", "https://knowledge.internal/v1/dispatch", "http://other.internal/v1/dispatch", "http://knowledge.internal/v1/dispatch?url=anything"]) {
    assert.equal((await handleKnowledgeOutbound(new Request(target, options), env)).status, 400);
  }
  assert.equal((await handleKnowledgeOutbound(new Request("http://knowledge.internal/v1/dispatch", {
    ...options, body: JSON.stringify({ padding: "a".repeat(66000) }),
  }), env)).status, 413);
  assert.equal((await handleKnowledgeOutbound(new Request("http://knowledge.internal/v1/dispatch", options), {})).status, 503);
  assert.equal(requests.length, 1);
  const container = collectContainerEnv({ ...env, EXA_API_KEY: "synthetic-test-key", FIRECRAWL_API_KEY: "synthetic-test-key" });
  assert.equal(container.KNOWLEDGE_SERVICE_ENABLED, "true");
  assert.equal(container.EXA_API_KEY, undefined);
  assert.equal(container.FIRECRAWL_API_KEY, undefined);
  assert.equal(collectContainerEnv({}).KNOWLEDGE_SERVICE_ENABLED, undefined);
});

test("bundled private Worker serves disabled setup through the real Durable Object binding", async t => {
  const bundle = await build({ entryPoints: ["worker/knowledge/index.mjs"], bundle: true, write: false,
    format: "esm", platform: "neutral", external: ["cloudflare:workers"] });
  const mf = new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, compatibilityDate: "2026-07-28", script: bundle.outputFiles[0].text,
    durableObjects: { KNOWLEDGE_AUTHORITY: { className: "KnowledgeCatalogue", useSQLite: true } } }));
  t.after(() => mf.dispose());
  const options = { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(envelope("status")) };
  const result = await mf.dispatchFetch("http://knowledge.internal/v1/dispatch", options);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get("cache-control"), "no-store");
  const payload = await result.json();
  assert.equal(payload.version, 1);
  assert.equal(payload.result.enabled, false);
  assert.equal(payload.result.ready, false);
  assert.equal((await mf.dispatchFetch("https://public.example/v1/dispatch", options)).status, 404);
});
