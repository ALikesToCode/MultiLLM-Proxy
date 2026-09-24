import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { dispatchKnowledge, scheduleSource } from "../worker/knowledge/service.mjs";
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
