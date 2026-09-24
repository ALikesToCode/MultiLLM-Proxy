import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout } from "node:timers/promises";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

test("native Workflow accepts ingestion step contracts and publishes once", async t => {
  const bundle = await build({ stdin: { resolveDir: process.cwd(), contents: `
    import worker, { KnowledgeCatalogue } from "./worker/knowledge/index.mjs";
    import { WorkflowEntrypoint } from "cloudflare:workers";
    import { KnowledgeCorpus } from "./worker/knowledge/corpus.mjs";
    import { runIngestion } from "./worker/knowledge/ingestion.mjs";
    export { KnowledgeCatalogue };
    export default worker;
    export class TestIngestion extends WorkflowEntrypoint {
      async run(event, step) {
        const snapshots = new KnowledgeCorpus(this.env);
        const corpus = {
          putSnapshot: (artifact, text) => snapshots.putSnapshot(artifact, text),
          getSnapshot: artifact => snapshots.getSnapshot(artifact),
          async reconcileRevision(artifact, id) {
            return id ? { id, key: artifact.index_key, status: "completed" } : null;
          },
          async uploadRevision(artifact) {
            return { id: "fixture-item", key: artifact.index_key, status: "completed" };
          },
          async verifySearchable() { return true; },
        };
        return runIngestion(this.env, step, event.payload.job_id, { corpus });
      }
    }
  ` }, bundle: true, write: false, format: "esm", platform: "neutral", external: ["cloudflare:workers"] });
  let acquisitions = 0;
  const mf = new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, script: bundle.outputFiles[0].text,
    compatibilityDate: "2026-07-28", bindings: { FIRECRAWL_API_KEY: "synthetic-key" },
    durableObjects: { KNOWLEDGE_AUTHORITY: { className: "KnowledgeCatalogue", useSQLite: true } },
    workflows: { KNOWLEDGE_INGESTION: { name: "test-ingestion", className: "TestIngestion" } },
    r2Buckets: ["KNOWLEDGE_SNAPSHOTS"],
    outboundService: async request => {
      acquisitions += 1;
      const { url } = await request.json();
      return Response.json({ success: true, data: { markdown: "# Python 3.11\n\nRunner manages an event loop.",
        metadata: { sourceURL: url, statusCode: 200 } } });
    },
  }));
  t.after(() => mf.dispose());
  async function dispatch(operation, payload = {}) {
    const response = await mf.dispatchFetch("http://knowledge.internal/v1/dispatch", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: 1, operation, principal: { id: "fixture", scopes: ["knowledge:manage"] }, payload }),
    });
    const body = await response.json();
    assert.equal(response.status, 200, JSON.stringify(body));
    return body.result;
  }
  const { policy } = await dispatch("status");
  const { revision, ...allocation } = policy;
  for (const id of ["firecrawl", "ai_search"]) Object.assign(allocation.providers[id], {
    enabled: true, limit: 10, background_limit: 10, hard_limit_confirmed: true, retention_allowed: true,
  });
  await dispatch("policy.update", { ...allocation, expected_revision: revision, enabled: true });
  const { source } = await dispatch("sources.create", {
    url: "https://docs.python.org/3.11/library/asyncio-runner.html", product: "python", version: "3.11",
  });
  const { job } = await dispatch("sources.refresh", { id: source.id });
  const bindings = await mf.getBindings();
  const instance = await bindings.KNOWLEDGE_INGESTION.get(job.id);
  let result;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    result = await instance.status();
    if (["complete", "errored"].includes(result.status)) break;
    await setTimeout(25);
  }
  assert.equal(result.status, "complete", JSON.stringify(result));
  const state = await dispatch("status");
  assert.equal(state.jobs[0].status, "completed", JSON.stringify(state.jobs[0]));
  assert.ok(state.sources[0].current_artifact);
  assert.equal(acquisitions, 1);
  assert.equal(state.usage.find(row => row.provider === "ai_search").confirmed, 2);
});
