import { authorize, fail, fields, parseQuery, publicUrl, validId } from "./contracts.mjs";
import { getAuthority } from "./authority-client.mjs";
import { KnowledgeCorpus } from "./corpus.mjs";
import { providerStatus } from "./providers/index.mjs";
import { retrieveKnowledge } from "./retrieval.mjs";
import { metered } from "./operations.mjs";
import { OPERATIONS as ALEXANDRIA_OPERATIONS } from "./alexandria/contracts.mjs";
import { dispatchAlexandria } from "./alexandria/service.mjs";

const OPERATIONS = new Set(["status", "context", "search", "artifact", "sources.create", "sources.update",
  "sources.refresh", "jobs.cancel", "policy.update", ...ALEXANDRIA_OPERATIONS]);
const READ = new Set(["context", "search", "artifact", ...ALEXANDRIA_OPERATIONS]);

export function setupStatus(env) {
  return [
    { id: "catalogue", label: "Durable catalogue and allowances", configured: Boolean(env.KNOWLEDGE_AUTHORITY), detail: "SQLite-backed Durable Object binding" },
    { id: "snapshots", label: "Immutable source snapshots", configured: Boolean(env.KNOWLEDGE_SNAPSHOTS), detail: "Private R2 bucket with a reviewed lifecycle policy" },
    { id: "index", label: "Search index", configured: Boolean(env.KNOWLEDGE_INDEX), detail: "AI Search instance with built-in storage and hybrid indexing" },
    { id: "ingestion", label: "Background indexing", configured: Boolean(env.KNOWLEDGE_INGESTION), detail: "Durable ingestion Workflow" },
  ];
}

async function status(env, authority) {
  const snapshot = await authority.call("snapshot");
  const providers = [...providerStatus(env), { id: "alexandria", label: "Firecrawl Alexandria",
    credential_env: "FIRECRAWL_API_KEY", docs_url: "https://docs.firecrawl.dev/features/alexandria",
    capabilities: ["capability_discovery", "structured_data"], kind: "catalogue",
    configured: Boolean(env.FIRECRAWL_API_KEY?.trim()) }, { id: "ai_search", label: "Cloudflare AI Search + storage",
    credential_env: null, docs_url: "https://developers.cloudflare.com/ai-search/", capabilities: ["index", "storage"],
    kind: "corpus", configured: Boolean(env.KNOWLEDGE_INDEX && env.KNOWLEDGE_SNAPSHOTS) }].map(provider => ({
    ...provider, enabled: snapshot.policy.providers[provider.id].enabled, connectivity: "not_checked",
  }));
  const setup = setupStatus(env);
  const ready = setup.every(item => item.configured) && snapshot.policy.enabled
    && providers.some(item => ["firecrawl", "exa"].includes(item.id) && item.configured && item.enabled)
    && snapshot.policy.providers.ai_search.enabled;
  return { ...snapshot, enabled: snapshot.policy.enabled, ready, setup, providers };
}

export async function scheduleSource(env, authority, sourceId, signal, artifactId) {
  const active = () => { if (signal?.aborted) fail("retrieval_deadline", "The retrieval deadline was reached.", 504); };
  active();
  if (!env.KNOWLEDGE_INGESTION) fail("ingestion_unavailable", "The ingestion Workflow is not configured.", 503);
  const snapshot = await authority.call("snapshot");
  const source = snapshot.sources.find(item => item.id === sourceId);
  if (!source) fail("source_missing", "The source was not found.", 404);
  if (!snapshot.policy.enabled || !(artifactId ? ["ai_search"] : [source.provider, "ai_search"]).every(id => {
    const allocation = snapshot.policy.providers[id];
    return allocation.enabled && allocation.background_limit >= allocation.units_per_call;
  })) fail("background_disabled", "Enable source and index background allowances before scheduling ingestion.", 409);
  active();
  const job = await authority.call("job.enqueue", { source_id: sourceId, ...(artifactId ? { artifact_id: artifactId } : {}) });
  try {
    active();
    const created = await env.KNOWLEDGE_INGESTION.createBatch([{ id: job.id, params: { job_id: job.id } }]);
    if (!created.length) {
      active();
      const instance = await env.KNOWLEDGE_INGESTION.get(job.id);
      const current = await instance.status();
      active();
      // Poll exhaustion ends a Workflow but leaves a pending catalogue job. Resume
      // reconciliation with the same durable receipts; acquisition/upload cannot replay.
      if (["complete", "errored"].includes(current.status)) await instance.restart();
    }
  } catch {
    // A timed-out creation can still have succeeded. Keep the same durable job ID.
    fail("schedule_unconfirmed", "The job is saved but Workflow creation is unconfirmed. Refresh the same source to reconcile scheduling.", 503);
  }
  return job;
}

async function artifactResult(env, authority, id, corpus) {
  if (!validId(id)) fail("invalid_artifact", "Invalid artifact identifier.");
  const snapshot = await authority.call("snapshot");
  const artifact = await authority.call("artifact.get", { id });
  const source = snapshot.sources.find(item => item.id === artifact?.source_id);
  if (!snapshot.policy.enabled || !artifact || artifact.status === "expiring" || !source?.enabled || Date.parse(artifact.expires_at) <= Date.now()
    || !snapshot.policy.providers[artifact.provider]?.enabled || !snapshot.policy.providers[artifact.provider]?.retention_allowed) {
    fail("artifact_unavailable", "The source snapshot is unavailable under the current policy.", 404);
  }
  publicUrl(artifact.canonical_url, snapshot.policy.allowed_hosts);
  const text = await (corpus || new KnowledgeCorpus(env)).getSnapshot(artifact);
  if (!text) fail("artifact_unavailable", "The source snapshot is no longer retained.", 404);
  const latest = await authority.call("snapshot");
  if (!latest.policy.enabled || latest.policy.revision !== snapshot.policy.revision || latest.generation !== snapshot.generation) {
    fail("artifact_unavailable", "The source eligibility changed while reading the snapshot.", 409);
  }
  return { artifact, text };
}

export async function dispatchKnowledge(env, envelope, options = {}) {
  fields(envelope, ["version", "operation", "principal", "payload"], ["version", "operation", "principal", "payload"]);
  if (envelope.version !== 1 || !OPERATIONS.has(envelope.operation)) fail("unknown_operation", "Unknown Knowledge operation.", 404);
  const { operation, principal, payload } = envelope;
  authorize(principal, READ.has(operation) ? "knowledge:read" : "knowledge:manage");
  const authority = options.authority || getAuthority(env);
  if (ALEXANDRIA_OPERATIONS.includes(operation)) return dispatchAlexandria(env, authority, principal, operation, payload, options);
  if (operation === "status") { fields(payload, []); return status(env, authority); }
  if (operation === "context" || operation === "search") {
    return retrieveKnowledge(env, authority, principal, parseQuery(payload), {
      ...options, schedule: (id, signal, artifactId) => scheduleSource(env, authority, id, signal, artifactId),
    });
  }
  if (operation === "artifact") { fields(payload, ["id"], ["id"]); return artifactResult(env, authority, payload.id, options.corpus); }
  if (operation === "policy.update") return { policy: await authority.call("policy.update", payload) };
  if (operation === "sources.create") return { source: await authority.call("source.create", payload), job: null };
  if (operation === "sources.update") return { source: await authority.call("source.update", payload) };
  fields(payload, ["id"], ["id"]);
  if (operation === "sources.refresh") return { job: await scheduleSource(env, authority, payload.id) };
  if (operation === "jobs.cancel") {
    const job = await authority.call("job.cancel", payload);
    // Logical cancellation is authoritative even when the Workflow control API is unavailable.
    try { await (await env.KNOWLEDGE_INGESTION?.get(job.id))?.terminate(); } catch { /* Future work is fenced in the catalogue. */ }
    return { job };
  }
  fail("unknown_operation", "Unknown Knowledge operation.", 404);
}

export async function maintainKnowledge(env) {
  const authority = getAuthority(env);
  await authority.call("maintenance");
  const snapshot = await authority.call("snapshot");
  if (!snapshot.policy.enabled) return;
  const corpus = new KnowledgeCorpus(env);
  for (const artifact of await authority.call("artifacts.expired")) {
    try {
      await metered(authority, { provider: "ai_search", operation_id: `expire:${artifact.id}:${Date.parse(artifact.expires_at)}`, background: true }, async () => {
        const claimed = await authority.call("artifact.expiration_claim", { id: artifact.id, expires_at: artifact.expires_at });
        await corpus.removeArtifact(claimed);
        await authority.call("artifact.expire", { id: artifact.id, expires_at: artifact.expires_at });
      });
    } catch { /* Expired artifacts remain unreadable; an uncertain cleanup is not replayed. */ }
  }
  for (const source of await authority.call("sources.due")) {
    await scheduleSource(env, authority, source.id).catch(() => {});
  }
}
