import { fail, fields, integer, parseSource, publicUrl, validId, PROVIDER_IDS } from "./contracts.mjs";
import { digest } from "./evidence.mjs";
import { defaultPolicy, validatePolicy, withProviderDefaults } from "./policy.mjs";
import { reserve, settle, usageFor, pruneSettled } from "./ledger.mjs";
import { alexandriaCatalogue, pruneAlexandria } from "./alexandria/catalogue.mjs";

const ACTIVE = new Set(["queued", "acquiring", "snapshot", "pending_index", "unknown"]);
const STATES = new Set([...ACTIVE, "completed", "failed", "cancelled"]);
const policyOf = async tx => withProviderDefaults(await tx.get("policy") ?? defaultPolicy());
const generationOf = async tx => await tx.get("generation") ?? 0;
const bump = async tx => tx.put("generation", (await generationOf(tx)) + 1);
const values = async (tx, prefix) => [...(await tx.list({ prefix })).values()];

function retainedByPolicy(artifact, policy) {
  if (!policy.enabled || !policy.providers[artifact.provider]?.enabled || !policy.providers[artifact.provider]?.retention_allowed) {
    fail("provider_disabled", "The revision is not eligible under the current provider policy.", 409);
  }
  publicUrl(artifact.canonical_url, policy.allowed_hosts);
}

async function sourceFor(tx, id) {
  if (!validId(id)) fail("invalid_source", "Invalid source identifier.");
  const source = await tx.get(`source:${id}`);
  if (!source) fail("source_missing", "The source was not found.", 404);
  return source;
}

async function jobFor(tx, id) {
  if (!validId(id)) fail("invalid_job", "Invalid job identifier.");
  const job = await tx.get(`job:${id}`);
  if (!job) fail("job_missing", "The indexing job was not found.", 404);
  return job;
}

async function createSource(tx, input, now, discovered = false) {
  const policy = await policyOf(tx);
  const parsed = parseSource(input, policy);
  const id = await digest(`${parsed.url}\0${parsed.product}\0${parsed.version}`);
  const existing = await tx.get(`source:${id}`);
  if (existing) return existing;
  if ((await tx.list({ prefix: "source:" })).size >= 200) fail("source_limit", "The corpus supports at most 200 sources.", 409);
  const source = { ...parsed, id, identity_confirmed: !discovered, revision: 1, fence: 0, current_artifact: null,
    created_at: new Date(now).toISOString(), last_checked_at: null };
  await tx.put(`source:${id}`, source);
  await bump(tx);
  return source;
}

async function updateSource(tx, input) {
  fields(input, ["id", "expected_revision", "enabled", "pinned", "refresh_hours"], ["id", "expected_revision"]);
  const source = await sourceFor(tx, input.id);
  if (input.expected_revision !== source.revision) fail("source_conflict", "Reload the source before saving changes.", 409);
  for (const name of ["enabled", "pinned"]) {
    if (input[name] !== undefined && typeof input[name] !== "boolean") fail("invalid_source", `${name} must be a boolean.`);
  }
  if (input.refresh_hours !== undefined) integer(input.refresh_hours, 1, 720, "refresh_hours");
  const { expected_revision, ...changes } = input;
  const updated = { ...source, ...changes, revision: source.revision + 1 };
  if (input.enabled === false) updated.fence += 1;
  if (input.enabled === false) {
    for (const job of await values(tx, "job:")) {
      if (job.source_id === source.id && ACTIVE.has(job.status)) {
        await tx.put(`job:${job.id}`, { ...job, status: "cancelled", reason: "source_disabled" });
      }
    }
  }
  await tx.put(`source:${source.id}`, updated);
  await bump(tx);
  return updated;
}

async function enqueue(tx, input, now) {
  const source = await sourceFor(tx, input.source_id);
  if (!source.enabled) fail("source_disabled", "Enable the source before scheduling a refresh.", 409);
  const jobs = await values(tx, "job:");
  const current = jobs.find(job => job.source_id === source.id && job.fence === source.fence && ACTIVE.has(job.status));
  if (current) return current;
  if (jobs.length >= 1000) fail("job_limit", "The job catalogue needs maintenance before more jobs can be scheduled.", 409);
  const id = crypto.randomUUID();
  const job = { id, source_id: source.id, fence: source.fence + 1, status: "queued", reason: null,
    artifact_id: null, item_id: null, index_key: null, created_at: new Date(now).toISOString(), updated_at: new Date(now).toISOString() };
  if (input.artifact_id) {
    const artifact = await tx.get(`artifact:${input.artifact_id}`);
    if (!artifact || artifact.source_id !== source.id || artifact.status === "expiring" || Date.parse(artifact.expires_at) <= now) {
      fail("invalid_artifact", "Indexing requires a retained revision of this source.", 409);
    }
    retainedByPolicy(artifact, await policyOf(tx));
    Object.assign(job, { status: "snapshot", artifact_id: artifact.id, index_key: artifact.index_key });
  }
  await tx.put(`source:${source.id}`, { ...source, fence: job.fence });
  await tx.put(`job:${id}`, job);
  return job;
}

async function dueSources(tx, now) {
  const policy = await policyOf(tx);
  if (!policy.enabled) return [];
  const eligible = (await values(tx, "source:")).filter(source => source.enabled
    && [source.provider, "ai_search"].every(id => policy.providers[id].enabled
      && policy.providers[id].background_limit >= policy.providers[id].units_per_call)
    && (!source.last_refreshed_at || now - Date.parse(source.last_refreshed_at) >= source.refresh_hours * 3600000))
    .sort((a, b) => a.id.localeCompare(b.id));
  const cursor = await tx.get("maintenance_cursor") ?? "";
  const next = eligible.findIndex(source => source.id > cursor);
  const offset = next < 0 ? 0 : next;
  const selected = [...eligible.slice(offset), ...eligible.slice(0, offset)].slice(0, 5);
  if (selected.length) await tx.put("maintenance_cursor", selected.at(-1).id);
  return selected;
}

async function updateJob(tx, input, now) {
  fields(input, ["id", "status", "reason", "artifact_id", "item_id", "index_key"], ["id"]);
  const job = await jobFor(tx, input.id);
  const source = await sourceFor(tx, job.source_id);
  if (job.status === "cancelled" || job.status === "completed" || !source.enabled || source.fence !== job.fence) {
    fail("job_inactive", "The indexing job is cancelled, completed or superseded.", 409);
  }
  if (input.status !== undefined && (!STATES.has(input.status) || input.status === "completed")) fail("invalid_job", "Invalid job transition.");
  if (input.reason !== undefined && input.reason !== null && (typeof input.reason !== "string" || !/^[a-z0-9_]{1,80}$/.test(input.reason))) {
    fail("invalid_job", "Use a safe error code for the job reason.");
  }
  for (const name of ["artifact_id", "item_id", "index_key"]) {
    if (input[name] !== undefined && input[name] !== null && (typeof input[name] !== "string" || input[name].length > 160)) {
      fail("invalid_job", "Invalid artifact or index reference.");
    }
  }
  const updated = { ...job, ...input, updated_at: new Date(now).toISOString() };
  await tx.put(`job:${job.id}`, updated);
  return updated;
}

async function saveArtifact(tx, artifact) {
  if (!artifact || !/^[a-f0-9]{64}$/.test(artifact.id ?? "") || !/^[a-f0-9]{64}$/.test(artifact.content_hash ?? "")
    || artifact.snapshot_key !== `snapshots/${artifact.id}.txt` || artifact.index_key !== `revisions/${artifact.id}.txt`
    || !Number.isSafeInteger(artifact.byte_length) || artifact.byte_length <= 0 || artifact.byte_length > 262144) {
    fail("invalid_artifact", "Invalid immutable source artifact.");
  }
  const source = await sourceFor(tx, artifact.source_id);
  if (artifact.canonical_url !== source.url || artifact.product !== source.product || artifact.requested_version !== source.version
    || !source.enabled) fail("invalid_artifact", "The artifact does not match an enabled source.");
  if (!Number.isFinite(Date.parse(artifact.expires_at)) || !Number.isFinite(Date.parse(artifact.fetched_at))) fail("invalid_artifact", "Invalid artifact timestamps.");
  const existing = await tx.get(`artifact:${artifact.id}`);
  if (existing) {
    if (existing.status === "expiring") fail("artifact_expiring", "This revision is being removed under its retention policy.", 409);
    if (existing.content_hash !== artifact.content_hash || existing.source_id !== artifact.source_id) fail("artifact_conflict", "Artifact identity cannot be changed.", 409);
    // A fresh acquisition may extend retention; it cannot erase publication evidence.
    const refreshed = { ...existing, checked_at: artifact.checked_at || existing.checked_at, expires_at: artifact.expires_at };
    await tx.put(`artifact:${artifact.id}`, refreshed);
    return refreshed;
  }
  if ((await tx.list({ prefix: "artifact:" })).size >= 1000) fail("artifact_limit", "The snapshot catalogue has reached its limit.", 409);
  const saved = { ...artifact, status: "live" };
  await tx.put(`artifact:${artifact.id}`, saved);
  await tx.put(`index:${artifact.index_key}`, artifact.id);
  return saved;
}

async function publish(tx, input, now) {
  const job = await jobFor(tx, input.id);
  const source = await sourceFor(tx, job.source_id);
  if (job.status === "completed") return job;
  if (!source.enabled || source.fence !== job.fence || job.status === "cancelled") {
    fail("publication_superseded", "A cancelled or superseded job cannot publish.", 409);
  }
  const artifact = await tx.get(`artifact:${input.artifact_id}`);
  if (!artifact || artifact.source_id !== source.id || artifact.index_key !== input.index_key
    || artifact.status === "expiring" || !input.item_id || Date.parse(artifact.expires_at) <= now) fail("invalid_publication", "A verified, retained artifact is required for publication.", 409);
  const timestamp = new Date(now).toISOString();
  retainedByPolicy(artifact, await policyOf(tx));
  await tx.put(`artifact:${artifact.id}`, { ...artifact, status: "published", published_at: timestamp, item_id: input.item_id });
  await tx.put(`source:${source.id}`, { ...source, current_artifact: artifact.id, last_checked_at: artifact.checked_at, last_refreshed_at: timestamp });
  const completed = { ...job, status: "completed", reason: null, artifact_id: artifact.id, item_id: input.item_id,
    index_key: input.index_key, updated_at: timestamp };
  await tx.put(`job:${job.id}`, completed);
  await bump(tx);
  return completed;
}

export class KnowledgeAuthority {
  constructor(storage, now = () => Date.now()) { this.storage = storage; this.now = now; }

  async call(operation, input = {}) {
    return this.storage.transaction(async tx => {
      const now = this.now();
      if (operation.startsWith("alexandria.")) return alexandriaCatalogue(tx, operation, input, await policyOf(tx), now);
      if (operation === "snapshot") {
        const policy = await policyOf(tx);
        const receipts = await values(tx, "reservation:");
        return { generation: await generationOf(tx), policy, sources: await values(tx, "source:"),
          jobs: (await values(tx, "job:")).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 100),
          usage: PROVIDER_IDS.map(provider => ({ ...usageFor(receipts, provider, now), limit: policy.providers[provider].limit })) };
      }
      if (operation === "policy.update") {
        const policy = validatePolicy(input);
        if ((await policyOf(tx)).revision !== input.expected_revision) fail("policy_conflict", "Reload the policy before saving changes.", 409);
        await tx.put("policy", policy);
        await bump(tx);
        return policy;
      }
      if (operation === "source.create") return createSource(tx, input, now);
      if (operation === "source.discover") return createSource(tx, input, now, true);
      if (operation === "source.update") return updateSource(tx, input);
      if (operation === "sources.due") return dueSources(tx, now);
      if (operation === "job.enqueue") return enqueue(tx, input, now);
      if (operation === "job.get") {
        const job = await jobFor(tx, input.id);
        return { job, source: await sourceFor(tx, job.source_id), artifact: job.artifact_id ? await tx.get(`artifact:${job.artifact_id}`) ?? null : null };
      }
      if (operation === "job.update") return updateJob(tx, input, now);
      if (operation === "job.publish") return publish(tx, input, now);
      if (operation === "job.cancel") {
        const job = await jobFor(tx, input.id);
        if (!ACTIVE.has(job.status)) return job;
        const cancelled = { ...job, status: "cancelled", updated_at: new Date(now).toISOString() };
        await tx.put(`job:${job.id}`, cancelled);
        return cancelled;
      }
      if (operation === "artifact.save") return saveArtifact(tx, input.artifact);
      if (operation === "artifact.get") return await tx.get(`artifact:${input.id}`) ?? null;
      if (operation === "artifact.for_key") {
        const id = await tx.get(`index:${input.key}`);
        return id ? await tx.get(`artifact:${id}`) ?? null : null;
      }
      if (operation === "reserve") return reserve(tx, await policyOf(tx), input, now);
      if (operation === "settle") return settle(tx, input, now);
      if (operation === "maintenance") { await pruneSettled(tx, now); await pruneAlexandria(tx, now); return { complete: true }; }
      if (operation === "artifacts.expired") return (await values(tx, "artifact:")).filter(item => Date.parse(item.expires_at) <= now).slice(0, 10);
      if (operation === "artifact.expiration_claim") {
        const artifact = await tx.get(`artifact:${input.id}`);
        if (!artifact || artifact.expires_at !== input.expires_at || Date.parse(artifact.expires_at) > now) {
          fail("artifact_not_expired", "The artifact is not eligible for expiration.", 409);
        }
        const claimed = { ...artifact, status: "expiring" };
        await tx.put(`artifact:${artifact.id}`, claimed);
        await bump(tx);
        return claimed;
      }
      if (operation === "artifact.expire") {
        const artifact = await tx.get(`artifact:${input.id}`);
        if (!artifact || artifact.status !== "expiring" || artifact.expires_at !== input.expires_at
          || Date.parse(artifact.expires_at) > now) fail("artifact_not_expired", "The artifact is not eligible for expiration.", 409);
        const source = await sourceFor(tx, artifact.source_id);
        if (source.current_artifact === artifact.id) await tx.put(`source:${source.id}`, { ...source, current_artifact: null });
        await tx.delete(`artifact:${artifact.id}`);
        await tx.delete(`index:${artifact.index_key}`);
        await tx.delete(`submission:${artifact.id}`);
        await bump(tx);
        return { expired: true };
      }
      fail("unknown_operation", "Unknown catalogue operation.", 404);
    });
  }
}
