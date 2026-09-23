import { publicUrl } from "./contracts.mjs";
import { createArtifact, normalizeSourceText } from "./evidence.mjs";
import { KnowledgeCorpus } from "./corpus.mjs";

const NO_RETRY = { retries: { limit: 0 }, timeout: "2 minutes" };
const READ_RETRY = { retries: { limit: 2, delay: "2 seconds", backoff: "constant" }, timeout: "30 seconds" };
const MAX_POLLS = 6;
const TERMINAL = new Set(["completed", "cancelled", "failed"]);
const UNKNOWN_ERRORS = new Set(["acquisition_outcome_unknown", "snapshot_outcome_unknown",
  "operation_already_submitted", "operation_outcome_unknown"]);
const REFUSED_ERRORS = new Set(["provider_disabled", "allowance_exhausted", "ledger_full", "invalid_reservation",
  "provider_not_configured", "invalid_source_policy", "source_not_allowed", "primary_source_unavailable",
  "invalid_source", "source_too_large", "invalid_snapshot", "artifact_conflict", "artifact_expiring"]);

function ingestionError(code) {
  return Object.assign(new Error("The knowledge ingestion job could not complete."), { code });
}

function safeCode(error) {
  return typeof error?.code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(error.code)
    ? error.code : "ingestion_failed";
}

async function dependencies(env, supplied) {
  return {
    authority: supplied.authority ?? (await import("./authority-client.mjs")).getAuthority(env),
    corpus: supplied.corpus ?? new KnowledgeCorpus(env),
    retrieve: supplied.retrieve ?? (await import("./providers/index.mjs")).retrieve,
    metered: supplied.metered ?? (await import("./operations.mjs")).metered,
    now: supplied.now ?? Date.now,
  };
}

async function current(context) {
  const value = await context.authority.call("job.get", { id: context.jobId });
  if (!value?.job || !value.source) throw ingestionError("job_not_found");
  if (value.job.status === "cancelled") throw ingestionError("job_cancelled");
  if (value.source.enabled === false) throw ingestionError("source_disabled");
  return value;
}

function update(context, values) {
  return context.authority.call("job.update", { id: context.jobId, ...values });
}

function matchingObservation(observations, source) {
  const url = publicUrl(source.url);
  return observations?.find(observation => {
    if (observation?.kind !== "source_excerpt" || typeof observation.text !== "string") return false;
    try { return publicUrl(observation.url) === url; }
    catch { return false; }
  });
}

async function recoverSnapshot(context, job, artifact) {
  if (!artifact) throw ingestionError("snapshot_missing");
  if (job.status === "acquiring" || job.status === "unknown" && job.reason === "snapshot_outcome_unknown") {
    if (await context.corpus.getSnapshot(artifact) === null) throw ingestionError("snapshot_outcome_unknown");
    await update(context, { status: "snapshot", reason: null });
  }
  return { artifact_id: artifact.id, checked_at: artifact.checked_at };
}

async function persistSnapshot(context, artifact, text) {
  const previous = await context.authority.call("artifact.for_key", { key: artifact.index_key });
  if (previous && previous.content_hash !== artifact.content_hash) throw ingestionError("artifact_conflict");
  await context.authority.call("artifact.save", { artifact });
  await update(context, { status: "acquiring", artifact_id: artifact.id, index_key: artifact.index_key });
  try {
    if (!previous || await context.corpus.getSnapshot(previous) !== text) {
      await context.metered(context.authority, {
        provider: "ai_search", operation_id: `${context.jobId}:snapshot`, background: true, job_id: context.jobId,
      }, () => context.corpus.putSnapshot(previous ?? artifact, text));
    }
  } catch (error) {
    if (REFUSED_ERRORS.has(safeCode(error))) throw error;
    throw ingestionError("snapshot_outcome_unknown");
  }
  await update(context, { status: "snapshot", artifact_id: artifact.id, index_key: artifact.index_key });
  return { artifact_id: artifact.id, checked_at: artifact.checked_at };
}

async function acquire(context) {
  const { job, source, artifact: saved } = await current(context);
  if (job.artifact_id) {
    const artifact = saved ?? await context.authority.call("artifact.get", { id: job.artifact_id });
    return recoverSnapshot(context, job, artifact);
  }
  if (job.status !== "queued") throw ingestionError("acquisition_outcome_unknown");
  const { policy } = await context.authority.call("snapshot");
  await update(context, { status: "acquiring" });
  const response = await context.retrieve(source.provider, {
    query: source.title || source.product || source.url, product: source.product,
    version: source.version, source_url: source.url, allowed_hosts: policy.allowed_hosts,
    freshness: "fresh",
  }, {
    env: context.env,
    invoke: (provider, suffix, callback) => context.metered(context.authority, {
      provider, operation_id: `${context.jobId}:${suffix}`, background: true, job_id: context.jobId,
    }, callback),
  });
  await current(context);
  const observation = matchingObservation(response?.observations, source);
  if (!observation) throw ingestionError("primary_source_unavailable");
  const text = normalizeSourceText(observation.text);
  const artifact = await createArtifact({ ...source, retention_hours: policy.retention_hours, origin_checked: observation.freshness === "live" },
    text, source.provider, context.now());
  return persistSnapshot(context, artifact, text);
}

async function storedArtifact(context, artifactId) {
  const artifact = await context.authority.call("artifact.get", { id: artifactId });
  if (!artifact) throw ingestionError("snapshot_missing");
  return artifact;
}

async function submit(context, artifactId) {
  const { job } = await current(context);
  const artifact = await storedArtifact(context, artifactId);
  const priorItemId = job.item_id || artifact.item_id;
  const reconciled = await context.corpus.reconcileRevision(artifact, priorItemId);
  if (reconciled) {
    await update(context, { status: "pending_index", item_id: reconciled.id, index_key: artifact.index_key });
    return { item_id: reconciled.id, uncertain: false };
  }
  // A saved pending marker may describe an accepted upload whose reply was lost.
  if (["pending_index", "unknown"].includes(job.status)) return { item_id: null, uncertain: true };
  if (job.status !== "snapshot") throw ingestionError("invalid_job_state");
  const text = await context.corpus.getSnapshot(artifact);
  if (text === null) throw ingestionError("snapshot_missing");
  try {
    const item = await context.metered(context.authority, {
      provider: "ai_search", operation_id: `${context.jobId}:upload`, background: true,
      job_id: context.jobId, revision_id: artifact.id,
    }, async () => {
      await update(context, { status: "pending_index", artifact_id: artifact.id, index_key: artifact.index_key });
      return context.corpus.uploadRevision(artifact, text);
    });
    await update(context, { status: "pending_index", item_id: item.id, index_key: artifact.index_key });
    return { item_id: item.id, uncertain: false };
  } catch (error) {
    const state = await current(context);
    if (state.job.status === "completed") return { item_id: state.job.item_id, uncertain: false };
    if (state.job.status === "snapshot") throw error;
    // Never resubmit an upload, including after a Workflow restart or lost acknowledgement.
    const item = await context.corpus.reconcileRevision(artifact).catch(() => null);
    if (item) {
      await update(context, { status: "pending_index", item_id: item.id, index_key: artifact.index_key });
      return { item_id: item.id, uncertain: false };
    }
    await update(context, { status: "unknown", reason: safeCode(error) });
    return { item_id: null, uncertain: true };
  }
}

async function inspect(context, reference, submission) {
  const { job } = await current(context);
  if (job.status === "completed") return { done: true, job };
  const artifact = await storedArtifact(context, reference.artifact_id);
  const item = await context.corpus.reconcileRevision(artifact, job.item_id || submission.item_id);
  if (!item) return { done: false, uncertain: true };
  if (["error", "skipped"].includes(item.status)) {
    return { done: true, job: await update(context, { status: "failed", reason: "index_processing_failed" }) };
  }
  if (item.status !== "completed" || !await context.corpus.verifySearchable(artifact, item)) {
    return { done: false, uncertain: false };
  }
  await current(context);
  return { done: true, job: await context.authority.call("job.publish", {
    id: context.jobId, artifact_id: artifact.id, item_id: item.id,
    index_key: artifact.index_key, checked_at: reference.checked_at,
  }) };
}

async function recordFailure(context, error) {
  const result = await context.authority.call("job.get", { id: context.jobId });
  if (result?.job && TERMINAL.has(result.job.status)) return result.job;
  const code = safeCode(error);
  const uncertain = UNKNOWN_ERRORS.has(code) || !REFUSED_ERRORS.has(code)
    && ["pending_index", "unknown", "acquiring"].includes(result?.job?.status);
  return update(context, { status: uncertain ? "unknown" : "failed", reason: code });
}

/** Run durable acquisition and publication without repeating ambiguous paid work. */
export async function runIngestion(env, step, jobId, supplied = {}) {
  const context = { ...await dependencies(env, supplied), env, jobId };
  try {
    const initial = await context.authority.call("job.get", { id: jobId });
    if (initial?.job && TERMINAL.has(initial.job.status)) return initial.job;
    const reference = await step.do("acquire-source", NO_RETRY, () => acquire(context));
    const submission = await step.do("submit-index-revision", NO_RETRY, () => submit(context, reference.artifact_id));
    let uncertain = submission.uncertain;
    for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
      const result = await step.do(`verify-index-${attempt}`, READ_RETRY, () => inspect(context, reference, submission));
      if (result.done) return result.job;
      uncertain = result.uncertain;
      if (attempt + 1 < MAX_POLLS) await step.sleep(`wait-for-index-${attempt}`, "10 seconds");
    }
    return await update(context, {
      status: uncertain ? "unknown" : "pending_index",
      reason: uncertain ? "upload_outcome_unknown" : "awaiting_verified_index",
    });
  } catch (error) {
    return recordFailure(context, error);
  }
}
