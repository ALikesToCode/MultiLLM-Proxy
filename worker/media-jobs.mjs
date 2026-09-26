/**
 * Asynchronous media jobs in D1: image batches and video webhook watches.
 *
 * The Container creates and reads jobs through the private handler below (fixed SQL, no
 * client SQL). A Cloudflare Workflow (media-workflow.mjs) drives each job, so a job
 * survives Container sleep and Worker restarts. A batch runs a few items at a time on
 * the Container's own image dispatch, with each item's failover. Items are claimed
 * before they are sent and never sent twice: an item whose attempt was interrupted is
 * recovered from the files it stored, or reported as `outcome_unknown`, because the
 * provider may already have generated and billed it.
 */
import { boundedBody } from "./control-users-d1.mjs";
import { logFailure } from "./log.mjs";
import { publicHttpsUrl } from "./media-outbound.mjs";
import { mediaSecret, webhookSignature } from "./media-signing.mjs";

const JOB_ID = { image_batch: /^imgbatch_[a-f0-9]{32}$/, video: /^vwatch_[a-f0-9]{32}$/ };
const CUSTOM_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const OWNER = /^[^\x00-\x1f\x7f]{1,256}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const TERMINAL = ["completed", "cancelled", "failed", "expired"];
const ACTIVE = ["queued", "in_progress", "cancelling"];
const MAX_ITEMS = 500;
const MAX_ITEM_BYTES = 48 * 1024;
const MAX_CREATE_BYTES = 4 * 1024 * 1024;
const MAX_BODY_BYTES = 16 * 1024;
const ITEM_ROWS_PER_INSERT = 16;
export const LEASE_SECONDS = 40 * 60;
const WEBHOOK_TIMEOUT_MS = 15000;
const RETRYABLE_WEBHOOK_STATUSES = new Set([408, 409, 425, 429]);

const nowSeconds = () => Math.floor(Date.now() / 1000);
const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);
const reply = (value, status = 200) => Response.json(status === 200 ? { version: 1, ...value }
  : { version: 1, error: { code: value, message: "Media job operation failed" } }, { status, headers: { "cache-control": "no-store" } });

function bounded(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

export function jobSettings(env = {}) {
  return {
    maxRunning: bounded(env.MEDIA_BATCH_MAX_RUNNING, 2, 1, 8),
    chunkSize: bounded(env.MEDIA_BATCH_CHUNK_SIZE, 4, 1, 8),
    maxActivePerOwner: bounded(env.MEDIA_BATCH_MAX_ACTIVE, 3, 1, 20),
    retentionDays: bounded(env.MEDIA_JOB_RETENTION_DAYS, 30, 1, 365),
  };
}

const parse = (value, fallback = null) => {
  if (typeof value !== "string") return fallback;
  try { return JSON.parse(value); } catch { return fallback; }
};

async function counts(db, id) {
  const { results } = await db.prepare("SELECT status, COUNT(*) AS n FROM media_job_items WHERE job_id = ? GROUP BY status")
    .bind(id).all();
  const tally = { queued: 0, running: 0, succeeded: 0, failed: 0, cancelled: 0 };
  for (const row of results) tally[row.status] = row.n;
  return tally;
}

async function summary(db, row) {
  return { id: row.id, kind: row.kind, owner: row.owner, status: row.status, item_count: row.item_count,
    counts: row.kind === "image_batch" ? await counts(db, row.id) : null, webhook_url: row.webhook_url ?? null,
    webhook_status: row.webhook_status ?? null, metadata: parse(row.metadata, {}), result: parse(row.result),
    created_at: row.created_at, started_at: row.started_at ?? null, completed_at: row.completed_at ?? null };
}

const jobRow = (db, id) => db.prepare("SELECT * FROM media_jobs WHERE id = ?").bind(id).first();

async function startWorkflow(env, id) {
  try {
    await env.MEDIA_JOBS.create({ id, params: { id } });
    return true;
  } catch (error) {
    // Creating the same instance twice is how a retried create proves it already started.
    if (/already exists|duplicate/i.test(String(error?.message ?? error))) return true;
    logFailure("media_job_start_failed", error, { job: id.slice(0, 9) });
    return false;
  }
}

async function prune(db, days, now) {
  const { results } = await db.prepare(`SELECT id FROM media_jobs WHERE status IN ('completed', 'cancelled', 'failed', 'expired')
    AND completed_at < ? ORDER BY completed_at LIMIT 20`).bind(now - days * 86400).all();
  for (const { id } of results) {
    await db.batch([db.prepare("DELETE FROM media_job_items WHERE job_id = ?").bind(id),
      db.prepare("DELETE FROM media_jobs WHERE id = ?").bind(id)]);
  }
}

function validCommon(body, kind) {
  return JOB_ID[kind].test(body.id ?? "") && OWNER.test(body.owner ?? "") && typeof body.principal === "string"
    && body.principal.length <= 2048 && DIGEST.test(body.request_digest ?? "") && isRecord(body.metadata)
    && (body.webhook_url === null || publicHttpsUrl(body.webhook_url) !== null);
}

async function existing(env, row, body) {
  if (row.owner !== body.owner || row.request_digest !== body.request_digest || row.kind !== body.kind) {
    return reply("idempotency_conflict", 409);
  }
  if (row.status === "queued" && !await startWorkflow(env, row.id)) return reply("batches_unavailable", 503);
  return reply({ created: false, job: await summary(env.INTELLIGENCE_DB, row) });
}

async function createJob(env, body, kind) {
  const db = env.INTELLIGENCE_DB;
  const now = nowSeconds();
  const settings = jobSettings(env);
  const items = kind === "image_batch" ? body.items : [];
  if (kind === "image_batch" && (!Array.isArray(items) || !items.length || items.length > MAX_ITEMS
    || !items.every(item => isRecord(item) && CUSTOM_ID.test(item.custom_id ?? "") && isRecord(item.request)
      && JSON.stringify(item.request).length <= MAX_ITEM_BYTES))) return reply("invalid_request", 400);
  const row = await jobRow(db, body.id);
  if (row) return existing(env, row, { ...body, kind });
  if (kind === "image_batch") {
    const active = await db.prepare(`SELECT COUNT(*) AS n FROM media_jobs WHERE owner = ? AND kind = 'image_batch'
      AND status IN ('queued', 'in_progress', 'cancelling')`).bind(body.owner).first();
    if (active.n >= settings.maxActivePerOwner) return reply("too_many_active_batches", 429);
  }
  const statements = [db.prepare(`INSERT INTO media_jobs (id, kind, owner, status, principal, request_digest, item_count,
      webhook_url, webhook_status, metadata, created_at) VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, NULL, ?, ?)
      ON CONFLICT(id) DO NOTHING`)
    .bind(body.id, kind, body.owner, body.principal, body.request_digest, items.length, body.webhook_url,
      JSON.stringify(body.metadata), now)];
  for (let start = 0; start < items.length; start += ITEM_ROWS_PER_INSERT) {
    const rows = items.slice(start, start + ITEM_ROWS_PER_INSERT);
    statements.push(db.prepare(`INSERT INTO media_job_items (job_id, idx, custom_id, request, status, updated_at) VALUES
      ${rows.map(() => "(?, ?, ?, ?, 'queued', ?)").join(", ")} ON CONFLICT(job_id, idx) DO NOTHING`)
      .bind(...rows.flatMap((item, offset) => [body.id, start + offset, item.custom_id, JSON.stringify(item.request), now])));
  }
  const [inserted] = await db.batch(statements);
  if (!inserted.meta?.changes) return existing(env, await jobRow(db, body.id), { ...body, kind });
  if (!await startWorkflow(env, body.id)) {
    await db.prepare("UPDATE media_jobs SET status = 'failed', completed_at = ? WHERE id = ?").bind(now, body.id).run();
    return reply("batches_unavailable", 503);
  }
  await prune(db, settings.retentionDays, now).catch(error => logFailure("media_job_prune_failed", error));
  return reply({ created: true, job: await summary(db, await jobRow(db, body.id)) });
}

async function ownedJob(db, body, kind) {
  if (!JOB_ID[kind]?.test(body.id ?? "") || !OWNER.test(body.owner ?? "")) return null;
  const row = await jobRow(db, body.id);
  return row && row.owner === body.owner && row.kind === kind ? row : null;
}

const pageSize = value => bounded(value, 20, 1, 100);

async function listJobs(db, body) {
  if (!OWNER.test(body.owner ?? "") || !Object.hasOwn(JOB_ID, body.kind ?? "")) return reply("invalid_request", 400);
  const limit = pageSize(body.limit);
  const before = bounded(body.before, Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER);
  const { results } = await db.prepare(`SELECT * FROM media_jobs WHERE owner = ? AND kind = ? AND created_at < ?
    ORDER BY created_at DESC, id DESC LIMIT ?`).bind(body.owner, body.kind, before, limit + 1).all();
  const jobs = [];
  for (const row of results.slice(0, limit)) jobs.push(await summary(db, row));
  return reply({ jobs, has_more: results.length > limit });
}

async function listItems(db, body) {
  const row = await ownedJob(db, body, "image_batch");
  if (!row) return reply("not_found", 404);
  const limit = pageSize(body.limit);
  const after = bounded(body.after, -1, -1, MAX_ITEMS);
  const { results } = await db.prepare(`SELECT idx, custom_id, status, model, files, error FROM media_job_items
    WHERE job_id = ? AND idx > ? ORDER BY idx LIMIT ?`).bind(row.id, after, limit + 1).all();
  return reply({ items: results.slice(0, limit).map(item => ({ index: item.idx, custom_id: item.custom_id, status: item.status,
    model: item.model ?? null, files: parse(item.files, []), error: parse(item.error) })), has_more: results.length > limit });
}

async function cancelJob(db, body) {
  const row = await ownedJob(db, body, "image_batch");
  if (!row) return reply("not_found", 404);
  if (ACTIVE.includes(row.status) && row.status !== "cancelling") {
    const now = nowSeconds();
    await db.batch([
      db.prepare("UPDATE media_jobs SET cancel_requested = 1 WHERE id = ?").bind(row.id),
      db.prepare("UPDATE media_job_items SET status = 'cancelled', updated_at = ? WHERE job_id = ? AND status = 'queued'").bind(now, row.id),
      // Nothing is running: the batch is cancelled now; otherwise running items finish first.
      db.prepare(`UPDATE media_jobs SET status = CASE WHEN EXISTS (SELECT 1 FROM media_job_items WHERE job_id = ?1
        AND status = 'running') THEN 'cancelling' ELSE 'cancelled' END,
        completed_at = CASE WHEN EXISTS (SELECT 1 FROM media_job_items WHERE job_id = ?1 AND status = 'running')
        THEN NULL ELSE ?2 END WHERE id = ?1`).bind(row.id, now),
    ]);
  }
  return reply({ job: await summary(db, await jobRow(db, row.id)) });
}

/** The private handler at http://intelligence.internal/v1/media-jobs. */
export async function handleMediaJobsRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/media-jobs"
    || url.search || url.hash || url.username || url.password) return reply("not_found", 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return reply("invalid_request", 400);
  }
  if (!env.INTELLIGENCE_DB || !env.MEDIA_JOBS) return reply("batches_not_configured", 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request, MAX_CREATE_BYTES));
    if (!isRecord(body) || body.version !== 1) return reply("invalid_request", 400);
  } catch { return reply("invalid_request", 400); }
  const db = env.INTELLIGENCE_DB;
  try {
    if (body.operation === "create_batch") {
      return validCommon(body, "image_batch") ? await createJob(env, body, "image_batch") : reply("invalid_request", 400);
    }
    if (JSON.stringify(body).length > MAX_BODY_BYTES) return reply("invalid_request", 400);
    if (body.operation === "watch_video") {
      return validCommon(body, "video") && typeof body.metadata.job_id === "string"
        ? await createJob(env, body, "video") : reply("invalid_request", 400);
    }
    if (body.operation === "get_job") {
      const row = await ownedJob(db, body, body.kind);
      return row ? reply({ job: await summary(db, row) }) : reply("not_found", 404);
    }
    if (body.operation === "list_jobs") return await listJobs(db, body);
    if (body.operation === "list_items") return await listItems(db, body);
    if (body.operation === "cancel_job") return await cancelJob(db, body);
    return reply("invalid_request", 400);
  } catch (error) {
    logFailure("media_job_storage_failed", error, { operation: String(body.operation).slice(0, 20) });
    return reply("storage_unavailable", 503);
  }
}

// ---- Workflow runtime --------------------------------------------------------------------

const SHORT_STEP = { retries: { limit: 5, delay: "10 seconds", backoff: "exponential" }, timeout: "2 minutes" };
// A chunk waits for image generation, which may take minutes per candidate.
const CHUNK_STEP = { retries: { limit: 3, delay: "30 seconds", backoff: "exponential" }, timeout: "45 minutes" };
const POLL_STEP = { retries: { limit: 3, delay: "15 seconds", backoff: "exponential" }, timeout: "10 minutes" };
const WEBHOOK_STEP = { retries: { limit: 6, delay: "30 seconds", backoff: "exponential" }, timeout: "1 minute" };
const MAX_SLOT_WAITS = 400;
const MAX_CHUNKS = 2000;
const MAX_VIDEO_POLLS = 400;

// Steps return JSON strings: object results can keep a Workflow invocation open.
async function stepJson(step, name, config, callback) {
  return JSON.parse(await step.do(name, config, async () => JSON.stringify(await callback() ?? null)));
}

export const itemFilePrefix = (jobId, index) => `mb_${jobId.slice(9)}_${index}_`;

async function acquireSlot(env, id, now) {
  const db = env.INTELLIGENCE_DB;
  const row = await db.prepare("SELECT status, cancel_requested FROM media_jobs WHERE id = ?").bind(id).first();
  if (!row) return "missing";
  if (TERMINAL.includes(row.status) || row.cancel_requested) return "stop";
  if (row.status === "in_progress") {
    await db.prepare("UPDATE media_jobs SET lease_until = ? WHERE id = ?").bind(now + LEASE_SECONDS, id).run();
    return "running";
  }
  // At most maxRunning batches run at once; a batch whose Workflow died stops counting when its lease ends.
  const claimed = await db.prepare(`UPDATE media_jobs SET status = 'in_progress', started_at = COALESCE(started_at, ?1),
    lease_until = ?2 WHERE id = ?3 AND status = 'queued' AND cancel_requested = 0 AND (SELECT COUNT(*) FROM media_jobs
    WHERE kind = 'image_batch' AND status = 'in_progress' AND lease_until > ?1) < ?4`)
    .bind(now, now + LEASE_SECONDS, id, jobSettings(env).maxRunning).run();
  return claimed.meta?.changes ? "running" : "wait";
}

async function storedFiles(env, jobId, index) {
  if (!env.MEDIA_BUCKET) return [];
  const listed = await env.MEDIA_BUCKET.list({ prefix: `media/${itemFilePrefix(jobId, index)}`, include: ["customMetadata", "httpMetadata"] });
  return listed.objects.map(object => ({ id: object.key.slice("media/".length), size: object.size,
    content_type: object.httpMetadata?.contentType ?? null, model: object.customMetadata?.model || null }));
}

async function recordItem(db, jobId, index, attempt, result, now) {
  await db.prepare(`UPDATE media_job_items SET status = ?, model = ?, files = ?, error = ?, lease_until = NULL, updated_at = ?
    WHERE job_id = ? AND idx = ? AND status = 'running' AND (? IS NULL OR attempt = ?)`)
    .bind(result.status, result.model ?? null, JSON.stringify(result.files ?? []), result.error ? JSON.stringify(result.error) : null,
      now, jobId, index, attempt, attempt).run();
}

/** An item left running by an interrupted attempt: recover what it stored, never resend it. */
async function recoverItem(env, jobId, index, now) {
  const files = await storedFiles(env, jobId, index);
  const result = files.length
    ? { status: "succeeded", model: files[0].model, files: files.map(({ model, ...file }) => file) }
    : { status: "failed", error: { code: "outcome_unknown", message: "The item was interrupted after it was sent. "
      + "It was not retried because the provider may already have generated and billed it." } };
  await recordItem(env.INTELLIGENCE_DB, jobId, index, null, result, now);
}

const FAILURE_MESSAGES = {
  principal_rejected: "The batch owner's account is no longer valid.",
  batch_interrupted: "The batch stopped after repeated storage or Container errors; the item was not retried.",
};

async function failRemaining(db, jobId, code, now) {
  await db.prepare(`UPDATE media_job_items SET status = 'failed', error = ?, lease_until = NULL, updated_at = ?
    WHERE job_id = ? AND status IN ('queued', 'running')`)
    .bind(JSON.stringify({ code, message: FAILURE_MESSAGES[code] }), now, jobId).run();
}

async function runChunk(env, id, deps) {
  const db = env.INTELLIGENCE_DB;
  const now = deps.now();
  const job = await db.prepare("SELECT principal, cancel_requested FROM media_jobs WHERE id = ?").bind(id).first();
  if (!job) return { done: true };
  await db.prepare("UPDATE media_jobs SET lease_until = ? WHERE id = ?").bind(now + LEASE_SECONDS, id).run();
  const { results: running } = await db.prepare("SELECT idx, lease_until FROM media_job_items WHERE job_id = ? AND status = 'running'")
    .bind(id).all();
  // An earlier attempt may still be generating these; wait for its lease before recovering them.
  if (running.some(item => item.lease_until > now)) return { wait: 60 };
  for (const item of running) await recoverItem(env, id, item.idx, now);
  if (job.cancel_requested) {
    await db.prepare("UPDATE media_job_items SET status = 'cancelled', updated_at = ? WHERE job_id = ? AND status = 'queued'")
      .bind(now, id).run();
    return { done: true };
  }
  const attempt = crypto.randomUUID();
  await db.prepare(`UPDATE media_job_items SET status = 'running', attempt = ?1, lease_until = ?2, updated_at = ?3
    WHERE job_id = ?4 AND status = 'queued' AND idx IN (SELECT idx FROM media_job_items WHERE job_id = ?4 AND status = 'queued'
    ORDER BY idx LIMIT ?5)`).bind(attempt, now + LEASE_SECONDS, now, id, jobSettings(env).chunkSize).run();
  const { results: claimed } = await db.prepare(`SELECT idx, custom_id, request FROM media_job_items WHERE job_id = ? AND attempt = ?
    AND status = 'running' ORDER BY idx`).bind(id, attempt).all();
  if (!claimed.length) return { done: true };
  const release = () => db.prepare(`UPDATE media_job_items SET status = 'queued', attempt = NULL, lease_until = NULL
    WHERE job_id = ? AND attempt = ? AND status = 'running'`).bind(id, attempt).run();
  // Wake the Container first: when this fails nothing was sent, so the items return to the queue.
  const healthy = await deps.container(new Request("http://container/healthz")).then(response => {
    void response.body?.cancel();
    return response.ok;
  }, () => false);
  if (!healthy) {
    await release();
    return { wait: 60 };
  }
  let response;
  try {
    response = await deps.container(new Request("http://container/internal/media/batch-items", {
      method: "POST", headers: { "content-type": "application/json", authorization: `MultiLLM-Principal ${job.principal}` },
      body: JSON.stringify({ job_id: id, items: claimed.map(item => ({ index: item.idx, custom_id: item.custom_id,
        request: JSON.parse(item.request) })) }) }));
  } catch (error) {
    // The items may have been sent: they stay claimed and are recovered after their lease.
    logFailure("media_batch_dispatch_failed", error, { job: id.slice(0, 9) });
    return { wait: 60 };
  }
  const payload = await response.json().catch(() => null);
  if (response.status === 503 && payload?.retry === true) {
    await release();
    return { wait: 120 };
  }
  if (response.status === 403) {
    await failRemaining(db, id, "principal_rejected", now);
    return { done: true };
  }
  if (!response.ok || !Array.isArray(payload?.results)) return { wait: 60 };
  for (const item of claimed) {
    const result = payload.results.find(entry => entry?.index === item.idx);
    const valid = result && ["succeeded", "failed"].includes(result.status) && (!result.files || Array.isArray(result.files));
    await recordItem(db, id, item.idx, attempt, valid ? result
      : { status: "failed", error: { code: "no_result", message: "The item returned no result." } }, deps.now());
  }
  return { done: false };
}

async function finalize(env, id, now) {
  const db = env.INTELLIGENCE_DB;
  const row = await jobRow(db, id);
  if (!row) return null;
  if (!TERMINAL.includes(row.status)) {
    let status = "expired";
    if (row.kind === "image_batch") {
      const tally = await counts(db, id);
      status = row.cancel_requested ? "cancelled" : tally.succeeded || !tally.failed ? "completed" : "failed";
    }
    await db.prepare(`UPDATE media_jobs SET status = ?, completed_at = ?, lease_until = NULL,
      webhook_status = CASE WHEN webhook_url IS NULL THEN NULL ELSE 'pending' END WHERE id = ?`).bind(status, now, id).run();
  } else if (row.webhook_url && !row.webhook_status) {
    await db.prepare("UPDATE media_jobs SET webhook_status = 'pending' WHERE id = ?").bind(id).run();
  }
  return summary(db, await jobRow(db, id));
}

export function webhookEvent(job) {
  if (job.kind === "video") {
    const result = job.result ?? {};
    return { type: `video.${job.status}`, data: { id: job.metadata?.job_id, object: "video", status: job.status,
      model: result.model ?? job.metadata?.model ?? null, ...(result.error ? { error: result.error } : {}) } };
  }
  return { type: `image.batch.${job.status}`, data: { id: job.id, object: "image.batch", status: job.status,
    request_counts: { total: job.item_count, ...job.counts }, metadata: job.metadata } };
}

/** POST the signed event; "delivered" or "rejected", or throw so the step retries. */
export async function deliverWebhook(env, job, fetcher = fetch, now = nowSeconds()) {
  const url = publicHttpsUrl(job.webhook_url);
  const secret = mediaSecret(env);
  if (!url || !secret) return "rejected";
  const event = webhookEvent(job);
  const body = JSON.stringify({ type: event.type, created_at: now, data: event.data });
  const messageId = `${job.id}.${job.status}`;
  const response = await fetcher(url.href, { method: "POST", redirect: "manual", signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    headers: { "content-type": "application/json", "user-agent": "MultiLLM-Webhooks/1", "webhook-id": messageId,
      "webhook-timestamp": String(now), "webhook-signature": await webhookSignature(secret, job.owner, messageId, now, body) },
    body });
  void response.body?.cancel();
  if (response.ok) return "delivered";
  if (response.status < 500 && !RETRYABLE_WEBHOOK_STATUSES.has(response.status)) return "rejected";
  throw new Error(`Webhook answered HTTP ${response.status}`);
}

async function sendWebhook(env, step, job, deps) {
  if (!job?.webhook_url) return;
  let outcome;
  try {
    outcome = await step.do("webhook", WEBHOOK_STEP, () => deliverWebhook(env, job, deps.fetch, nowSeconds()));
  } catch {
    outcome = "failed";
  }
  await step.do("webhook status", SHORT_STEP, async () => {
    await env.INTELLIGENCE_DB.prepare("UPDATE media_jobs SET webhook_status = ? WHERE id = ?").bind(outcome, job.id).run();
    return outcome;
  });
}

async function runImageBatch(env, step, id, deps) {
  let state = "wait";
  for (let attempt = 0; attempt < MAX_SLOT_WAITS; attempt += 1) {
    state = await stepJson(step, `slot ${attempt}`, SHORT_STEP, () => acquireSlot(env, id, deps.now()));
    if (state !== "wait") break;
    await step.sleep(`slot wait ${attempt}`, `${Math.min(300, 15 * 2 ** Math.min(attempt, 4))} seconds`);
  }
  if (state === "running") {
    try {
      for (let chunk = 0; chunk < MAX_CHUNKS; chunk += 1) {
        const outcome = await stepJson(step, `chunk ${chunk}`, CHUNK_STEP, () => runChunk(env, id, deps));
        if (outcome.done) break;
        if (outcome.wait) await step.sleep(`chunk wait ${chunk}`, `${outcome.wait} seconds`);
      }
    } catch (error) {
      // A step that exhausted its retries: end the batch instead of leaving it running.
      logFailure("media_batch_interrupted", error, { job: id.slice(0, 9) });
      await stepJson(step, "interrupted", SHORT_STEP, () => failRemaining(env.INTELLIGENCE_DB, id, "batch_interrupted", deps.now())
        .then(() => true));
    }
  } else if (state === "wait") {
    await stepJson(step, "queue timeout", SHORT_STEP, () => env.INTELLIGENCE_DB.prepare(`UPDATE media_job_items
      SET status = 'failed', error = ?, updated_at = ? WHERE job_id = ? AND status = 'queued'`)
      .bind(JSON.stringify({ code: "queue_timeout", message: "The batch waited too long for a free slot." }), deps.now(), id).run()
      .then(() => true));
  }
  const job = await stepJson(step, "finalize", SHORT_STEP, () => finalize(env, id, deps.now()));
  await sendWebhook(env, step, job, deps);
}

const pollDelay = poll => (poll < 8 ? 15 : poll < 40 ? 30 : 60);

async function pollVideo(env, id, deps) {
  const db = env.INTELLIGENCE_DB;
  const row = await jobRow(db, id);
  if (!row || TERMINAL.includes(row.status)) return { done: true };
  const metadata = parse(row.metadata, {});
  let response;
  try {
    response = await deps.container(new Request("http://container/internal/media/video-status", {
      method: "POST", headers: { "content-type": "application/json", authorization: `MultiLLM-Principal ${row.principal}` },
      body: JSON.stringify({ watch_id: id, job_id: metadata.job_id }) }));
  } catch {
    return { done: false };
  }
  const payload = await response.json().catch(() => null);
  if (response.status === 403 || response.status === 404) {
    await db.prepare("UPDATE media_jobs SET status = 'failed', result = ?, completed_at = ? WHERE id = ?")
      .bind(JSON.stringify({ error: { code: "watch_rejected", message: "The video job can no longer be read." } }), deps.now(), id).run();
    return { done: true };
  }
  if (!response.ok || !["completed", "failed"].includes(payload?.status)) return { done: false };
  const result = { model: typeof payload.model === "string" ? payload.model : null,
    ...(isRecord(payload.error) ? { error: { message: String(payload.error.message ?? "").slice(0, 500) } } : {}) };
  await db.prepare("UPDATE media_jobs SET status = ?, result = ?, completed_at = ? WHERE id = ?")
    .bind(payload.status, JSON.stringify(result), deps.now(), id).run();
  return { done: true };
}

async function runVideoWatch(env, step, id, deps) {
  try {
    for (let poll = 0; poll < MAX_VIDEO_POLLS; poll += 1) {
      if (poll) await step.sleep(`poll wait ${poll}`, `${pollDelay(poll)} seconds`);
      if ((await stepJson(step, `poll ${poll}`, POLL_STEP, () => pollVideo(env, id, deps))).done) break;
    }
  } catch (error) {
    // Storage kept failing: report the watch as expired rather than never ending it.
    logFailure("media_video_watch_interrupted", error, { job: id.slice(0, 7) });
  }
  const job = await stepJson(step, "finalize", SHORT_STEP, () => finalize(env, id, deps.now()));
  await sendWebhook(env, step, job, deps);
}

/** Entry point of one Workflow instance; `deps.container` sends a Request to the Container. */
export async function runMediaJob(env, id, step, deps) {
  const options = { now: nowSeconds, fetch, ...deps };
  const kind = await stepJson(step, "load", SHORT_STEP, async () => (await jobRow(env.INTELLIGENCE_DB, id))?.kind ?? null);
  if (kind === "image_batch") await runImageBatch(env, step, id, options);
  else if (kind === "video") await runVideoWatch(env, step, id, options);
}
