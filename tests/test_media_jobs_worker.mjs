import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { collectContainerEnv } from "../worker/container-env.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { deliverWebhook, handleMediaJobsRequest, itemFilePrefix, runMediaJob } from "../worker/media-jobs.mjs";
import { webhookSignature } from "../worker/media-signing.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const BATCH = `imgbatch_${"a".repeat(32)}`;
const WATCH = `vwatch_${"b".repeat(32)}`;
const DIGEST = "0".repeat(64);

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}",
    d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  return db;
}

function workflows() {
  const created = [];
  return { created, async create(options) {
    if (created.some(item => item.id === options.id)) throw new Error("instance already exists");
    created.push(options);
    return { id: options.id };
  } };
}

function bucket() {
  const objects = new Map();
  return { objects, async list({ prefix }) {
    return { objects: [...objects.entries()].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => ({ key, ...value })) };
  } };
}

const call = (env, body) => handleMediaJobsRequest(new Request("http://intelligence.internal/v1/media-jobs", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);

const batchBody = (overrides = {}) => ({ operation: "create_batch", id: BATCH, owner: "alice", principal: "principal.token",
  request_digest: DIGEST, webhook_url: "https://hooks.example.com/batches", metadata: { project: "launch" },
  items: Array.from({ length: 5 }, (_, index) => ({ custom_id: `item-${index}`, request: { prompt: `image ${index}` } })), ...overrides });

function fakeStep() {
  const names = [];
  const sleeps = [];
  return { names, sleeps,
    async do(name, config, callback) { names.push(name); return (callback ?? config)(); },
    async sleep(name, duration) { sleeps.push([name, duration]); } };
}

test("the private handler stores a batch once, starts its Workflow and serves it only to its owner", async t => {
  const env = { INTELLIGENCE_DB: await database(t), MEDIA_JOBS: workflows() };
  const created = await (await call(env, batchBody())).json();
  assert.equal(created.created, true);
  assert.deepEqual(created.job.counts, { queued: 5, running: 0, succeeded: 0, failed: 0, cancelled: 0 });
  assert.deepEqual(env.MEDIA_JOBS.created, [{ id: BATCH, params: { id: BATCH } }]);
  const again = await (await call(env, batchBody())).json();
  assert.equal(again.created, false, "the same batch is not stored or started twice");
  assert.equal(env.MEDIA_JOBS.created.length, 1);
  assert.equal((await call(env, batchBody({ request_digest: "1".repeat(64) }))).status, 409);
  assert.equal((await call(env, { operation: "get_job", id: BATCH, owner: "mallory", kind: "image_batch" })).status, 404);
  const items = await (await call(env, { operation: "list_items", id: BATCH, owner: "alice", after: 1, limit: 2 })).json();
  assert.deepEqual(items.items.map(item => item.custom_id), ["item-2", "item-3"]);
  assert.equal(items.has_more, true);
  const listed = await (await call(env, { operation: "list_jobs", owner: "alice", kind: "image_batch", limit: 20, before: null })).json();
  assert.deepEqual(listed.jobs.map(job => job.id), [BATCH]);
  for (const bad of [batchBody({ id: "imgbatch_short" }), batchBody({ items: [] }), batchBody({ webhook_url: "https://127.0.0.1/x" }),
    batchBody({ webhook_url: "http://hooks.example.com/x" }), { operation: "drop_table" }]) {
    assert.equal((await call(env, bad)).status, 400, JSON.stringify(bad).slice(0, 80));
  }
  assert.equal((await call({ INTELLIGENCE_DB: env.INTELLIGENCE_DB }, batchBody())).status, 503);
});

test("an owner may keep only a few batches active and cancelling stops queued items", async t => {
  const env = { INTELLIGENCE_DB: await database(t), MEDIA_JOBS: workflows(), MEDIA_BATCH_MAX_ACTIVE: "2" };
  for (const letter of ["c", "d"]) assert.equal((await call(env, batchBody({ id: `imgbatch_${letter.repeat(32)}` }))).status, 200);
  const refused = await call(env, batchBody());
  assert.equal(refused.status, 429);
  assert.equal((await refused.json()).error.code, "too_many_active_batches");
  const cancelled = await (await call(env, { operation: "cancel_job", id: `imgbatch_${"c".repeat(32)}`, owner: "alice" })).json();
  assert.equal(cancelled.job.status, "cancelled");
  assert.equal(cancelled.job.counts.cancelled, 5);
  assert.equal((await call(env, batchBody())).status, 200);
});

test("the Workflow runs items a few at a time, records results and signs the webhook", async t => {
  const env = { INTELLIGENCE_DB: await database(t), MEDIA_JOBS: workflows(), MEDIA_BATCH_CHUNK_SIZE: "2",
    MEDIA_SIGNING_SECRET: "media-secret", MEDIA_BUCKET: bucket() };
  await call(env, batchBody());
  const sent = [];
  const container = async request => {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return Response.json({ status: "healthy" });
    assert.equal(request.headers.get("authorization"), "MultiLLM-Principal principal.token");
    const body = await request.json();
    sent.push(body.items.map(item => item.index));
    return Response.json({ version: 1, results: body.items.map(item => item.index === 3
      ? { index: 3, status: "failed", error: { status: 400, message: "content policy" } }
      : { index: item.index, status: "succeeded", model: "gguu:gpt-image-2", files: [{ id: `${itemFilePrefix(BATCH, item.index)}0`, size: 1 }] }) });
  };
  const hooks = [];
  const fetcher = async (url, init) => { hooks.push({ url, init }); return new Response("ok"); };
  const step = fakeStep();
  await runMediaJob(env, BATCH, step, { container, fetch: fetcher });
  assert.deepEqual(sent, [[0, 1], [2, 3], [4]]);
  const job = await (await call(env, { operation: "get_job", id: BATCH, owner: "alice", kind: "image_batch" })).json();
  assert.equal(job.job.status, "completed");
  assert.equal(job.job.webhook_status, "delivered");
  assert.deepEqual(job.job.counts, { queued: 0, running: 0, succeeded: 4, failed: 1, cancelled: 0 });
  assert.equal(hooks.length, 1);
  const { url, init } = hooks[0];
  assert.equal(url, "https://hooks.example.com/batches");
  assert.equal(init.redirect, "manual");
  const event = JSON.parse(init.body);
  assert.equal(event.type, "image.batch.completed");
  assert.deepEqual(event.data.request_counts, { total: 5, queued: 0, running: 0, succeeded: 4, failed: 1, cancelled: 0 });
  assert.equal(init.headers["webhook-signature"], await webhookSignature("media-secret", "alice", init.headers["webhook-id"],
    Number(init.headers["webhook-timestamp"]), init.body));
  assert.ok(step.names.includes("finalize") && step.names.includes("webhook"));
});

test("an interrupted item is recovered from its stored files or reported, never sent again", async t => {
  const db = await database(t);
  const env = { INTELLIGENCE_DB: db, MEDIA_JOBS: workflows(), MEDIA_BUCKET: bucket() };
  await call(env, batchBody({ webhook_url: null, items: batchBody().items.slice(0, 3) }));
  await db.prepare("UPDATE media_job_items SET status = 'running', attempt = 'old', lease_until = 1 WHERE job_id = ? AND idx < 2")
    .bind(BATCH).run();
  env.MEDIA_BUCKET.objects.set(`media/${itemFilePrefix(BATCH, 0)}0`, { size: 7, httpMetadata: { contentType: "image/png" },
    customMetadata: { model: "gguu:gpt-image-2" } });
  const sent = [];
  const container = async request => {
    if (new URL(request.url).pathname === "/healthz") return new Response("ok");
    const body = await request.json();
    sent.push(...body.items.map(item => item.index));
    return Response.json({ results: body.items.map(item => ({ index: item.index, status: "succeeded", files: [] })) });
  };
  await runMediaJob(env, BATCH, fakeStep(), { container });
  assert.deepEqual(sent, [2]);
  const { results } = await db.prepare("SELECT idx, status, model, files, error FROM media_job_items WHERE job_id = ? ORDER BY idx")
    .bind(BATCH).all();
  assert.equal(results[0].status, "succeeded");
  assert.equal(results[0].model, "gguu:gpt-image-2");
  assert.deepEqual(JSON.parse(results[0].files), [{ id: `${itemFilePrefix(BATCH, 0)}0`, size: 7, content_type: "image/png" }]);
  assert.equal(results[1].status, "failed");
  assert.equal(JSON.parse(results[1].error).code, "outcome_unknown");
});

test("items return to the queue when the Container cannot start, and stop when the owner is gone", async t => {
  const db = await database(t);
  const env = { INTELLIGENCE_DB: db, MEDIA_JOBS: workflows() };
  await call(env, batchBody({ webhook_url: null }));
  let healthy = false;
  const container = async request => {
    if (new URL(request.url).pathname === "/healthz") {
      if (!healthy) { healthy = true; throw new Error("container not ready"); }
      return new Response("ok");
    }
    return Response.json({ error: "principal_rejected" }, { status: 403 });
  };
  const step = fakeStep();
  await runMediaJob(env, BATCH, step, { container });
  assert.deepEqual(step.sleeps.find(([name]) => name === "chunk wait 0"), ["chunk wait 0", "60 seconds"]);
  const { results } = await db.prepare("SELECT status, error FROM media_job_items WHERE job_id = ?").bind(BATCH).all();
  assert.ok(results.every(item => item.status === "failed" && JSON.parse(item.error).code === "principal_rejected"));
  assert.equal((await db.prepare("SELECT status FROM media_jobs WHERE id = ?").bind(BATCH).first()).status, "failed");
});

test("a batch whose steps keep failing ends instead of running forever", async t => {
  const db = await database(t);
  const env = { INTELLIGENCE_DB: db, MEDIA_JOBS: workflows() };
  await call(env, batchBody({ webhook_url: null }));
  const step = fakeStep();
  const original = step.do;
  step.do = async (name, config, callback) => {
    if (name.startsWith("chunk ")) throw new Error("step exhausted its retries");
    return original(name, config, callback);
  };
  await runMediaJob(env, BATCH, step, { container: async () => new Response("ok") });
  const row = await db.prepare("SELECT status FROM media_jobs WHERE id = ?").bind(BATCH).first();
  assert.equal(row.status, "failed");
  const { results } = await db.prepare("SELECT error FROM media_job_items WHERE job_id = ?").bind(BATCH).all();
  assert.ok(results.every(item => JSON.parse(item.error).code === "batch_interrupted"));
});

test("only a bounded number of batches run at once", async t => {
  const db = await database(t);
  const env = { INTELLIGENCE_DB: db, MEDIA_JOBS: workflows(), MEDIA_BATCH_MAX_RUNNING: "1" };
  const other = `imgbatch_${"e".repeat(32)}`;
  await call(env, batchBody({ id: other, owner: "bob", webhook_url: null }));
  await db.prepare("UPDATE media_jobs SET status = 'in_progress', lease_until = ? WHERE id = ?")
    .bind(Math.floor(Date.now() / 1000) + 600, other).run();
  await call(env, batchBody({ webhook_url: null }));
  const step = fakeStep();
  let slots = 0;
  const original = step.do;
  step.do = async (name, config, callback) => {
    if (name.startsWith("slot ") && ++slots === 3) {
      await db.prepare("UPDATE media_jobs SET status = 'completed' WHERE id = ?").bind(other).run();
    }
    return original(name, config, callback);
  };
  await runMediaJob(env, BATCH, step, { container: async request => new URL(request.url).pathname === "/healthz"
    ? new Response("ok") : Response.json({ results: (await request.json()).items.map(item => ({ index: item.index, status: "succeeded", files: [] })) }) });
  assert.deepEqual(step.sleeps.slice(0, 2).map(([name]) => name), ["slot wait 0", "slot wait 1"]);
  assert.equal((await db.prepare("SELECT status FROM media_jobs WHERE id = ?").bind(BATCH).first()).status, "completed");
});

test("a video watch polls until the job ends and posts video.completed", async t => {
  const db = await database(t);
  const env = { INTELLIGENCE_DB: db, MEDIA_JOBS: workflows(), FLASK_SECRET_KEY: "flask-secret" };
  const created = await call(env, { operation: "watch_video", id: WATCH, owner: "alice", principal: "video.principal",
    request_digest: DIGEST, webhook_url: "https://hooks.example.com/video", metadata: { job_id: "video_abc.sig", model: "openai:sora-2" } });
  assert.equal(created.status, 200);
  const states = ["in_progress", "in_progress", "completed"];
  const container = async request => {
    assert.equal(new URL(request.url).pathname, "/internal/media/video-status");
    assert.deepEqual(await request.json(), { watch_id: WATCH, job_id: "video_abc.sig" });
    return Response.json({ status: states.shift(), model: "openai:sora-2" });
  };
  const hooks = [];
  const step = fakeStep();
  await runMediaJob(env, WATCH, step, { container, fetch: async (url, init) => { hooks.push(JSON.parse(init.body)); return new Response("ok"); } });
  assert.deepEqual(step.sleeps.map(([, duration]) => duration), ["15 seconds", "15 seconds"]);
  assert.equal(hooks[0].type, "video.completed");
  assert.deepEqual(hooks[0].data, { id: "video_abc.sig", object: "video", status: "completed", model: "openai:sora-2" });
});

test("webhooks go only to public HTTPS hosts and retry only when the receiver may recover", async () => {
  const job = { id: BATCH, kind: "image_batch", owner: "alice", status: "completed", item_count: 1, counts: {}, metadata: {} };
  const env = { MEDIA_SIGNING_SECRET: "s" };
  let calls = 0;
  const fetcher = status => async () => { calls += 1; return new Response(null, { status }); };
  for (const url of ["http://hooks.example.com/x", "https://10.0.0.1/x", "https://localhost/x", "https://metadata.google.internal/x",
    "https://hooks.example.com:8443/x"]) {
    assert.equal(await deliverWebhook(env, { ...job, webhook_url: url }, fetcher(200)), "rejected", url);
  }
  assert.equal(calls, 0);
  assert.equal(await deliverWebhook(env, { ...job, webhook_url: "https://hooks.example.com/x" }, fetcher(204)), "delivered");
  assert.equal(await deliverWebhook(env, { ...job, webhook_url: "https://hooks.example.com/x" }, fetcher(410)), "rejected");
  await assert.rejects(deliverWebhook(env, { ...job, webhook_url: "https://hooks.example.com/x" }, fetcher(503)));
  await assert.rejects(deliverWebhook(env, { ...job, webhook_url: "https://hooks.example.com/x" }, fetcher(429)));
  assert.equal(await deliverWebhook({}, { ...job, webhook_url: "https://hooks.example.com/x" }, fetcher(200)), "rejected");
});

test("media jobs are reachable only privately, and the Container learns about the binding", async () => {
  const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/media-jobs", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "list_jobs" }) }), {});
  assert.equal(response.status, 503);
  const worker = (await loadWorkerModule()).default;
  let forwarded = 0;
  const env = { MULTILLM_PROXY_CONTAINER: { getByName: () => ({ fetch: async () => { forwarded += 1; return new Response("ok"); } }) } };
  for (const path of ["/internal/media/batch-items", "/%69nternal/media/batch-items", "//internal/media/video-status", "/internal"]) {
    const blocked = await worker.fetch(new Request(`https://gateway.example${path}`, { method: "POST",
      headers: { authorization: "MultiLLM-Principal x" } }), env);
    assert.equal(blocked.status, 404, path);
  }
  assert.equal(forwarded, 0);
  assert.equal(collectContainerEnv({ MEDIA_JOBS: {}, INTELLIGENCE_DB: {} }).MEDIA_JOBS_ENABLED, "true");
  assert.equal(collectContainerEnv({ MEDIA_JOBS: {} }).MEDIA_JOBS_ENABLED, undefined);
});
