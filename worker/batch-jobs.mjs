/** Durable, single-submission batch execution on the owner's managed Container path. */
import { batchFlag, record, reply, failure, ENDPOINTS, newId, ownedFile, inputItems,
  handleFileOperation, pageLimit, listObject, readBatchBody, MAX_RESULT_BYTES,
  MAX_OUTPUT_BYTES, storeFile } from "./batch-files.mjs";
import { boundedBytes } from "./media-outbound.mjs";

const ACTIVE = "('validating','in_progress','cancelling','finalizing')";
const nowSeconds = () => Math.floor(Date.now() / 1000);
const units = value => Number.isSafeInteger(value) && value >= 0;
const row = (db, id) => db.prepare("SELECT * FROM gateway_batches WHERE id=?").bind(id).first();
const owned = (db, body) => db.prepare("SELECT * FROM gateway_batches WHERE id=? AND owner=?").bind(body.id ?? "", body.owner).first();
export const batchesEnabled = env => batchFlag(env, "GATEWAY_BATCHES_ENABLED");
export function shouldForwardBatchSpillover(request, env) {
  return batchesEnabled(env) && batchFlag(env, "BATCH_SPILLOVER_ENABLED") && request.method === "POST"
    && new URL(request.url).pathname === "/v1/chat/completions"
    && request.headers.get("X-MultiLLM-Priority")?.trim().toLowerCase() === "batch"
    && (request.headers.get("Prefer") ?? "").split(",").some(v => v.trim().toLowerCase() === "respond-async");
}

async function schema(env) {
  if (!env.INTELLIGENCE_DB || !env.multillm_media) throw Error("batch_storage_missing");
  for (const table of ["gateway_batch_files", "gateway_batches", "gateway_batch_items"]) {
    await env.INTELLIGENCE_DB.prepare(`SELECT 1 FROM ${table} LIMIT 1`).first();
  }
}

async function batchObject(db, batch) {
  const { results } = await db.prepare("SELECT status,COUNT(*) AS n FROM gateway_batch_items WHERE batch_id=? GROUP BY status").bind(batch.id).all();
  const counts = { total: 0, completed: 0, failed: 0 };
  for (const item of results) {
    counts.total += item.n;
    if (item.status === "completed") counts.completed += item.n;
    if (item.status === "failed") counts.failed += item.n;
  }
  const result = { id: batch.id, object: "batch", endpoint: batch.endpoint,
    errors: null, input_file_id: batch.input_file_id, completion_window: "24h", status: batch.status,
    output_file_id: batch.output_file_id ?? null, error_file_id: batch.error_file_id ?? null,
    created_at: batch.created_at, expires_at: batch.expires_at, request_counts: counts, metadata: JSON.parse(batch.metadata) };
  for (const name of ["in_progress_at", "finalizing_at", "completed_at", "failed_at", "expired_at", "cancelling_at", "cancelled_at"]) result[name] = batch[name] ?? null;
  return result;
}

async function createBatch(body, env, now) {
  const db = env.INTELLIGENCE_DB;
  if (!ENDPOINTS.has(body.endpoint) || body.completion_window !== "24h" || !record(body.metadata)
    || Object.keys(body.metadata).length > 16 || Object.entries(body.metadata).some(([k,v]) => k.length > 64 || typeof v !== "string" || v.length > 512)
    || !units(body.budget_units) || body.budget_units === 0 || body.budget_units > 1e15
    || typeof body.principal !== "string" || body.principal.length > 2048
    || ![body.client_ip, body.key_hash, body.key_prefix].every(v => typeof v === "string" && v.length <= 128)) {
    return failure("invalid_batch", "Send an endpoint, 24h window, metadata budget and valid owner principal.");
  }
  const file = await ownedFile(db, body.owner, body.input_file_id ?? "");
  if (!file || file.purpose !== "batch") return failure("not_found", "Input file not found.", 404);
  const items = await inputItems(env, file);
  if (!Array.isArray(body.estimates) || body.estimates.length !== items.length
    || items.some((v,i) => v.url !== body.endpoint || body.estimates[i]?.custom_id !== v.custom_id
      || !units(body.estimates[i]?.estimate_units) || body.estimates[i].estimate_units > 1e15)) {
    return failure("invalid_batch", "Every item must match the endpoint and have a known bounded price.");
  }
  const id = body.id ?? newId("batch");
  if (!/^batch_[a-f0-9]{32}$/.test(id)) return failure("invalid_batch", "Invalid batch id.");
  const statements = [db.prepare(`INSERT INTO gateway_batches
    (id,owner,input_file_id,endpoint,status,metadata,principal,client_ip,key_hash,key_prefix,budget_units,created_at,expires_at)
    VALUES (?,?,?,?,'validating',?,?,?,?,?,?,?,?)`)
    .bind(id, body.owner, file.id, body.endpoint, JSON.stringify(body.metadata), body.principal,
      body.client_ip, body.key_hash, body.key_prefix, body.budget_units, now, now + 86400)];
  // D1 binds at most 100 values per statement; a single batch is transactional.
  for (let start = 0; start < items.length; start += 16) {
    const page = items.slice(start, start + 16);
    statements.push(db.prepare(`INSERT INTO gateway_batch_items (batch_id,idx,owner,custom_id,estimate_units) VALUES
      ${page.map(() => "(?,?,?,?,?)").join(",")}`)
      .bind(...page.flatMap((v,i) => [id, start + i, body.owner, v.custom_id, body.estimates[start + i].estimate_units])));
  }
  await db.batch(statements);
  return reply({ batch: await batchObject(db, await row(db, id)) });
}

async function cancelBatch(body, env, now) {
  const db = env.INTELLIGENCE_DB, batch = await owned(db, body);
  if (!batch) return failure("not_found", "Batch not found.", 404);
  await db.batch([
    db.prepare(`UPDATE gateway_batches SET status='cancelling',cancelling_at=COALESCE(cancelling_at,?),terminal_status='cancelled'
      WHERE id=? AND status IN ('validating','in_progress')`).bind(now, batch.id),
    db.prepare(`UPDATE gateway_batch_items SET status='failed',error_code='cancelled'
      WHERE batch_id=? AND status='queued' AND EXISTS (SELECT 1 FROM gateway_batches WHERE id=? AND status='cancelling')`).bind(batch.id, batch.id),
  ]);
  return reply({ batch: await batchObject(db, await row(db, batch.id)) });
}

export async function handleBatchRequest(request, env, { now = nowSeconds } = {}) {
  if (new URL(request.url).origin !== "http://intelligence.internal"
    || new URL(request.url).pathname !== "/v1/gateway-batches" || request.method !== "POST" || !batchesEnabled(env)) {
    return failure("not_found", "Not found.", 404);
  }
  try {
    await schema(env);
    const body = await readBatchBody(request);
    if (!body || body.version !== 1 || typeof body.owner !== "string" || !/^[^\x00-\x1f\x7f]{1,256}$/.test(body.owner)) return failure("invalid_request", "Invalid batch operation.");
    if (body.operation?.startsWith("file_")) return await handleFileOperation(body, env, now());
    if (body.operation === "batch_create") return await createBatch(body, env, now());
    if (body.operation === "batch_cancel") return await cancelBatch(body, env, now());
    const db = env.INTELLIGENCE_DB;
    if (body.operation === "item_start") {
      const batch = await owned(db, body);
      if (!batch || !Number.isSafeInteger(body.idx) || typeof body.lease_token !== "string") return failure("not_found", "Claim not found.", 404);
      const updated = await db.prepare(`UPDATE gateway_batch_items SET status='executing'
        WHERE batch_id=? AND idx=? AND status='dispatched' AND lease_token=? AND lease_until>?`)
        .bind(batch.id, body.idx, body.lease_token, now()).run();
      if (!updated.meta?.changes) return failure("claim_rejected", "The item claim was already used or expired.", 409);
      const file = await ownedFile(db, batch.owner, batch.input_file_id);
      const items = await inputItems(env, file);
      const stored = await db.prepare("SELECT estimate_units FROM gateway_batch_items WHERE batch_id=? AND idx=?").bind(batch.id, body.idx).first();
      return reply({ item: { ...items[body.idx], estimate_units: stored.estimate_units },
        batch: { id: batch.id, client_ip: batch.client_ip, key_hash: batch.key_hash, key_prefix: batch.key_prefix } });
    }
    if (body.operation === "batch_list") {
      const limit = pageLimit(body.limit);
      const { results } = await db.prepare("SELECT * FROM gateway_batches WHERE owner=? AND id>? ORDER BY id LIMIT ?")
        .bind(body.owner, body.after ?? "", limit + 1).all();
      return reply(listObject(await Promise.all(results.map(v => batchObject(db, v))), limit));
    }
    if (body.operation === "batch_get") {
      const batch = await owned(db, body);
      return batch ? reply({ batch: await batchObject(db, batch) }) : failure("not_found", "Batch not found.", 404);
    }
    return failure("invalid_operation", "Unknown batch operation.");
  } catch {
    return failure("gateway_batches_unavailable", "Batch storage is unavailable; check the media bucket and apply the gateway batch D1 migration.", 503);
  }
}

async function recover(db, now) {
  await db.batch([
    db.prepare(`UPDATE gateway_batch_items SET status='failed',error_code='outcome_unknown'
      WHERE status IN ('dispatched','executing') AND lease_until<=?`).bind(now),
    db.prepare(`UPDATE gateway_batches SET terminal_status='expired',expired_at=?
      WHERE expires_at<=? AND status IN ('validating','in_progress')`).bind(now, now),
    db.prepare(`UPDATE gateway_batch_items SET status='failed',error_code='expired' WHERE status='queued'
      AND batch_id IN (SELECT id FROM gateway_batches WHERE terminal_status='expired')`),
  ]);
}

async function claim(db, batch, index, token, now) {
  // Claim and hold are one CAS. Concurrent schedules include all other measured/held spend.
  const result = await db.prepare(`UPDATE gateway_batch_items SET status='dispatched',lease_token=?,lease_until=?,held_units=estimate_units
    WHERE batch_id=? AND idx=? AND status='queued' AND EXISTS
    (SELECT 1 FROM gateway_batches b WHERE b.id=? AND b.status IN ('validating','in_progress')
      AND b.terminal_status IS NULL AND b.expires_at>? AND b.budget_units >= gateway_batch_items.estimate_units +
      (SELECT COALESCE(SUM(cost_units+held_units),0) FROM gateway_batch_items WHERE batch_id=b.id)
      AND (b.budget_units > (SELECT COALESCE(SUM(cost_units+held_units),0) FROM gateway_batch_items WHERE batch_id=b.id)))`)
    .bind(token, now + 40, batch.id, index, batch.id, now).run();
  if (!result.meta?.changes) return false;
  await db.prepare(`UPDATE gateway_batches SET status='in_progress',in_progress_at=COALESCE(in_progress_at,?)
    WHERE id=? AND status='validating'`).bind(now, batch.id).run();
  return true;
}

async function exhaustBudget(db, id) {
  await db.prepare(`UPDATE gateway_batch_items SET status='failed',error_code='budget_exhausted'
    WHERE batch_id=? AND status='queued' AND EXISTS (SELECT 1 FROM gateway_batches b WHERE b.id=? AND
    (b.budget_units <= (SELECT COALESCE(SUM(cost_units+held_units),0) FROM gateway_batch_items WHERE batch_id=b.id)
      OR b.budget_units < gateway_batch_items.estimate_units +
      (SELECT COALESCE(SUM(cost_units+held_units),0) FROM gateway_batch_items WHERE batch_id=b.id)))`).bind(id, id).run();
}

export async function containerBatchDispatch(item, batch, container, signal) {
  if (!container) throw Error("batch_container_unavailable");
  const response = await container.fetch(new Request("http://container/internal/gateway/batch-item", {
    method: "POST", headers: { "content-type": "application/json", Authorization: `BatchPrincipal ${batch.principal}` },
    body: JSON.stringify({ batch_id: batch.id, idx: item.idx, lease_token: item.lease_token }), signal,
  }));
  const bytes = await boundedBytes(response, MAX_RESULT_BYTES + 8192);
  if (!response.ok || !bytes) throw Error("batch_dispatch_unknown");
  const outcome = JSON.parse(new TextDecoder().decode(bytes));
  if (!record(outcome) || !Number.isInteger(outcome.status_code) || !record(outcome.body)
    || typeof outcome.ambiguous !== "boolean" || (outcome.cost_units !== null && !units(outcome.cost_units))) throw Error("batch_dispatch_unknown");
  return outcome;
}

async function execute(env, batch, stored, item, dispatch, container, now) {
  let outcome;
  const controller = new AbortController();
  let timer;
  try {
    outcome = await Promise.race([
      dispatch({ ...item, idx: stored.idx, lease_token: stored.lease_token, estimate_units: stored.estimate_units }, batch, container, controller.signal),
      new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(Error("batch_deadline")); }, 30000); }),
    ]);
  } catch { outcome = { status_code: 504, body: {}, ambiguous: true, cost_units: null }; }
  finally { clearTimeout(timer); }
  if (!record(outcome) || !record(outcome.body) || !Number.isInteger(outcome.status_code)
    || (outcome.cost_units !== null && !units(outcome.cost_units))) outcome = { status_code: 502, body: {}, ambiguous: true, cost_units: null };
  const unknown = outcome.ambiguous || outcome.cost_units === null;
  const success = !unknown && outcome.status_code === 200 && !outcome.body.error;
  const code = unknown ? "outcome_unknown" : success ? null : outcome.error_code ?? "request_failed";
  const result = { id: newId("batch_req"), custom_id: item.custom_id,
    response: unknown ? null : { status_code: outcome.status_code, request_id: outcome.request_id ?? null, body: outcome.body },
    error: success ? null : { code, message: unknown ? "The provider outcome is unknown; this item will not be retried." : "The batch item failed." } };
  const content = JSON.stringify(result) + "\n";
  const key = `batches/results/${batch.id}/${stored.idx}/${stored.lease_token}`;
  if (new TextEncoder().encode(content).byteLength > MAX_RESULT_BYTES) {
    // A billed oversized result is not retried; the hold remains if usage was not measured.
    result.response = null; result.error = { code: "result_too_large", message: "Batch result exceeds 1 MiB." };
  }
  await env.multillm_media.put(key, JSON.stringify(result) + "\n");
  await env.INTELLIGENCE_DB.prepare(`UPDATE gateway_batch_items SET status=?,result_key=?,error_code=?,cost_units=?,held_units=?
    WHERE batch_id=? AND idx=? AND status IN ('dispatched','executing') AND lease_token=? AND lease_until>?`)
    .bind(success && !result.error ? "completed" : "failed", key, result.error?.code ?? null,
      unknown ? 0 : outcome.cost_units, unknown ? stored.estimate_units : 0,
      batch.id, stored.idx, stored.lease_token, now()).run();
}

function overflowResult(item) {
  return JSON.stringify({ id: newId("batch_req"), custom_id: item.custom_id, response: null,
    error: { code: "output_file_too_large", message: "Aggregate result content exceeds its size bound." } }) + "\n";
}

async function appendFinalResult(env, batch, item, state) {
  let content;
  if (item.error_code === "output_file_too_large") content = overflowResult(item);
  else if (item.result_key) {
    const object = await env.multillm_media.get(item.result_key);
    if (!object) throw Error("batch_result_missing");
    content = await object.text();
  } else content = JSON.stringify({ id: newId("batch_req"), custom_id: item.custom_id, response: null,
    error: { code: item.error_code, message: "The batch item was not completed." } }) + "\n";
  const side = item.status === "completed" ? "output" : "errors";
  const counter = side === "output" ? "outputBytes" : "errorBytes";
  const size = new TextEncoder().encode(content).byteLength;
  // Reserve room for every remaining item's compact error before large errors.
  const capacity = side === "errors" ? MAX_OUTPUT_BYTES - 1000 * 1024 : MAX_OUTPUT_BYTES;
  if (state[counter] + size > capacity) {
    const compact = overflowResult(item);
    state.errors += compact;
    state.errorBytes += new TextEncoder().encode(compact).byteLength;
    await env.INTELLIGENCE_DB.prepare("UPDATE gateway_batch_items SET status='failed',error_code='output_file_too_large' WHERE batch_id=? AND idx=?")
      .bind(batch.id, item.idx).run();
  } else { state[side] += content; state[counter] += size; }
}

async function finalization(env, batch, now, clock, deadline) {
  const db = env.INTELLIGENCE_DB;
  const active = await db.prepare("SELECT 1 FROM gateway_batch_items WHERE batch_id=? AND status IN ('queued','dispatched','executing') LIMIT 1").bind(batch.id).first();
  if (active || clock() >= deadline) return;
  const token = newId("lease");
  const claimed = await db.prepare(`UPDATE gateway_batches SET status='finalizing',finalizing_at=COALESCE(finalizing_at,?),lease_token=?,lease_until=?
    WHERE id=? AND status IN ${ACTIVE} AND (lease_until IS NULL OR lease_until<=?)`).bind(now(), token, now() + 90, batch.id, now()).run();
  if (!claimed.meta?.changes) return;
  batch = await row(db, batch.id);
  let state = { output: "", errors: "" }, cursor = batch.finalize_cursor;
  if (batch.checkpoint) {
    const object = await env.multillm_media.get(batch.checkpoint);
    if (!object) throw Error("batch_checkpoint_missing");
    state = JSON.parse(await object.text());
  }
  state.outputBytes = new TextEncoder().encode(state.output).byteLength;
  state.errorBytes = new TextEncoder().encode(state.errors).byteLength;
  // Bounded pages and a durable checkpoint allow finalization to continue next cron.
  let done = false;
  for (let page = 0; page < 10 && clock() < deadline; page++) {
    const { results } = await db.prepare("SELECT * FROM gateway_batch_items WHERE batch_id=? AND idx>=? ORDER BY idx LIMIT 100").bind(batch.id, cursor).all();
    if (!results.length) { done = true; break; }
    for (const item of results) {
      if (clock() >= deadline) break;
      await appendFinalResult(env, batch, item, state);
      cursor = item.idx + 1;
    }
  }
  if (!done) {
    const remaining = await db.prepare("SELECT 1 FROM gateway_batch_items WHERE batch_id=? AND idx>=? LIMIT 1").bind(batch.id, cursor).first();
    done = !remaining;
  }
  if (!done) {
    const key = `batches/checkpoints/${batch.id}/${token}`;
    await env.multillm_media.put(key, JSON.stringify(state));
    await db.prepare("UPDATE gateway_batches SET checkpoint=?,finalize_cursor=?,lease_until=NULL WHERE id=? AND lease_token=?").bind(key, cursor, batch.id, token).run();
    return;
  }
  let output = null, errors = null;
  if (state.output) output = await storeFile(env, batch.owner, `${batch.id}-output.jsonl`, state.output, "batch_output", now());
  if (state.errors) errors = await storeFile(env, batch.owner, `${batch.id}-errors.jsonl`, state.errors, "batch_output", now());
  const status = batch.terminal_status ?? "completed";
  await db.prepare(`UPDATE gateway_batches SET status=?,output_file_id=?,error_file_id=?,completed_at=?,
    cancelled_at=CASE WHEN ?='cancelled' THEN ? ELSE NULL END,lease_until=NULL WHERE id=? AND lease_token=?`)
    .bind(status, output?.id ?? null, errors?.id ?? null, now(), status, now(), batch.id, token).run();
}

export async function runScheduledBatches(env, container, { now = nowSeconds, clock = () => performance.now(),
  dispatch = containerBatchDispatch } = {}) {
  if (!batchesEnabled(env)) return { claimed: 0 };
  const deadline = clock() + 65000, db = env.INTELLIGENCE_DB;
  await schema(env);
  await recover(db, now());
  const { results: batches } = await db.prepare(`SELECT * FROM gateway_batches WHERE status IN ${ACTIVE} ORDER BY created_at,id LIMIT 20`).all();
  let claimed = 0;
  for (const batch of batches) {
    if (clock() >= deadline) break;
    if (["validating", "in_progress"].includes(batch.status) && !batch.terminal_status && batch.expires_at > now()) {
      const file = await ownedFile(db, batch.owner, batch.input_file_id);
      const items = file ? await inputItems(env, file) : null;
      if (!items) throw Error("batch_input_missing");
      const { results } = await db.prepare("SELECT * FROM gateway_batch_items WHERE batch_id=? AND status='queued' ORDER BY idx LIMIT 1000").bind(batch.id).all();
      for (const item of results) {
        if (claimed >= 2 || clock() + 30000 > deadline) break;
        const token = newId("lease");
        if (!await claim(db, batch, item.idx, token, now())) continue;
        claimed++;
        await execute(env, batch, { ...item, lease_token: token }, items[item.idx], dispatch, container, now);
      }
      await exhaustBudget(db, batch.id);
    }
    await finalization(env, await row(db, batch.id), now, clock, deadline);
  }
  return { claimed };
}
