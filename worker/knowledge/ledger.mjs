import { fail, integer, PROVIDER_IDS, string } from "./contracts.mjs";

const DAY = 86400000;
// Rows that still count toward an allowance, plus unresolved credit charges. Rows outside
// the window are pruned first, so only a day of real traffic can fill the ledger.
export const LEDGER_LIMIT = 5000;
// Alexandria spends real credits: its pending and unknown charges count until a receipt
// resolves them. The other providers are metered in allowance units, a daily budget in
// which a pending or unknown charge is assumed spent when it was reserved.
const STRICT_PROVIDERS = new Set(["alexandria"]);

export function countsToward(row, now) {
  if (STRICT_PROVIDERS.has(row.provider) && row.state !== "confirmed") return true;
  return row.created_at >= now - DAY;
}

export function usageFor(records, provider, now = Date.now()) {
  const usage = { provider, confirmed: 0, pending: 0, unknown: 0, background: 0, total: 0 };
  for (const row of records) {
    if (row.provider !== provider || !countsToward(row, now)) continue;
    usage[row.state] += row.units;
    usage.total += row.units;
    if (row.background) usage.background += row.units;
  }
  return usage;
}

export function ledgerStats(records, now = Date.now()) {
  const stats = { rows: records.length, limit: LEDGER_LIMIT, counting: 0, pending: 0, unknown: 0 };
  for (const row of records) {
    if (countsToward(row, now)) stats.counting += 1;
    if (row.state === "pending" || row.state === "unknown") stats[row.state] += 1;
  }
  return stats;
}

export async function reserve(tx, policy, input, now) {
  const id = string(input.operation_id, 240, "operation_id");
  if (!/^[\w:.-]+$/.test(id) || !PROVIDER_IDS.includes(input.provider) || typeof input.background !== "boolean") {
    fail("invalid_reservation", "Invalid operation reservation.");
  }
  const key = `reservation:${id}`;
  const existing = await tx.get(key);
  if (existing) {
    if (existing.provider !== input.provider || existing.background !== input.background || existing.job_id !== (input.job_id ?? null)) {
      fail("reservation_conflict", "The operation identifier already names different work.", 409);
    }
    return { ...existing, replay: true };
  }
  const allocation = policy.providers[input.provider];
  if (!policy.enabled || !allocation.enabled || !allocation.hard_limit_confirmed || !allocation.retention_allowed) {
    fail("provider_disabled", "The provider is disabled or its billing and retention controls have not been confirmed.", 503);
  }
  let job;
  if (input.job_id) {
    job = await tx.get(`job:${input.job_id}`);
    const source = job && await tx.get(`source:${job.source_id}`);
    if (!job || !source?.enabled || source.fence !== job.fence || ["cancelled", "completed", "failed"].includes(job.status)) {
      fail("job_inactive", "This job no longer accepts new operations.", 409);
    }
  }
  if (input.revision_id !== undefined) {
    const artifact = /^[a-f0-9]{64}$/.test(input.revision_id) && await tx.get(`artifact:${input.revision_id}`);
    if (input.provider !== "ai_search" || !input.background || !job || !artifact
      || artifact.source_id !== job.source_id || artifact.status === "expiring") {
      fail("invalid_reservation", "Index submissions require an active job and retained revision.");
    }
    const claim = await tx.get(`submission:${input.revision_id}`);
    if (claim) return { ...claim, replay: true };
  }
  let records = [...(await tx.list({ prefix: "reservation:" })).values()];
  // Hourly maintenance normally keeps the ledger small; a burst between runs prunes here.
  if (records.length >= LEDGER_LIMIT) records = await pruneSettled(tx, now);
  if (records.length >= LEDGER_LIMIT) fail("ledger_full", "A day of reservations fills the ledger. Wait for older operations to leave the daily window.", 503);
  const used = usageFor(records, input.provider, now);
  // Native provider calls reserve their own bound (for example a crawl's page limit).
  const units = input.provider === "alexandria" ? integer(input.credits, 0, 100000, "reserved credits")
    : input.units === undefined ? allocation.units_per_call : integer(input.units, 1, 100000, "reserved units");
  if (used.total + units > allocation.limit || (input.background && (
    used.background + units > allocation.background_limit || used.total + units > allocation.limit - allocation.interactive_reserve))) {
    fail("allowance_exhausted", "This operation exceeds the configured provider or background allowance.", 429);
  }
  const receipt = { id, provider: input.provider, units, background: input.background,
    job_id: input.job_id ?? null, state: "pending", created_at: now, updated_at: now };
  await tx.put(key, receipt);
  // Revision claims survive ledger pruning and job cancellation: an acknowledged or
  // ambiguous upload must be reconciled, never submitted again under a new job ID.
  if (input.revision_id) await tx.put(`submission:${input.revision_id}`, receipt);
  return { ...receipt, replay: false };
}

export async function settle(tx, input, now) {
  const id = string(input.id, 240, "reservation id");
  if (!["confirmed", "unknown"].includes(input.outcome)) fail("invalid_settlement", "Invalid reservation outcome.");
  const key = `reservation:${id}`;
  const receipt = await tx.get(key);
  if (!receipt) fail("reservation_missing", "The operation reservation was not found.", 404);
  if (receipt.state !== "pending") return receipt;
  const units = input.outcome === "confirmed" && input.unused === true ? 0
    : receipt.provider === "alexandria" && input.outcome === "confirmed"
    ? integer(input.credits, 0, Number.MAX_SAFE_INTEGER, "charged credits") : receipt.units;
  const updated = { ...receipt, units, state: input.outcome, updated_at: now };
  await tx.put(key, updated);
  return updated;
}

/**
 * Remove rows that no longer count toward any allowance and returns the rest. Operation
 * identifiers are single-use request or job IDs, and index uploads keep their own
 * revision claims, so a pruned row cannot authorize a replay.
 */
export async function pruneSettled(tx, now) {
  const kept = [];
  for (const [key, receipt] of await tx.list({ prefix: "reservation:" })) {
    if (countsToward(receipt, now)) kept.push(receipt);
    else await tx.delete(key);
  }
  return kept;
}
