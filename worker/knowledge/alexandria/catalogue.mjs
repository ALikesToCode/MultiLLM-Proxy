import { fail } from "../contracts.mjs";
import { reserve, settle } from "../ledger.mjs";
import { validateOptions } from "./contracts.mjs";

const QUOTE_LIFETIME = 10 * 60 * 1000;

async function quoteFor(tx, input, now) {
  const quote = await tx.get(`alexandria:quote:${input.quote_id}`);
  if (!quote || quote.principal_id !== input.principal_id || quote.expires_at <= now) {
    fail("discovery_required", "Discover this capability again; its quote is missing, expired or belongs to another client.", 409);
  }
  return quote;
}

async function receiptFor(tx, input) {
  const receipt = await tx.get(`alexandria:receipt:${input.receipt_id}`);
  if (receipt && receipt.principal_id !== input.principal_id) fail("receipt_missing", "Receipt not found.", 404);
  return receipt;
}

export async function pruneAlexandria(tx, now) {
  for (const [key, quote] of await tx.list({ prefix: "alexandria:quote:" })) {
    if (quote.expires_at <= now) await tx.delete(key);
  }
  // Receipts are replay fences. Even zero-cost and completed calls retain identity.
}

export async function alexandriaCatalogue(tx, operation, input, policy, now) {
  if (operation === "alexandria.quotes") {
    await pruneAlexandria(tx, now);
    if ((await tx.list({ prefix: "alexandria:quote:" })).size + input.tools.length > 500) {
      fail("catalogue_full", "Wait for earlier discoveries to expire before searching again.", 429);
    }
    const tools = [];
    for (const tool of input.tools) {
      const quote_id = crypto.randomUUID();
      const expires_at = now + QUOTE_LIFETIME;
      await tx.put(`alexandria:quote:${quote_id}`, { quote_id, expires_at, principal_id: input.principal_id, tool });
      tools.push({ ...tool, quote_id, expires_at: new Date(expires_at).toISOString() });
    }
    return tools;
  }
  if (operation === "alexandria.quote") return quoteFor(tx, input, now);
  if (operation === "alexandria.receipt") {
    const receipt = await receiptFor(tx, input);
    if (!receipt) fail("receipt_missing", "Receipt not found. This does not prove an in-flight request was not submitted.", 404);
    return receipt;
  }
  if (operation === "alexandria.begin") {
    const existing = await receiptFor(tx, input);
    if (existing) {
      if (existing.fingerprint !== input.fingerprint) fail("request_conflict", "This request id already identifies different options or a different quote.", 409);
      return { ...existing, replay: true };
    }
    const quote = await quoteFor(tx, input, now);
    validateOptions(quote.tool, input.options);
    if (input.reserve_credits < quote.tool.creditsCost) fail("insufficient_reservation", "Reserve at least the published credit price.");
    if (quote.tool.perRecord && input.accept_variable_cost !== true) fail("variable_cost_acknowledgement", "This capability charges per record. Acknowledge that the final cost can exceed the credit reservation.");
    if ((await tx.list({ prefix: "alexandria:receipt:" })).size >= 5000) fail("ledger_full", "Alexandria receipts need archival before more calls can be admitted.", 503);
    const reservation = await reserve(tx, policy, { provider: "alexandria", operation_id: input.receipt_id,
      credits: input.reserve_credits, background: false }, now);
    const receipt = { id: input.receipt_id, request_id: input.request_id, upstream_request_id: input.receipt_id, principal_id: input.principal_id,
      fingerprint: input.fingerprint, provider: quote.tool.provider, capability: quote.tool.capability,
      published_credits: quote.tool.creditsCost, per_record: quote.tool.perRecord, reserved_credits: reservation.units,
      cost: { credits: null, state: "pending" }, status: "pending", created_at: new Date(now).toISOString() };
    await tx.put(`alexandria:receipt:${input.receipt_id}`, receipt);
    return { ...receipt, tool: quote.tool, replay: false };
  }
  if (operation === "alexandria.finish") {
    const receipt = await receiptFor(tx, input);
    if (!receipt) fail("receipt_missing", "Receipt not found.", 404);
    if (receipt.cost.state !== "pending") return receipt;
    const known = input.credits !== null;
    await settle(tx, { id: receipt.id, outcome: known ? "confirmed" : "unknown", ...(known ? { credits: input.credits } : {}) }, now);
    const updated = { ...receipt, status: input.status, cost: { credits: input.credits, state: known ? "confirmed" : "unknown" },
      reservation_exceeded: known && input.credits > receipt.reserved_credits, scrape_id: input.scrape_id ?? null,
      error: input.error ?? null, updated_at: new Date(now).toISOString() };
    await tx.put(`alexandria:receipt:${input.receipt_id}`, updated);
    return updated;
  }
  fail("unknown_operation", "Unknown Alexandria catalogue operation.", 404);
}
