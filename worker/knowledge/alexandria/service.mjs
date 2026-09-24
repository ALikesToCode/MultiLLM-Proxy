import { fail, isRecord, KnowledgeError } from "../contracts.mjs";
import { digest } from "../evidence.mjs";
import { jsonPost, requestJSON, ProviderError, invalidResponse } from "../providers/transport.mjs";
import { discoveredTools, FREE_COST, parseRequest, scrapeResult } from "./contracts.mjs";
import { configuredKeys } from "../providers/keys.mjs";

function publicReceipt(receipt) {
  const { principal_id, fingerprint, id, ...result } = receipt;
  return result;
}

function safeError(error) {
  if (error instanceof KnowledgeError || error instanceof ProviderError) {
    return { code: error.code, message: error.message, ...(error.requires_action ? { requires_action: error.requires_action } : {}) };
  }
  return { code: "alexandria_unavailable", message: "Alexandria could not complete the request. No automatic retry was started." };
}

function requireCredentials(env) {
  if (!configuredKeys("alexandria", env).length) fail("provider_not_configured", "Configure FIRECRAWL_API_KEY or its numbered keys on the private Knowledge Worker.", 503);
}

async function priorReceipt(authority, identity) {
  try { return await authority.call("alexandria.receipt", identity); }
  catch (error) {
    if (error?.code === "receipt_missing") return null;
    throw error;
  }
}

function transport(env, options) {
  requireCredentials(env);
  // Callers admit paid requests durably before invoking this fixed transport.
  // Search restricted to Alexandria and find-tools are free catalogue operations.
  return (path, body, requestId = crypto.randomUUID()) => requestJSON("alexandria", path,
    `https://api.firecrawl.dev/v2/${path}`, jsonPost(body, { "x-request-id": requestId }),
    { env, authority: options.authority, fetchImpl: options.fetchImpl ?? fetch, signal: options.signal, invoke: (_provider, _operation, run) => run() });
}

async function discover(authority, identity, payload, send) {
  const response = await send("search", { ...payload, sources: ["alexandria"], toolDetail: "full" });
  if (Number.isSafeInteger(response?.creditsUsed) && response.creditsUsed > 0) return unexpectedCharge(response.creditsUsed);
  const tools = discoveredTools(response);
  return { status: "ok", tools: await authority.call("alexandria.quotes", { ...identity, tools }), cost: FREE_COST };
}

async function inspect(authority, identity, payload, send) {
  const { tool } = await authority.call("alexandria.quote", { ...identity, ...payload });
  const response = await send("scrape", { alexandria: { provider: "firecrawl", capability: "find-tools",
    options: { providers: [tool.provider], capabilities: [tool.capability], level: "tools", expand: ["options", "response", "examples"], limit: 1 } } });
  const { item, credits } = scrapeResult(response, "firecrawl", "find-tools");
  if (credits !== 0) return unexpectedCharge(credits);
  if (item.error || !Array.isArray(item.data?.items)) throw invalidResponse("alexandria");
  return { status: "ok", quote_id: payload.quote_id, tool, details: item.data, cost: FREE_COST };
}

function unexpectedCharge(credits) {
  return { status: "failed", cost: { credits, state: "confirmed" }, error: {
    code: "unexpected_catalogue_charge", message: "Firecrawl reported a charge for a documented free catalogue call. Stop and reconcile this with Firecrawl before continuing.",
  } };
}

async function execute(authority, identity, payload, connect) {
  const fingerprint = await digest(JSON.stringify({ quote_id: payload.quote_id, options: payload.options,
    reserve_credits: payload.reserve_credits, accept_variable_cost: payload.accept_variable_cost ?? false },
  (_key, value) => isRecord(value) ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) : value));
  // A replay returns its durable cost without re-executing or retaining provider data.
  const begun = await authority.call("alexandria.begin", { ...identity, ...payload, fingerprint });
  if (begun.replay) return { ...publicReceipt(begun), replay: true, data_retained: false, call_cost: FREE_COST };
  let receipt, data;
  try {
    const { tool } = begun;
    const send = connect();
    const response = await send("scrape", { alexandria: { provider: tool.provider, capability: tool.capability, options: payload.options }, timeout: 10000 }, identity.receipt_id);
    const result = scrapeResult(response, tool.provider, tool.capability);
    const error = result.item.error ? { code: "capability_failed", message: "The provider reported a capability failure. See the confirmed cost and receipt before making another request." } : null;
    receipt = await authority.call("alexandria.finish", { ...identity, credits: result.credits, status: error ? "failed" : "ok",
      scrape_id: result.scrape_id, error });
    data = result.item.data;
  } catch (error) {
    const rejected = error instanceof ProviderError && error.no_charge === true;
    receipt = await authority.call("alexandria.finish", { ...identity, credits: rejected ? 0 : null,
      status: rejected ? "failed" : "unknown", error: safeError(error) });
  }
  return { ...publicReceipt(receipt), ...(data === undefined ? {} : { data }) };
}

export async function dispatchAlexandria(env, authority, principal, operation, body, options = {}) {
  const payload = parseRequest(operation, body);
  const identity = { principal_id: principal.id };
  if (payload.request_id) identity.receipt_id = `alexandria:${await digest(`${principal.id}\0${payload.request_id}`)}`;
  if (operation === "alexandria.receipt") return { ...publicReceipt(await authority.call("alexandria.receipt", identity)), call_cost: FREE_COST };
  const connect = () => transport(env, { ...options, authority });
  if (operation === "alexandria.execute") {
    // A durable replay needs no provider credentials; a new request is refused before admission.
    if (!configuredKeys("alexandria", env).length && !await priorReceipt(authority, identity)) requireCredentials(env);
    return execute(authority, identity, payload, connect);
  }
  const send = connect();
  try {
    return operation === "alexandria.search" ? await discover(authority, identity, payload, send)
      : await inspect(authority, identity, payload, send);
  } catch (error) { return { status: "failed", cost: FREE_COST, error: safeError(error) }; }
}
