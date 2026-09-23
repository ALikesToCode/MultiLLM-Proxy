import { fail, fields, integer, isRecord, string, validId } from "../contracts.mjs";
import { invalidResponse } from "../providers/transport.mjs";

export const OPERATIONS = ["alexandria.search", "alexandria.inspect", "alexandria.execute", "alexandria.receipt"];
export const FREE_COST = Object.freeze({ credits: 0, state: "confirmed" });

export function parseRequest(operation, body) {
  if (operation === "alexandria.search") {
    fields(body, ["query", "limit"], ["query"]);
    return { query: string(body.query, 500, "query"), limit: integer(body.limit ?? 5, 1, 10, "limit") };
  }
  const execute = operation === "alexandria.execute";
  const names = operation === "alexandria.receipt" ? ["request_id"] : execute
    ? ["quote_id", "request_id", "options", "reserve_credits", "accept_variable_cost"] : ["quote_id"];
  fields(body, names, names.filter(name => name !== "accept_variable_cost"));
  for (const name of ["quote_id", "request_id"]) {
    if (names.includes(name) && !validId(body[name])) fail("invalid_request", `Invalid ${name}.`);
  }
  if (execute) {
    if (!isRecord(body.options) || JSON.stringify(body.options).length > 16000) fail("invalid_request", "Provide an options object of at most 16,000 characters.");
    integer(body.reserve_credits, 0, 100000, "reserve_credits");
    if (body.accept_variable_cost !== undefined && typeof body.accept_variable_cost !== "boolean") fail("invalid_request", "accept_variable_cost must be a boolean.");
  }
  return body;
}

export function discoveredTools(response) {
  if (response?.success !== true || !Array.isArray(response.data?.tools) || response.data.tools.length > 100) throw invalidResponse("alexandria");
  return response.data.tools.slice(0, 10).map(tool => {
    if (!isRecord(tool) || !/^[a-zA-Z0-9_-]{1,100}$/.test(tool.provider ?? "")
      || !/^[a-zA-Z0-9_./-]{1,200}$/.test(tool.capability ?? "")
      || !Number.isSafeInteger(tool.creditsCost) || tool.creditsCost < 0
      || typeof tool.perRecord !== "boolean" || !Array.isArray(tool.options)
      || tool.options.some(option => !isRecord(option) || typeof option.name !== "string" || typeof option.type !== "string")
      || typeof tool.name !== "string" || typeof tool.description !== "string"
      || JSON.stringify(tool).length > 32000) throw invalidResponse("alexandria");
    // Keep the provider's input, response and attribution contracts for inspection.
    return { provider: tool.provider, capability: tool.capability, name: tool.name, description: tool.description,
      creditsCost: tool.creditsCost, perRecord: tool.perRecord, options: tool.options,
      ...Object.fromEntries(["requiresOneOf", "response", "whenToUse", "attribution", "examples"]
        .filter(key => Object.hasOwn(tool, key)).map(key => [key, tool[key]])) };
  });
}

export function scrapeResult(response, provider, capability) {
  const data = response?.data;
  if (response?.success !== true || !Number.isSafeInteger(data?.creditsCost) || data.creditsCost < 0
    || !Array.isArray(data.alexandria) || data.alexandria.length !== 1) throw invalidResponse("alexandria");
  const item = data.alexandria[0];
  if (!isRecord(item) || (item.provider !== undefined && item.provider !== provider)
    || (item.capability !== undefined && item.capability !== capability)
    || (!item.error && (item.provider !== provider || item.capability !== capability))
    || (!item.error && (!Object.hasOwn(item, "data") || item.creditsCost !== data.creditsCost))) throw invalidResponse("alexandria");
  return { item, credits: data.creditsCost,
    scrape_id: typeof response.scrape_id === "string" ? response.scrape_id.slice(0, 128) : null };
}

export function validateOptions(tool, options) {
  const allowed = new Set(tool.options.map(option => option.name));
  if (Object.keys(options).some(key => !allowed.has(key))) fail("invalid_options", "Use only option names returned by discovery.");
  for (const option of tool.options) {
    if (option.required && !Object.hasOwn(options, option.name)) fail("invalid_options", `Missing required option: ${option.name}.`);
  }
}
