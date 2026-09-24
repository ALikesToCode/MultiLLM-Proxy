export class KnowledgeError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export const PROVIDER_IDS = ["context7", "firecrawl", "exa", "mintlify", "deepwiki", "ai_search", "alexandria"];
export const MAX_SNAPSHOT_BYTES = 256 * 1024;
export const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);
export const validId = value => typeof value === "string" && /^[a-zA-Z0-9_-]{1,80}$/.test(value);

export function fail(code, message, status = 400) {
  throw new KnowledgeError(code, message, status);
}

export function fields(value, allowed, required = []) {
  if (!isRecord(value) || Object.keys(value).some(key => !allowed.includes(key))
    || required.some(key => !Object.hasOwn(value, key))) {
    fail("invalid_request", "The request contains missing or unsupported fields.");
  }
}

export function integer(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail("invalid_request", `${name} must be an integer from ${minimum} to ${maximum}.`);
  }
  return value;
}

export function string(value, maximum, name, { optional = false } = {}) {
  if (optional && (value === undefined || value === "")) return "";
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\x00-\x1f\x7f]/.test(value)) {
    fail("invalid_request", `${name} must be a nonempty string of at most ${maximum} characters.`);
  }
  return value.trim();
}

// One rule for policy validation and the provider layer, so an approved host is always fetchable.
const RESERVED_HOST = /(?:^|\.)(?:localhost|local|internal|lan|home|test|invalid|example|onion)$/;

export function publicHost(value) {
  return typeof value === "string" && value.length <= 253
    && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)
    && !RESERVED_HOST.test(value);
}

export function publicUrl(value, allowedHosts) {
  let url;
  try { url = new URL(string(value, 2048, "url")); }
  catch { fail("invalid_source_url", "Use an approved public HTTPS source URL."); }
  if (url.protocol !== "https:" || !publicHost(url.hostname) || url.username || url.password || url.port
    || [...url.searchParams.keys()].some(key => /(?:token|secret|password|credential|signature|api[_-]?key|^key$|^sig$)/i.test(key))
    || (allowedHosts && !allowedHosts.includes(url.hostname))) {
    fail("source_not_allowed", "The source must use HTTPS on an approved public host, without credentials.");
  }
  url.hash = "";
  return url.href;
}

export function parseQuery(body) {
  fields(body, ["query", "product", "version", "repository", "mode", "token_budget", "freshness"], ["query"]);
  const query = string(body.query, 500, "query");
  const product = string(body.product, 100, "product", { optional: true }).toLowerCase();
  const version = string(body.version, 80, "version", { optional: true });
  const repository = string(body.repository, 200, "repository", { optional: true });
  if (version && !product) fail("invalid_request", "A version requires a product.");
  if (repository && !/^[\w.-]+\/[\w.-]+$/.test(repository)) fail("invalid_request", "repository must be owner/name.");
  if (!["economy", "smart", "deep"].includes(body.mode ?? "smart")
    || !["normal", "fresh"].includes(body.freshness ?? "normal")) fail("invalid_request", "Invalid retrieval mode or freshness.");
  return { query, product, version, repository, mode: body.mode ?? "smart",
    token_budget: integer(body.token_budget ?? 6000, 256, 16000, "token_budget"), freshness: body.freshness ?? "normal" };
}

export function parseSource(body, policy) {
  fields(body, ["url", "title", "product", "version", "provider", "refresh_hours", "pinned"], ["url", "product"]);
  const provider = body.provider ?? "firecrawl";
  if (!["firecrawl", "exa"].includes(provider)) fail("invalid_request", "Source acquisition requires Firecrawl or Exa.");
  if (body.pinned !== undefined && typeof body.pinned !== "boolean") fail("invalid_request", "pinned must be a boolean.");
  return { url: publicUrl(body.url, policy.allowed_hosts), product: string(body.product, 100, "product").toLowerCase(),
    title: string(body.title, 200, "title", { optional: true }), version: string(body.version, 80, "version", { optional: true }),
    provider, refresh_hours: integer(body.refresh_hours ?? 24, 1, 720, "refresh_hours"), pinned: body.pinned ?? false,
    retention_hours: policy.retention_hours, enabled: true };
}

export function authorize(principal, scope) {
  fields(principal, ["id", "scopes"], ["id", "scopes"]);
  string(principal.id, 256, "principal id");
  if (!Array.isArray(principal.scopes) || principal.scopes.length > 12
    || principal.scopes.some(item => typeof item !== "string")) fail("invalid_principal", "Invalid principal.", 403);
  if (!principal.scopes.includes("admin") && !principal.scopes.includes(scope)) {
    fail("insufficient_scope", `The key requires ${scope}.`, 403);
  }
}

export async function readJson(request, maxBytes = 64 * 1024) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    fail("unsupported_content_type", "Use application/json.", 415);
  }
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) fail("request_too_large", "Request is too large.", 413);
  if (!request.body) fail("invalid_request", "A JSON object is required.");
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { void reader.cancel().catch(() => {}); fail("request_too_large", "Request is too large.", 413); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const buffer = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer)); }
  catch { fail("invalid_json", "The request must contain valid JSON."); }
}

export function reply(result, status = 200) {
  return Response.json({ version: 1, result }, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

export function errorReply(error) {
  const known = error instanceof KnowledgeError;
  return Response.json({ version: 1, error: {
    code: known ? error.code : "knowledge_unavailable",
    message: known ? error.message : "The Knowledge service could not complete the operation.",
  } }, { status: known ? error.status : 503, headers: { "cache-control": "no-store" } });
}
