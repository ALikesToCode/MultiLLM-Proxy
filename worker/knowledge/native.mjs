/**
 * Each provider's own capabilities (Context7, Exa, Firecrawl, DeepWiki, Mintlify) behind
 * the gateway's key pool, allowances and host policy. Results are returned as the
 * provider sent them: untrusted data, not retained and not verified evidence.
 */
import TOOLS from "./native-tools.json" with { type: "json" };
import { fail, hostAllowed, isRecord, publicHost } from "./contracts.mjs";
import { metered } from "./operations.mjs";
import { callTool } from "./providers/mcp.mjs";
import { jsonPost, ProviderError, requestJSON } from "./providers/transport.mjs";
import { providerStatus } from "./providers/index.mjs";

export const NATIVE_TOOLS = TOOLS;
export const NATIVE_OPERATIONS = Object.keys(TOOLS).map(name => `native.${name}`);

// Sorted-key JSON, byte-identical to Python's json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False), so the edge catalogue and this Worker agree on the contract they serve.
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : isRecord(value) ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
  : JSON.stringify(value);

export async function nativeToolsHash(tools = TOOLS) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(tools)));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
}
const NATIVE_TIMEOUT_MS = 45000;
const NATIVE_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_ARGUMENT_BYTES = 64 * 1024;

const typeOf = value => value === null ? "null" : Array.isArray(value) ? "array"
  : Number.isInteger(value) ? "integer" : typeof value;

function matchesType(value, type) {
  const actual = typeOf(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  return actual === type;
}

function invalid(tool, path) {
  fail("invalid_request", `Invalid ${tool} argument${path ? ` ${path}` : ""}.`);
}

function check(tool, schema, value, path) {
  if (schema.anyOf) {
    if (!schema.anyOf.some(option => { try { check(tool, option, value, path); return true; } catch { return false; } })) invalid(tool, path);
    return;
  }
  const types = schema.type === undefined ? null : [].concat(schema.type);
  if (types && !types.some(type => matchesType(value, type))) invalid(tool, path);
  if (schema.enum && !schema.enum.includes(value)) invalid(tool, path);
  if (typeof value === "string") {
    if ((schema.minLength !== undefined && value.length < schema.minLength) || (schema.maxLength !== undefined && value.length > schema.maxLength)
      || value.includes("\u0000") || (schema.pattern && !new RegExp(schema.pattern).test(value))) invalid(tool, path);
  }
  if (typeof value === "number" && ((schema.minimum !== undefined && value < schema.minimum) || (schema.maximum !== undefined && value > schema.maximum))) {
    invalid(tool, path);
  }
  if (Array.isArray(value)) {
    if ((schema.minItems !== undefined && value.length < schema.minItems) || (schema.maxItems !== undefined && value.length > schema.maxItems)) invalid(tool, path);
    if (schema.items) value.forEach((item, index) => check(tool, schema.items, item, `${path}[${index}]`));
  }
  if (isRecord(value) && schema.properties) {
    for (const name of schema.required ?? []) if (!Object.hasOwn(value, name)) invalid(tool, name);
    for (const [name, item] of Object.entries(value)) {
      const property = schema.properties[name];
      if (!property) { if (schema.additionalProperties === false) invalid(tool, name); continue; }
      check(tool, property, item, path ? `${path}.${name}` : name);
    }
  }
}

// URLs the provider will fetch follow the same host policy as retrieval; "*" admits
// any public host. Globs (Firecrawl extract) are checked by their host.
function checkTarget(tool, value, allowedHosts) {
  let url;
  try { url = new URL(value); } catch { invalid(tool, "url"); }
  if (!["https:", "http:"].includes(url.protocol) || url.username || url.password || !publicHost(url.hostname)) {
    fail("source_not_allowed", "Provider tools accept only public http(s) URLs without credentials.");
  }
  if (!hostAllowed(url.hostname, allowedHosts)) fail("source_not_allowed", `The Knowledge host policy does not allow ${url.hostname}.`);
}

/*
 * Allowance units follow provider billing, so one call cannot fetch unbounded pages for a
 * single unit. One unit is one basic request; pages are charged per started block of ten
 * per content type (Exa), or per page at Firecrawl's credit weights, where LLM formats
 * and enhanced proxies cost up to five credits. These are estimates that bound work, not
 * invoices, and units_per_call scales every count.
 */
const blocks = count => Math.ceil(count / 10);
const DEEP_SEARCH = { "deep-lite": 2, deep: 3, "deep-reasoning": 5 };
const LLM_FORMATS = new Set(["json", "summary", "changeTracking"]);
const ENHANCED_PROXIES = new Set(["enhanced", "stealth"]);
// Extraction runs an LLM over every page; a glob can expand to many pages.
const EXTRACT_PAGE = 5;
const EXTRACT_GLOB_PAGES = 25;
const isGlob = url => url.includes("*");
const contentKinds = options => ["text", "highlights", "summary"].filter(kind => options?.[kind]).length;

function scrapeCost(options = {}) {
  const formats = Array.isArray(options.formats) ? options.formats : [];
  const llm = formats.some(format => LLM_FORMATS.has(typeof format === "string" ? format : format?.type));
  return 1 + (llm ? 4 : 0) + (ENHANCED_PROXIES.has(options.proxy) ? 4 : 0);
}

const WORK = {
  exa_search: p => {
    const results = p.numResults ?? 10;
    return (DEEP_SEARCH[p.type] ?? 1) + blocks(Math.max(0, results - 10))
      + contentKinds(p.contents) * blocks(results * (1 + (p.contents?.subpages ?? 0)));
  },
  // Exa returns text when no content type is named.
  exa_contents: p => Math.max(1, contentKinds(p)) * blocks(p.urls.length * (1 + (p.subpages ?? 0))),
  exa_answer: p => 1 + (p.text ? 1 : 0),
  firecrawl_scrape: p => scrapeCost(p),
  firecrawl_search: p => 2 * blocks(p.limit ?? 5) + (p.scrapeOptions ? (p.limit ?? 5) * scrapeCost(p.scrapeOptions) : 0),
  firecrawl_crawl: p => (p.limit ?? 10) * scrapeCost(p.scrapeOptions),
  firecrawl_extract: p => EXTRACT_PAGE * p.urls.reduce((pages, url) => pages + (isGlob(url) ? EXTRACT_GLOB_PAGES : 1), 0)
    + (p.enableWebSearch ? EXTRACT_PAGE * EXTRACT_GLOB_PAGES : 0),
};

export function nativeUnits(tool, payload, allocation) {
  if (TOOLS[tool].units.free) return 0;
  return Math.min(100000, allocation.units_per_call * (WORK[tool]?.(payload) ?? 1));
}

const canManage = principal => principal.scopes.includes("admin") || principal.scopes.includes("knowledge:manage");

// Read keys are agent keys: they read untrusted provider text, so they cannot steer the
// gateway's Firecrawl browser with their own headers, scripts, TLS or proxy settings,
// reach hosts beyond the request, or make one call fetch unbounded pages.
const SCRAPE_CONTROLS = ["headers", "actions", "skipTlsVerification"];
const READ_LIMITS = {
  exa_search: p => [["numResults", p.numResults, 25], ["contents.subpages", p.contents?.subpages, 5]],
  exa_contents: p => [["urls", p.urls.length, 25], ["subpages", p.subpages, 5]],
  firecrawl_search: p => [["limit", p.limit, 25]],
  firecrawl_crawl: p => [["limit", p.limit ?? 10, 100]],
};

function managedOptions(tool, payload) {
  const scrape = tool === "firecrawl_scrape" ? payload : payload.scrapeOptions;
  const used = [];
  if (tool.startsWith("firecrawl_") && scrape && typeof scrape === "object") {
    const prefix = scrape === payload ? "" : "scrapeOptions.";
    used.push(...SCRAPE_CONTROLS.filter(name => scrape[name] !== undefined && scrape[name] !== false).map(name => prefix + name));
    if (ENHANCED_PROXIES.has(scrape.proxy)) used.push(`${prefix}proxy`);
  }
  if (["firecrawl_crawl", "firecrawl_extract"].includes(tool) && payload.allowExternalLinks) used.push("allowExternalLinks");
  if (tool === "firecrawl_extract") {
    if (payload.enableWebSearch) used.push("enableWebSearch");
    if (payload.urls.some(isGlob)) used.push("urls (glob)");
  }
  return used;
}

function authorizeArguments(tool, payload, principal) {
  if (canManage(principal)) return;
  const [option] = managedOptions(tool, payload);
  if (option) fail("insufficient_scope", `The ${tool} option ${option} requires knowledge:manage.`, 403);
  for (const [name, value, limit] of READ_LIMITS[tool]?.(payload) ?? []) {
    if (value !== undefined && value > limit) fail("insufficient_scope", `The ${tool} ${name} above ${limit} requires knowledge:manage.`, 403);
  }
}

const get = (base, parameters) => {
  const url = new URL(base);
  for (const [name, value] of Object.entries(parameters)) if (value !== undefined) url.searchParams.set(name, String(value));
  return [url.href, { method: "GET", headers: {} }];
};

// Provider request for each tool; arguments were validated against the shared contract.
const REQUESTS = {
  context7_resolve_library: p => get("https://context7.com/api/v2/libs/search", p),
  context7_docs: p => get("https://context7.com/api/v2/context", { type: "json", ...p }),
  exa_search: p => ["https://api.exa.ai/search", jsonPost(p)],
  exa_contents: p => ["https://api.exa.ai/contents", jsonPost(p)],
  exa_code_context: p => ["https://api.exa.ai/context", jsonPost({ tokensNum: "dynamic", ...p })],
  exa_answer: p => ["https://api.exa.ai/answer", jsonPost({ ...p, stream: false })],
  firecrawl_scrape: p => ["https://api.firecrawl.dev/v2/scrape", jsonPost(p)],
  firecrawl_search: p => ["https://api.firecrawl.dev/v2/search", jsonPost(p)],
  firecrawl_map: p => ["https://api.firecrawl.dev/v2/map", jsonPost(p)],
  firecrawl_crawl: p => ["https://api.firecrawl.dev/v2/crawl", jsonPost({ limit: 10, ...p })],
  firecrawl_crawl_status: p => get(`https://api.firecrawl.dev/v2/crawl/${p.id}`, { skip: p.skip }),
  firecrawl_extract: p => ["https://api.firecrawl.dev/v2/extract", jsonPost(p)],
  firecrawl_extract_status: p => get(`https://api.firecrawl.dev/v2/extract/${p.id}`, {}),
};

const MCP_TOOLS = {
  deepwiki_structure: ["https://mcp.deepwiki.com/mcp", "read_wiki_structure"],
  deepwiki_contents: ["https://mcp.deepwiki.com/mcp", "read_wiki_contents"],
  deepwiki_ask: ["https://mcp.deepwiki.com/mcp", "ask_wiki_question"],
  mintlify_context: ["https://index.mintlify.com/mcp", "context"],
};

export async function dispatchNative(env, authority, principal, operation, payload, options = {}) {
  const tool = operation.slice("native.".length);
  const spec = TOOLS[tool];
  if (!spec) fail("unknown_operation", "Unknown Knowledge operation.", 404);
  if (!isRecord(payload) || JSON.stringify(payload).length > MAX_ARGUMENT_BYTES) invalid(tool, "");
  check(tool, spec.input, payload, "");
  authorizeArguments(tool, payload, principal);
  const snapshot = await authority.call("catalogue.state");
  const allocation = snapshot.policy.providers[spec.provider];
  if (!snapshot.policy.enabled || !allocation?.enabled) {
    fail("provider_disabled", `Enable Knowledge and the ${spec.provider} allowance before using its tools.`, 503);
  }
  if (!providerStatus(env).some(item => item.id === spec.provider && item.configured)) {
    fail("provider_not_configured", `The ${spec.provider} credential is not configured.`, 503);
  }
  for (const field of spec.url_fields ?? []) {
    for (const value of [].concat(payload[field])) checkTarget(tool, value, snapshot.policy.allowed_hosts);
  }
  const reserved = nativeUnits(tool, payload, allocation);
  const requestId = crypto.randomUUID();
  const context = {
    env, authority, signal: options.signal, fetchImpl: options.fetchImpl, timeoutMs: NATIVE_TIMEOUT_MS,
    maxResponseBytes: NATIVE_RESPONSE_BYTES, acceptText: true,
    invoke: (provider, suffix, callback) => reserved === 0 ? callback()
      : metered(authority, { provider, operation_id: `native:${requestId}:${suffix}`, background: false, units: reserved }, callback),
  };
  let result;
  try {
    if (MCP_TOOLS[tool]) {
      const [endpoint, name] = MCP_TOOLS[tool];
      result = { text: await callTool(spec.provider, endpoint, name, payload, context, tool) };
    } else {
      const [url, request] = REQUESTS[tool](payload);
      result = await requestJSON(spec.provider, tool, url, request, context);
    }
  } catch (error) {
    // Report the provider's own failure (timeout, rate limit, exhausted keys) so the
    // caller can decide whether to retry; its message never contains upstream text.
    if (error instanceof ProviderError) fail(error.code, error.message, error.status >= 400 && error.status < 600 ? error.status : 502);
    throw error;
  }
  return { provider: spec.provider, tool, result, usage: { provider: spec.provider, units: reserved },
    verification: "provider_generated_unverified" };
}
