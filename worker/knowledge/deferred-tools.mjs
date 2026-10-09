/** Permission-first discovery; no provider calls, embeddings or cached authorization. */
import { KnowledgeError, isRecord, fail } from "./contracts.mjs";
import { catalogueDigest, contractDigest, digestsEnabled } from "./contract-drift.mjs";
import { rankToolDefinitions } from "./skills-index.mjs";
import { revisionSyncSettings } from "../config-revision.mjs";

export const MAX_DISCOVERY_BYTES = 64 * 1024;
export const CURSOR_TTL_SECONDS = 120;
const MAX_GRANTS = 4096;
const RPC_ENVELOPE_RESERVE = 4096;
// Workers forbid random values in global scope, so the per-isolate revision is made on first use.
let processRevision;
const currentProcessRevision = () => processRevision ??= crypto.randomUUID();
const encoder = new TextEncoder();
const services = new WeakMap();
let warned = false;

export function deferredEnabled(value, warn = message => console.warn(message)) {
  if (typeof value === "boolean") return value;
  if (value === undefined || value === null) return false;
  if (typeof value === "string") {
    const flag = value.trim().toLowerCase();
    if (["", "0", "false", "off", "no"].includes(flag)) return false;
    if (["1", "true", "on", "yes"].includes(flag)) return true;
  }
  if (!warned) { warn("Invalid DEFERRED_TOOLS_ENABLED; deferred tools disabled"); warned = true; }
  return false;
}

const unavailable = () => new KnowledgeError("tool_grants_unavailable", "The tool grant authority is unavailable. No tool was executed.", 503);
const hex = bytes => [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
const hash = async value => hex(await crypto.subtle.digest("SHA-256", encoder.encode(JSON.stringify(value))));
const base64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

function identity(user) {
  const id = user?.id || user?.username, scopes = user?.scopes ?? [];
  if (typeof id !== "string" || !id || id.length > 128 || id === "*" || !Array.isArray(scopes)
    || scopes.some(scope => typeof scope !== "string")) fail("invalid_principal", "The authenticated identity is unavailable.", 403);
  return { id, scopes: user.is_admin ? ["admin"] : scopes };
}

function parseDiscovery(params) {
  if (!isRecord(params) || Object.keys(params).some(key => !["query", "cursor", "limit"].includes(key))) {
    fail("invalid_request", "Discovery accepts query, cursor and limit only.");
  }
  const { query, cursor } = params, limit = Object.hasOwn(params, "limit") ? params.limit : 16;
  if (typeof query !== "string" || !query.trim() || [...query].length > 500 || !query.isWellFormed()
    || /[\x00-\x1f\x7f]/.test(query) || !Number.isSafeInteger(limit) || limit < 1 || limit > 16
    || cursor !== undefined && cursor !== null && (typeof cursor !== "string" || !cursor || cursor.length > 4096)) {
    fail("invalid_request", "Use a query up to 500 characters, limit 1–16 and a valid cursor.");
  }
  return { query: query.trim().toLowerCase(), limit, cursor };
}

function validatedGrants(rows, id) {
  if (!Array.isArray(rows) || rows.length > MAX_GRANTS) throw unavailable();
  const grants = new Map();
  for (const row of rows) {
    if (!isRecord(row) || !["*", id].includes(row.principal_id) || typeof row.tool_name !== "string"
      || !row.tool_name || row.tool_name.length > 128 || ![0, 1].includes(row.allowed)
      || !Number.isSafeInteger(row.revision) || row.revision < 0 || !Array.isArray(row.scopes) || !row.scopes.length
      || row.scopes.some(scope => typeof scope !== "string" || !scope || scope.length > 80)) throw unavailable();
    const key = JSON.stringify([row.principal_id, row.tool_name]);
    if (grants.has(key)) throw unavailable();
    grants.set(key, { principal_id: row.principal_id, tool_name: row.tool_name, scopes: row.scopes, allowed: row.allowed, revision: row.revision });
  }
  return grants;
}

function permitted(entry, principal, grants) {
  if (!principal.scopes.includes("admin") && !principal.scopes.includes(entry.scope)) return false;
  const name = entry.definition.name;
  const row = grants.get(JSON.stringify([principal.id, name])) ?? grants.get(JSON.stringify(["*", name]));
  return Boolean(row?.allowed && (principal.scopes.includes("admin") || row.scopes.every(scope => principal.scopes.includes(scope))));
}

/** A fixed read-only D1 collaborator, also usable by the private Container dispatcher. */
export async function readGrantSnapshot(env, principalId) {
  try {
    identity({ id: principalId, scopes: [] });
    const db = env.INTELLIGENCE_DB;
    if (!db?.prepare) throw unavailable();
    const statements = [db.prepare("SELECT principal_id, tool_name, scopes_json, allowed, revision FROM tool_grants WHERE principal_id IN ('*', ?) ORDER BY principal_id, tool_name LIMIT 4097").bind(principalId)];
    const revisionEnabled = revisionSyncSettings(env).enabled;
    if (revisionEnabled) statements.push(db.prepare("SELECT COALESCE((SELECT revision FROM control_revisions WHERE domain=?), 0) AS revision").bind("model_grants"));
    const results = db.batch ? await db.batch(statements) : await Promise.all(statements.map(statement => statement.all()));
    if (results.some(result => result.success === false || !Array.isArray(result.results))) throw unavailable();
    const grants = results[0].results.map(row => ({ principal_id: row.principal_id, tool_name: row.tool_name,
      scopes: JSON.parse(row.scopes_json), allowed: row.allowed, revision: row.revision }));
    validatedGrants(grants, principalId);
    const revision = revisionEnabled ? results[1].results[0]?.revision : currentProcessRevision();
    if (revisionEnabled && (!Number.isSafeInteger(revision) || revision < 0)) throw unavailable();
    return { grants, revision };
  } catch { throw unavailable(); }
}

export class DeferredTools {
  constructor(readGrants, { revision = null, clock = () => Date.now() / 1000 } = {}) {
    this.readGrants = readGrants; this.revision = revision; this.clock = clock;
    this.key = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]);
  }

  async snapshot(principal) {
    try {
      const value = await this.readGrants(principal.id);
      const grants = validatedGrants(Array.isArray(value) ? value : value.grants, principal.id);
      const revision = this.revision ? await this.revision() : value.revision ?? currentProcessRevision();
      if (!(typeof revision === "string" && revision || Number.isSafeInteger(revision) && revision >= 0)) throw unavailable();
      const rows = [...grants.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, row]) => row);
      return { grants, revision, stamp: await hash(rows) };
    } catch (error) {
      if (error instanceof KnowledgeError) throw error;
      throw unavailable();
    }
  }

  async listTools(entries, user) {
    const principal = identity(user), { grants } = await this.snapshot(principal);
    return entries.filter(entry => permitted(entry, principal, grants)).map(entry => entry.definition);
  }

  async authorizeCall(entry, user, arguments_, validate) {
    const principal = identity(user), { grants } = await this.snapshot(principal);
    if (!permitted(entry, principal, grants)) fail("tool_not_granted", "The key is not granted permission for this tool.", 403);
    if (typeof validate !== "function") fail("tool_validation_unavailable", "The complete runtime schema validator is unavailable.", 503);
    let valid;
    try { valid = isRecord(arguments_) && await validate(entry.definition.inputSchema, arguments_, entry); }
    catch (error) {
      if (error instanceof KnowledgeError) throw error;
      fail("tool_validation_unavailable", "The complete runtime schema validator is unavailable.", 503);
    }
    if (valid !== true) fail("invalid_arguments", "The arguments do not match the complete runtime tool schema.");
    const latest = await this.snapshot(principal);
    if (!permitted(entry, principal, latest.grants)) fail("tool_not_granted", "The key is not granted permission for this tool.", 403);
  }

  async sign(payload) {
    const encoded = base64(encoder.encode(JSON.stringify(payload)));
    return `${encoded}.${hex(await crypto.subtle.sign("HMAC", await this.key, encoder.encode(encoded)))}`;
  }

  async decode(cursor, binding, count) {
    try {
      const [encoded, signature, extra] = cursor.split(".");
      if (extra !== undefined || !/^[A-Za-z0-9_-]+$/.test(encoded) || !/^[a-f0-9]{64}$/.test(signature ?? "")) throw new Error();
      const bytes = Uint8Array.from(signature.match(/../g), byte => Number.parseInt(byte, 16));
      if (!await crypto.subtle.verify("HMAC", await this.key, bytes, encoder.encode(encoded))) throw new Error();
      const raw = atob(encoded.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - encoded.length % 4) % 4));
      const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(raw, char => char.charCodeAt(0))));
      if (!isRecord(payload) || Object.keys(payload).length !== Object.keys(binding).length + 2
        || Object.entries(binding).some(([key, value]) => payload[key] !== value)
        || !Number.isSafeInteger(payload.o) || payload.o < 1 || payload.o >= count
        || !Number.isFinite(payload.exp) || payload.exp <= this.clock() || payload.exp > this.clock() + CURSOR_TTL_SECONDS) throw new Error();
      return { offset: payload.o, expires: payload.exp };
    } catch { fail("invalid_cursor", "The discovery cursor expired or its permissions or contract changed."); }
  }

  async discover(entries, user, params, { digests = false } = {}) {
    const { query, limit, cursor } = parseDiscovery(params), principal = identity(user);
    const { grants, revision, stamp } = await this.snapshot(principal);
    let tools = entries.filter(entry => permitted(entry, principal, grants)).map(entry => entry.definition);
    let digest;
    try { digest = await catalogueDigest(tools); }
    catch { fail("tool_schema_too_large", "The authorized tool catalogue exceeds contract digest limits.", 413); }
    if (digests) tools = await Promise.all(tools.map(async tool => ({ ...tool, _meta: { ...tool._meta, contract_digest: await contractDigest(tool) } })));
    const ranked = rankToolDefinitions(tools, query);
    const binding = { v: 1, p: await hash(principal), d: digest, r: revision, g: stamp, q: await hash(query), l: limit };
    const { offset, expires } = cursor ? await this.decode(cursor, binding, ranked.length)
      : { offset: 0, expires: this.clock() + CURSOR_TTL_SECONDS };
    let page = { tools: [], _meta: { contract_digest: digest } };
    for (let end = offset + 1; end <= Math.min(ranked.length, offset + limit); end++) {
      const candidate = { tools: ranked.slice(offset, end), _meta: page._meta };
      if (end < ranked.length) candidate.nextCursor = await this.sign({ ...binding, o: end, exp: expires });
      if (encoder.encode(JSON.stringify(candidate)).length + RPC_ENVELOPE_RESERVE > MAX_DISCOVERY_BYTES) {
        if (!page.tools.length) fail("tool_schema_too_large", "A complete tool schema cannot fit in a discovery response.", 413);
        break;
      }
      page = candidate;
    }
    const latest = await this.snapshot(principal);
    if (revision !== latest.revision || stamp !== latest.stamp) fail("tool_grants_changed", "Tool grants changed during discovery. Start discovery again.", 409);
    return page;
  }
}

function runtimeService(env) {
  if (!services.has(env)) services.set(env, new DeferredTools(id => readGrantSnapshot(env, id)));
  return services.get(env);
}

const SCHEMA_KEYWORDS = new Set(["type", "required", "properties", "additionalProperties", "minLength", "maxLength",
  "pattern", "enum", "minimum", "maximum", "items", "minItems", "maxItems", "uniqueItems", "anyOf", "oneOf", "default", "description"]);
const SCHEMA_TYPES = new Set(["object", "array", "string", "number", "integer", "boolean", "null"]);
const validationUnavailable = () => fail("tool_validation_unavailable", "The complete runtime schema validator is unavailable.", 503);

function validationBudget() {
  let work = 0, nodes = 0, characters = 0;
  const spend = (depth = 0) => { if (++work > 65536 || depth > 32) validationUnavailable(); };
  const inspect = (value, depth = 0) => {
    spend(depth);
    if (++nodes > 8192) validationUnavailable();
    if (typeof value === "string") {
      characters += value.length;
      if (characters > 262144 || !value.isWellFormed()) validationUnavailable();
    } else if (typeof value === "number") {
      if (!Number.isFinite(value)) validationUnavailable();
    } else if (Array.isArray(value)) {
      for (const item of value) inspect(item, depth + 1);
    } else if (isRecord(value)) {
      for (const [key, item] of Object.entries(value)) { inspect(key, depth + 1); inspect(item, depth + 1); }
    } else if (value !== null && typeof value !== "boolean") validationUnavailable();
  };
  const canonical = (value, depth = 0) => {
    spend(depth);
    if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(",")}]`;
    if (isRecord(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`).join(",")}}`;
    return JSON.stringify(value);
  };
  return { spend, inspect, canonical, patterns: new Map(), enums: new Map() };
}

function compileRuntimeSchema(node, budget, depth = 0) {
  const { spend, canonical, patterns, enums } = budget;
  spend(depth);
  if (typeof node === "boolean") return;
  if (!isRecord(node) || Object.keys(node).some(key => !SCHEMA_KEYWORDS.has(key))) validationUnavailable();
  for (const [key, value] of Object.entries(node)) {
    spend();
    if (key === "type") {
      const types = Array.isArray(value) ? value : [value];
      if (!types.length || types.some(type => !SCHEMA_TYPES.has(type)) || new Set(types).size !== types.length) validationUnavailable();
    } else if (key === "required") {
      if (!Array.isArray(value) || value.some(name => typeof name !== "string") || new Set(value).size !== value.length) validationUnavailable();
    } else if (key === "properties") {
      if (!isRecord(value)) validationUnavailable();
      for (const child of Object.values(value)) compileRuntimeSchema(child, budget, depth + 1);
    } else if (["items", "additionalProperties"].includes(key)) {
      compileRuntimeSchema(value, budget, depth + 1);
    } else if (["anyOf", "oneOf"].includes(key)) {
      if (!Array.isArray(value) || !value.length) validationUnavailable();
      for (const child of value) compileRuntimeSchema(child, budget, depth + 1);
    } else if (["minLength", "maxLength", "minItems", "maxItems"].includes(key)) {
      if (!Number.isSafeInteger(value) || value < 0) validationUnavailable();
    } else if (["minimum", "maximum"].includes(key)) {
      if (typeof value !== "number" || !Number.isFinite(value)) validationUnavailable();
    } else if (key === "uniqueItems") {
      if (typeof value !== "boolean") validationUnavailable();
    } else if (key === "enum") {
      if (!Array.isArray(value) || !value.length) validationUnavailable();
      const options = new Set(value.map(item => canonical(item)));
      if (options.size !== value.length) validationUnavailable();
      enums.set(node, options);
    } else if (key === "pattern") {
      if (typeof value !== "string" || value.length > 512) validationUnavailable();
      try { patterns.set(node, new RegExp(value, "u")); }
      catch { validationUnavailable(); }
    } else if (key === "description" && typeof value !== "string") validationUnavailable();
  }
}

function matchesType(type, value) {
  if (type === "object") return isRecord(value);
  if (type === "array") return Array.isArray(value);
  if (type === "null") return value === null;
  if (type === "integer") return typeof value === "number" && Number.isInteger(value);
  return typeof value === type;
}

function matchesRuntimeSchema(node, value, budget, depth = 0) {
  const { spend, canonical, patterns, enums } = budget;
  spend(depth);
  if (typeof node === "boolean") return node;
  if (node.type !== undefined && !(Array.isArray(node.type) ? node.type : [node.type]).some(type => matchesType(type, value))) return false;
  if (enums.has(node) && !enums.get(node).has(canonical(value))) return false;
  if (node.anyOf && !node.anyOf.some(child => matchesRuntimeSchema(child, value, budget, depth + 1))) return false;
  if (node.oneOf && node.oneOf.filter(child => matchesRuntimeSchema(child, value, budget, depth + 1)).length !== 1) return false;
  if (typeof value === "string") {
    const length = [...value].length;
    spend();
    if (node.minLength !== undefined && length < node.minLength || node.maxLength !== undefined && length > node.maxLength) return false;
    // Patterns come from the static, reviewed catalogue, never from request arguments.
    if (patterns.has(node) && !patterns.get(node).test(value)) return false;
  } else if (typeof value === "number") {
    if (node.minimum !== undefined && value < node.minimum || node.maximum !== undefined && value > node.maximum) return false;
  } else if (Array.isArray(value)) {
    if (node.minItems !== undefined && value.length < node.minItems || node.maxItems !== undefined && value.length > node.maxItems) return false;
    if (node.uniqueItems) {
      const seen = new Set();
      for (const item of value) { const key = canonical(item); if (seen.has(key)) return false; seen.add(key); }
    }
    if (node.items !== undefined && !value.every(item => matchesRuntimeSchema(node.items, item, budget, depth + 1))) return false;
  } else if (isRecord(value)) {
    if (node.required?.some(name => !Object.hasOwn(value, name))) return false;
    const properties = node.properties ?? {};
    for (const [key, item] of Object.entries(value)) {
      spend();
      if (Object.hasOwn(properties, key)) {
        if (!matchesRuntimeSchema(properties[key], item, budget, depth + 1)) return false;
      } else if (node.additionalProperties !== undefined && !matchesRuntimeSchema(node.additionalProperties, item, budget, depth + 1)) return false;
    }
  }
  return true;
}

/** Validate the static catalogue subset; unsupported schemas and exhausted budgets fail closed. */
export function validateToolArguments(schema, arguments_) {
  const budget = validationBudget();
  budget.inspect(schema); budget.inspect(arguments_);
  compileRuntimeSchema(schema, budget);
  return matchesRuntimeSchema(schema, arguments_, budget);
}

/** Return a JSON-RPC response, or null to continue the existing dispatcher after preflight. */
export async function handleDeferredMcp(body, env, principal, entries, { service = null, validate = validateToolArguments, toolsets = null } = {}) {
  if (!deferredEnabled(env.DEFERRED_TOOLS_ENABLED) || !["tools/list", "tools/call", "multillm.tools.discover"].includes(body.method)) return null;
  const respond = (field, value, status = 200) => Response.json({ jsonrpc: "2.0", id: body.id, [field]: value },
    { status, headers: { "cache-control": "no-store" } });
  try {
    const authority = service ?? runtimeService(env);
    if (body.method === "tools/call") {
      const entry = entries.find(entry => entry.definition.name === body.params?.name);
      if (!entry) return null;
      const arguments_ = Object.hasOwn(body.params ?? {}, "arguments") ? body.params.arguments : {};
      await authority.authorizeCall(entry, principal, arguments_, validate);
      return null;
    }
    const selected = entries.filter(entry => toolsets === null || toolsets.includes(entry.toolset));
    if (body.method === "multillm.tools.discover") return respond("result", await authority.discover(selected, principal, body.params ?? {}, { digests: digestsEnabled(env.MCP_CONTRACT_DIGESTS_ENABLED) }));
    const tools = await authority.listTools(selected, principal);
    const result = digestsEnabled(env.MCP_CONTRACT_DIGESTS_ENABLED)
      ? { tools: await Promise.all(tools.map(async tool => ({ ...tool, _meta: { ...tool._meta, contract_digest: await contractDigest(tool) } }))),
        _meta: { contract_digest: await catalogueDigest(tools) } } : { tools };
    return respond("result", result);
  } catch (error) {
    if (!(error instanceof KnowledgeError)) throw error;
    return respond("error", { code: error.code, message: error.message }, error.status);
  }
}
