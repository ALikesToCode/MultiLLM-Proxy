/**
 * Knowledge MCP and REST at the edge for credentials the Worker can verify itself:
 * the bootstrap ADMIN_API_KEY, durable D1 integration keys and, when accounts live in
 * D1, dashboard keys. Those requests go straight to the private Knowledge service, so
 * agents never wait for the Container to wake. Any other credential is left to the
 * Container before the body is read.
 */
import { Buffer } from "node:buffer";
import { createHash, scrypt, timingSafeEqual } from "node:crypto";
import catalogue from "./knowledge-mcp-catalogue.json" with { type: "json" };
import { authStorageBackend } from "./container-env.mjs";
import { activeUsersByPrefix, adminUsernames, grantsAdmin, validUser } from "./control-users-d1.mjs";
import { INTEGRATION_SCOPES, lookupIntegrationPrincipal } from "./intelligence-auth-d1.mjs";
import { logFailure } from "./log.mjs";

const KNOWLEDGE_SCOPES = ["knowledge:read", "knowledge:manage"];
const KEY_NAMESPACE = "mllm_intelligence_";
const KEY_PATTERN = /^mllm_intelligence_[A-Za-z0-9_-]{32,128}$/;
const ID_PATTERN = /^integration:[a-z][a-z0-9_-]{0,63}$/;
const HASH_PATTERN = /^scrypt:32768:8:1\$([A-Za-z0-9]{8,32})\$([a-f0-9]{128})$/;
const PRINCIPAL_FIELDS = ["createdAt", "credentialVersion", "id", "keyHash", "keyPrefix", "revokedAt", "scopes"];
const IDENTIFIER = /^[A-Za-z0-9_-]{1,80}$/;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,79}$/;
const MAX_REQUEST_BYTES = 65536;
// Provider tools may wait up to 45 s upstream (for example a DeepWiki answer).
const DEADLINE_MS = 55000;
const MAX_VERIFIED = 256;
const MAX_KEY_LENGTH = 1024;
const TOOLS = new Map(catalogue.tools.map(entry => [entry.definition.name, entry]));
const NATIVE_OPERATIONS = new Set(catalogue.tools.map(entry => entry.operation).filter(operation => operation.startsWith("native.")));
const ALEXANDRIA_OPERATIONS = ["search", "inspect", "execute", "receipt"];
// Werkzeug scrypt:32768:8:1 needs 32 MiB, above Node's default ceiling.
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
// Only the expensive hash check is memoized; each request still reads the current
// D1 row, so rotation and revocation take effect immediately.
const verifiedHashes = new Map();
// Each check holds 32 MiB in an isolate that also serves chat. Bound concurrent checks,
// and after repeated wrong keys for one prefix stop deriving for a minute; a key this
// isolate already verified still passes, so a guessed prefix cannot lock out its owner.
const SCRYPT_SLOTS = 2;
const SCRYPT_QUEUE = 16;
const FAILURE_WINDOW_MS = 60000;
const FAILURES_PER_PREFIX = 5;
const MAX_TRACKED_PREFIXES = 1024;
const prefixFailures = new Map();
const scryptWaiters = [];
let scryptActive = 0;

class KnowledgeEdgeError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const unavailable = () => new KnowledgeEdgeError("knowledge_unavailable",
  "The Knowledge service is unavailable. No automatic retry was started.", 503);
const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);
const noStore = { "cache-control": "no-store" };
const json = (value, status = 200, headers = {}) => Response.json(value, { status, headers: { ...noStore, ...headers } });
const restError = (code, message, status) => json({ error: { code, message } }, status);
const rpcError = (id, code, message, status = 200, headers = {}) => json({ jsonrpc: "2.0", id, error: { code, message } }, status, headers);
const rpcResult = (id, result) => json({ jsonrpc: "2.0", id, result });

export function isKnowledgeEdgePath(pathname) {
  return pathname === "/mcp" || pathname.startsWith("/v1/knowledge/");
}

function requestKey(headers) {
  const direct = headers.get("x-multillm-api-key")?.trim();
  if (direct) return direct;
  const value = headers.get("authorization") ?? "";
  const separator = value.indexOf(" ");
  if (separator < 0 || value.slice(0, separator).toLowerCase() !== "bearer") return null;
  return value.slice(separator + 1).trim() || null;
}

function sameSecret(provided, expected) {
  const digest = value => createHash("sha256").update(String(value)).digest();
  return Boolean(provided && expected) && timingSafeEqual(digest(provided), digest(expected));
}

function adminUsername(env) {
  const name = (env.ADMIN_USERNAME ?? "admin").trim();
  return name && name.length <= 128 && !/[\x00-\x1f\x7f]/.test(name) ? name : null;
}

function validRecord(record, prefix) {
  const scopes = record?.scopes;
  return isRecord(record) && Object.keys(record).sort().join() === PRINCIPAL_FIELDS.join()
    && typeof record.id === "string" && ID_PATTERN.test(record.id)
    && Array.isArray(scopes) && scopes.length > 0 && scopes.length <= INTEGRATION_SCOPES.length
    && scopes.every(scope => INTEGRATION_SCOPES.includes(scope)) && new Set(scopes).size === scopes.length
    && Number.isSafeInteger(record.credentialVersion) && record.credentialVersion >= 1
    && record.keyPrefix === prefix && typeof record.keyHash === "string" && HASH_PATTERN.test(record.keyHash)
    && typeof record.createdAt === "string" && (record.revokedAt === null || typeof record.revokedAt === "string");
}

async function withScryptSlot(callback) {
  if (scryptActive < SCRYPT_SLOTS) scryptActive += 1;
  else if (scryptWaiters.length >= SCRYPT_QUEUE) {
    throw new KnowledgeEdgeError("knowledge_busy", "Too many keys are being verified. Retry shortly.", 503);
  } else await new Promise(resolve => scryptWaiters.push(resolve));
  try { return await callback(); }
  finally {
    // A waiting check inherits this slot; otherwise it is released.
    const next = scryptWaiters.shift();
    if (next) next(); else scryptActive -= 1;
  }
}

function prefixThrottled(prefix, now = Date.now()) {
  const record = prefixFailures.get(prefix);
  return Boolean(record && record.until > now && record.count >= FAILURES_PER_PREFIX);
}

function recordPrefixFailure(prefix, now = Date.now()) {
  const previous = prefixFailures.get(prefix);
  const record = previous && previous.until > now ? previous : { count: 0, until: now + FAILURE_WINDOW_MS };
  record.count += 1;
  prefixFailures.delete(prefix);
  prefixFailures.set(prefix, record);
  if (prefixFailures.size > MAX_TRACKED_PREFIXES) prefixFailures.delete(prefixFailures.keys().next().value);
}

/** Index of the stored hash the key matches, or -1 after recording a failure for the prefix. */
async function matchingHash(key, keyHashes, prefix) {
  const digest = createHash("sha256").update(key).digest("hex");
  const known = keyHashes.findIndex(keyHash => verifiedHashes.has(`${keyHash}\n${digest}`));
  if (known >= 0) return known;
  if (prefixThrottled(prefix)) {
    throw new KnowledgeEdgeError("key_throttled", "Too many invalid keys were presented for this key prefix. Retry in a minute.", 429);
  }
  for (const [index, keyHash] of keyHashes.entries()) {
    const [, salt, expected] = HASH_PATTERN.exec(keyHash);
    const derived = await withScryptSlot(() => new Promise((resolve, reject) => {
      scrypt(key, salt, 64, SCRYPT, (error, value) => (error ? reject(error) : resolve(value)));
    }));
    if (!timingSafeEqual(derived, Buffer.from(expected, "hex"))) continue;
    if (verifiedHashes.size >= MAX_VERIFIED) verifiedHashes.delete(verifiedHashes.keys().next().value);
    verifiedHashes.set(`${keyHash}\n${digest}`, true);
    return index;
  }
  recordPrefixFailure(prefix);
  return -1;
}

// Mirrors the Container: administrators hold both Knowledge scopes. Only usernames the
// Worker configures can be administrators, whatever a stored row claims.
function accountScopes(user, env) {
  if (grantsAdmin(user) && adminUsernames(env).has(user.username)) return [...KNOWLEDGE_SCOPES];
  return user.scopes.split(",").map(scope => scope.trim()).filter(scope => KNOWLEDGE_SCOPES.includes(scope));
}

// Dashboard accounts in D1 use the Container's key prefix and Werkzeug hashes.
async function accountPrincipal(env, key) {
  if (key.length > MAX_KEY_LENGTH) return { denied: true };
  const prefix = `mllm_${key.slice(0, 8)}`;
  let users;
  try { users = await activeUsersByPrefix(env.INTELLIGENCE_DB, prefix); }
  catch (error) {
    logFailure("knowledge_edge_account_lookup_failed", error);
    return null;
  }
  if (!users.every(validUser)) return null;
  const verifiable = users.filter(user => HASH_PATTERN.test(user.api_key_hash));
  const index = verifiable.length ? await matchingHash(key, verifiable.map(user => user.api_key_hash), prefix) : -1;
  if (index >= 0) return { principal: { id: verifiable[index].username, scopes: accountScopes(verifiable[index], env) } };
  // A hash format the edge cannot check is left to the Container.
  return verifiable.length < users.length ? null : { denied: true };
}

/**
 * Returns {principal}, {denied: true} for a key that is definitively invalid, or null
 * when the Container must decide (unverifiable key types, storage or data faults).
 */
async function resolvePrincipal(request, env) {
  const key = requestKey(request.headers);
  if (!key) return null;
  if (env.ADMIN_API_KEY && sameSecret(key, env.ADMIN_API_KEY)) {
    const id = adminUsername(env);
    return id ? { principal: { id, scopes: [...KNOWLEDGE_SCOPES] } } : null;
  }
  if (!env.INTELLIGENCE_DB) return null;
  if (!key.startsWith(KEY_NAMESPACE)) return authStorageBackend(env) === "d1" ? accountPrincipal(env, key) : null;
  if (!KEY_PATTERN.test(key)) return { denied: true };
  const prefix = key.slice(0, KEY_NAMESPACE.length + 16);
  let record;
  try { record = await lookupIntegrationPrincipal(env.INTELLIGENCE_DB, prefix); }
  catch (error) {
    logFailure("knowledge_edge_credential_lookup_failed", error);
    return null;
  }
  if (record === null) return { denied: true };
  if (!validRecord(record, prefix)) return null;
  if (record.revokedAt !== null || await matchingHash(key, [record.keyHash], prefix) < 0) return { denied: true };
  return { principal: { id: record.id, scopes: record.scopes.filter(scope => KNOWLEDGE_SCOPES.includes(scope)) } };
}

const permits = (principal, scope) => principal.scopes.includes(scope);

async function readBody(request) {
  const type = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() ?? "";
  if (type !== "application/json" && !/^application\/[^/]+\+json$/.test(type)) {
    throw new KnowledgeEdgeError("invalid_request", "Use an application/json request body.", 415);
  }
  const tooLarge = () => new KnowledgeEdgeError("request_too_large", "The Knowledge request exceeds 64 KiB.", 413);
  const length = request.headers.get("content-length");
  if (length !== null && Number(length) > MAX_REQUEST_BYTES) throw tooLarge();
  const chunks = [];
  let size = 0;
  if (request.body) {
    const reader = request.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_REQUEST_BYTES) { void reader.cancel().catch(() => {}); throw tooLarge(); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
  }
  let payload;
  try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size))); }
  catch { throw new KnowledgeEdgeError("invalid_json", "The request body is not valid JSON.", 400); }
  if (!isRecord(payload)) throw new KnowledgeEdgeError("invalid_request", "The request body must be an object.", 400);
  return payload;
}

// Whether the deployed Knowledge Worker serves the contract this edge advertises.
function contractCheck(status) {
  const reported = isRecord(status.contract) ? status.contract : {};
  const operations = new Set(Array.isArray(reported.operations) ? reported.operations : []);
  const missing = [...new Set(catalogue.tools.map(entry => entry.operation))].filter(operation => !operations.has(operation)).sort();
  return { matched: reported.native_tools_hash === catalogue.nativeToolsHash && missing.length === 0,
    expected_native_tools_hash: catalogue.nativeToolsHash, missing_operations: isRecord(status.contract) ? missing : null };
}

async function dispatch(env, operation, principal, payload, signal) {
  const body = JSON.stringify({ version: 1, operation, principal, payload });
  if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
    throw new KnowledgeEdgeError("request_too_large", "The Knowledge request exceeds 64 KiB.", 413);
  }
  const deadline = AbortSignal.timeout(DEADLINE_MS);
  let response;
  let result;
  try {
    response = await env.KNOWLEDGE_SERVICE.fetch("http://knowledge.internal/v1/dispatch", {
      method: "POST", headers: { "content-type": "application/json" }, body,
      signal: signal ? AbortSignal.any([signal, deadline]) : deadline,
    });
    result = await response.json();
  } catch (error) {
    logFailure(deadline.aborted ? "knowledge_service_timeout" : "knowledge_service_failed", error, { operation });
    if (deadline.aborted) {
      throw new KnowledgeEdgeError("knowledge_timeout",
        "The Knowledge request timed out. Accepted work may still finish; no retry was started.", 504);
    }
    throw unavailable();
  }
  if (response.ok && isRecord(result) && result.version === 1 && (isRecord(result.result) || Array.isArray(result.result))) {
    return operation === "status" && isRecord(result.result) && Object.hasOwn(result.result, "contract")
      ? { ...result.result, contract_check: contractCheck(result.result) } : result.result;
  }
  const error = result?.error;
  if (!response.ok && response.status >= 400 && isRecord(error) && ERROR_CODE.test(error.code ?? "")
    && typeof error.message === "string" && error.message.length > 0 && error.message.length <= 1000) {
    throw new KnowledgeEdgeError(error.code, error.message, response.status);
  }
  logFailure("knowledge_service_invalid_reply", new Error(`HTTP ${response.status}`), { operation });
  throw unavailable();
}

function validOrigin(request) {
  const origin = request.headers.get("origin");
  if (origin === null) return true;
  try {
    const supplied = new URL(origin);
    const expected = new URL(request.url);
    return ["http:", "https:"].includes(supplied.protocol) && !supplied.username && !supplied.password
      && supplied.pathname === "/" && !supplied.search && !supplied.hash
      && supplied.protocol === expected.protocol && supplied.host === expected.host;
  } catch { return false; }
}

function acceptsJson(header) {
  return header.split(",").some(part => {
    const [range, ...parameters] = part.split(";").map(item => item.trim().toLowerCase());
    const quality = parameters.find(item => item.startsWith("q="));
    return ["application/json", "application/*", "*/*"].includes(range) && (!quality || Number(quality.slice(2)) > 0);
  });
}

async function callTool(env, request, principal, id, params) {
  const entry = typeof params.name === "string" ? TOOLS.get(params.name) : undefined;
  if (!entry) return rpcError(id, -32602, "Unknown Knowledge tool.");
  const failure = (code, message) => rpcResult(id, { isError: true, content: [{ type: "text",
    text: JSON.stringify({ error: { code, message } }) }] });
  if (!permits(principal, entry.scope)) {
    return failure("insufficient_scope", "The key is not authorized for this Knowledge tool.");
  }
  const args = params.arguments ?? {};
  if (!isRecord(args)) return rpcError(id, -32602, "Tool arguments must be an object.");
  try {
    // The private service validates every contract identically for REST and MCP.
    const result = await dispatch(env, entry.operation, principal, args, request.signal);
    const toolResult = { content: [{ type: "text", text: JSON.stringify(result) }], isError: Boolean(result?.error) };
    if (isRecord(result)) toolResult.structuredContent = result;
    return rpcResult(id, toolResult);
  } catch (error) {
    if (!(error instanceof KnowledgeEdgeError)) throw error;
    return failure(error.code, error.message);
  }
}

async function handleMcp(request, env, principal) {
  if (!validOrigin(request)) return restError("invalid_origin", "MCP requests must use the gateway origin.", 403);
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST", ...noStore } });
  const accept = request.headers.get("accept");
  if (accept && !acceptsJson(accept)) return rpcError(null, -32600, "Accept must include application/json.", 406);
  const protocol = request.headers.get("mcp-protocol-version");
  if (protocol !== null && !catalogue.protocolVersions.includes(protocol)) {
    return rpcError(null, -32600, "Unsupported MCP protocol version.", 400);
  }
  let body;
  try { body = await readBody(request); }
  catch (error) {
    if (!(error instanceof KnowledgeEdgeError)) throw error;
    return rpcError(null, error.code === "invalid_json" ? -32700 : -32600, error.message, error.status);
  }
  const { id, method } = body;
  const params = body.params ?? {};
  const hasId = Object.hasOwn(body, "id");
  // A client's reply to a server request carries no method; it is accepted without a body.
  if (body.jsonrpc === "2.0" && !Object.hasOwn(body, "method") && hasId
    && Object.hasOwn(body, "result") !== Object.hasOwn(body, "error")) {
    return new Response(null, { status: 202, headers: noStore });
  }
  if (body.jsonrpc !== "2.0" || typeof method !== "string" || !isRecord(params)
    || (hasId && !((typeof id === "string" && id.length <= 200) || Number.isSafeInteger(id)))) {
    return rpcError(null, -32600, "Invalid JSON-RPC request.", 400);
  }
  if (!hasId) {
    return method.startsWith("notifications/") ? new Response(null, { status: 202, headers: noStore })
      : rpcError(null, -32600, "An MCP request requires an id.", 400);
  }
  if (method === "initialize") {
    if (typeof params.protocolVersion !== "string" || !isRecord(params.capabilities ?? {}) || !isRecord(params.clientInfo ?? {})) {
      return rpcError(id, -32602, "Initialize requires a protocolVersion string.");
    }
    const versions = catalogue.protocolVersions;
    return rpcResult(id, { protocolVersion: versions.includes(params.protocolVersion) ? params.protocolVersion : versions[0],
      capabilities: { tools: {} }, serverInfo: catalogue.serverInfo, instructions: catalogue.instructions });
  }
  if (method === "ping") return rpcResult(id, {});
  if (method === "tools/list") {
    // /mcp?toolsets=core,exa narrows discovery to what an agent uses; every tool stays callable.
    const requested = new URL(request.url).searchParams.get("toolsets");
    const toolsets = requested === null ? null : new Set(requested.split(",").map(name => name.trim()).filter(Boolean));
    if (toolsets && (!toolsets.size || [...toolsets].some(name => !catalogue.toolsets.includes(name)))) {
      return rpcError(id, -32602, `Unknown toolset. Use any of: ${catalogue.toolsets.join(", ")}.`);
    }
    return rpcResult(id, { tools: catalogue.tools.filter(entry => permits(principal, entry.scope)
      && (!toolsets || toolsets.has(entry.toolset))).map(entry => entry.definition) });
  }
  if (method !== "tools/call") return rpcError(id, -32601, "Method not found.");
  return callTool(env, request, principal, id, params);
}

function restRoute(method, pathname) {
  const path = pathname.slice("/v1/knowledge/".length).split("/");
  const [first, second, third] = path;
  if (path.length === 1 && method === "POST" && ["context", "search"].includes(first)) {
    return { operation: first, scope: "knowledge:read", body: true };
  }
  if (path.length === 2 && method === "POST" && first === "alexandria" && ALEXANDRIA_OPERATIONS.includes(second)) {
    return { operation: `alexandria.${second}`, scope: "knowledge:read", body: true };
  }
  if (path.length === 2 && method === "GET" && first === "artifacts") return { operation: "artifact", scope: "knowledge:read", id: second };
  if (path.length === 2 && method === "POST" && first === "native" && NATIVE_OPERATIONS.has(`native.${second}`)) {
    return { operation: `native.${second}`, scope: "knowledge:read", body: true };
  }
  if (path.length === 1 && method === "GET" && first === "status") return { operation: "status", scope: "knowledge:manage" };
  if (path.length === 1 && method === "PUT" && first === "policy") return { operation: "policy.update", scope: "knowledge:manage", body: true };
  if (first === "sources") {
    if (path.length === 1 && method === "POST") return { operation: "sources.create", scope: "knowledge:manage", body: true };
    if (path.length === 2 && method === "PATCH") return { operation: "sources.update", scope: "knowledge:manage", body: true, id: second };
    if (path.length === 3 && method === "POST" && third === "refresh") return { operation: "sources.refresh", scope: "knowledge:manage", id: second };
  }
  if (first === "jobs" && path.length === 3 && method === "POST" && third === "cancel") {
    return { operation: "jobs.cancel", scope: "knowledge:manage", id: second };
  }
  return null;
}

async function handleRest(request, env, principal, route) {
  if (!permits(principal, route.scope)) {
    return json({ error: "insufficient_scope", message: `The authenticated key requires the ${route.scope} scope` }, 403);
  }
  try {
    const payload = route.body ? await readBody(request) : {};
    if (route.id !== undefined) {
      if (Object.hasOwn(payload, "id")) throw new KnowledgeEdgeError("invalid_request", "Source and job ids belong in the URL.", 400);
      if (!IDENTIFIER.test(route.id)) throw new KnowledgeEdgeError("invalid_identifier", "Invalid Knowledge identifier.", 400);
      payload.id = route.id;
    }
    return json(await dispatch(env, route.operation, principal, payload, request.signal));
  } catch (error) {
    if (!(error instanceof KnowledgeEdgeError)) throw error;
    return restError(error.code, error.message, error.status);
  }
}

/** Returns a Response for edge-verifiable credentials, or null to use the Container. */
export async function handleKnowledgeEdgeRequest(request, env) {
  const { pathname } = new URL(request.url);
  if (!env.KNOWLEDGE_SERVICE || request.method === "OPTIONS") return null;
  const route = pathname === "/mcp" ? "mcp" : restRoute(request.method, pathname);
  if (!route) return null;
  let resolved;
  try { resolved = await resolvePrincipal(request, env); }
  catch (error) {
    if (!(error instanceof KnowledgeEdgeError)) throw error;
    const retry = { "retry-after": error.status === 429 ? "60" : "1" };
    return route === "mcp" ? rpcError(null, -32000, error.message, error.status, retry) : json({ error: { code: error.code, message: error.message } }, error.status, retry);
  }
  if (!resolved) return null;
  if (resolved.denied) return json({ error: "Invalid API key", message: "The provided API key is not valid" }, 401);
  const { principal } = resolved;
  if (!KNOWLEDGE_SCOPES.some(scope => permits(principal, scope))) {
    // Either Knowledge scope opens MCP, so a key with neither needs the smaller one.
    const scope = route === "mcp" ? "knowledge:read" : route.scope;
    return json({ error: "insufficient_scope", message: `The authenticated key requires the ${scope} scope` }, 403);
  }
  try {
    return route === "mcp" ? await handleMcp(request, env, principal) : await handleRest(request, env, principal, route);
  } catch {
    const error = unavailable();
    return route === "mcp" ? rpcError(null, -32603, error.message, error.status) : restError(error.code, error.message, error.status);
  }
}
