/** Exact context bodies in R2, signed principal/session/revision handles in D1. */
import { RoleplayTurnError } from "./roleplay/turn-runtime.mjs";
import { mediaMac, mediaSecret, toBase64, toBase64Url } from "./media-signing.mjs";
import { retentionAllowsContent, retentionPolicySnapshot } from "./retention-policy.mjs";

export const MAX_PAGE_BYTES = 65536;
export const MAX_SESSION_BYTES = 1048576;
export const TTL_SECONDS = 3600;
export const TOOL_SCHEMA = Object.freeze({ type: "function", function: {
  name: "multillm_context_retrieve", description: "Retrieve an exact stored historical context page.",
  parameters: { type: "object", properties: { page_id: { type: "string" } },
    required: ["page_id"], additionalProperties: false },
} });
const PAGE_ID = /^cp_[a-f0-9]{32}_[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
let warned = false;

export class ContextPageError extends RoleplayTurnError {
  constructor(code, status = 503) {
    super(code, status, code);
    this.code = code;
    this.status = status;
  }
}

export function contextPagingEnabled(env = {}) {
  const flag = String(env.CONTEXT_PAGING_ENABLED ?? "").trim().toLowerCase();
  if (["", "0", "false", "no", "off"].includes(flag)) return false;
  if (["1", "true", "yes", "on"].includes(flag)) return true;
  if (!warned) { console.warn("Invalid CONTEXT_PAGING_ENABLED; context paging disabled"); warned = true; }
  return false;
}

function checkedScope(scope) {
  if (!scope || ["principal", "session", "revision"].some(key =>
    typeof scope[key] !== "string" || !scope[key] || encoder.encode(scope[key]).length > 256)) {
    throw new ContextPageError("context_paging_authority_unavailable");
  }
  return scope;
}

export function contextPagingEligible({ env, managed, capabilities, retentionPolicy }) {
  return contextPagingEnabled(env) && managed === true && Array.isArray(capabilities)
    && capabilities.includes("multillm_context_retrieve") && retentionAllowsContent(retentionPolicySnapshot(retentionPolicy));
}

const sha256 = async body => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)),
  byte => byte.toString(16).padStart(2, "0")).join("");

function completeGroup(group) {
  const pending = new Set();
  const seen = new Set();
  for (const message of group) {
    if (!message || !["user", "assistant", "tool"].includes(message.role)
      || ["function_call", "tool_use", "tool_uses"].some(key => Object.hasOwn(message, key))) return false;
    const calls = message.tool_calls ?? [];
    if (!Array.isArray(calls) || (calls.length && message.role !== "assistant")
      || (pending.size && message.role !== "tool")) return false;
    for (const call of calls) {
      if (typeof call?.id !== "string" || !call.id || seen.has(call.id)) return false;
      seen.add(call.id);
      pending.add(call.id);
    }
    if (message.role === "tool" && !pending.delete(message.tool_call_id)) return false;
  }
  return pending.size === 0 && group.length > 0 && ["assistant", "tool"].includes(group.at(-1).role);
}

function removableGroups(messages, protectedIndices = []) {
  const starts = messages.flatMap((message, index) => message?.role === "user" ? [index] : []);
  return starts.slice(0, -1).flatMap((start, index) => {
    const end = starts[index + 1];
    return completeGroup(messages.slice(start, end)) && !protectedIndices.some(position => position >= start && position < end)
      ? [{ start, end }] : [];
  });
}

function marker(meta) {
  return { role: "assistant", content: "[Stored historical context; retrieve explicitly with multillm_context_retrieve]\n"
    + JSON.stringify({ page_id: meta.page_id, sha256: meta.sha256, expires_at: meta.expires_at }) };
}

const metadata = row => ({ page_id: row.page_id, sha256: row.sha256,
  expires_at: row.expires_at, tool_schema: structuredClone(TOOL_SCHEMA) });

function failure(error) {
  const known = error instanceof ContextPageError ? error : new ContextPageError("context_paging_unavailable");
  return Response.json({ version: 1, error: { code: known.code, message: "Context paging could not be completed." } },
    { status: known.status, headers: { "cache-control": "private, no-store" } });
}

export class ContextPageStore {
  constructor(env, { clock = () => Date.now() / 1000 } = {}) {
    this.env = env;
    this.clock = clock;
  }

  async ready() {
    if (!contextPagingEnabled(this.env)) throw new ContextPageError("context_page_not_found", 404);
    if (!this.env.INTELLIGENCE_DB || !this.env.multillm_media || !mediaSecret(this.env)) {
      throw new ContextPageError("context_paging_unavailable");
    }
    try {
      await this.env.INTELLIGENCE_DB.prepare("SELECT page_id FROM context_pages LIMIT 1").bind().first();
    } catch { throw new ContextPageError("context_paging_unavailable"); }
  }

  async _signedId(row, nonce) {
    return "cp_" + nonce + "_" + toBase64Url(await mediaMac(mediaSecret(this.env), "context-page",
      JSON.stringify([row.principal, row.session_hash, row.revision, row.sha256, row.expires_at, nonce])));
  }

  async put(scope, bodies) {
    checkedScope(scope);
    await this.ready();
    if (!Array.isArray(bodies) || !bodies.length || bodies.some(body => !(body instanceof Uint8Array)
      || !body.length || body.length > MAX_PAGE_BYTES)) throw new ContextPageError("context_page_limit", 413);
    const total = bodies.reduce((size, body) => size + body.length, 0);
    if (total > MAX_SESSION_BYTES) throw new ContextPageError("context_session_limit", 413);
    const now = Math.floor(this.clock());
    const sessionHash = await sha256(encoder.encode(scope.session));
    const principalHash = await sha256(encoder.encode(scope.principal));
    const rows = [];
    const written = [];
    try {
      for (const body of bodies) {
        const nonce = crypto.randomUUID().replaceAll("-", "");
        const row = { principal: scope.principal, session_hash: sessionHash, revision: scope.revision,
          sha256: await sha256(body), byte_length: body.length, expires_at: now + TTL_SECONDS };
        row.page_id = await this._signedId(row, nonce);
        row.r2_key = `context-pages/${principalHash}/${sessionHash}/${row.page_id}`;
        rows.push(row);
      }
      for (let index = 0; index < rows.length; index += 1) {
        // Record the new key first so an ambiguous put can also be cleaned up.
        written.push(rows[index].r2_key);
        await this.env.multillm_media.put(rows[index].r2_key, bodies[index], {
          httpMetadata: { contentType: "application/json; charset=utf-8" },
        });
      }
      // One statement inserts all pages or none. D1 serializes this limit check
      // with the writes, including requests from other Container instances.
      const result = await this.env.INTELLIGENCE_DB.prepare(`
        INSERT INTO context_pages (page_id, principal, session_hash, revision, sha256, byte_length, expires_at, r2_key)
        SELECT json_extract(value, '$.page_id'), json_extract(value, '$.principal'),
          json_extract(value, '$.session_hash'), json_extract(value, '$.revision'),
          json_extract(value, '$.sha256'), json_extract(value, '$.byte_length'),
          json_extract(value, '$.expires_at'), json_extract(value, '$.r2_key')
        FROM json_each(?) WHERE ? + (
          SELECT COALESCE(SUM(byte_length), 0) FROM context_pages
          WHERE principal = ? AND session_hash = ? AND expires_at > ?
        ) <= ?`).bind(JSON.stringify(rows), total, scope.principal, sessionHash, now, MAX_SESSION_BYTES).run();
      if (result?.success === false) throw new ContextPageError("context_paging_unavailable");
      if (result?.meta?.changes === 0) throw new ContextPageError("context_session_limit", 413);
      if (result?.meta?.changes !== rows.length) throw new ContextPageError("context_paging_unavailable");
      return rows.map(metadata);
    } catch (error) {
      // Only newly generated keys are removed. Existing stored pages are preserved.
      await Promise.allSettled(written.map(key => this.env.multillm_media.delete(key)));
      throw error instanceof ContextPageError ? error : new ContextPageError("context_paging_unavailable");
    }
  }

  async get(scope, pageId) {
    checkedScope(scope);
    await this.ready();
    if (typeof pageId !== "string" || !PAGE_ID.test(pageId)) throw new ContextPageError("context_page_not_found", 404);
    try {
      const sessionHash = await sha256(encoder.encode(scope.session));
      const row = await this.env.INTELLIGENCE_DB.prepare(`SELECT * FROM context_pages
        WHERE page_id = ? AND principal = ? AND session_hash = ? AND revision = ? AND expires_at > ?`)
        .bind(pageId, scope.principal, sessionHash, scope.revision, Math.floor(this.clock())).first();
      if (!row) throw new ContextPageError("context_page_not_found", 404);
      const expected = await this._signedId(row, pageId.slice(3, 35));
      let difference = expected.length ^ pageId.length;
      for (let index = 0; index < expected.length; index += 1) difference |= expected.charCodeAt(index) ^ pageId.charCodeAt(index);
      if (difference) throw new ContextPageError("context_page_not_found", 404);
      const key = `context-pages/${await sha256(encoder.encode(scope.principal))}/${sessionHash}/${pageId}`;
      if (row.r2_key !== key || row.byte_length > MAX_PAGE_BYTES) throw new ContextPageError("context_page_integrity_failed");
      const object = await this.env.multillm_media.get(key);
      if (!object || object.size !== row.byte_length) throw new ContextPageError("context_page_integrity_failed");
      const body = new Uint8Array(await object.arrayBuffer());
      if (body.length !== row.byte_length || await sha256(body) !== row.sha256) throw new ContextPageError("context_page_integrity_failed");
      const messages = JSON.parse(decoder.decode(body));
      if (!Array.isArray(messages) || !completeGroup(messages)) throw new ContextPageError("context_page_integrity_failed");
      return { ...metadata(row), body_base64: toBase64(body), messages };
    } catch (error) {
      throw error instanceof ContextPageError ? error : new ContextPageError("context_paging_unavailable");
    }
  }
}

/** Preflight every replacement before persisting any body. */
export async function pageContextMessages(options) {
  const { messages, inputBudget, scope, estimateTokens, protectedIndices = [] } = options;
  const original = { fit: true, messages, estimatedInputTokens: estimateTokens(messages)
    + (options.tools?.length ? estimateTokens(options.tools) : 0), pages: [], tools: [] };
  if (!contextPagingEligible(options)) return original;
  checkedScope(scope);
  const store = options.store ?? new ContextPageStore(options.env);
  await store.ready();
  if (!Number.isSafeInteger(inputBudget) || inputBudget <= 0) throw new ContextPageError("context_window_exceeded", 413);
  if (original.estimatedInputTokens <= inputBudget) return original;
  const tools = options.tools ?? [];
  if (!Array.isArray(tools) || tools.some(tool => tool?.function?.name === "multillm_context_retrieve")) {
    throw new ContextPageError("context_retrieval_tool_conflict", 400);
  }
  const outgoingTools = [...tools, structuredClone(TOOL_SCHEMA)];
  const now = Math.floor(store.clock());
  const groups = removableGroups(messages, protectedIndices);
  const selected = [];
  const replacements = new Map();
  const removed = new Set();
  let view = messages;
  let total = 0;
  const estimate = value => estimateTokens(value) + estimateTokens(outgoingTools);
  for (const group of groups) {
    const body = encoder.encode(JSON.stringify(messages.slice(group.start, group.end)));
    if (body.length > MAX_PAGE_BYTES) throw new ContextPageError("context_page_limit", 413);
    total += body.length;
    if (total > MAX_SESSION_BYTES) throw new ContextPageError("context_session_limit", 413);
    selected.push({ ...group, body });
    replacements.set(group.start, marker({ page_id: "cp_" + "0".repeat(32) + "_" + "s".repeat(43),
      sha256: await sha256(body), expires_at: now + TTL_SECONDS }));
    for (let index = group.start + 1; index < group.end; index += 1) removed.add(index);
    view = messages.flatMap((message, index) => removed.has(index) ? [] : [replacements.get(index) ?? message]);
    if (estimate(view) <= inputBudget) break;
  }
  if (!selected.length || estimate(view) > inputBudget) throw new ContextPageError("context_window_exceeded", 413);
  const cache = options.pageCache ?? new Map();
  const keys = await Promise.all(selected.map(async group => JSON.stringify([scope, await sha256(group.body)])));
  const missing = selected.flatMap((group, index) => cache.has(keys[index]) ? [] : [{ ...group, key: keys[index] }]);
  const created = missing.length ? await store.put(scope, missing.map(group => group.body)) : [];
  if (!Array.isArray(created) || created.length !== missing.length) throw new ContextPageError("context_page_integrity_failed");
  missing.forEach((group, index) => cache.set(group.key, created[index]));
  const pages = keys.map(key => cache.get(key));
  if (!Array.isArray(pages) || pages.length !== selected.length) throw new ContextPageError("context_page_integrity_failed");
  for (let index = 0; index < selected.length; index += 1) replacements.set(selected[index].start, marker(pages[index]));
  view = messages.flatMap((message, index) => removed.has(index) ? [] : [replacements.get(index) ?? message]);
  if (estimate(view) > inputBudget) throw new ContextPageError("context_window_exceeded", 413);
  return { fit: true, messages: view, estimatedInputTokens: estimate(view), pages, tools: outgoingTools };
}

/** Only explicit calls retrieve content; this never dispatches or replays generation. */
export async function retrieveContextTool(arguments_, { scope, granted, retentionPolicy, store }) {
  if (!arguments_ || Object.keys(arguments_).length !== 1 || !Object.hasOwn(arguments_, "page_id")) {
    throw new ContextPageError("invalid_context_retrieve", 400);
  }
  if (granted !== true || !retentionAllowsContent(retentionPolicySnapshot(retentionPolicy))) throw new ContextPageError("context_page_forbidden", 403);
  return store.get(scope, arguments_.page_id);
}

export async function handleContextPageRequest(request, env, { authorize, store = new ContextPageStore(env) } = {}) {
  const match = /^\/v1\/context\/pages\/([^/]+)$/.exec(new URL(request.url).pathname);
  if (!match) return null;
  try {
    if (!contextPagingEnabled(env)) throw new ContextPageError("context_page_not_found", 404);
    if (request.method !== "GET") throw new ContextPageError("method_not_allowed", 405);
    if (typeof authorize !== "function") throw new ContextPageError("context_paging_authority_unavailable");
    const authority = await authorize(request);
    const result = await retrieveContextTool({ page_id: match[1] }, { ...authority, store });
    return Response.json(result, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return failure(error); }
}

/** Private Container calls are reachable only through the authenticated state dispatcher. */
export async function handleContextPageStateRequest(request, env) {
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/managed-state/context-pages"
    || url.search || url.hash || url.username || url.password || request.method !== "POST") return failure(new ContextPageError("invalid_store_target", 400));
  try {
    if (!contextPagingEnabled(env)) throw new ContextPageError("context_page_not_found", 404);
    const reader = request.body?.getReader();
    if (!reader) throw new ContextPageError("invalid_context_operation", 400);
    const chunks = [];
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 2 * MAX_SESSION_BYTES) {
        await reader.cancel();
        throw new ContextPageError("context_session_limit", 413);
      }
      chunks.push(value);
    }
    const input = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { input.set(chunk, offset); offset += chunk.length; }
    const body = JSON.parse(decoder.decode(input));
    const policy = retentionPolicySnapshot(body.retention_policy);
    if (body.granted !== true || !retentionAllowsContent(policy)) throw new ContextPageError("context_page_forbidden", 403);
    const store = new ContextPageStore(env);
    if (body.operation === "get") {
      return Response.json(await store.get(body.scope, body.page_id), { headers: { "cache-control": "private, no-store" } });
    }
    if (body.operation !== "put" || !Array.isArray(body.bodies)) throw new ContextPageError("invalid_context_operation", 400);
    const bodies = body.bodies.map(value => {
      if (typeof value !== "string" || value.length > Math.ceil(MAX_PAGE_BYTES / 3) * 4
        || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new ContextPageError("context_page_limit", 413);
      const decoded = Uint8Array.from(atob(value), char => char.charCodeAt(0));
      const group = JSON.parse(decoder.decode(decoded));
      if (!Array.isArray(group) || !completeGroup(group)) throw new ContextPageError("invalid_context_messages", 400);
      return decoded;
    });
    return Response.json({ version: 1, pages: await store.put(body.scope, bodies) });
  } catch (error) { return failure(error); }
}
