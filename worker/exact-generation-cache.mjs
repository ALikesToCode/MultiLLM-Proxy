import { organisationsEnabled, tenantStorageKey } from "./tenants-d1.mjs";
/** Opt-in exact Chat Completions caching after native authentication and retention. */
import { GenerationCacheD1, MAX_BODY_BYTES, digest, completeCacheBody } from "./generation-cache-d1.mjs";
import { createUsageObserver } from "./request-telemetry.mjs";
import { retentionAllowsContent } from "./retention-policy.mjs";
const warned = new Set();
function warn(event) { if (!warned.has(event)) { warned.add(event); console.warn(JSON.stringify({event: `generation_cache_${event}`})); } }
export function generationCacheSettings(env = {}) {
  const backend = String(env.GENERATION_CACHE_BACKEND ?? "").trim() || "memory";
  const flag = String(env.GENERATION_CACHE_SHARED_ENABLED ?? "").trim().toLowerCase();
  if (!["memory", "d1-r2"].includes(backend) || !["", "false", "0", "no", "off", "true", "1", "yes", "on"].includes(flag)) {
    warn("invalid_setting"); return {enabled: false, backend: "memory"};
  }
  return {enabled: backend === "d1-r2" && ["true", "1", "yes", "on"].includes(flag), backend};
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
export function eligibleRequest(value) {
  if ([value?.tools, value?.functions].some(tools => tools != null && !Array.isArray(tools))) return false;
  return value && typeof value === "object" && !Array.isArray(value) && !value.stream && typeof value.model === "string"
    && value.model !== "auto:intelligence" && !Object.hasOwn(value, "routing") && (value.n ?? 1) === 1
    && (!(value.tools?.length || value.functions?.length) || value.tool_choice === "none")
    && (value.temperature === 0 || Number.isSafeInteger(value.seed));
}
async function boundedBytes(stream, maximum) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader(); const parts = []; let size = 0, timer;
  const expired = new Promise(resolve => {timer = setTimeout(() => resolve(null), 2000);});
  try {
    while (true) {
      const item = await Promise.race([reader.read(), expired]);
      if (!item) return null;
      if (item.done) break;
      size += item.value.length; if (size > maximum) return null;
      parts.push(item.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) {bytes.set(part, offset); offset += part.length;}
    return bytes;
  } finally {clearTimeout(timer); void reader.cancel().catch(() => {});}
}
export async function exactCacheIdentity(request, env, authority, context) {
  if (!retentionAllowsContent(context.retentionPolicy) || request.method !== "POST"
    || !authority.route?.endsWith("/chat/completions") || new URL(request.url).search) return null;
  const source = authority.cacheRequest ?? request;
  if (new URL(source.url).search || ["x-api-key", "api-key", "x-multillm-api-key", "x-opencode-session", "x-grok-conv-id",
    "x-provider", "x-model", "x-multillm-provider", "idempotency-key"]
    .some(key => source.headers.has(key))) return null;
  if (!authority.principal?.id || !env.ADMIN_API_KEY) return null;
  const bytes = await boundedBytes(request.clone().body, MAX_BODY_BYTES);
  if (!bytes) return null;
  let payload;
  try {payload = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));} catch {return null;}
  if (!eligibleRequest(payload)) return null;
  const principalId = organisationsEnabled(env) ? tenantStorageKey(authority.principal.id, authority.tenantContext ?? context.tenantContext) : authority.principal.id;
  const principal = await digest(`${principalId}\0${await digest(env.ADMIN_API_KEY)}`);
  const policyHash = await nativePolicyHash(request, env, authority, context);
  const key = await digest(JSON.stringify([principal, authority.route, policyHash, canonical(payload)]));
  return {principal_hash: principal, cache_key: key, policy_hash: policyHash, model: payload.model};
}
async function nativePolicyHash(request, env, authority, context) {
  const source = authority.cacheRequest ?? request;
  const revisions = typeof context.cacheRevisions === "function" ? context.cacheRevisions() : context.cacheRevisions ?? {};
  const policy = {version: "native-exact-v1", endpoint: request.url, provider: authority.provider, route: authority.route,
    retention: context.retentionPolicy, retention_config: env.CONTENT_RETENTION_POLICY_JSON ?? "",
    retention_enabled: env.CONTENT_RETENTION_ENABLED ?? "", revisions,
    secret_policy: env.SECRET_SCAN_DEFAULT ?? "redact", secret_enabled: env.SECRET_SCAN_ENABLED ?? "",
    principal_secret_policy: authority.principal.secret_scan_mode ?? null,
    headers: Object.fromEntries(["openai-organization", "openai-project", "openai-beta", "anthropic-version", "anthropic-beta"]
      .map(key => [key, source.headers.get(key)]))};
  return digest(JSON.stringify(canonical(policy)));
}
function mode(request) {
  const value = request.headers.get("X-MultiLLM-Cache")?.trim().toLowerCase();
  const control = request.headers.get("Cache-Control")?.toLowerCase() ?? "";
  if (!["on", "true", "1", "yes", "refresh"].includes(value) || control.includes("no-store")) return null;
  const age = control.match(/(?:^|,)\s*max-age\s*=\s*(\d{1,9})\s*(?:,|$)/);
  return {refresh: value === "refresh" || control.includes("no-cache"), maxAge: age ? Number(age[1]) : null};
}
function mark(response, value) {
  const headers = new Headers(response.headers);
  headers.set("X-MultiLLM-Cache", value); headers.set("X-MultiLLM-Cache-Backend", "d1-r2");
  headers.delete("X-MultiLLM-Usage-Basis"); headers.delete("X-MultiLLM-Provider-Calls");
  if (value === "hit") {headers.set("X-MultiLLM-Usage-Basis", "cache-served"); headers.set("X-MultiLLM-Provider-Calls", "0");}
  return new Response(response.body, {status: response.status, statusText: response.statusText, headers});
}
async function optionalStorage(operation) {
  let timer;
  const deadline = new Promise((_, reject) => {timer = setTimeout(() => reject(new Error("cache_timeout")), 2000);});
  try {return await Promise.race([operation, deadline]);}
  finally {clearTimeout(timer);}
}
export async function prepareNativeCache(request, env, authority, context) {
  if (!generationCacheSettings(env).enabled || !retentionAllowsContent(context.retentionPolicy)) return null;
  const selected = mode(authority.cacheRequest ?? request); if (!selected) return null;
  let identity;
  try {identity = await exactCacheIdentity(request, env, authority, context);} catch {warn("identity_unavailable"); return null;}
  if (!identity) return null;
  const store = new GenerationCacheD1(env);
  return { async lookup() {
    if (selected.refresh || request.signal.aborted) return null;
    try {
      const entry = await optionalStorage(store.get(identity, selected));
      if (!entry || request.signal.aborted || await nativePolicyHash(request, env, authority, context) !== identity.policy_hash) return null;
      const response = new Response(entry.body, {headers: {"content-type": entry.metadata.content_type, ...entry.metadata.headers, Age: String(Math.floor(entry.age))}});
      return mark(response, "hit");
    } catch {warn("storage_unavailable"); return null;}
  }, async store(response, { canStore = () => true } = {}) {
    if (request.signal.aborted || response.status !== 200 || response.headers.get("content-type")?.split(";", 1)[0] !== "application/json"
      || response.headers.get("content-encoding") && response.headers.get("content-encoding") !== "identity") return mark(response, "miss");
    try {
      const length = response.headers.get("content-length");
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) return mark(response, "miss");
      const body = await boundedBytes(response.clone().body, MAX_BODY_BYTES);
      const current = await nativePolicyHash(request, env, authority, context);
      const observer = createUsageObserver();
      if (body) observer.feed(body);
      const classified = observer.finish();
      if (body && completeCacheBody(body) && classified.completed && !classified.failed
          && classified.usage.input_tokens !== null && classified.usage.output_tokens !== null
          && canStore() && !request.signal.aborted && current === identity.policy_hash) {
        await optionalStorage(store.put(identity, body,
          {content_type: "application/json", headers: {}, provider: authority.provider, model: identity.model}));
      }
    } catch {warn("storage_unavailable");}
    return mark(response, "miss");
  } };
}
export function cacheServedEvent(response, context) {
  return {...context, status: response.status, outcome: "success", duration_ms: Math.max(0, Math.round(performance.now() - context.startedAt)),
    ttft_ms: null, input_tokens: null, output_tokens: null, usage_basis: "cache-served", provider_calls: 0, cost_usd: 0, cost_basis: "cache"};
}
