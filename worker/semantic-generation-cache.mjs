import { governanceEnabled, GovernanceError } from "./tenant-governance-d1.mjs";
import { creditsEnforcement } from "./credits-d1.mjs";
import { CreditsAdmissionError } from "./credits-admission.mjs";
import { organisationsEnabled, tenantStorageKey } from "./tenants-d1.mjs";
/** Native semantic lookup after authentication and policy, before generation dispatch. */
import { digest, MAX_BODY_BYTES, completeCacheBody } from "./generation-cache-d1.mjs";
import { SemanticCacheD1, validVector, vectorSimilarity, schemaMissing, schemaErrorResponse } from "./semantic-cache-d1.mjs";
import { retentionAllowsContent } from "./retention-policy.mjs";
import { cacheServedEvent } from "./exact-generation-cache.mjs";
import { createReservationLifecycle, nativeReservationLifecycle, handleReservationsRequest, reservationSettings } from "./reservations-d1.mjs";
import { recordNativeUsage } from "./usage-ledger-d1.mjs";
const object = value => value && typeof value === "object" && !Array.isArray(value);
const MODEL = /^[a-z][a-z0-9-]*:[A-Za-z0-9@][A-Za-z0-9._:/+@-]{0,255}$/;
const VOLATILE = /\b(?:today|tomorrow|yesterday|now|current|latest|live|weather|stock|real.?time)\b/i;
let invalidWarned = false;
const warned = new Set();
function warn(event) {if (!warned.has(event)) {warned.add(event); console.warn(`Semantic generation cache ${event}`);}}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (object(value)) return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
export function semanticCacheSettings(env = {}) {
  const flag = String(env.SEMANTIC_CACHE_ENABLED ?? "").trim().toLowerCase();
  if (["", "false", "0", "no", "off"].includes(flag)) return {enabled: false, policy: {}};
  try {
    if (!["true", "1", "yes", "on"].includes(flag)) throw Error();
    const policy = JSON.parse(String(env.SEMANTIC_CACHE_POLICY_JSON ?? "").trim() || "{}");
    if (!object(policy) || Object.keys(policy).some(k => !["routes", "keys", "embedding_model", "revision", "model_revision", "allow_tools", "allow_streams"].includes(k))
      || ["allow_tools", "allow_streams"].some(k => Object.hasOwn(policy, k) && policy[k] !== false)) throw Error();
    for (const key of ["routes", "keys"]) if (!Array.isArray(policy[key] ?? [])
      || (policy[key] ?? []).some(v => typeof v !== "string" || !v.length || v.length > 256)) throw Error();
    if (((policy.routes?.length ?? 0) || (policy.keys?.length ?? 0)) && !MODEL.test(policy.embedding_model)) throw Error();
    for (const key of ["revision", "model_revision"]) if (Object.hasOwn(policy, key)
      && (typeof policy[key] !== "string" || !policy[key].length || policy[key].length > 256)) throw Error();
    return {enabled: true, policy};
  } catch {
    if (!invalidWarned) {invalidWarned = true; console.warn("Semantic generation cache invalid_configuration");}
    return {enabled: false, policy: {}};
  }
}
export function semanticEligible(payload) {
  if (!object(payload) || typeof payload.model !== "string" || !payload.model.length || /^(auto|free|cascade):/.test(payload.model)
    || payload.stream || (Object.hasOwn(payload,"n") ? payload.n : 1) !== 1 || Object.hasOwn(payload, "routing")
    || ["tools", "functions", "tool_choice", "function_call"].some(k => payload[k] != null
      && (!Array.isArray(payload[k]) || payload[k].length > 0))) return false;
  const messages = payload.messages;
  if (!Array.isArray(messages) || !messages.length || messages.some(m => !object(m)
    || !["user", "system", "assistant", "developer"].includes(m.role) || m.tool_calls && (!Array.isArray(m.tool_calls) || m.tool_calls.length) || m.function_call || m.tool_call_id)) return false;
  const last = messages.at(-1);
  return last.role === "user" && typeof last.content === "string" && !!last.content.trim()
    && new TextEncoder().encode(last.content).length <= 4096 && !VOLATILE.test(last.content);
}
export async function guardHash(text) {
  const facts = text.toLowerCase().match(/[-+]?\d+(?:[.,:/-]\d+)*|\b(?:no|not|never|without|cannot|neither|nor|nothing|nobody|none)\b|\b\w+n['’]t\b/g) ?? [];
  const datesAndNumbers = text.toLowerCase().match(/\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|trillion|first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth)\b/g) ?? [];
  const quotes = text.match(/"[^"\n]*"|(?<!\w)'[^'\n]*'|“[^”\n]*”|‘[^’\n]*’/g) ?? [];
  return digest(JSON.stringify([facts, datesAndNumbers, quotes]));
}
export function cosine(one, two) {
  return vectorSimilarity(one, two);
}
export async function semanticPartition(principal, provider, route, payload, context, policy, env = {}) {
  const revisions = typeof context.cacheRevisions === "function" ? context.cacheRevisions() : context.cacheRevisions ?? {};
  const messages = [...payload.messages.slice(0, -1), {...payload.messages.at(-1), content: null}];
  const invariant = {provider, route, payload: {...payload, messages}, revisions, policy, retention: context.retentionPolicy,
    retention_config: env.CONTENT_RETENTION_POLICY_JSON ?? "", retention_enabled: env.CONTENT_RETENTION_ENABLED ?? "",
    secret_policy: env.SECRET_SCAN_DEFAULT ?? "redact", secret_enabled: env.SECRET_SCAN_ENABLED ?? "",
    security: context.semanticSecurity ?? {}};
  if (organisationsEnabled(env)) principal = tenantStorageKey(principal, context.tenantContext);
  return {principal_hash: await digest(principal), partition_hash: await digest(JSON.stringify(canonical(invariant))),
    model_revision: await digest(JSON.stringify([policy.embedding_model, policy.model_revision ?? "1"]))};
}
export function embeddingPrice(env, model, tokens = 1024) {
  try {
    const table = JSON.parse(env.MODEL_PRICING_USD_PER_MILLION ?? "{}");
    const normalized = model.toLowerCase(), provider = normalized.split(":", 1)[0];
    const entry = table[normalized] ?? table[`${provider}:*`] ?? table["*"];
    if (!object(entry)) return null;
    const flatOnly = Object.hasOwn(entry, "request") && !["input", "output", "input_cost_per_million", "output_cost_per_million"].some(k => Object.hasOwn(entry, k));
    const input = flatOnly ? 0 : entry.input ?? entry.input_cost_per_million;
    const output = flatOnly ? 0 : entry.output ?? entry.output_cost_per_million;
    const flat = Object.hasOwn(entry, "request") ? entry.request : 0;
    if ([input, output, flat].some(v => !["string", "number"].includes(typeof v) || String(v).trim() === ""
      || !Number.isFinite(Number(v)) || Number(v) < 0)) return null;
    const cost = Number(input)*tokens/1_000_000+Number(flat);
    return Number.isFinite(cost) ? cost : null;
  } catch {return null;}
}
async function boundedBytes(stream, maximum) {
  if (!stream) return null;
  const reader = stream.getReader(), parts = []; let size = 0, timer;
  const deadline = new Promise(resolve => {timer = setTimeout(() => resolve(null), 2000);});
  try {
    while (true) {
      const part = await Promise.race([reader.read(), deadline]);
      if (!part) return null;
      if (part.done) break;
      size += part.value.length; if (size > maximum) return null;
      parts.push(part.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) {bytes.set(part, offset); offset += part.length;}
    return bytes;
  } finally {clearTimeout(timer); void reader.cancel().catch(() => {});}
}
async function optional(operation) {
  let timer;
  try {return await Promise.race([operation, new Promise((_, reject) => {timer = setTimeout(() => reject(Error("semantic_cache_timeout")), 2000);})]);}
  finally {clearTimeout(timer);}
}
function markHit(entry) {
  return new Response(entry.body, {headers: {"content-type": "application/json", ...entry.metadata.headers,
    "X-MultiLLM-Cache": "semantic-hit", "X-MultiLLM-Cache-Backend": "semantic-d1-r2",
    "X-MultiLLM-Usage-Basis": "cache-served", "X-MultiLLM-Provider-Calls": "0", Age: String(Math.floor(entry.age))}});
}
async function paidEmbedding(env, authority, request, policy, text, price, collaborators) {
  if (["embed", "accountEmbedding", "embeddingAllowed", "reserveEmbedding"].some(key => typeof collaborators[key] !== "function")) return null;
  if (await optional(collaborators.embeddingAllowed(policy.embedding_model, authority)) !== true) return null;
  const reservation = await optional(collaborators.reserveEmbedding(policy.embedding_model, price, authority));
  if (reservation === false) return null;
  const controller = new AbortController(), abort = () => controller.abort(request.signal.reason);
  request.signal.addEventListener("abort", abort, {once: true});
  const started = performance.now(); let result, status = 502, dispatched = false;
  try {
    if (request.signal.aborted) {status = 499; return null;}
    dispatched = true;
    result = await optional(collaborators.embed(policy.embedding_model, text, {signal: controller.signal, reservation}));
    const vector = object(result) ? result.data?.[0]?.embedding : result;
    status = validVector(vector) ? 200 : 502;
    return validVector(vector) ? vector : null;
  } finally {
    if (request.signal.aborted) status = 499;
    controller.abort(); request.signal.removeEventListener("abort", abort);
    const actual = result?.usage?.prompt_tokens ?? result?.usage?.input_tokens;
    const measured = Number.isSafeInteger(actual) && actual >= 0;
    await optional(collaborators.accountEmbedding({provider: policy.embedding_model.split(":", 1)[0], model: policy.embedding_model,
      principal: authority.principal.id, endpoint: "/v1/embeddings", status, input_tokens: !dispatched ? 0 : measured ? actual : 1024,
      output_tokens: 0, cost_usd: !dispatched ? 0 : measured ? embeddingPrice(env, policy.embedding_model, actual) : price,
      cost_basis: measured ? "usage" : "estimate", provider_calls: dispatched ? 1 : 0,
      submission_outcome: !dispatched ? "before-dispatch" : result ? "response" : "unknown",
      duration_ms: Math.round(performance.now()-started), reservation}));
  }
}

export async function prepareSemanticCache(request, env, authority, context, collaborators = {}) {
  const config = semanticCacheSettings(env), policy = config.policy;
  const source = authority.cacheRequest ?? request;
  if (!config.enabled || request.signal.aborted || !retentionAllowsContent(context.retentionPolicy) || request.method !== "POST"
    || !authority.route?.endsWith("/chat/completions") || !authority.principal?.id
    || !(policy.routes?.includes(authority.route) || policy.keys?.includes(authority.principal.id))
    || source.headers.get("Cache-Control")?.toLowerCase().includes("no-store") || new URL(source.url).search
    || ["x-api-key", "api-key", "x-multillm-api-key", "x-provider", "x-model", "x-multillm-provider", "idempotency-key"]
      .some(key => source.headers.has(key))) return null;
  const price = embeddingPrice(env, policy.embedding_model);
  if (price === null || price > 0.001) return null;
  let payload;
  try {
    const bytes = await boundedBytes(request.clone().body, MAX_BODY_BYTES);
    if (!bytes) return null;
    payload = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
  } catch {return null;}
  if (!semanticEligible(payload)) return null;
  const keyHash = authority.principal.keyHash ?? (env.ADMIN_API_KEY ? await digest(env.ADMIN_API_KEY) : null);
  if (!keyHash) return null;
  const principal = `${authority.principal.id}\0${keyHash}`;
  const policyContext = () => ({...context, semanticSecurity: {grants: authority.principal.model_allowlist ?? null,
    secret_policy: authority.principal.secret_scan_mode ?? null,
    headers: Object.fromEntries(["openai-organization", "openai-project", "openai-beta", "anthropic-version", "anthropic-beta"]
      .map(key => [key, source.headers.get(key)]))}});
  const current = () => semanticPartition(principal, authority.provider, authority.route, payload, policyContext(),
    semanticCacheSettings(env).policy, env);
  const identity = await current(), guard = await guardHash(payload.messages.at(-1).content);
  const store = collaborators.store ?? new SemanticCacheD1(env);
  try {await optional(store.ready());}
  catch (error) {
    if (schemaMissing(error)) return {async lookup() {return schemaErrorResponse();}, async store(response) {return response;}};
    warn("storage_unavailable"); return null;
  }
  let vector;
  try {vector = await paidEmbedding(env, authority, request, policy, payload.messages.at(-1).content, price, collaborators);}
  catch (error) {
    if (error instanceof CreditsAdmissionError || error instanceof GovernanceError) throw error;
    warn("embedding_unavailable"); return null;
  }
  if (!vector || request.signal.aborted) return null;
  const unchanged = async () => semanticCacheSettings(env).enabled && retentionAllowsContent(context.retentionPolicy)
    && JSON.stringify(await current()) === JSON.stringify(identity) && !request.signal.aborted
    && await optional(collaborators.embeddingAllowed(policy.embedding_model, authority)) === true;
  return {
    async lookup() {
      const control = source.headers.get("Cache-Control")?.toLowerCase() ?? "";
      if (control.includes("no-cache") || source.headers.get("X-MultiLLM-Cache")?.toLowerCase() === "refresh") return null;
      try {
        const rows = await optional(store.scan(identity));
        const candidates = rows.filter(row => row.guard_hash === guard && cosine(vector, row.vector) >= 0.98)
          .sort((a,b) => cosine(vector,b.vector)-cosine(vector,a.vector));
        const age = control.match(/(?:^|,)\s*max-age\s*=\s*(\d{1,9})\s*(?:,|$)/);
        for (const row of candidates) {
          const entry = await optional(store.body(identity, row));
          if (entry && (!age || entry.age <= Number(age[1])) && await unchanged()) return markHit(entry);
        }
      } catch (error) {if (schemaMissing(error)) return schemaErrorResponse(); warn("storage_unavailable");}
      return null;
    },
    async store(response, {canStore = () => false} = {}) {
      if (response.status !== 200 || response.headers.get("content-type")?.split(";",1)[0] !== "application/json"
        || response.headers.get("Cache-Control")?.toLowerCase().includes("no-store")
        || response.headers.get("content-encoding") && response.headers.get("content-encoding") !== "identity") return response;
      try {
        const body = await boundedBytes(response.clone().body, MAX_BODY_BYTES);
        if (body && completeCacheBody(body) && canStore() === true && await unchanged()) {
          await optional(store.put(identity, vector, guard, body,
            {content_type:"application/json",headers:{},provider:authority.provider,model:payload.model}));
        }
      } catch {warn("storage_unavailable");}
      return response;
    },
  };
}
export const semanticCacheServedEvent = cacheServedEvent;

/** Reuse only the already authenticated direct provider transport and its origin. */
export function createNativeSemanticCollaborators(request, env, ctx, authority, fetcher, context) {
  let account = authority.principal;
  const sameProvider = model => MODEL.test(model) && model.split(":", 1)[0] === authority.provider;
  const allowed = (model, patterns) => patterns == null || (Array.isArray(patterns) ? patterns : String(patterns).split(","))
    .some(pattern => new RegExp("^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*") + "$", "i").test(model));
  const ledgerPrincipal = async () => context.principal ?? `edge:${await digest(`native-admin:${authority.principal.id}`)}`;
  return {
    async embeddingAllowed(model) {
      if (!sameProvider(model) || request.signal.aborted) return false;
      if (env.INTELLIGENCE_DB) {
        const stored = await env.INTELLIGENCE_DB.prepare(`SELECT allowed_models, revoked_at, expires_at,
          daily_budget_usd, monthly_budget_usd FROM control_users WHERE username = ? AND is_admin = 1`)
          .bind(authority.principal.id).first();
        if (stored) account = { ...authority.principal, ...stored };
      }
      return !account.revoked_at && (!account.expires_at || Date.parse(account.expires_at) > Date.now())
        && allowed(model, account.allowed_models ?? account.model_allowlist);
    },
    async reserveEmbedding(model, price) {
      const limits = { daily_budget_usd: account.daily_budget_usd ?? null, monthly_budget_usd: account.monthly_budget_usd ?? null };
      const budgeted = Object.values(limits).some(value => value !== null);
      if (budgeted && !reservationSettings(env).enabled) return false;
      if (governanceEnabled(env) || creditsEnforcement(env) !== "off") {
        const embeddingRequest = new Request(request.url, { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ model: model.slice(model.indexOf(":") + 1), input: "" }) });
        const legacyPrincipal = await ledgerPrincipal();
        const principal = organisationsEnabled(env) ? tenantStorageKey(legacyPrincipal, authority.tenantContext) : legacyPrincipal;
        const day = new Date().toISOString().slice(0, 10);
        const baseline = budgeted ? await env.INTELLIGENCE_DB.prepare(`SELECT
          COALESCE(SUM(CASE WHEN day=? THEN cost_usd ELSE 0 END),0) AS day_spent_usd,
          COALESCE(SUM(cost_usd),0) AS month_spent_usd FROM usage_daily WHERE principal=? AND day>=? AND day<=?`)
          .bind(day, principal, `${day.slice(0,7)}-01`, day).first() : { day_spent_usd: 0, month_spent_usd: 0 };
        if (!baseline) throw Error("semantic_embedding_budget_unavailable");
        const lifecycle = nativeReservationLifecycle(embeddingRequest, env, { ...authority, principal: account }, {
          identity: async () => ({ principal, estimate_usd: price, ...limits, ...baseline }),
        });
        const event = { ...context, model: model.slice(model.indexOf(":")+1), provider: authority.provider };
        await lifecycle.authorize(event); await lifecycle.admit(event);
        let handedOff = false;
        return { ...lifecycle, get handedOff() { return handedOff; }, handoff() { handedOff = true; } };
      }
      const lifecycle = createReservationLifecycle(env, { call: async body => {
        const response = await handleReservationsRequest(new Request("http://intelligence.internal/v1/reservations", {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
        }), env);
        return response.json();
      }, identity: async () => {
        if (!budgeted) return limits;
        const day = new Date().toISOString().slice(0, 10), principal = await ledgerPrincipal();
        const baseline = await env.INTELLIGENCE_DB.prepare(`SELECT
          COALESCE(SUM(CASE WHEN day = ? THEN cost_usd ELSE 0 END), 0) AS day_spent_usd,
          COALESCE(SUM(cost_usd), 0) AS month_spent_usd FROM usage_daily WHERE principal = ? AND day >= ? AND day <= ?`)
          .bind(day, principal, `${day.slice(0, 7)}-01`, day).first();
        if (!baseline) throw Error("semantic_embedding_budget_unavailable");
        return { principal, estimate_usd: price, ...limits, ...baseline };
      } });
      await lifecycle.admit({ model });
      return lifecycle;
    },
    async embed(model, text, { signal, reservation }) {
      await reservation?.before_dispatch();
      if (signal.aborted) throw new DOMException("Embedding canceled", "AbortError");
      const target = new URL(request.url);
      target.pathname = target.pathname.replace(/\/chat\/completions$/, "/embeddings");
      target.search = "";
      const headers = new Headers(request.headers);
      for (const name of ["content-length", "idempotency-key", "x-multillm-cache", "x-multillm-deadline-ms", "x-multillm-internal-deadline-ms"]) headers.delete(name);
      headers.set("content-type", "application/json"); headers.set("cache-control", "no-store");
      const embeddingAuthority = { ...authority, provider: model.split(":", 1)[0],
        route: authority.route.replace(/\/chat\/completions$/, "/embeddings") };
      reservation?.handoff?.();
      const response = await fetcher(new Request(target, { method: "POST", headers, signal, redirect: "manual",
        body: JSON.stringify({ model: model.slice(model.indexOf(":") + 1), input: text }) }), env, embeddingAuthority);
      const bytes = await boundedBytes(response.body, MAX_BODY_BYTES);
      if (!response.ok || !bytes) throw Error("semantic_embedding_failed");
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    },
    async accountEmbedding(event) {
      const handedOff = typeof event.reservation?.handedOff === "boolean" ? event.reservation.handedOff : event.submission_outcome !== "before-dispatch";
      const outcome = event.status === 200 ? "success" : event.status === 499 ? "canceled" : "transport_error";
      try {
        await recordNativeUsage(env, { ...event, ...(authority.tenantContext ? { tenantContext: authority.tenantContext } : {}), principal: await ledgerPrincipal(), requestId: crypto.randomUUID(),
          model: event.model.slice(event.model.indexOf(":") + 1), outcome,
          ttft_ms: null, usage_basis: event.cost_basis === "usage" ? "measured" : "estimated" }, ctx);
      } finally {
        await event.reservation?.finalize({ ...event, handedOff, outcome });
      }
    },
  };
}
