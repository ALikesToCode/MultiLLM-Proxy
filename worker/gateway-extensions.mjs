/** Static registration boundary for native dispatch; later integrations supply named hooks. */
import { generationCacheSettings, prepareNativeCache, cacheServedEvent } from "./exact-generation-cache.mjs";
import { createGatewayLifecycle } from "./gateway-lifecycle.mjs";
import { observeNativeResponse, appendNativeMetrics, PARSER_LIMIT } from "./request-telemetry.mjs";
import { recordNativeUsage } from "./usage-ledger-d1.mjs";
import { admissionSettings, admissionModelGroup, principalHash, runWithAdmission, AdmissionError } from "./admission-do.mjs";
import { resolveRetentionPolicy, retentionRequestId } from "./retention-policy.mjs";
import { nativeRevisionConsumer, tickNativeRevisionSync } from "./native-config-sync.mjs";
import { UpstreamCancellation } from "./upstream-cancellation.mjs";

let warned = false;
export function nativeMetricsEnabled(env) {
  const value = String(env.NATIVE_EDGE_METRICS_ENABLED ?? "").trim().toLowerCase();
  if (!value || value === "false") return false;
  if (value === "true") return true;
  if (!warned) { warned = true; console.error(JSON.stringify({ event: "native_metrics_invalid_setting" })); }
  return false;
}

async function requestedModel(request) {
  if (!request.body) return null;
  const reader = request.clone().body.getReader(); let size = 0, parts = [];
  try {
    while (true) {
      const result = await reader.read(); if (result.done) break;
      size += result.value.byteLength; if (size > PARSER_LIMIT) return null;
      parts.push(result.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    const model = JSON.parse(new TextDecoder().decode(bytes)).model;
    return typeof model === "string" ? model : null;
  } catch { return null; }
  finally { void reader.cancel().catch(() => {}); }
}

async function dispatchNative(request, env, authority, fetcher, owner) {
  owner.throwIfAborted();
  owner.handoff();
  try {
    const upstream = new Request(request, { signal: owner.controller.signal });
    return owner.wrapResponse(await fetcher(upstream, env, authority));
  } catch (error) {
    await owner.close("interrupted");
    throw error;
  }
}

async function nativeContext(request, env, authority, metrics) {
  const startedAt = performance.now();
  const principal = metrics ? `edge:${await retentionRequestId(`native-admin:${authority.principal.id}`)}` : null;
  const retentionIdentity = { keyId: (env.ADMIN_USERNAME || "admin").trim(), route: authority.route,
    header: authority.retentionHeader ?? request.headers.get("X-MultiLLM-Retention") ?? "" };
  let retentionPolicy = resolveRetentionPolicy(env, retentionIdentity);
  if (retentionPolicy.enabled) retentionPolicy = resolveRetentionPolicy(env,
    { ...retentionIdentity, keyHash: await retentionRequestId(env.ADMIN_API_KEY) });
  const model = await requestedModel(request);
  const revision = nativeRevisionConsumer(env);
  const cacheRevisions = () => revision ? Object.fromEntries(Object.entries(revision.status().domains)
    .map(([name, state]) => [name, state.revision])) : {};
  return Object.freeze({ provider: authority.provider, principal,
    model: typeof model === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,223}$/.test(model) ? model : null,
    modelGroup: admissionModelGroup(authority.provider, model),
    requestId: crypto.randomUUID(), endpoint: authority.route, startedAt, retentionPolicy, cacheRevisions });
}

export async function nativeGenerationFetch(request, env, ctx, authority, fetcher, collaborators = []) {
  const path = authority.route ?? new URL(request.url).pathname;
  if (request.method !== "POST"
    || !/(?:\/(?:chat\/completions|responses|messages|embeddings|images\/(?:generations|edits))|:(?:generateContent|streamGenerateContent))$/.test(path)) {
    return fetcher(request, env, authority);
  }
  // The route has already authenticated the bootstrap key. Only public route metadata is trusted.
  const revision = nativeRevisionConsumer(env);
  tickNativeRevisionSync(env, ctx);
  const rejection = revision?.requireFreshSecurity();
  if (rejection) return rejection;
  const metrics = nativeMetricsEnabled(env);
  const admission = admissionSettings(env).enabled;
  const cacheEnabled = generationCacheSettings(env).enabled;
  const registrations = collaborators.filter(hook => typeof hook.enabled === "function" ? hook.enabled(env)
    : hook.flag ? ["true", "1", "yes", "on"].includes(String(env[hook.flag] ?? "").trim().toLowerCase()) : metrics);
  const owner = new UpstreamCancellation({ signal: request.signal, onOutcome: authority.onCancellationOutcome });
  if (!metrics && !admission && !revision && !resolveRetentionPolicy(env).enabled && !registrations.length && !cacheEnabled) {
    return dispatchNative(request, env, authority, fetcher, owner);
  }
  const context = await nativeContext(request, env, authority, metrics);
  let resolveDone;
  ctx?.waitUntil?.(new Promise(resolve => { resolveDone = resolve; }));
  const lifecycle = createGatewayLifecycle([...registrations, { async finalize(event) {
    try { if (metrics) await recordNativeUsage(env, event); }
    finally { resolveDone?.(); }
  } }]);
  const observation = { env, metrics, signal: owner.controller.signal,
    finalize: event => lifecycle.finalize({ ...event, cancellationOutcome: owner.outcome }) };
  try {
    await lifecycle.authorize(context);
    await lifecycle.admit(context);
    const cache = cacheEnabled ? await prepareNativeCache(request, env, authority, context) : null;
    const hit = await cache?.lookup();
    owner.throwIfAborted();
    if (hit) {
      owner.complete();
      await lifecycle.finalize(cacheServedEvent(hit, context));
      return hit;
    }
    const identity = admission ? { principal_hash: await principalHash((env.ADMIN_USERNAME || "admin").trim()),
      model_group: context.modelGroup, request_id: context.requestId,
      deadline_ms: Date.now() + 86_400_000 } : null;
    const dispatch = async () => {
      await lifecycle.before_dispatch(context);
      let response = await dispatchNative(request, env, authority, fetcher, owner);
      if (cache) response = await cache.store(response);
      await lifecycle.observe(context);
      return response;
    };
    const response = admission ? await runWithAdmission(identity, env, dispatch,
      { signal: request.signal, onLost: error => owner.close(error) }) : await dispatch();
    return await observeNativeResponse(response, context, observation);
  } catch (error) {
    await owner.close("interrupted");
    const status = error instanceof AdmissionError ? error.status : request.signal.aborted ? 499 : 502;
    await observeNativeResponse(new Response(null, { status }), context,
      { ...observation, outcome: request.signal.aborted ? "canceled" : "transport_error" });
    if (error instanceof AdmissionError && !request.signal.aborted) return error.response();
    throw error;
  }
}

export function withForwardedCorrelation(headers, env) {
  if (!nativeMetricsEnabled(env)) return headers;
  for (const key of ["x-multillm-principal", "x-multillm-request-id", "x-multillm-ledger-owner"]) headers.delete(key);
  headers.set("x-request-id", crypto.randomUUID());
  return headers;
}

export function withNativeMetrics(response, env) {
  return nativeMetricsEnabled(env) ? appendNativeMetrics(response) : response;
}

const CACHE_RESPONSE_HEADERS = new Set(["x-multillm-cache", "x-multillm-cache-backend", "x-multillm-usage-basis", "x-multillm-provider-calls", "age"]);
export function nativeCacheHeader(name, headers, env) {
  return generationCacheSettings(env).enabled && headers.get("X-MultiLLM-Cache-Backend") === "d1-r2" && CACHE_RESPONSE_HEADERS.has(name);
}
