/** Static registration boundary for native dispatch; later integrations supply named hooks. */
import { generationCacheSettings, prepareNativeCache, cacheServedEvent } from "./exact-generation-cache.mjs";
import { createGatewayLifecycle } from "./gateway-lifecycle.mjs";
import { observeNativeResponse, appendNativeMetrics, PARSER_LIMIT } from "./request-telemetry.mjs";
import { recordNativeUsage } from "./usage-ledger-d1.mjs";
import { admissionSettings, admissionModelGroup, principalHash, runWithAdmission, AdmissionError } from "./admission-do.mjs";
import { resolveRetentionPolicy, retentionRequestId } from "./retention-policy.mjs";
import { nativeRevisionConsumer, tickNativeRevisionSync } from "./native-config-sync.mjs";
import { generationDeadlineHook, createGenerationDeadline, forwardedDeadlineHeaders, GenerationDeadlineExceeded, InvalidGenerationDeadline } from "./generation-deadline.mjs";
import { nativeReservationLifecycle, reservationSettings, ReservationError } from "./reservations-d1.mjs";
export { runScheduledMaintenance, scheduledMaintenanceEnabled } from "./scheduled-maintenance.mjs";
export { handleResponsesStateRequest, responsesStateEnabled } from "./responses-state-d1.mjs";
import { UpstreamCancellation } from "./upstream-cancellation.mjs";
import { prepareSemanticCache, semanticCacheSettings, createNativeSemanticCollaborators } from "./semantic-generation-cache.mjs";
import { createNativeObservabilityHook, observabilityEnabled } from "./observability-export.mjs";
import { prepareNativePromptInjection, resolveInjectionPolicy, applyInjectionHeader } from "./prompt-injection-detection.mjs";

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
  const model = await requestedModel(request) ?? new URL(request.url).pathname.match(/\/models\/([^/]+):(?:generateContent|streamGenerateContent)$/)?.[1] ?? null;
  const revision = nativeRevisionConsumer(env);
  const cacheRevisions = () => revision ? Object.fromEntries(Object.entries(revision.status().domains)
    .map(([name, state]) => [name, state.revision])) : {};
  return Object.freeze({ provider: authority.provider, principal,
    model: typeof model === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,223}$/.test(model) ? model : null,
    modelGroup: admissionModelGroup(authority.provider, model),
    requestId: crypto.randomUUID(), endpoint: authority.route, startedAt, retentionPolicy, cacheRevisions });
}

class NativeGenerationRejection extends Error {
  constructor(response) { super("Native generation rejected"); this.rejection = response; }
  response() { return this.rejection; }
}

export function generationErrorResponse(error) {
  return error instanceof GenerationDeadlineExceeded || error instanceof InvalidGenerationDeadline
    || error instanceof ReservationError || error instanceof AdmissionError || error instanceof NativeGenerationRejection ? error.response() : null;
}

export function forwardedGenerationHeaders(request, env, deadline = createGenerationDeadline(request, env)) {
  return forwardedDeadlineHeaders(request.headers, deadline);
}

export function nativeGenerationSetup(request, env) {
  const path = new URL(request.url).pathname;
  if (!generationPath(request, path)) return { hook: null, run: action => action() };
  const rejection = nativeRevisionConsumer(env)?.requireFreshSecurity();
  if (rejection) throw new NativeGenerationRejection(rejection);
  if (!request.headers.has("X-MultiLLM-Deadline-Ms")) return { hook: null, run: action => action() };
  const hook = generationDeadlineHook(request, env, { protocol: path.endsWith("/messages") ? "anthropic" : path.endsWith("/responses") ? "responses" : "chat" });
  return { hook, run(action) {
    const pending = (async () => {
      try { return hook.deadline ? await hook.deadline.run(action, hook.owner) : await action(); }
      catch (error) { hook.deadline?.stop(); await hook.owner.close("interrupted"); throw error; }
    })();
    // Concurrent metadata setup can finish after the caller has already returned an error.
    void pending.catch(() => {});
    return pending;
  } };
}

function generationPath(request, path) {
  return request.method === "POST"
    && /(?:\/(?:chat\/completions|responses|messages|embeddings|images\/(?:generations|edits))|:(?:generateContent|streamGenerateContent))$/.test(path);
}

async function dispatchWithNativeHooks(request, env, authority, fetcher, state) {
  const { lifecycle, context, owner, hook, reservation, cacheEnabled, race } = state;
  const cache = cacheEnabled ? await race(() => prepareNativeCache(request, env, authority, context)) : null;
  let hit = await race(() => cache?.lookup());
  if (!hit && state.semanticEnabled) {
    const semanticRequest = new Request(request.clone(), { signal: owner.controller.signal });
    state.semantic = await race(() => prepareSemanticCache(semanticRequest, env, authority, context,
      authority.semanticCollaborators ?? createNativeSemanticCollaborators(request, env, state.ctx, authority, fetcher, context)));
    hit = await race(() => state.semantic?.lookup());
    if (hit?.status >= 400) throw new NativeGenerationRejection(hit);
  }
  owner.throwIfAborted();
  await race(() => reservation?.admit({ ...context, cacheServed: Boolean(hit) }));
  owner.throwIfAborted();
  if (hit) {
    owner.complete();
    await lifecycle.finalize(cacheServedEvent(hit, context));
    return hit;
  }
  await race(() => lifecycle.before_dispatch(context));
  owner.throwIfAborted(); hook.deadline?.check();
  await race(() => reservation?.before_dispatch(context));
  owner.throwIfAborted(); hook.deadline?.check();
  let response = hook.deadline ? await hook.fetch(upstream => fetcher(upstream, env, authority), request)
    : await dispatchNative(request, env, authority, fetcher, owner);
  // Observe before optional storage, so failed lifecycle checks cannot persist a success.
  if (response.status < 400) await race(() => lifecycle.observe(context));
  if (cache) response = await cache.store(response, { canStore: () => !owner.outcome?.ambiguous });
  return response;
}

async function runNativeLifecycle(request, env, ctx, authority, fetcher, registrations, settings, hook) {
  const owner = hook.owner;
  const race = action => hook.deadline ? hook.deadline.run(action, owner) : action();
  let context, lifecycle, resolveDone, classified;
  const reservation = settings.reservations ? nativeReservationLifecycle(request, env, authority) : null;
  const finish = async event => {
    await lifecycle.finalize({ ...event, cancellationOutcome: owner.outcome, handedOff: owner.handedOff });
    classified = event;
  };
  try {
    context = await race(() => nativeContext(request, env, authority, settings.metrics || settings.observability));
    const injection = settings.injection ? await race(() => prepareNativePromptInjection(request, env, authority)) : null;
    if (injection?.action === "blocked") {
      hook.deadline?.stop(); owner.complete();
      const response = Response.json({ error: { code: "prompt_injection_suspected",
        message: "Prompt injection heuristics exceeded the configured threshold" } }, { status: 422 });
      applyInjectionHeader(response.headers, injection);
      return response;
    }
    if (["baseline", "candidate"].includes(authority.canary?.cohort)
        && ["shadow", "live"].includes(authority.canary?.mode)) {
      context = { ...context, canary: { cohort: authority.canary.cohort, mode: authority.canary.mode } };
    }
    ctx?.waitUntil?.(new Promise(resolve => { resolveDone = resolve; }));
    lifecycle = createGatewayLifecycle([...registrations, { finalize: event => reservation?.finalize(event) }, { async finalize(event) {
      try { if (settings.metrics) await recordNativeUsage(env,
        settings.semantic && event.cost_basis === "cache" ? { ...event, cost_basis: null } : event, ctx); }
      finally { hook.deadline?.stop(); resolveDone?.(); }
    } }]);
    await race(() => lifecycle.authorize(context));
    await race(() => lifecycle.admit(context));
    const state = { lifecycle: { ...lifecycle, finalize: finish }, context, owner, hook, reservation,
      cacheEnabled: settings.cache, semanticEnabled: settings.semantic, race, ctx };
    const dispatch = () => dispatchWithNativeHooks(request, env, authority, fetcher, state);
    const identity = settings.admission ? { principal_hash: await principalHash((env.ADMIN_USERNAME || "admin").trim()),
      model_group: context.modelGroup, request_id: context.requestId,
      deadline_ms: Date.now() + (hook.deadline?.remainingMs() ?? 86_400_000) } : null;
    const response = await race(() => identity ? runWithAdmission(identity, env, dispatch,
      { signal: owner.controller.signal, onLost: error => owner.close(error) }) : dispatch());
    applyInjectionHeader(response.headers, injection);
    if (["hit", "semantic-hit"].includes(response.headers.get("X-MultiLLM-Cache"))) return response;
    const observed = await observeNativeResponse(response, context, { env, metrics: settings.metrics,
      canary: context.canary, signal: hook.deadline ? request.signal : owner.controller.signal, finalize: finish });
    return state.semantic ? await state.semantic.store(observed, { canStore: () => classified?.outcome === "success"
      && !owner.outcome?.ambiguous && !request.signal.aborted }) : observed;
  } catch (error) {
    hook.deadline?.stop();
    await owner.close("interrupted");
    const rejection = generationErrorResponse(error);
    if (lifecycle) await finish({ ...context, status: rejection?.status ?? (request.signal.aborted ? 499 : 502),
      outcome: request.signal.aborted ? "canceled" : "transport_error", input_tokens: null, output_tokens: null,
      duration_ms: Math.max(0, Math.round(performance.now() - context.startedAt)), ttft_ms: null, cost_usd: null, cost_basis: null });
    if (rejection && !request.signal.aborted) return rejection;
    throw error;
  }
}

export async function nativeGenerationFetch(request, env, ctx, authority, fetcher, collaborators = []) {
  const path = authority.route ?? new URL(request.url).pathname;
  if (!generationPath(request, path)) return fetcher(request, env, authority);
  // The route has already authenticated the bootstrap key. Only public route metadata is trusted.
  const revision = nativeRevisionConsumer(env);
  tickNativeRevisionSync(env, ctx);
  const rejection = revision?.requireFreshSecurity();
  if (rejection) { authority.deadlineHook?.deadline?.stop(); return rejection; }
  const settings = { metrics: nativeMetricsEnabled(env), admission: admissionSettings(env).enabled,
    cache: generationCacheSettings(env).enabled, reservations: reservationSettings(env).enabled,
    semantic: semanticCacheSettings(env).enabled, observability: observabilityEnabled(env),
    injection: resolveInjectionPolicy(env).mode !== "off" };
  const registrations = collaborators.filter(hook => typeof hook.enabled === "function" ? hook.enabled(env)
    : hook.flag ? ["true", "1", "yes", "on"].includes(String(env[hook.flag] ?? "").trim().toLowerCase()) : settings.metrics);
  if (settings.observability) registrations.push(createNativeObservabilityHook(env, ctx));
  let hook;
  try { hook = authority.deadlineHook ?? generationDeadlineHook(request, env, { onOutcome: authority.onCancellationOutcome,
    protocol: path.endsWith("/messages") ? "anthropic" : path.endsWith("/responses") ? "responses" : "chat" }); }
  catch (error) { const response = generationErrorResponse(error); if (response) return response; throw error; }
  if (authority.onCancellationOutcome) hook.owner.onOutcome = authority.onCancellationOutcome;
  if (!settings.metrics && !settings.admission && !revision && !resolveRetentionPolicy(env).enabled
      && !registrations.length && !settings.cache && !settings.reservations && !settings.semantic && !settings.injection && !hook.deadline) {
    return dispatchNative(request, env, authority, fetcher, hook.owner);
  }
  return runNativeLifecycle(request, env, ctx, authority, fetcher, registrations, settings, hook);
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
  if (name === "x-multillm-injection-action") return resolveInjectionPolicy(env).mode !== "off";
  return CACHE_RESPONSE_HEADERS.has(name) && (generationCacheSettings(env).enabled && headers.get("X-MultiLLM-Cache-Backend") === "d1-r2"
    || semanticCacheSettings(env).enabled && headers.get("X-MultiLLM-Cache-Backend") === "semantic-d1-r2");
}
export { handleRoleplayContextPageRequest } from "./context-pages-d1.mjs";
