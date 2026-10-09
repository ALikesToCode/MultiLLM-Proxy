import { governanceEnabled, GovernanceError } from "./tenant-governance-d1.mjs";
import { creditsEnforcement } from "./credits-d1.mjs";
import { CreditsAdmissionError } from "./credits-admission.mjs";
/** Static registration boundary for native dispatch; later integrations supply named hooks. */
import { organisationsEnabled, resolveAccountTenant, tenantNamespace, TenantError } from "./tenants-d1.mjs";
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
export { handleRealtimeRequest } from "./realtime.mjs";
import { UpstreamCancellation } from "./upstream-cancellation.mjs";
import { prepareLatencySLO, latencySLOSettings, recordLatencyObservation } from "./latency-slo.mjs";
import { prepareStreamCostBreaker, wrapStreamCost, streamCostEnabled, STREAM_CAP_FIELD } from "./stream-cost-breaker.mjs";
import { prepareRequest, finalizeResponse, resolvePolicy as resolveCanaryPolicy, ContextCanaryError } from "./context-canary.mjs";
import { boundedBody } from "./control-users-d1.mjs";
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
    ...((organisationsEnabled(env) || authority.tenantContext) ? { tenantContext: authority.tenantContext, tenantNamespace: tenantNamespace(authority.tenantContext) } : {}),
    modelGroup: admissionModelGroup(authority.provider, model),
    requestId: crypto.randomUUID(), endpoint: authority.route, startedAt, retentionPolicy, cacheRevisions });
}

class NativeGenerationRejection extends Error {
  constructor(response) { super("Native generation rejected"); this.rejection = response; }
  response() { return this.rejection; }
}

export function generationErrorResponse(error) {
  if (error instanceof GovernanceError) return Response.json({ error: { code: error.code,
    message: "Workspace governance denied generation", ...error.details } }, { status: error.status });
  return error instanceof GenerationDeadlineExceeded || error instanceof InvalidGenerationDeadline
    || error instanceof CreditsAdmissionError || error instanceof ReservationError || error instanceof AdmissionError || error instanceof NativeGenerationRejection ? error.response() : null;
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

function canonicalModel(provider, model) {
  return typeof model === "string" && !model.includes(":") ? `${provider}:${model}` : model;
}

function dispatchPayload(request, payload) {
  const headers = new Headers(request.headers); headers.delete("content-length");
  return new Request(request, { headers, body: JSON.stringify(payload) });
}

async function nativeStreamPolicy(request, env, authority, context, payload, invalidPayload, settings, protocol, race) {
  const streaming = request.url.includes(":streamGenerateContent") || payload?.stream === true;
  if (!settings.streamCost || !streaming && !invalidPayload) return null;
  let user = authority.principal;
  if (user?.id && !Object.hasOwn(user, STREAM_CAP_FIELD) && env.INTELLIGENCE_DB) {
    try {
      const stored = await race(() => env.INTELLIGENCE_DB.prepare(`SELECT max_stream_cost_microusd FROM control_users
        WHERE username = ? AND is_admin = 1 AND revoked_at IS NULL`).bind(user.id).first());
      user = { ...user, [STREAM_CAP_FIELD]: stored?.[STREAM_CAP_FIELD] ?? null };
    } catch (error) {
      if (generationErrorResponse(error) || request.signal.aborted) throw error;
      throw new NativeGenerationRejection(Response.json({ error: { code: "stream_cost_storage_unavailable" } }, { status: 503 }));
    }
  }
  if (invalidPayload && user?.[STREAM_CAP_FIELD] != null) throw new NativeGenerationRejection(
    Response.json({ error: { code: "stream_cost_unpriced" } }, { status: 503 }));
  if (!streaming) return null;
  const models = authority.eligibleModels ?? [context.model];
  try {
    return prepareStreamCostBreaker(env, user, models.map(model => canonicalModel(context.provider, model)),
      new TextEncoder().encode(JSON.stringify(payload ?? {})).byteLength + (settings.canary ? 256 : 0), protocol === "messages" ? "anthropic" : protocol);
  } catch (error) {
    throw new NativeGenerationRejection(Response.json({ error: { code: error.code,
      message: "Stream cost enforcement could not admit this request" } }, { status: error.status ?? 503 }));
  }
}

async function prepareNativePolicies(request, env, authority, context, settings, hook, race) {
  if (!settings.latency && !settings.streamCost && !settings.canary)
    return { request, authority, context, streamCost: null, canary: null, dispatchRequest: request };
  let payload, invalidPayload = false;
  const route = authority.route ?? context.endpoint ?? new URL(request.url).pathname;
  const protocol = route.endsWith("/messages") ? "messages" : route.endsWith("/responses") ? "responses" : "chat";
  const latency = settings.latency ? await race(() => prepareLatencySLO(request, env, { ...authority,
    model: canonicalModel(context.provider, context.model), keyId: authority.keyId ?? authority.principal?.id,
    deadline: hook.deadline })) : null;
  if (latency?.response) throw new NativeGenerationRejection(latency.response);
  if (latency?.action === "reroute") {
    authority = { ...authority, candidates: latency.candidates, eligibleModels: latency.candidates.map(item => item.model) };
    payload = JSON.parse(await race(() => boundedBody(request.clone(), PARSER_LIMIT)));
    payload = { ...payload, model: latency.candidates[0].model };
    request = dispatchPayload(request, payload);
    const prefix = context.provider + ":";
    context = { ...context, model: payload.model.startsWith(prefix) ? payload.model.slice(prefix.length) : payload.model,
      modelGroup: payload.model };
  }
  if (settings.streamCost || settings.canary) {
    try { payload ??= JSON.parse(await race(() => boundedBody(request.clone(), PARSER_LIMIT))); }
    catch (error) {
      if (generationErrorResponse(error) || request.signal.aborted) throw error;
      if (settings.canary) throw new ContextCanaryError();
      invalidPayload = true;
    }
  }
  const streamCost = await nativeStreamPolicy(request, env, authority, context, payload, invalidPayload, settings, protocol, race);
  let prepared = { context: null };
  if (settings.canary) {
    payload ??= JSON.parse(await race(() => boundedBody(request.clone(), PARSER_LIMIT)));
    prepared = await race(() => prepareRequest(payload, env, { route,
      keyScope: authority.keyId ?? authority.principal?.id ?? "", protocol }));
  }
  return { request, authority, context, streamCost, canary: prepared.context,
    dispatchRequest: prepared.context ? dispatchPayload(request, prepared.payload) : request };
}

async function protectNativeResponse(response, state) {
  const { owner, accounting } = state;
  response = await finalizeResponse(response, state.canary, { signal: state.request.signal,
    cancel: reason => owner.close(reason), accounting });
  if (state.streamCost && response.body && response.headers.get("content-type")?.includes("text/event-stream")) {
    const headers = new Headers(response.headers); headers.delete("content-length");
    response = new Response(wrapStreamCost(response.body, state.streamCost, {
      abort: () => owner.close("stream_cost_cap_exceeded"),
      onFinal: result => { accounting.ambiguous ||= result.exceeded || !result.finalUsage; },
    }), { status: response.status, statusText: response.statusText, headers });
  }
  return response;
}

async function dispatchWithNativeHooks(request, env, authority, fetcher, state) {
  const { lifecycle, context, owner, hook, reservation, cacheEnabled, race } = state;
  const cache = cacheEnabled && !state.canary ? await race(() => prepareNativeCache(request, env, authority, context)) : null;
  let hit = await race(() => cache?.lookup());
  if (!hit && state.semanticEnabled && !state.canary) {
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
  let response = hook.deadline ? await hook.fetch(upstream => fetcher(upstream, env, state.authority), state.dispatchRequest)
    : await dispatchNative(state.dispatchRequest, env, state.authority, fetcher, owner);
  // Observe before optional storage, so failed lifecycle checks cannot persist a success.
  if (!state.canary && !state.streamCost && response.status < 400) await race(() => lifecycle.observe(context));
  if (cache) response = await cache.store(response, { canStore: () => !owner.outcome?.ambiguous });
  return response;
}

function classifyNativeEvent(event, accounting, policies, owner) {
  const uncertain = accounting.ambiguous || policies?.canary?.ambiguous || policies?.streamCost?.exceeded;
  return { ...event, ...(uncertain ? { outcome: "canceled", status: 499, usage_basis: "unknown",
    cost_usd: null, cost_basis: null } : {}),
    cancellationOutcome: uncertain ? { ...owner.outcome, ambiguous: true, replayPermission: false } : owner.outcome,
    handedOff: owner.handedOff };
}

function nativeFinalizers(env, ctx, settings, reservation, complete) {
  const metrics = async event => {
    if (settings.metrics) await recordNativeUsage(env,
      settings.semantic && event.cost_basis === "cache" ? { ...event, cost_basis: null } : event, ctx);
  };
  const settlement = event => reservation?.finalize(event);
  const current = settings.latency || settings.streamCost || settings.canary;
  return [{ finalize: current ? metrics : settlement }, { async finalize(event) {
    try { await (current ? settlement : metrics)(event); } finally { complete(); }
  } }];
}

async function runNativeLifecycle(request, env, ctx, authority, fetcher, registrations, settings, hook) {
  const owner = hook.owner;
  const race = action => hook.deadline ? hook.deadline.run(action, owner) : action();
  let context, lifecycle, resolveDone, classified, policies;
  const accounting = { ambiguous: false };
  let reservation;
  const classifyEvent = event => classifyNativeEvent(event, accounting, policies, owner);
  const finish = async event => {
    event = classifyEvent(event);
    if (settings.latency) recordLatencyObservation(event, env, { observations: authority.observations, now: authority.now });
    await lifecycle.finalize(event);
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
    policies = await prepareNativePolicies(request, env, authority, context, settings, hook, race);
    request = policies.request; authority = policies.authority; context = policies.context;
    reservation = (settings.reservations || settings.enterprise) ? nativeReservationLifecycle(policies.dispatchRequest, env, authority) : null;
    if (["baseline", "candidate"].includes(authority.canary?.cohort)
        && ["shadow", "live"].includes(authority.canary?.mode)) {
      context = { ...context, canary: { cohort: authority.canary.cohort, mode: authority.canary.mode } };
    }
    ctx?.waitUntil?.(new Promise(resolve => { resolveDone = resolve; }));
    lifecycle = createGatewayLifecycle([...registrations, ...nativeFinalizers(env, ctx, settings, reservation,
      () => { hook.deadline?.stop(); resolveDone?.(); })]);
    await race(() => reservation?.authorize?.(context));
    await race(() => lifecycle.authorize(context));
    await race(() => lifecycle.admit(context));
    if (settings.enterprise) await race(() => reservation.admit(context));
    const state = { ...policies, lifecycle: { ...lifecycle, finalize: finish }, context, owner, hook, reservation,
      cacheEnabled: settings.cache, semanticEnabled: settings.semantic, race, ctx, accounting };
    const dispatch = () => dispatchWithNativeHooks(request, env, authority, fetcher, state);
    const identity = settings.admission ? { principal_hash: await principalHash((env.ADMIN_USERNAME || "admin").trim()),
      model_group: context.modelGroup, request_id: context.requestId,
      deadline_ms: Date.now() + (hook.deadline?.remainingMs() ?? 86_400_000) } : null;
    let response = await race(() => identity ? runWithAdmission(identity, env, dispatch,
      { signal: policies.canary || policies.streamCost ? request.signal : owner.controller.signal,
        onLost: error => owner.close(error) }) : dispatch());
    // Policy stops own upstream cancellation but must still deliver their protocol error.
    // Inspect after the header deadline race and keep admission tied to caller cancellation.
    response = await protectNativeResponse(response, state);
    if ((policies.canary || policies.streamCost) && response.status < 400)
      await lifecycle.observe(context);
    applyInjectionHeader(response.headers, injection);
    if (["hit", "semantic-hit"].includes(response.headers.get("X-MultiLLM-Cache"))) return response;
    const observed = await observeNativeResponse(response, context, { env, metrics: settings.metrics,
      canary: context.canary, signal: hook.deadline || policies.canary || policies.streamCost ? request.signal : owner.controller.signal,
      classifyEvent: settings.latency || settings.streamCost || settings.canary ? classifyEvent : undefined, finalize: finish });
    return state.semantic ? await state.semantic.store(observed, { canStore: () => classified?.outcome === "success"
      && !owner.outcome?.ambiguous && !request.signal.aborted }) : observed;
  } catch (error) {
    hook.deadline?.stop();
    await owner.close("interrupted");
    const rejection = error instanceof ContextCanaryError ? Response.json({ error: { code: error.code,
      message: "Managed response inspection stopped generation" } }, { status: 502 }) : generationErrorResponse(error);
    if (!lifecycle && reservation) await reservation.finalize({ ...context, handedOff: false });
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
  let enterprise = authority.authenticated === true && (governanceEnabled(env) || creditsEnforcement(env) !== "off");
  if ((organisationsEnabled(env) || enterprise) && authority.authenticated === true) {
    try {
      const tenantContext = await resolveAccountTenant(env.INTELLIGENCE_DB, authority.principal?.id ?? authority.keyId, env);
      authority = { ...authority, tenantContext, tenantNamespace: tenantNamespace(tenantContext) };
    } catch (error) {
      authority.deadlineHook?.deadline?.stop();
      if (error instanceof TenantError) return error.response();
      throw error;
    }
  }
  enterprise = authority.authenticated === true && (creditsEnforcement(env) !== "off"
    || governanceEnabled(env) && authority.tenantContext?.org_id != null);
  // The route has already authenticated the bootstrap key. Only public route metadata is trusted.
  const revision = nativeRevisionConsumer(env);
  tickNativeRevisionSync(env, ctx);
  const rejection = revision?.requireFreshSecurity();
  if (rejection) { authority.deadlineHook?.deadline?.stop(); return rejection; }
  const settings = { enterprise, metrics: nativeMetricsEnabled(env), admission: admissionSettings(env).enabled,
    cache: generationCacheSettings(env).enabled, reservations: reservationSettings(env).enabled,
    semantic: semanticCacheSettings(env).enabled, observability: observabilityEnabled(env),
    injection: resolveInjectionPolicy(env).mode !== "off",
    latency: latencySLOSettings(env).mode !== "off" && authority.authenticated === true && !authority.passthrough,
    streamCost: streamCostEnabled(env) && authority.authenticated === true && !authority.passthrough,
    canary: authority.authenticated === true && !authority.passthrough && /\/(?:chat\/completions|messages|responses)$/.test(path)
      && Boolean(resolveCanaryPolicy(env, { route: path, keyScope: authority.keyId ?? authority.principal?.id ?? "" })) };
  const registrations = collaborators.filter(hook => typeof hook.enabled === "function" ? hook.enabled(env)
    : hook.flag ? ["true", "1", "yes", "on"].includes(String(env[hook.flag] ?? "").trim().toLowerCase()) : settings.metrics);
  if (settings.observability) registrations.push(createNativeObservabilityHook(env, ctx));
  let hook;
  try { hook = authority.deadlineHook ?? generationDeadlineHook(request, env, { onOutcome: authority.onCancellationOutcome,
    protocol: path.endsWith("/messages") ? "anthropic" : path.endsWith("/responses") ? "responses" : "chat" }); }
  catch (error) { const response = generationErrorResponse(error); if (response) return response; throw error; }
  if (authority.onCancellationOutcome) hook.owner.onOutcome = authority.onCancellationOutcome;
  if (!settings.metrics && !settings.admission && !revision && !resolveRetentionPolicy(env).enabled
      && !registrations.length && !settings.cache && !settings.reservations && !settings.enterprise && !settings.semantic && !settings.injection && !settings.latency && !settings.streamCost && !settings.canary && !hook.deadline) {
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
