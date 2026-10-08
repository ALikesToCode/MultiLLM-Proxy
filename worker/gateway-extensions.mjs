/** Static registration boundary for native dispatch; later integrations supply named hooks. */
import { createGatewayLifecycle } from "./gateway-lifecycle.mjs";
import { observeNativeResponse, appendNativeMetrics, PARSER_LIMIT } from "./request-telemetry.mjs";
import { recordNativeUsage } from "./usage-ledger-d1.mjs";

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
    return typeof model === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,223}$/.test(model) ? model : null;
  } catch { return null; }
  finally { void reader.cancel().catch(() => {}); }
}

export async function nativeGenerationFetch(request, env, ctx, authority, fetcher, collaborators = []) {
  const path = new URL(request.url).pathname;
  if (!nativeMetricsEnabled(env) || request.method !== "POST"
    || !/\/(?:chat\/completions|responses|messages|embeddings|images\/generations)$/.test(path)) {
    return fetcher(request, env, authority);
  }
  // This call site is after native route authentication. Ignore all client identity labels.
  const startedAt = performance.now();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`native-admin:${authority.principal.id}`));
  const principal = `edge:${[...new Uint8Array(digest)].map(n => n.toString(16).padStart(2, "0")).join("")}`;
  const context = Object.freeze({ provider: authority.provider, principal, model: await requestedModel(request),
    requestId: crypto.randomUUID(), endpoint: authority.route, startedAt });
  let resolveDone;
  const done = new Promise(resolve => { resolveDone = resolve; });
  ctx?.waitUntil?.(done);
  const lifecycle = createGatewayLifecycle([...collaborators, { async finalize(event) {
    try { await recordNativeUsage(env, event); }
    finally { resolveDone(); }
  } }]);
  try {
    await lifecycle.authorize(context); await lifecycle.admit(context); await lifecycle.before_dispatch(context);
    const response = await fetcher(request, env, authority);
    await lifecycle.observe(context);
    return await observeNativeResponse(response, context, { env, signal: request.signal, finalize: event => lifecycle.finalize(event) });
  } catch (error) {
    await observeNativeResponse(new Response(null, { status: request.signal.aborted ? 499 : 502 }), context,
      { env, outcome: request.signal.aborted ? "canceled" : "transport_error", finalize: event => lifecycle.finalize(event) });
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
