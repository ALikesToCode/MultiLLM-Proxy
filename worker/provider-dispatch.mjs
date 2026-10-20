import { KEY_CONTROLS } from "./key-controls-capability.mjs";
/** Sole provider network boundary. Deferred work carries identity, never cached policy. */
import { AsyncLocalStorage } from "node:async_hooks";
import { currentDataControls, legacyDataControls, mergePreferences, parsePreferences, providerClassPermitted } from "./key-data-guards.mjs";
import { admittedNetwork } from "./dispatch-network.mjs";
import { dataPolicy } from "./dispatch-policy.mjs";

const context = new AsyncLocalStorage();
export const dispatchContext = () => context.getStore();
export const withDispatchPrincipal = (env, authority, run) => context.run({ env, authority }, run);
export class DispatchError extends Error {
  constructor(code, status = 503) { super(code); this.code = code; this.status = status; }
}
export const dispatchFailure = error => Response.json({ error: { code: error.code ?? "key_data_controls_unavailable" } },
  { status: error.status ?? 503 });

export function bindingPrincipal(request, legacyId) {
  if (!request.headers.has("X-MultiLLM-Dispatch-Principal")) {
    return legacyId ? { authenticated: true, keyId: legacyId } : { legacyBinding: true };
  }
  try {
    const value = JSON.parse(request.headers.get("X-MultiLLM-Dispatch-Principal"));
    if (value.version !== 1 || typeof value.username !== "string" || !value.username
      || Object.keys(value).sort().join() !== "username,version") throw Error();
    return { authenticated: true, keyId: value.username };
  } catch { throw new DispatchError("key_data_controls_unavailable"); }
}

async function admission(provider, options) {
  const state = options.env ? options : dispatchContext();
  try {
    if (!KEY_CONTROLS.enforcement && state?.env && (!state.authority || state.authority.legacyBinding)) {
      return { ...state, policy: await legacyDataControls(state.env) };
    }
    if (!state?.authority || state.authority.authenticated !== true) throw Error();
    const user = await currentDataControls(state.env, state.authority);
    const policy = dataPolicy(user);
    if (!providerClassPermitted(policy, provider, state.env)) throw new DispatchError("provider_class_not_allowed", 403);
    return { ...state, policy };
  } catch (error) {
    if (error instanceof DispatchError) throw error;
    throw new DispatchError("key_data_controls_unavailable");
  }
}

const apiOrigins = {
  openai: "https://api.openai.com", anthropic: "https://api.anthropic.com", xai: "https://api.x.ai",
  gemini: "https://generativelanguage.googleapis.com", gemma: "https://generativelanguage.googleapis.com",
  openrouter: "https://openrouter.ai", cerebras: "https://api.cerebras.ai", groq: "https://api.groq.com",
  together: "https://api.together.xyz", azure: "https://models.inference.ai.azure.com",
  hyperbolic: "https://api.hyperbolic.xyz", sambanova: "https://api.sambanova.ai", scaleway: "https://api.scaleway.ai",
  opencode: "https://opencode.ai", nanogpt: "https://nano-gpt.com", linkapi: "https://hk.linkapi.ai",
};
function apiOrigin(provider, url, env, options) {
  const prefix = provider.toUpperCase().replaceAll("-", "_");
  const configured = env[`${prefix}_BASE_URL`] ?? (provider === "opencode" ? env.OPENCODE_GO_BASE_URL : null);
  try {
    const allowed = [apiOrigins[provider], configured].filter(Boolean).map(value => new URL(value).origin);
    if (options.realtime) {
      for (const [model, entry] of Object.entries(JSON.parse(env.REALTIME_PROVIDERS_JSON ?? "{}"))) {
        if (!model.startsWith(provider + ":")) continue;
        const endpoint = new URL(entry.url);
        if (endpoint.protocol !== "wss:" || endpoint.username || endpoint.password) continue;
        endpoint.protocol = "https:";
        allowed.push(endpoint.origin);
      }
    }
    return url.protocol === "https:" && !url.username && !url.password && allowed.includes(url.origin);
  } catch { return false; }
}

function credentials(provider, request, env, policy, options) {
  if (!policy.official_only && policy.forced_provider_preferences === null || provider === "cloudflare") return request;
  const url = new URL(request.url);
  if ([...url.searchParams.keys()].some(name => name.toLowerCase() === "key")) {
    throw new DispatchError("provider_credential_not_allowed", 403);
  }
  if (!apiOrigin(provider, url, env, options)) throw new DispatchError("attested_credential_unavailable");
  const names = { gemini: ["GEMINI_API_KEY"], opencode: ["OPENCODE_GO_API_KEY", "OPENCODE_API_KEY"] }[provider]
    ?? [`${provider.toUpperCase().replaceAll("-", "_")}_API_KEY`];
  const key = names.map(name => env[name]).find(value => typeof value === "string" && value.trim()
    && !/^(?:your[-_]|changeme|replace[-_]?me|<)/i.test(value));
  if (!key) throw new DispatchError("attested_credential_unavailable");
  const headers = new Headers(request.headers);
  for (const name of ["authorization", "x-api-key", "x-goog-api-key", "api-key"]) headers.delete(name);
  const name = { gemini: "x-goog-api-key", anthropic: "x-api-key", azure: "api-key" }[provider] ?? "authorization";
  headers.set(name, name === "authorization" ? `Bearer ${key}` : key);
  return new Request(request, { headers });
}

export async function providerFetch(provider, input, init = {}, options = {}) {
  const state = await admission(provider, options);
  if (!KEY_CONTROLS.enforcement) return admittedNetwork(() => (options.send ?? fetch)(new Request(input, init)));
  const forced = parsePreferences(state.policy.forced_provider_preferences);
  if ((options.realtime || options.unsupportedPreferences) && forced !== null) throw new DispatchError("forced_provider_preferences_not_supported", 403);
  let request = new Request(input, init);
  if (options.publicAsset) {
    const headers = new Headers(request.headers);
    for (const name of ["authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie"]) headers.delete(name);
    request = new Request(request, { headers });
  } else request = credentials(provider, request, state.env, state.policy, options);
  if (provider === "openrouter" && forced !== null && request.body) {
    let payload;
    try { payload = await request.clone().json(); if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw Error(); }
    catch { throw new DispatchError("invalid_request", 400); }
    payload.provider = mergePreferences(payload.provider, forced);
    const headers = new Headers(request.headers); headers.delete("content-length");
    request = new Request(request, { headers, body: JSON.stringify(payload) });
  }
  const headers = new Headers(request.headers); headers.delete("x-multillm-dispatch-principal");
  request = new Request(request, { headers, redirect: "manual" });
  return admittedNetwork(() => (options.send ?? fetch)(request));
}

/** SDK/binding calls use the same admission, including embeddings and background work. */
export async function providerOperation(provider, run, options = {}) {
  const state = await admission(provider, options);
  if (provider === "openrouter" && state.policy.forced_provider_preferences !== null) {
    throw new DispatchError("forced_provider_preferences_not_supported", 403);
  }
  return admittedNetwork(run);
}

/** Keep adapter transports compatible while passing only the admitted request. */
export async function transportOptions(request, original = {}) {
  const headers = {};
  for (const [name, value] of request.headers) {
    const spelling = Object.keys(original.headers ?? {}).find(key => key.toLowerCase() === name) ?? name;
    headers[spelling] = value;
  }
  return { ...original, method: request.method, headers, body: request.body ? await request.text() : undefined,
    signal: request.signal, redirect: request.redirect };
}
