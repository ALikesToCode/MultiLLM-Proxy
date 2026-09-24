import { digest } from "../evidence.mjs";
import { ProviderError } from "./errors.mjs";

const CREDENTIALS = { context7: "CONTEXT7_API_KEY", exa: "EXA_API_KEY", firecrawl: "FIRECRAWL_API_KEY", alexandria: "FIRECRAWL_API_KEY" };
const poolProvider = provider => provider === "alexandria" ? "firecrawl" : provider;
export const MAX_KEYS = 32;

export function configuredKeys(provider, env = {}) {
  const base = CREDENTIALS[provider];
  if (!base) return [];
  const numbered = new RegExp(`^${base}_(\\d+)$`);
  const names = Object.keys(env).filter(name => numbered.test(name)).sort((a, b) =>
    Number(a.slice(base.length + 1)) - Number(b.slice(base.length + 1)) || a.localeCompare(b));
  const seen = new Set();
  return [base, ...names].flatMap(name => {
    const key = typeof env[name] === "string" ? env[name].trim() : "";
    if (!key || seen.has(key)) return [];
    seen.add(key);
    return [{ name, key }];
  });
}

function authorizedOptions(provider, options, key) {
  const entries = options.headers instanceof Headers ? [...options.headers.entries()] : Object.entries(options.headers || {});
  const headers = Object.fromEntries(entries.filter(([name]) => !["authorization", "x-api-key"].includes(name.toLowerCase())));
  if (provider === "exa") headers["x-api-key"] = key;
  else headers.Authorization = `Bearer ${key}`;
  return { ...options, headers };
}

export async function withProviderKey(provider, options, context, send) {
  if (!CREDENTIALS[provider]) return send(options);
  const keys = configuredKeys(provider, context.env);
  if (!keys.length) throw new ProviderError(provider, "provider_not_configured", "The knowledge provider credential is not configured.", 503);
  if (keys.length > MAX_KEYS) throw new ProviderError(provider, "provider_key_limit", "Configure at most 32 distinct keys per provider.", 503);
  if (keys.length > 1 && !context.authority) throw new ProviderError(provider, "provider_key_state_required", "Multiple provider keys require the durable Knowledge catalogue.", 503);
  const pool = poolProvider(provider);
  const fingerprints = await Promise.all(keys.map(({ key }) => digest(`${pool}\0${key}`)));
  const attempted = new Set();
  while (attempted.size < keys.length) {
    if (context.signal?.aborted) throw new ProviderError(provider, "provider_timeout", "The knowledge provider request was cancelled or timed out.", 504);
    const selected = context.authority
      ? await context.authority.call("credentials.select", { provider: pool, fingerprints, excluded: [...attempted] })
      : { fingerprint: fingerprints[0] };
    if (!selected.fingerprint) break;
    const index = fingerprints.indexOf(selected.fingerprint);
    if (index < 0 || attempted.has(selected.fingerprint)) throw new ProviderError(provider, "provider_key_state_invalid", "The credential selection is unavailable.", 503);
    attempted.add(selected.fingerprint);
    if (context.signal?.aborted) throw new ProviderError(provider, "provider_timeout", "The knowledge provider request was cancelled or timed out.", 504);
    try { return await send(authorizedOptions(provider, options, keys[index].key)); }
    catch (error) {
      if (!(error instanceof ProviderError) || !error.key_rejection) throw error;
      if (context.authority) await context.authority.call("credentials.reject", {
        provider: pool, fingerprint: selected.fingerprint, ...error.key_rejection,
      });
      else throw error;
    }
  }
  const error = new ProviderError(provider, "provider_keys_exhausted", "All configured provider keys are exhausted or cooling down. Add capacity or wait for their reset window.", 429);
  error.no_charge = true;
  throw error;
}
