const FEATURE_NAMES = Object.freeze([
  "MODEL_COOLDOWN_ENABLED",
  "MODEL_PRICING_USD_PER_MILLION",
  "MULTILLM_STREAM_PREFLIGHT",
  "POOL_RESET_SCHEDULING_ENABLED",
  "PROMPT_CACHE_AFFINITY_ENABLED",
  "PROMPT_CACHE_USAGE_BUCKETS_ENABLED",
  "ROLEPLAY_CANDIDATE_CONTEXT_REFIT",
  "ROLEPLAY_HANDOFF_FROM",
  "ROLEPLAY_HANDOFF_TO",
  "UPSTREAM_RETRY_AFTER_ADVICE_ENABLED",
]);

/** Individual bindings retain precedence over the grouped nonsecret settings. */
export function runtimeFeatureValue(source, name) {
  if (!FEATURE_NAMES.includes(name)) return undefined;
  if (source[name] !== undefined) return source[name];
  const flags = source.RUNTIME_FEATURE_FLAGS;
  if (!flags || typeof flags !== "object" || Array.isArray(flags)
    || !Object.hasOwn(flags, name)) return undefined;
  const value = flags[name];
  return typeof value === "string" || typeof value === "boolean" ? value : undefined;
}

/** The operator's price table, from its own binding or the grouped settings. */
export function modelPricingTable(source = {}) {
  return runtimeFeatureValue(source, "MODEL_PRICING_USD_PER_MILLION");
}

const TIER_PRICE_NAMES = Object.freeze(["input", "output", "cache_read", "cache_write", "cache_write_1h"]);

/**
 * A price entry's long_context tier ({ above, prices }), or null without one. A
 * tier prices a whole request whose prompt, cache reads and writes included, is
 * over above_input_tokens. A malformed tier throws rather than being guessed around.
 */
export function longContextTier(entry) {
  if (!Object.hasOwn(entry, "long_context")) return null;
  const tier = entry.long_context;
  if (!tier || typeof tier !== "object" || Array.isArray(tier)) throw new TypeError("Invalid long_context price tier");
  const { above_input_tokens: above, ...prices } = tier;
  const names = Object.keys(prices);
  if (!Number.isSafeInteger(above) || above < 0 || !names.length || names.some(name => !TIER_PRICE_NAMES.includes(name)))
    throw new TypeError("Invalid long_context price tier");
  return { above, prices };
}

/** The entry's prices for a prompt of inputTokens, or null when its tier is malformed. */
export function pricesForPrompt(entry, inputTokens) {
  let tier;
  try { tier = longContextTier(entry); } catch { return null; }
  return tier && Number.isFinite(inputTokens) && inputTokens > tier.above ? { ...entry, ...tier.prices } : entry;
}

export function withRuntimeFeatureFlags(source = {}) {
  const resolved = { ...source };
  for (const name of FEATURE_NAMES) {
    const value = runtimeFeatureValue(source, name);
    if (value !== undefined) resolved[name] = value;
  }
  return resolved;
}
