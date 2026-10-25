const FEATURE_NAMES = Object.freeze([
  "MODEL_COOLDOWN_ENABLED",
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

export function withRuntimeFeatureFlags(source = {}) {
  const resolved = { ...source };
  for (const name of FEATURE_NAMES) {
    const value = runtimeFeatureValue(source, name);
    if (value !== undefined) resolved[name] = value;
  }
  return resolved;
}
