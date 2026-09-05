import { RoleplayRequestError } from "./validation.mjs";
import { applyReasoningPolicy } from "./reasoning.mjs";
import { glmModelVariant } from "./model-selection.mjs";

const MODES = ["provider-priority", "fastest-eligible", "quality", "pinned"];
const PROVIDERS = ["nanogpt", "opencode", "openrouter", "linkapi", "navyai"];

export function parseRoutingPolicy(value) {
  if (value === undefined) value = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RoleplayRequestError("routing must be an object");
  if (Object.keys(value).some((key) => !["mode", "provider", "model", "billing", "fallback"].includes(key))) {
    throw new RoleplayRequestError("Unsupported routing option");
  }
  const result = { mode: "provider-priority", provider: "", model: "", billing: "configured", fallback: "safe", ...value };
  if (!MODES.includes(result.mode) || !["configured", "subscription-only"].includes(result.billing) || !["safe", "none"].includes(result.fallback)) {
    throw new RoleplayRequestError("Invalid routing mode, billing, or fallback");
  }
  if (result.provider !== "" && !PROVIDERS.includes(result.provider)) throw new RoleplayRequestError("Invalid routing provider");
  if (typeof result.model !== "string" || result.model.length > 200 || /[\s\u0000-\u001f]/.test(result.model)) throw new RoleplayRequestError("Invalid routing model");
  if (result.mode === "pinned" && (!result.provider || !result.model)) throw new RoleplayRequestError("Pinned routing requires provider and model");
  return result;
}

export function filterRoutingCandidates(candidates, policy) {
  return candidates.filter((candidate) =>
    (!policy.provider || candidate.provider === policy.provider) &&
    (!policy.model || candidate.model === policy.model) &&
    (policy.billing !== "subscription-only" || candidate.subscriptionOnly === true));
}

export function rankFastestEligible(candidates, stats, now, referenceTokens = 1024) {
  const scored = candidates.map((candidate, index) => {
    const key = candidate.credentialId === "primary" ? `${candidate.provider}:${candidate.model}`
      : `${candidate.provider}:${candidate.model}:${candidate.credentialId}`;
    const observation = stats[key] || {};
    const fresh = observation.lastUsedAt > now - 24 * 60 * 60 * 1000;
    const measured = fresh && observation.successes >= 2 && observation.ewmaTokensPerSecond > 0;
    const visible = observation.firstContentSamplesMs || [];
    const first = visible.length ? visible.reduce((sum, n) => sum + n, 0) / visible.length : observation.ewmaTtfbMs;
    const failures = 1 - (observation.successes || 0) / Math.max(1, observation.attempts || 0);
    const score = measured && Number.isFinite(first)
      ? first + referenceTokens / observation.ewmaTokensPerSecond * 1000 + failures * 12000 + (observation.consecutiveFailures || 0) * 4000
      : Number.MAX_SAFE_INTEGER;
    return { ...candidate, key, score, index, measured,
      cooling: observation.cooldownUntil > now,
      selectionReason: measured ? "measured_fastest_eligible" : "unmeasured_provider_priority" };
  });
  // Unknown/stale routes do not get a fake speed advantage. The comparison lab
  // informs manual pins; automatic speed selection uses this session's evidence.
  return scored.filter((candidate) => !candidate.cooling).sort((a, b) => a.score - b.score || a.index - b.index);
}

export function rankQualityEligible(candidates, stats, now) {
  const priority = (candidate) => {
    if (candidate.family !== "glm") return candidate.modelRank;
    const variant = glmModelVariant(candidate.model);
    if (variant.flash) return variant.uncensored ? 1 : 0;
    if (variant.version === "5.2") return 2;
    return 3 + candidate.modelRank;
  };
  // Explicit product preference, not a claim of measured intelligence. Unlike
  // provider-priority, this keeps the preferred model ahead across providers.
  return candidates.map((candidate) => {
    const key = candidate.credentialId === "primary" ? `${candidate.provider}:${candidate.model}`
      : `${candidate.provider}:${candidate.model}:${candidate.credentialId}`;
    return { ...candidate, key, selectionReason: "cross_provider_model_priority" };
  }).filter((candidate) => !(stats[candidate.key]?.cooldownUntil > now))
    .sort((a, b) => a.familyRank - b.familyRank || priority(a) - priority(b) || a.providerRank - b.providerRank || a.credentialRank - b.credentialRank);
}

export function parameterReceipt(parsed, candidate, settings) {
  const requested = parsed.forwarded.reasoning_effort ?? settings.defaultReasoningEffort;
  const mapped = applyReasoningPolicy({ reasoning_effort: requested }, candidate, { defaultEffort: settings.defaultReasoningEffort });
  return { requestedEffort: requested, wireEffort: mapped.reasoning_effort ?? mapped.reasoning?.effort ?? "native",
    providerAcknowledged: false, billingMode: candidate.billingMode,
    routingMode: parsed.routing.mode, fallback: parsed.routing.fallback,
    maxOutputTokens: candidate.resolvedMaxOutputTokens ?? null };
}
