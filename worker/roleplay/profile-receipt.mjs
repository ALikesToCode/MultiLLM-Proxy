import { buildConfiguredCandidates, getRoleplaySettings } from "./config.mjs";
import { parseRoutingPolicy, filterRoutingCandidates, parameterReceipt } from "./routing-policy.mjs";
import { RoleplayRequestError } from "./validation.mjs";

export function previewProfile(payload, env) {
  const settings = getRoleplaySettings(env);
  const routing = parseRoutingPolicy(payload.routing);
  const effort = payload.reasoning_effort ?? settings.defaultReasoningEffort;
  if (!["none", "minimal", "low", "medium", "high", "xhigh", "max"].includes(effort)) throw new RoleplayRequestError("Invalid reasoning effort");
  const kind = payload.kind ?? "roleplay";
  if (!["roleplay", "direct"].includes(kind)) throw new RoleplayRequestError("Invalid connection kind");
  let candidates = buildConfiguredCandidates(env, settings);
  if (kind === "direct") {
    if (routing.mode !== "pinned" || routing.fallback !== "none") throw new RoleplayRequestError("Direct profiles must be pinned with no fallback");
    candidates = candidates.map((candidate) => ({ ...candidate,
      subscriptionOnly: candidate.provider === "nanogpt" && routing.billing === "subscription-only",
      billingMode: candidate.provider === "nanogpt" && routing.billing === "subscription-only" ? "subscription" : "standard" }));
  }
  candidates = filterRoutingCandidates(candidates, routing);
  const unique = [...new Map(candidates.map((candidate) => [`${candidate.provider}:${candidate.model}`, candidate])).values()];
  if (!unique.length) throw new RoleplayRequestError("No configured model matches this profile", 422);
  const parsed = { routing, forwarded: { reasoning_effort: effort } };
  const choices = unique.map((candidate) => ({ provider: candidate.provider, model: candidate.model,
    ...parameterReceipt(parsed, candidate, settings) }));
  return { valid: true, validation: "configured credentials and local capability mapping; no provider call made",
    selection: routing.mode === "pinned" ? "pinned" : "resolved per session at generation time",
    selected: routing.mode === "pinned" ? choices[0] : null, candidates: choices };
}
