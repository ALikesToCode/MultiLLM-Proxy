const MAXIMUM_EFFORT_BY_PROVIDER = Object.freeze({
  navyai: "xhigh",
  linkapi: "high",
  nanogpt: "xhigh",
});
const REASONING_EFFORT_ORDER = Object.freeze([
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
]);

function normalizedCandidate(candidate) {
  return {
    provider:
      typeof candidate?.provider === "string"
        ? candidate.provider.toLowerCase()
        : "",
    family:
      typeof candidate?.family === "string"
        ? candidate.family.toLowerCase()
        : "",
  };
}

export function maximumReasoningProfile(candidate) {
  const { provider, family } = normalizedCandidate(candidate);

  if (provider === "opencode") {
    // Kimi K2.6 exposes fixed native thinking through OpenCode Go without a
    // supported effort overlay. GLM 5.2 accepts `max` on this transport.
    return family === "glm"
      ? { mode: "max", effort: "max", fields: { reasoning_effort: "max" } }
      : { mode: "max", effort: "native", fields: {} };
  }

  if (provider === "openrouter") {
    // OpenRouter maps xhigh to GLM 5.2's native maximum. High is the strongest
    // portable reasoning profile for Kimi and other routed reasoning models.
    const effort = family === "glm" ? "xhigh" : "high";
    return {
      mode: "max",
      effort,
      fields: { reasoning: { effort } },
    };
  }

  const effort = MAXIMUM_EFFORT_BY_PROVIDER[provider];
  if (effort) {
    return {
      mode: "max",
      effort,
      fields: { reasoning_effort: effort },
    };
  }

  throw new TypeError(`No maximum reasoning profile for provider: ${provider}`);
}

function reasoningFields(candidate, effort) {
  const { provider, family } = normalizedCandidate(candidate);
  const maximum = maximumReasoningProfile(candidate).effort;
  if (maximum === "native" || (provider === "opencode" && family !== "glm")) {
    return {};
  }
  const requestedIndex = REASONING_EFFORT_ORDER.indexOf(effort);
  const maximumIndex = REASONING_EFFORT_ORDER.indexOf(maximum);
  const mappedEffort = REASONING_EFFORT_ORDER[
    Math.min(requestedIndex, maximumIndex)
  ];
  if (provider === "openrouter") {
    return { reasoning: { effort: mappedEffort } };
  }
  return { reasoning_effort: mappedEffort };
}

export function applyReasoningPolicy(payload, candidate) {
  const normalized = { ...payload };
  const explicitEffort = normalized.reasoning_effort;
  if (
    explicitEffort !== undefined &&
    !REASONING_EFFORT_ORDER.includes(explicitEffort)
  ) {
    return normalized;
  }
  delete normalized.reasoning;
  delete normalized.reasoning_effort;
  return {
    ...normalized,
    ...(explicitEffort === undefined
      ? maximumReasoningProfile(candidate).fields
      : reasoningFields(candidate, explicitEffort)),
  };
}
