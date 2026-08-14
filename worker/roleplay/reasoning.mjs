const MAXIMUM_EFFORT_BY_PROVIDER = Object.freeze({
  navyai: "xhigh",
  linkapi: "high",
  nanogpt: "xhigh",
});

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

export function enforceMaximumReasoning(payload, candidate) {
  const normalized = { ...payload };
  delete normalized.reasoning;
  delete normalized.reasoning_effort;
  return {
    ...normalized,
    ...maximumReasoningProfile(candidate).fields,
  };
}
