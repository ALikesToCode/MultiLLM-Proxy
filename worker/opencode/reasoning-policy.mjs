const REASONING_EFFORTS = new Set([
  "none", "minimal", "low", "medium", "high", "xhigh", "max",
]);

export function isOpencodeGlmModel(model) {
  return typeof model === "string" && model.trim().toLowerCase()
    .split("/").at(-1).split(":")[0].startsWith("glm-5.");
}

export function opencodeGlmReasoningFields(effort = "max") {
  // Effort only takes effect with thinking enabled. Keep explicit opt-outs
  // intact so the upstream can validate models that require thinking.
  return {
    reasoning_effort: effort === "xhigh" ? "max" : effort,
    ...(["none", "minimal"].includes(effort) ? {} : { thinking: { type: "enabled" } }),
  };
}

export function applyOpencodeGlmReasoningPolicy(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return payload;
  }
  if (!isOpencodeGlmModel(payload.model)) return payload;

  let requested = "max";
  if (Object.hasOwn(payload, "reasoning_effort")) {
    requested = payload.reasoning_effort;
  } else if (Object.hasOwn(payload, "reasoning")) {
    requested = payload.reasoning?.effort;
  }
  const effort = typeof requested === "string" ? requested.toLowerCase() : "";
  if (!REASONING_EFFORTS.has(effort)) return payload;

  const fields = opencodeGlmReasoningFields(effort);
  if (Object.hasOwn(payload, "thinking")) delete fields.thinking;
  const normalized = { ...payload, ...fields };
  delete normalized.reasoning;
  return normalized;
}
