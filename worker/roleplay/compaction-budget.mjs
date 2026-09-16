import { prepareRoleplayCandidates } from "./capacity.mjs";

export function compactionOutputBudget(candidate, settings) {
  // Console Go reserves 1,024 output tokens and requires at least another
  // 1,024 for GLM thinking. A 1,200-token total is rejected before generation.
  const minimum = candidate.provider === "opencode" && candidate.family === "glm"
    ? 2048 : 1;
  return Math.max(settings.compactionMaxTokens, minimum);
}

export function prepareCompactionCandidates(candidates, inputTokens, settings) {
  return candidates.flatMap((candidate) => {
    const budget = compactionOutputBudget(candidate, settings);
    return prepareRoleplayCandidates([candidate], inputTokens, budget, settings)
      .filter((prepared) => prepared.resolvedMaxOutputTokens >= budget);
  });
}
