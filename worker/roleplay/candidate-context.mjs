import { isProtectedDirective } from "./directives.mjs";

export function parseCandidateContextMode(value) {
  return typeof value === "string" && value.trim().toLowerCase() === "window"
    ? "window"
    : "off";
}

function protectedMessage(message) {
  return isProtectedDirective(message) ||
    ["system", "developer"].includes(message?.role?.toLowerCase());
}

function completeGroup(messages, indices) {
  const pending = new Set();
  const seen = new Set();
  let lastRole;
  for (const index of indices) {
    const message = messages[index];
    lastRole = message?.role;
    if (!["user", "assistant", "tool"].includes(lastRole)) return false;
    // Legacy function exchanges cannot be proven complete by tool-call IDs.
    if (message.function_call) return false;
    if (message.tool_calls !== undefined) {
      if (lastRole !== "assistant" || !Array.isArray(message.tool_calls)) return false;
      for (const call of message.tool_calls) {
        if (typeof call?.id !== "string" || !call.id || seen.has(call.id)) return false;
        seen.add(call.id);
        pending.add(call.id);
      }
    }
    if (lastRole === "tool") {
      if (!pending.delete(message.tool_call_id)) return false;
    }
  }
  return pending.size === 0 && ["assistant", "tool"].includes(lastRole);
}

function removableGroups(messages) {
  const groups = [];
  let group = [];
  let latestUser = -1;
  for (let index = 0; index < messages.length; index += 1) {
    const message = messages[index];
    if (protectedMessage(message)) continue;
    if (message?.role === "user") {
      latestUser = index;
      if (group.length) groups.push(group);
      group = [];
    }
    group.push(index);
  }
  if (group.length) groups.push(group);
  return groups.filter((indices, index) =>
    index < groups.length - 1 &&
    indices.every(position => position < latestUser) &&
    completeGroup(messages, indices));
}

function candidateView(messages, omittedAt, omittedGroups) {
  return messages.filter((_, index) =>
    omittedAt[index] === undefined || omittedAt[index] >= omittedGroups);
}

export function prepareCandidateContext({
  contextWindow,
  messages,
  outputReserveTokens = 0,
  safetyTokens = 0,
  estimateTokens,
}) {
  const estimatedInputTokens = estimateTokens(messages);
  const original = { messages, estimatedInputTokens, omittedGroups: 0 };
  if (!Number.isSafeInteger(contextWindow) || contextWindow <= 0) {
    return { ...original, fit: true, reason: "unknown_window" };
  }
  const inputBudget = contextWindow - outputReserveTokens - safetyTokens;
  if (estimatedInputTokens <= inputBudget) {
    return { ...original, fit: true, reason: "fits" };
  }
  const groups = removableGroups(messages);
  const omittedAt = [];
  groups.forEach((indices, groupIndex) => {
    for (const index of indices) omittedAt[index] = groupIndex;
  });
  const protectedView = candidateView(messages, omittedAt, groups.length);
  const protectedEstimate = estimateTokens(protectedView);
  if (protectedEstimate > inputBudget) {
    return {
      fit: false, messages: protectedView,
      estimatedInputTokens: protectedEstimate, omittedGroups: groups.length,
      reason: "protected_context_too_large",
    };
  }

  // The existing byte estimator is monotone under whole-message omission.
  // Search for the smallest old prefix to omit without repeatedly counting it.
  let lower = 1;
  let upper = groups.length;
  let view = protectedView;
  let estimate = protectedEstimate;
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2);
    const middleView = candidateView(messages, omittedAt, middle);
    const middleEstimate = estimateTokens(middleView);
    if (middleEstimate <= inputBudget) {
      upper = middle;
      view = middleView;
      estimate = middleEstimate;
    } else {
      lower = middle + 1;
    }
  }
  return {
    fit: true, messages: view, estimatedInputTokens: estimate,
    omittedGroups: upper, reason: "windowed",
  };
}
