function estimateInputTokens(messages) {
  const bytes = new TextEncoder().encode(
    JSON.stringify({ messages }),
  ).byteLength;
  return Math.max(1, Math.ceil(bytes / 4));
}

function result(payload, status, mode, estimatedInputTokens) {
  return {
    payload,
    promptCache: {
      status,
      mode,
      estimatedInputTokens,
    },
  };
}

export function applyRoleplayPromptCache(
  payload,
  candidate,
  messages,
  settings,
  requestEnabled = true,
) {
  const estimatedInputTokens = estimateInputTokens(messages);
  if (!settings.promptCacheEnabled || !requestEnabled) {
    return result(
      payload,
      "skipped",
      requestEnabled ? "disabled" : "request-disabled",
      estimatedInputTokens,
    );
  }
  if (estimatedInputTokens < settings.promptCacheMinTokens) {
    return result(
      payload,
      "skipped",
      "below-threshold",
      estimatedInputTokens,
    );
  }

  if (candidate.provider === "nanogpt" && candidate.subscriptionOnly) {
    const subscriptionPayload = { ...payload };
    delete subscriptionPayload.caching;
    return result(
      subscriptionPayload,
      "skipped",
      "nanogpt-subscription-only",
      estimatedInputTokens,
    );
  }
  if (candidate.provider === "nanogpt") {
    return result(
      { ...payload, caching: true },
      "applied",
      "nanogpt-routing",
      estimatedInputTokens,
    );
  }
  return result(
    payload,
    "implicit",
    "implicit-prefix",
    estimatedInputTokens,
  );
}
