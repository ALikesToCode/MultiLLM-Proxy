const FAMILY_LIMITS = {
  kimi: {
    contextWindow: 262_144,
    maxOutputTokens: 262_144,
    source: "model-family-default",
  },
  glm: {
    contextWindow: 262_144,
    maxOutputTokens: 131_072,
    source: "model-family-default",
  },
};

// Provider context limits come from exercised live catalogs. When a catalog
// omits output capacity, the same model family's verified output limit is used
// and identified separately. Gateways can expose different limits for one
// underlying model, so provider entries always win over family fallbacks.
const PROVIDER_LIMITS = {
  nanogpt: {
    kimi: {
      contextWindow: 256_000,
      maxOutputTokens: 65_536,
      source: "provider-catalog",
    },
    glm: {
      contextWindow: 1_048_576,
      maxOutputTokens: 131_072,
      source: "provider-catalog",
    },
  },
  navyai: {
    kimi: {
      contextWindow: 262_144,
      maxOutputTokens: 262_144,
      source: "provider-catalog",
    },
    glm: {
      contextWindow: 1_048_576,
      maxOutputTokens: 131_072,
      source: "provider-context-and-model-output",
    },
  },
  openrouter: {
    kimi: {
      contextWindow: 262_144,
      maxOutputTokens: 262_144,
      source: "provider-catalog",
    },
    glm: {
      contextWindow: 262_144,
      maxOutputTokens: 131_072,
      source: "provider-context-and-model-output",
    },
  },
};

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function normalizedLimit(value, fallback) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return fallback;
  }
  const contextWindow = positiveInteger(
    value.context_window ?? value.contextWindow,
  );
  const maxOutputTokens = positiveInteger(
    value.max_output_tokens ?? value.maxOutputTokens,
  );
  if (!contextWindow || !maxOutputTokens) {
    return fallback;
  }
  return {
    contextWindow,
    maxOutputTokens,
    source: "environment-override",
  };
}

export function parseRoleplayProviderLimits(value) {
  if (typeof value !== "string" || !value.trim()) {
    return {};
  }
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : {};
  } catch {
    return {};
  }
}

export function resolveRoleplayCandidateLimits(overrides, provider, family) {
  const fallback =
    PROVIDER_LIMITS[provider]?.[family] ?? FAMILY_LIMITS[family];
  return normalizedLimit(overrides?.[provider]?.[family], fallback);
}

function requestedOutputFits(candidate, requestedOutputTokens) {
  return (
    requestedOutputTokens === null ||
    requestedOutputTokens <= candidate.maxOutputTokens
  );
}

function candidateInputCapacity(candidate, requestedOutputTokens, settings) {
  if (!requestedOutputFits(candidate, requestedOutputTokens)) {
    return 0;
  }
  const reserve =
    requestedOutputTokens ?? settings.contextReplyReserveTokens;
  return Math.max(
    0,
    candidate.contextWindow - reserve - settings.contextSafetyTokens,
  );
}

export function resolveRoleplayContextPolicy(
  candidates,
  requestedOutputTokens,
  settings,
) {
  const dynamicHardLimit = Math.max(
    0,
    ...candidates.map((candidate) =>
      candidateInputCapacity(candidate, requestedOutputTokens, settings),
    ),
  );
  const hardInputTokens = settings.hardInputTokens
    ? Math.min(settings.hardInputTokens, dynamicHardLimit)
    : dynamicHardLimit;
  const compactTriggerTokens =
    settings.compactTriggerTokens ||
    Math.max(
      1,
      Math.floor(
        hardInputTokens * (settings.compactTriggerPercent / 100),
      ),
    );
  return {
    hardInputTokens,
    compactTriggerTokens: Math.min(
      hardInputTokens,
      compactTriggerTokens,
    ),
  };
}

export function prepareRoleplayCandidates(
  candidates,
  estimatedInputTokens,
  requestedOutputTokens,
  settings,
) {
  return candidates.flatMap((candidate) => {
    if (!requestedOutputFits(candidate, requestedOutputTokens)) {
      return [];
    }
    const availableOutputTokens =
      candidate.contextWindow -
      estimatedInputTokens -
      settings.contextSafetyTokens;
    if (availableOutputTokens < 1) {
      return [];
    }
    const resolvedMaxOutputTokens = Math.min(
      requestedOutputTokens ?? candidate.maxOutputTokens,
      availableOutputTokens,
    );
    if (
      requestedOutputTokens !== null &&
      resolvedMaxOutputTokens < requestedOutputTokens
    ) {
      return [];
    }
    return [{ ...candidate, resolvedMaxOutputTokens }];
  });
}

export function shouldPreserveFullGeneration(plan, parsed, policy) {
  return (
    plan.storageForced &&
    !plan.contextForced &&
    !plan.manualForced &&
    plan.estimatedTokens <= policy.hardInputTokens
  );
}
