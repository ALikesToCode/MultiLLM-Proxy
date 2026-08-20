import {
  parseRoleplayProviderLimits,
  resolveRoleplayCandidateLimits,
} from "./capacity.mjs";

const DEFAULT_PROVIDER_ORDER = [
  "nanogpt",
  "opencode",
  "linkapi",
  "openrouter",
  "navyai",
];

const PROVIDERS = {
  opencode: {
    defaultBaseUrl: "https://opencode.ai/zen/go/v1",
    keyNames: ["OPENCODE_GO_API_KEY", "OPENCODE_API_KEY"],
    baseUrlNames: ["OPENCODE_GO_BASE_URL", "OPENCODE_BASE_URL"],
    defaultPath: "/chat/completions",
  },
  navyai: {
    defaultBaseUrl: "https://api.navy",
    keyNames: ["NAVYAI_API_KEY", "NAVY_API_KEY"],
    baseUrlNames: ["NAVYAI_BASE_URL"],
    defaultPath: "/v1/chat/completions",
  },
  linkapi: {
    defaultBaseUrl: "https://api.linkapi.ai",
    keyNames: ["LINKAPI_KEY", "LINKAPI_API_KEY"],
    baseUrlNames: ["LINKAPI_BASE_URL"],
    defaultPath: "/v1/chat/completions",
  },
  nanogpt: {
    defaultBaseUrl: "https://nano-gpt.com/api",
    subscriptionBaseUrl: "https://nano-gpt.com/api/subscription",
    keyNames: ["NANOGPT_API_KEY", "NANO_GPT_KEY"],
    keyListNames: ["NANOGPT_API_KEYS", "NANO_GPT_KEYS"],
    numberedKeyPrefixes: ["NANOGPT_API_KEY", "NANO_GPT_KEY"],
    preferredKeyIndexName: "NANOGPT_PREFERRED_KEY_INDEX",
    baseUrlNames: ["NANOGPT_BASE_URL"],
    defaultPath: "/v1/chat/completions",
  },
  openrouter: {
    defaultBaseUrl: "https://openrouter.ai/api/v1",
    keyNames: ["OPENROUTER_API_KEY"],
    baseUrlNames: [],
    defaultPath: "/chat/completions",
  },
};

const SAFE_FALLBACK_STATUSES = new Set([401, 402, 403, 404, 429]);
const MODEL_FAMILIES = ["kimi", "glm"];
const DEFAULT_MODELS = {
  kimi: "kimi-k2.6",
  glm: "glm-5.2",
};
const PROVIDER_DEFAULT_MODELS = {
  nanogpt: {
    glm: "zai-org/glm-5.2:thinking",
  },
};

function firstNonEmpty(env, names) {
  for (const name of names) {
    const value = env[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "";
}

function listedProviderTokens(value) {
  if (typeof value !== "string" || !value.trim()) {
    return [];
  }
  const trimmed = value.trim();
  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return parsed
          .filter((entry) => typeof entry === "string" && entry.trim())
          .map((entry) => entry.trim());
      }
    } catch {
      // Fall through to the comma/newline format.
    }
  }
  return trimmed
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function configuredProviderTokens(env, definition) {
  const tokens = [];
  for (const name of definition.keyNames) {
    const value = env[name];
    if (typeof value === "string" && value.trim()) {
      tokens.push({ index: 0, token: value.trim() });
    }
  }
  for (const name of definition.keyListNames ?? []) {
    tokens.push(
      ...listedProviderTokens(env[name]).map((token) => ({
        index: null,
        token,
      })),
    );
  }

  const prefixes = definition.numberedKeyPrefixes ?? [];
  const numbered = [];
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== "string" || !value.trim()) {
      continue;
    }
    prefixes.forEach((prefix, prefixRank) => {
      const match = name.match(new RegExp(`^${prefix}_(\\d+)$`));
      if (match) {
        numbered.push({
          index: Number.parseInt(match[1], 10),
          prefixRank,
          token: value.trim(),
        });
      }
    });
  }
  numbered.sort(
    (left, right) =>
      left.index - right.index || left.prefixRank - right.prefixRank,
  );
  tokens.push(...numbered);

  const preferredValue = String(
    env[definition.preferredKeyIndexName] ?? "",
  ).trim();
  const preferredIndex = /^\d+$/.test(preferredValue)
    ? Number.parseInt(preferredValue, 10)
    : null;
  const ordered =
    preferredIndex === null
      ? tokens
      : [
          ...tokens.filter((entry) => entry.index === preferredIndex),
          ...tokens.filter((entry) => entry.index !== preferredIndex),
        ];
  return [...new Set(ordered.map((entry) => entry.token))];
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(maximum, Math.max(minimum, parsed));
}

function booleanSetting(value, fallback = true) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(
    String(value).trim().toLowerCase(),
  );
}

function nanogptBillingMode(value) {
  return String(value ?? "subscription").trim().toLowerCase() === "standard"
    ? "standard"
    : "subscription";
}

function parseProviderOrder(value) {
  if (typeof value !== "string" || !value.trim()) {
    return DEFAULT_PROVIDER_ORDER;
  }

  const seen = new Set();
  const providers = [];
  for (const candidate of value.split(",")) {
    const provider = candidate.trim().toLowerCase();
    if (!PROVIDERS[provider] || seen.has(provider)) {
      continue;
    }
    seen.add(provider);
    providers.push(provider);
  }
  return providers.length ? providers : DEFAULT_PROVIDER_ORDER;
}

function parseProviderModelOverrides(value) {
  if (typeof value !== "string" || !value.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }

    const overrides = {};
    for (const [provider, models] of Object.entries(parsed)) {
      if (!PROVIDERS[provider] || !models || typeof models !== "object") {
        continue;
      }
      const providerModels = {};
      for (const family of MODEL_FAMILIES) {
        const model = models[family];
        if (
          typeof model === "string" &&
          model.trim() &&
          model.length <= 200 &&
          !/[\u0000-\u001f\u007f]/.test(model)
        ) {
          providerModels[family] = model.trim();
        }
      }
      if (Object.keys(providerModels).length) {
        overrides[provider] = providerModels;
      }
    }
    return overrides;
  } catch {
    return {};
  }
}

function parseProviderFamilies(value) {
  if (typeof value !== "string" || !value.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }

    const providerFamilies = {};
    for (const [provider, families] of Object.entries(parsed)) {
      if (!PROVIDERS[provider] || !Array.isArray(families)) {
        continue;
      }
      providerFamilies[provider] = [
        ...new Set(
          families
            .filter((family) => typeof family === "string")
            .map((family) => family.trim().toLowerCase())
            .filter((family) => MODEL_FAMILIES.includes(family)),
        ),
      ];
    }
    return providerFamilies;
  } catch {
    return {};
  }
}

function trustedBaseUrl(configuredValue, fallback) {
  const value =
    typeof configuredValue === "string" && configuredValue.trim()
      ? configuredValue.trim()
      : fallback;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
      return new URL(fallback);
    }
    return url;
  } catch {
    return new URL(fallback);
  }
}

function appendEndpointPath(baseUrl, endpointPath) {
  const url = new URL(baseUrl);
  const basePath = url.pathname.replace(/\/+$/, "");
  const normalizedEndpoint = endpointPath.startsWith("/")
    ? endpointPath
    : `/${endpointPath}`;

  if (
    basePath.toLowerCase().endsWith("/v1") &&
    normalizedEndpoint.toLowerCase().startsWith("/v1/")
  ) {
    url.pathname = `${basePath}${normalizedEndpoint.slice(3)}`;
  } else {
    url.pathname = `${basePath}${normalizedEndpoint}`;
  }
  return url;
}

function configuredModelFor(env, overrides, provider, family) {
  const globalName =
    family === "kimi" ? "ROLEPLAY_KIMI_MODEL" : "ROLEPLAY_GLM_MODEL";
  const configuredGlobal =
    typeof env[globalName] === "string" ? env[globalName].trim() : "";
  const providerDefault =
    PROVIDER_DEFAULT_MODELS[provider]?.[family] ?? DEFAULT_MODELS[family];
  const globalDefault =
    configuredGlobal && configuredGlobal !== DEFAULT_MODELS[family]
      ? configuredGlobal
      : providerDefault;
  return overrides[provider]?.[family] ?? globalDefault;
}

export function getRoleplaySettings(env) {
  return {
    promptCacheEnabled: booleanSetting(env.PROMPT_CACHE_ENABLED, true),
    promptCacheMinTokens: boundedInteger(
      env.PROMPT_CACHE_MIN_TOKENS,
      1_024,
      1,
      1_000_000,
    ),
    compactTriggerTokens: boundedInteger(
      env.ROLEPLAY_COMPACT_TRIGGER_TOKENS,
      0,
      0,
      1_000_000,
    ),
    compactTriggerPercent: boundedInteger(
      env.ROLEPLAY_COMPACT_TRIGGER_PERCENT,
      90,
      50,
      99,
    ),
    hardInputTokens: boundedInteger(
      env.ROLEPLAY_HARD_INPUT_TOKENS,
      0,
      0,
      2_000_000,
    ),
    memoryTargetTokens: boundedInteger(
      env.ROLEPLAY_MEMORY_TARGET_TOKENS,
      1_200,
      500,
      250_000,
    ),
    keepRecentMessages: boundedInteger(
      env.ROLEPLAY_KEEP_RECENT_MESSAGES,
      8,
      4,
      64,
    ),
    imagePromptMinOutputTokens: boundedInteger(
      env.ROLEPLAY_IMAGE_PROMPT_MIN_OUTPUT_TOKENS,
      2_048,
      512,
      8_192,
    ),
    contextReplyReserveTokens: boundedInteger(
      env.ROLEPLAY_CONTEXT_REPLY_RESERVE_TOKENS,
      4_096,
      1_024,
      131_072,
    ),
    contextSafetyTokens: boundedInteger(
      env.ROLEPLAY_CONTEXT_SAFETY_TOKENS,
      1_024,
      256,
      32_768,
    ),
    maxRequestBytes: boundedInteger(
      env.ROLEPLAY_MAX_REQUEST_BYTES,
      8_388_608,
      16_384,
      16_777_216,
    ),
    maxStoredBytes: boundedInteger(
      env.ROLEPLAY_MAX_STORED_BYTES,
      64_000,
      16_000,
      80_000,
    ),
    compactionMaxTokens: boundedInteger(
      env.ROLEPLAY_COMPACTION_MAX_TOKENS,
      1_200,
      256,
      4_096,
    ),
    compactionTimeoutMs: boundedInteger(
      env.ROLEPLAY_COMPACTION_TIMEOUT_MS,
      8_000,
      1_000,
      30_000,
    ),
    upstreamHeaderTimeoutMs: boundedInteger(
      env.ROLEPLAY_UPSTREAM_HEADER_TIMEOUT_MS,
      90_000,
      5_000,
      300_000,
    ),
    streamHeartbeatMs: boundedInteger(
      env.ROLEPLAY_STREAM_HEARTBEAT_MS,
      10_000,
      3_000,
      30_000,
    ),
    sessionTtlSeconds: boundedInteger(
      env.ROLEPLAY_SESSION_TTL_SECONDS,
      2_592_000,
      3_600,
      31_536_000,
    ),
    nanogptKeyCheckEveryRequests: boundedInteger(
      env.NANOGPT_KEY_CHECK_EVERY_REQUESTS,
      50,
      1,
      100_000,
    ),
    nanogptKeyCheckTimeoutMs:
      boundedInteger(
        env.NANOGPT_KEY_CHECK_TIMEOUT_SECONDS,
        5,
        1,
        30,
      ) * 1_000,
    providerOrder: parseProviderOrder(env.ROLEPLAY_PROVIDER_ORDER),
    providerModelOverrides: parseProviderModelOverrides(
      env.ROLEPLAY_PROVIDER_MODELS,
    ),
    providerFamilies: parseProviderFamilies(env.ROLEPLAY_PROVIDER_FAMILIES),
    providerLimits: parseRoleplayProviderLimits(
      env.ROLEPLAY_PROVIDER_LIMITS,
    ),
  };
}

export function buildConfiguredCandidates(env, settings) {
  const candidates = [];

  settings.providerOrder.forEach((provider, providerRank) => {
    const definition = PROVIDERS[provider];
    const tokens = configuredProviderTokens(env, definition);
    if (!tokens.length) {
      return;
    }

    const billingMode =
      provider === "nanogpt"
        ? nanogptBillingMode(env.NANOGPT_BILLING_MODE)
        : "standard";
    const subscriptionOnly =
      provider === "nanogpt" && billingMode === "subscription";
    const configuredBase = subscriptionOnly
      ? firstNonEmpty(env, ["NANOGPT_SUBSCRIPTION_BASE_URL"])
      : firstNonEmpty(env, definition.baseUrlNames);
    const baseUrl = trustedBaseUrl(
      configuredBase,
      subscriptionOnly
        ? definition.subscriptionBaseUrl
        : definition.defaultBaseUrl,
    );
    const endpoint = appendEndpointPath(baseUrl, definition.defaultPath);
    const catalogEndpoint = appendEndpointPath(baseUrl, "/v1/models");
    const enabledFamilies = Object.hasOwn(
      settings.providerFamilies,
      provider,
    )
      ? settings.providerFamilies[provider]
      : MODEL_FAMILIES;

    tokens.forEach((token, credentialRank) => {
      enabledFamilies.forEach((family) => {
        const familyRank = MODEL_FAMILIES.indexOf(family);
        const limits = resolveRoleplayCandidateLimits(
          settings.providerLimits,
          provider,
          family,
        );
        candidates.push({
          provider,
          providerRank,
          family,
          familyRank,
          model: configuredModelFor(
            env,
            settings.providerModelOverrides,
            provider,
            family,
          ),
          endpoint: endpoint.toString(),
          catalogEndpoint: catalogEndpoint.toString(),
          token,
          credentialId:
            tokens.length > 1 ? `key-${credentialRank + 1}` : "primary",
          credentialRank,
          billingMode,
          subscriptionOnly,
          ...limits,
        });
      });
    });
  });

  return candidates;
}

function successRate(stats) {
  if (!stats?.attempts) {
    return 1;
  }
  return (stats.successes ?? 0) / stats.attempts;
}

function candidateScore(candidate, stats, now) {
  if ((stats?.cooldownUntil ?? 0) > now) {
    return Number.POSITIVE_INFINITY;
  }

  if (!stats?.attempts) {
    return -1_000_000 + candidate.familyRank;
  }

  if ((stats.successes ?? 0) < 2) {
    return -500_000 + stats.attempts * 1_000 + candidate.familyRank;
  }

  const ttfb = stats.ewmaTtfbMs ?? 2_000;
  const total = stats.ewmaTotalMs ?? ttfb * 2;
  const failurePenalty = (1 - successRate(stats)) * 12_000;
  const recentFailurePenalty = (stats.consecutiveFailures ?? 0) * 4_000;
  return ttfb * 0.72 + total * 0.28 + failurePenalty + recentFailurePenalty;
}

export function rankRoleplayCandidates(
  candidates,
  modelStats,
  preference = "auto",
  now = Date.now(),
  activeCredentials = {},
) {
  const normalizedPreference =
    typeof preference === "string" ? preference.toLowerCase() : "auto";
  const allowedFamilies =
    normalizedPreference === "kimi" || normalizedPreference === "glm"
      ? new Set([normalizedPreference])
      : new Set(MODEL_FAMILIES);

  const eligible = candidates.filter((candidate) =>
    allowedFamilies.has(candidate.family),
  );
  const providerRanks = [...new Set(eligible.map((candidate) => candidate.providerRank))];
  const ranked = [];

  for (const providerRank of providerRanks) {
    const tier = eligible
      .filter((candidate) => candidate.providerRank === providerRank)
      .map((candidate) => {
        const key =
          candidate.credentialId === "primary"
            ? `${candidate.provider}:${candidate.model}`
            : `${candidate.provider}:${candidate.model}:${candidate.credentialId}`;
        return {
          ...candidate,
          key,
          score: candidateScore(candidate, modelStats[key], now),
          activeCredential:
            activeCredentials[candidate.provider] === candidate.credentialId,
        };
      })
      .sort(
        (left, right) =>
          Number(right.activeCredential) - Number(left.activeCredential) ||
          left.score - right.score ||
          left.credentialRank - right.credentialRank ||
          left.familyRank - right.familyRank ||
          left.model.localeCompare(right.model),
      );

    const available = tier.filter((candidate) => Number.isFinite(candidate.score));
    ranked.push(...(available.length ? available : tier));
  }
  return ranked;
}

export function roleplayCatalog(env, settings) {
  const catalog = new Map();
  for (const candidate of buildConfiguredCandidates(env, settings)) {
    const key = `${candidate.provider}:${candidate.family}:${candidate.model}`;
    if (!catalog.has(key)) {
      catalog.set(key, {
        provider: candidate.provider,
        provider_rank: candidate.providerRank,
        family: candidate.family,
        model: candidate.model,
        context_window: candidate.contextWindow,
        max_output_tokens: candidate.maxOutputTokens,
        limits_source: candidate.source,
        billing_mode:
          candidate.provider === "nanogpt"
            ? candidate.billingMode
            : undefined,
      });
    }
  }
  return [...catalog.values()];
}

export function buildProviderHeaders(candidate, env, idempotencyKey = "") {
  const headers = new Headers({
    Accept: "application/json",
    Authorization: `Bearer ${candidate.token}`,
    "Content-Type": "application/json",
  });

  if (idempotencyKey) {
    headers.set("Idempotency-Key", idempotencyKey);
  }
  if (candidate.provider === "openrouter") {
    const referer = firstNonEmpty(env, [
      "OPENROUTER_SITE_URL",
      "OPENROUTER_REFERER",
    ]);
    const appName = firstNonEmpty(env, ["OPENROUTER_APP_NAME", "APP_NAME"]);
    if (referer) {
      headers.set("HTTP-Referer", referer);
    }
    if (appName) {
      headers.set("X-Title", appName);
    }
  }
  return headers;
}

export function isSafeFallbackStatus(status) {
  return SAFE_FALLBACK_STATUSES.has(status);
}
