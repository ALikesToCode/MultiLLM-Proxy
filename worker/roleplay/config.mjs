import {
  rankFastestEligible,
  rankPriorityChain,
  rankQualityEligible,
} from "./routing-policy.mjs";
import { clientContextHeaders, withClientDefaults, withOpencodeSession } from "../client-headers.mjs";
import {
  parseRoleplayProviderLimits,
  resolveRoleplayCandidateLimits,
} from "./capacity.mjs";
import { roleplayCandidateMatchesPreference } from "./model-selection.mjs";
import { applyGlmQualityLatencyGuard } from "./quality-routing.mjs";
import { estimatedGenerationMs } from "./model-performance.mjs";

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
  // ClinePass serves only the roleplay:intelligence chain; it is not in the
  // default provider order.
  "cline-pass": {
    defaultBaseUrl: "https://api.cline.bot/api/v1",
    keyNames: ["CLINE_API_KEY", "CLINE_PASS_API_KEY"],
    baseUrlNames: [],
    defaultPath: "/chat/completions",
  },
};

// These responses unambiguously reject the current candidate before a usable
// completion is returned. Pre-response transport failures have a separate
// operator-controlled policy because they do not produce an HTTP status.
export const ROLEPLAY_SAFE_FALLBACK_STATUSES = Object.freeze([
  400,
  401,
  402,
  403,
  404,
  413,
  415,
  422,
  429,
  503,
]);
const SAFE_FALLBACK_STATUSES = new Set(ROLEPLAY_SAFE_FALLBACK_STATUSES);
const MODEL_FAMILIES = ["kimi", "glm"];
const REASONING_EFFORTS = new Set([
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
]);
const MAX_PROVIDER_MODELS_PER_FAMILY = 8;
const MAX_INTELLIGENCE_CHAIN_ENTRIES = 32;
// roleplay:intelligence tries these strictly in order: MiMo-V2.6-Pro on NanoGPT
// then ClinePass, then GLM-5.3-Flash, GLM-5.3 and GLM-5.2 on every subscription
// or allowance provider. ROLEPLAY_INTELLIGENCE_MODELS replaces the list.
const DEFAULT_INTELLIGENCE_CHAIN = [
  "nanogpt:xiaomi/mimo-v2.6-pro",
  "cline-pass:cline-pass/mimo-v2.6-pro",
  "nanogpt:z-ai/glm-5.3-flash",
  "cline-pass:cline-pass/glm-5.3-flash",
  "opencode:glm-5.3-flash",
  "navyai:glm-5.3-flash",
  "nanogpt:z-ai/glm-5.3",
  "cline-pass:cline-pass/glm-5.3",
  "opencode:glm-5.3",
  "navyai:glm-5.3",
  "nanogpt:z-ai/glm-5.2",
  "opencode:glm-5.2",
  "navyai:glm-5.2",
];
const DEFAULT_MODELS = {
  kimi: "kimi-k2.6",
  glm: "glm-5.3-flash",
};
const PROVIDER_DEFAULT_MODELS = {
  nanogpt: {
    glm: [
      "z-ai/glm-5.3-flash",
      "z-ai/glm-5.3-flash-uncensored",
      "zai-org/glm-5.2:thinking",
      "z-ai/glm-5.3",
    ],
  },
  opencode: {
    glm: ["glm-5.3-flash", "glm-5.2", "glm-5.3"],
  },
  navyai: {
    glm: "glm-5.2-venice",
  },
  linkapi: {
    glm: "glm-5.2",
  },
  openrouter: {
    glm: "glm-5.2",
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
      const numberedPrefix = `${prefix}_`;
      if (!name.startsWith(numberedPrefix)) {
        return;
      }
      const indexText = name.slice(numberedPrefix.length);
      if (/^\d+$/.test(indexText)) {
        numbered.push({
          index: Number.parseInt(indexText, 10),
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

// NanoGPT picks a provider from a `:fast` / `:throughput` / `:latency` model
// suffix. Those routes leave subscription coverage and bill pay-as-you-go plus
// a provider-selection markup, so an unset value keeps the subscription route.
const NANOGPT_SPEED_ROUTING_SUFFIXES = new Set([
  "fast",
  "latency",
  "throughput",
]);

function nanogptSpeedRouting(value) {
  const suffix = String(value ?? "").trim().toLowerCase();
  return NANOGPT_SPEED_ROUTING_SUFFIXES.has(suffix) ? suffix : "";
}

// Provider selection is pay-as-you-go. Once the account refuses to pay for it,
// stop suffixing until the cooldown lapses so the run degrades to subscription
// instead of 402ing every candidate and tripping the upstream rate limit.
let nanogptPaygoBlockedUntil = 0;

export function noteNanogptPaygoRejection(cooldownMs = 900_000, now = Date.now()) {
  nanogptPaygoBlockedUntil = Math.max(nanogptPaygoBlockedUntil, now + cooldownMs);
  return nanogptPaygoBlockedUntil;
}

export function nanogptSpeedRoutingAllowed(now = Date.now()) {
  return now >= nanogptPaygoBlockedUntil;
}

export function resetNanogptPaygoBreaker() {
  nanogptPaygoBlockedUntil = 0;
}

export function nanogptModelHasSpeedSuffix(model) {
  if (typeof model !== "string" || !model.includes(":")) {
    return false;
  }
  const tail = model.slice(model.lastIndexOf(":") + 1).trim().toLowerCase();
  return NANOGPT_SPEED_ROUTING_SUFFIXES.has(tail);
}

function withNanogptSpeedSuffix(model, suffix) {
  if (!suffix || typeof model !== "string" || !model.trim()) {
    return model;
  }
  return nanogptModelHasSpeedSuffix(model) ? model : `${model}:${suffix}`;
}

function defaultReasoningEffort(value) {
  const normalized = String(value ?? "max").trim().toLowerCase();
  return REASONING_EFFORTS.has(normalized) ? normalized : "max";
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

// Compaction is a summarisation job, not generation, so it can run on a
// newer model than the one telling the story. Keyed by provider because each
// candidate keeps its own endpoint and credential: a model name is only valid
// for the gateway that serves it.
function parseCompactionModels(value) {
  if (typeof value !== "string" || !value.trim()) {
    return {};
  }
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const models = {};
    for (const [provider, model] of Object.entries(parsed)) {
      if (
        !PROVIDERS[provider] ||
        typeof model !== "string" ||
        !model.trim() ||
        model.length > 200 ||
        /[\u0000-\u001f\u007f]/.test(model)
      ) {
        continue;
      }
      models[provider] = model.trim();
    }
    return models;
  } catch {
    return {};
  }
}

export function compactionModelFor(candidate, settings) {
  const override = settings?.compactionModels?.[candidate?.provider];
  return override || candidate?.upstreamModel || candidate?.model;
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
        const configured = Array.isArray(models[family])
          ? models[family]
          : [models[family]];
        const orderedModels = [
          ...new Set(
            configured
              .filter(
                (model) =>
                  typeof model === "string" &&
                  model.trim() &&
                  model.length <= 200 &&
                  !/[\u0000-\u001f\u007f]/.test(model),
              )
              .map((model) => model.trim()),
          ),
        ].slice(0, MAX_PROVIDER_MODELS_PER_FAMILY);
        if (orderedModels.length) {
          providerModels[family] = orderedModels;
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

function validModelName(model) {
  return (
    typeof model === "string" &&
    model.trim() &&
    model.length <= 200 &&
    !/[\u0000-\u001f\u007f]/.test(model)
  );
}

// Accepts a JSON array or a comma/newline list of provider:model entries.
function parseIntelligenceChain(value) {
  const entries =
    typeof value === "string" && value.trim()
      ? listedProviderTokens(value)
      : DEFAULT_INTELLIGENCE_CHAIN;
  const seen = new Set();
  const chain = [];
  for (const entry of entries) {
    const separator = entry.indexOf(":");
    const provider = entry.slice(0, separator).trim().toLowerCase();
    const model = entry.slice(separator + 1).trim();
    const key = `${provider}:${model}`;
    if (
      separator < 1 ||
      !PROVIDERS[provider] ||
      !validModelName(model) ||
      seen.has(key)
    ) {
      continue;
    }
    seen.add(key);
    chain.push({ provider, model });
    if (chain.length === MAX_INTELLIGENCE_CHAIN_ENTRIES) {
      break;
    }
  }
  return chain;
}

export function intelligenceModelFamily(model) {
  const normalized = String(model ?? "").toLowerCase();
  if (/(?:^|\/)glm[-_]?[0-9]/.test(normalized)) return "glm";
  if (normalized.includes("kimi")) return "kimi";
  return "mimo";
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

function configuredModelsFor(env, overrides, provider, family) {
  const globalName =
    family === "kimi" ? "ROLEPLAY_KIMI_MODEL" : "ROLEPLAY_GLM_MODEL";
  const configuredGlobal =
    typeof env[globalName] === "string" ? env[globalName].trim() : "";
  const providerDefault =
    PROVIDER_DEFAULT_MODELS[provider]?.[family] ?? DEFAULT_MODELS[family];
  const providerOverrides = overrides[provider]?.[family];
  if (Array.isArray(providerOverrides) && providerOverrides.length) {
    return providerOverrides;
  }
  if (typeof providerOverrides === "string" && providerOverrides.trim()) {
    return [providerOverrides.trim()];
  }
  const globalDefault =
    configuredGlobal && configuredGlobal !== DEFAULT_MODELS[family]
      ? configuredGlobal
      : providerDefault;
  return Array.isArray(globalDefault) ? globalDefault : [globalDefault];
}

export function getRoleplaySettings(env) {
  return {
    maxPendingTurns: boundedInteger(env.ROLEPLAY_MAX_PENDING_TURNS, 4, 1, 32),
    queueTimeoutMs: boundedInteger(env.ROLEPLAY_QUEUE_TIMEOUT_MS, 120_000, 1_000, 600_000),
    turnTimeoutMs: boundedInteger(env.ROLEPLAY_TURN_TIMEOUT_MS, 600_000, 10_000, 1_800_000),
    streamIdleTimeoutMs: boundedInteger(env.ROLEPLAY_STREAM_IDLE_TIMEOUT_MS, 90_000, 1_000, 600_000),
    defaultReasoningEffort: defaultReasoningEffort(
      env.ROLEPLAY_DEFAULT_REASONING_EFFORT,
    ),
    promptCacheEnabled: booleanSetting(env.PROMPT_CACHE_ENABLED, true),
    preResponseFallbackEnabled: booleanSetting(
      env.ROLEPLAY_PRE_RESPONSE_FALLBACK_ENABLED,
      true,
    ),
    providerErrorFallbackEnabled: booleanSetting(
      env.ROLEPLAY_PROVIDER_ERROR_FALLBACK_ENABLED,
      true,
    ),
    refusalFallbackEnabled: booleanSetting(
      env.ROLEPLAY_REFUSAL_FALLBACK_ENABLED,
      true,
    ),
    promptCacheMinTokens: boundedInteger(
      env.PROMPT_CACHE_MIN_TOKENS,
      1_024,
      1,
      1_000_000,
    ),
    compactTriggerTokens: boundedInteger(
      env.ROLEPLAY_COMPACT_TRIGGER_TOKENS,
      128_000,
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
      32,
      4,
      512,
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
      640_000,
      16_000,
      1_800_000,
    ),
    // Thinking models spend this budget on reasoning before writing the
    // digest, so the ceiling has to leave room for both.
    compactionMaxTokens: boundedInteger(
      env.ROLEPLAY_COMPACTION_MAX_TOKENS,
      1_200,
      256,
      16_384,
    ),
    // A compaction that runs out of time is abandoned and the turn falls back
    // to a local extractive digest, so the ceiling is generous. Note the
    // platform kills a blocking request long before the upper bound.
    compactionTimeoutMs: boundedInteger(
      env.ROLEPLAY_COMPACTION_TIMEOUT_MS,
      30_000,
      1_000,
      1_000_000,
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
    maxAutoContinuations: boundedInteger(
      env.ROLEPLAY_MAX_AUTO_CONTINUATIONS,
      8,
      0,
      32,
    ),
    maxOutputContractRepairs: boundedInteger(
      env.ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS,
      1,
      0,
      2,
    ),
    nanogptPaygoCooldownMs: boundedInteger(
      env.NANOGPT_SPEED_ROUTING_COOLDOWN_SECONDS,
      900,
      30,
      86400,
    ) * 1000,
    qualityLatencyPremiumPercent: boundedInteger(
      env.ROLEPLAY_QUALITY_LATENCY_PREMIUM_PERCENT,
      20,
      0,
      100,
    ),
    qualityMinimumSamples: boundedInteger(
      env.ROLEPLAY_QUALITY_MIN_SAMPLES,
      3,
      1,
      100,
    ),
    speedReferenceOutputTokens: boundedInteger(
      env.ROLEPLAY_SPEED_REFERENCE_OUTPUT_TOKENS,
      1_024,
      128,
      131_072,
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
    compactionModels: parseCompactionModels(env.ROLEPLAY_COMPACTION_MODELS),
    providerFamilies: parseProviderFamilies(env.ROLEPLAY_PROVIDER_FAMILIES),
    providerLimits: parseRoleplayProviderLimits(
      env.ROLEPLAY_PROVIDER_LIMITS,
    ),
    intelligenceChain: parseIntelligenceChain(env.ROLEPLAY_INTELLIGENCE_MODELS),
    autoRoute:
      String(env.ROLEPLAY_AUTO_ROUTE ?? "").trim().toLowerCase() === "intelligence"
        ? "intelligence"
        : "adaptive",
  };
}

// The preference a turn ranks with: plain roleplay:auto follows ROLEPLAY_AUTO_ROUTE,
// while explicit routing options keep the adaptive pool they were written for.
export function autoRoutePreference(parsed, settings) {
  return parsed.modelPreference === "auto" &&
    settings.autoRoute === "intelligence" &&
    parsed.routing?.mode === "provider-priority" &&
    !parsed.routing?.model
    ? "intelligence"
    : parsed.modelPreference;
}

// Credentials, billing mode and endpoints of one provider, or null without a key.
function providerRoute(env, provider, allowSpeedRouting = true) {
  const definition = PROVIDERS[provider];
  const tokens = configuredProviderTokens(env, definition);
  if (!tokens.length) {
    return null;
  }

  const speedRouting =
    provider === "nanogpt" && allowSpeedRouting && nanogptSpeedRoutingAllowed()
      ? nanogptSpeedRouting(env.NANOGPT_SPEED_ROUTING)
      : "";
  const billingMode =
    provider === "nanogpt" && !speedRouting
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
  return {
    tokens,
    speedRouting,
    billingMode,
    subscriptionOnly,
    endpoint: appendEndpointPath(baseUrl, definition.defaultPath).toString(),
    catalogEndpoint: appendEndpointPath(baseUrl, "/v1/models").toString(),
  };
}

// The request speed routing replaced: the plain model on the endpoint and billing
// mode NanoGPT would get with NANOGPT_SPEED_ROUTING unset.
export function withoutNanogptSpeedRouting(candidate, env) {
  const route = providerRoute(env, candidate.provider, false);
  if (!route) {
    return { ...candidate, upstreamModel: candidate.model };
  }
  return {
    ...candidate,
    upstreamModel: candidate.model,
    endpoint: route.endpoint,
    catalogEndpoint: route.catalogEndpoint,
    billingMode: route.billingMode,
    subscriptionOnly: route.subscriptionOnly,
  };
}

export function buildConfiguredCandidates(env, settings) {
  const candidates = [];

  settings.providerOrder.forEach((provider, providerRank) => {
    const route = providerRoute(env, provider);
    if (!route) {
      return;
    }
    const { tokens, speedRouting, billingMode, subscriptionOnly } = route;
    const enabledFamilies = Object.hasOwn(
      settings.providerFamilies,
      provider,
    )
      ? settings.providerFamilies[provider]
      : MODEL_FAMILIES;

    tokens.forEach((token, credentialRank) => {
      enabledFamilies.forEach((family) => {
        const familyRank = MODEL_FAMILIES.indexOf(family);
        const models = configuredModelsFor(
          env,
          settings.providerModelOverrides,
          provider,
          family,
        );
        models.forEach((model, modelRank) => {
          const limits = resolveRoleplayCandidateLimits(
            settings.providerLimits,
            provider,
            family,
            model,
          );
          candidates.push({
            provider,
            providerRank,
            family,
            familyRank,
            model,
            // Routing, stats and telemetry stay keyed on the plain model id;
            // only the upstream request body carries the speed suffix.
            upstreamModel: withNanogptSpeedSuffix(model, speedRouting),
            modelRank,
            endpoint: route.endpoint,
            catalogEndpoint: route.catalogEndpoint,
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
  });

  return candidates;
}

// The roleplay:intelligence chain: one candidate per entry and credential, in list
// order. Entries whose provider has no key are skipped.
export function buildIntelligenceCandidates(env, settings) {
  const candidates = [];
  const routes = new Map();
  settings.intelligenceChain.forEach(({ provider, model }, priorityRank) => {
    if (!routes.has(provider)) {
      routes.set(provider, providerRoute(env, provider));
    }
    const route = routes.get(provider);
    if (!route) {
      return;
    }
    const family = intelligenceModelFamily(model);
    const limits = resolveRoleplayCandidateLimits(
      settings.providerLimits,
      provider,
      family,
      model,
    );
    route.tokens.forEach((token, credentialRank) => {
      candidates.push({
        route: "intelligence",
        priorityRank,
        provider,
        providerRank: priorityRank,
        family,
        familyRank: 0,
        model,
        upstreamModel: withNanogptSpeedSuffix(model, route.speedRouting),
        modelRank: 0,
        endpoint: route.endpoint,
        catalogEndpoint: route.catalogEndpoint,
        token,
        credentialId:
          route.tokens.length > 1 ? `key-${credentialRank + 1}` : "primary",
        credentialRank,
        billingMode: route.billingMode,
        subscriptionOnly: route.subscriptionOnly,
        ...limits,
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

function candidateScore(candidate, stats, now, routingPolicy = {}) {
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
  if (routingPolicy.throughputAware) {
    const generationMs = estimatedGenerationMs(
      stats,
      routingPolicy.referenceOutputTokens ?? 1_024,
    );
    if (generationMs !== null) {
      return ttfb + generationMs + failurePenalty + recentFailurePenalty;
    }
  }
  return ttfb * 0.72 + total * 0.28 + failurePenalty + recentFailurePenalty;
}

export function rankRoleplayCandidates(
  candidates,
  modelStats,
  preference = "auto",
  now = Date.now(),
  activeCredentials = {},
  qualityPolicy = {},
) {
  const normalizedPreference =
    typeof preference === "string" ? preference.toLowerCase() : "auto";
  if (normalizedPreference === "intelligence") {
    return rankPriorityChain(candidates, modelStats, now, activeCredentials);
  }
  const eligible = candidates.filter((candidate) =>
    candidate.route !== "intelligence" &&
    (qualityPolicy.exactModel || roleplayCandidateMatchesPreference(candidate, normalizedPreference)),
  );
  if (qualityPolicy.mode === "fastest-eligible") {
    return rankFastestEligible(eligible, modelStats, now, qualityPolicy.referenceOutputTokens);
  }
  if (qualityPolicy.mode === "quality") return rankQualityEligible(eligible, modelStats, now);
  const providerRanks = [...new Set(eligible.map((candidate) => candidate.providerRank))];
  const ranked = [];
  const coolingDown = [];

  for (const providerRank of providerRanks) {
    const scoredTier = eligible
      .filter((candidate) => candidate.providerRank === providerRank)
      .map((candidate) => {
        const key =
          candidate.credentialId === "primary"
            ? `${candidate.provider}:${candidate.model}`
            : `${candidate.provider}:${candidate.model}:${candidate.credentialId}`;
        return {
          ...candidate,
          key,
          score: candidateScore(candidate, modelStats[key], now, {
            throughputAware: ["speed", "glm-speed"].includes(
              normalizedPreference,
            ),
            referenceOutputTokens: qualityPolicy.referenceOutputTokens,
          }),
          cooldownUntil: modelStats[key]?.cooldownUntil ?? 0,
          activeCredential:
            activeCredentials[candidate.provider] === candidate.credentialId,
        };
      });
    const tier = applyGlmQualityLatencyGuard(
      scoredTier,
      modelStats,
      normalizedPreference,
      qualityPolicy,
    )
      .sort(
        (left, right) =>
          left.routingRank - right.routingRank ||
          Number(right.activeCredential) - Number(left.activeCredential) ||
          left.score - right.score ||
          left.modelRank - right.modelRank ||
          left.credentialRank - right.credentialRank ||
          left.familyRank - right.familyRank ||
          left.model.localeCompare(right.model),
      );

    const available = tier.filter((candidate) => Number.isFinite(candidate.score));
    if (available.length) {
      ranked.push(...available);
    } else {
      coolingDown.push(...tier);
    }
  }
  if (ranked.length) {
    return ranked;
  }
  return coolingDown.sort(
    (left, right) =>
      left.cooldownUntil - right.cooldownUntil ||
      left.providerRank - right.providerRank ||
      left.modelRank - right.modelRank ||
      left.credentialRank - right.credentialRank,
  );
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
        model_priority: candidate.modelRank,
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

export function buildProviderHeaders(candidate, env, idempotencyKey = "", clientHeaders = {}) {
  let headers = withClientDefaults(clientContextHeaders(clientHeaders, candidate.provider), env);
  if (candidate.provider === "opencode") headers = withOpencodeSession(headers);
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${candidate.token}`);
  headers.set("Content-Type", "application/json");

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
