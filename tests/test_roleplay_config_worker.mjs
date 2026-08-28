import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import {
  buildConfiguredCandidates,
  getRoleplaySettings,
  isSafeFallbackStatus,
  ROLEPLAY_SAFE_FALLBACK_STATUSES,
} from "../worker/roleplay/config.mjs";

const { MultiLLMProxyContainer } = await loadWorkerModule();

test("roleplay defaults to NanoGPT first and NavyAI last", () => {
  const settings = getRoleplaySettings({});

  assert.deepEqual(settings.providerOrder, [
    "nanogpt",
    "opencode",
    "linkapi",
    "openrouter",
    "navyai",
  ]);
});

test("roleplay defaults to a 128k raw history window", () => {
  const settings = getRoleplaySettings({});

  assert.equal(settings.compactTriggerTokens, 128_000);
  assert.equal(settings.keepRecentMessages, 32);
  assert.equal(settings.maxStoredBytes, 640_000);
});

test("output-contract repair has an independent bounded retry limit", () => {
  assert.equal(getRoleplaySettings({}).maxAutoContinuations, 8);
  assert.equal(getRoleplaySettings({}).maxOutputContractRepairs, 1);
  assert.equal(
    getRoleplaySettings({
      ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "99",
    }).maxOutputContractRepairs,
    2,
  );
});

test("roleplay guards full GLM quality routing with measured p95 latency", () => {
  const settings = getRoleplaySettings({});

  assert.equal(settings.qualityLatencyPremiumPercent, 20);
  assert.equal(settings.qualityMinimumSamples, 3);
  assert.equal(
    getRoleplaySettings({
      ROLEPLAY_QUALITY_LATENCY_PREMIUM_PERCENT: "25",
      ROLEPLAY_QUALITY_MIN_SAMPLES: "5",
    }).qualityLatencyPremiumPercent,
    25,
  );
});

test("roleplay defaults NanoGPT GLM to Flash with explicit quality fallbacks", () => {
  const env = {
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
  };
  const candidates = buildConfiguredCandidates(env, getRoleplaySettings(env));

  assert.deepEqual(
    candidates.map((candidate) => candidate.model),
    [
      "z-ai/glm-5.3-flash",
      "zai-org/glm-5.3",
      "zai-org/glm-5.2:thinking",
      "z-ai/glm-5.3-flash-uncensored",
    ],
  );
  const uncensored = candidates.at(-1);
  assert.equal(uncensored.contextWindow, 262_144);
  assert.equal(uncensored.maxOutputTokens, 32_768);
});

test("roleplay promotes the configured NanoGPT key index", () => {
  const env = {
    NANOGPT_API_KEY: "key-zero",
    NANOGPT_API_KEY_1: "key-one",
    NANOGPT_API_KEY_2: "key-two",
    NANOGPT_PREFERRED_KEY_INDEX: "1",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  };
  const candidates = buildConfiguredCandidates(env, getRoleplaySettings(env));
  const kimiCandidates = candidates.filter(
    (candidate) => candidate.family === "kimi",
  );

  assert.deepEqual(
    kimiCandidates.map((candidate) => candidate.token),
    ["key-one", "key-zero", "key-two"],
  );
});

test("roleplay limits each provider to configured model families", () => {
  const env = {
    NANOGPT_API_KEY: "nano-key",
    NAVYAI_API_KEY: "navy-key",
    OPENCODE_GO_API_KEY: "opencode-key",
    OPENROUTER_API_KEY: "openrouter-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt,navyai,opencode,openrouter",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({
      nanogpt: ["glm", "invalid", "glm"],
      navyai: ["glm"],
      opencode: ["kimi"],
      openrouter: [],
    }),
  };
  const settings = getRoleplaySettings(env);
  const candidates = buildConfiguredCandidates(env, settings);

  assert.deepEqual(settings.providerFamilies, {
    nanogpt: ["glm"],
    navyai: ["glm"],
    opencode: ["kimi"],
    openrouter: [],
  });
  assert.deepEqual(
    [...new Set(candidates.map(({ provider, family }) => `${provider}:${family}`))],
    ["nanogpt:glm", "navyai:glm", "opencode:kimi"],
  );
});

test("roleplay preserves ordered per-provider model fallbacks", () => {
  const env = {
    OPENCODE_GO_API_KEY: "opencode-key",
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3", "glm-5.2", "glm-5.3"] },
    }),
  };
  const candidates = buildConfiguredCandidates(env, getRoleplaySettings(env));

  assert.deepEqual(
    candidates.map(({ model, modelRank }) => ({ model, modelRank })),
    [
      { model: "glm-5.3", modelRank: 0 },
      { model: "glm-5.2", modelRank: 1 },
    ],
  );
});

test("roleplay HTTP fallback only advances after explicit rejections", () => {
  assert.deepEqual(ROLEPLAY_SAFE_FALLBACK_STATUSES, [
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
  for (const status of ROLEPLAY_SAFE_FALLBACK_STATUSES) {
    assert.equal(isSafeFallbackStatus(status), true, String(status));
  }
  for (const status of [408, 409, 500, 502, 504]) {
    assert.equal(isSafeFallbackStatus(status), false, String(status));
  }
});

test("roleplay enables pre-response transport fallback by default", () => {
  assert.equal(getRoleplaySettings({}).preResponseFallbackEnabled, true);
  assert.equal(
    getRoleplaySettings({
      ROLEPLAY_PRE_RESPONSE_FALLBACK_ENABLED: "false",
    }).preResponseFallbackEnabled,
    false,
  );
});

test("roleplay enables explicit provider-error fallback by default", () => {
  assert.equal(getRoleplaySettings({}).providerErrorFallbackEnabled, true);
  assert.equal(
    getRoleplaySettings({
      ROLEPLAY_PROVIDER_ERROR_FALLBACK_ENABLED: "false",
    }).providerErrorFallbackEnabled,
    false,
  );
});

test("Cloudflare forwards NanoGPT key preference into the container", () => {
  const container = new MultiLLMProxyContainer(
    {},
    { NANOGPT_PREFERRED_KEY_INDEX: "1" },
  );

  assert.equal(container.envVars.NANOGPT_PREFERRED_KEY_INDEX, "1");
});

test("deployment prefers NanoGPT key index one", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(config.vars?.NANOGPT_PREFERRED_KEY_INDEX, "1");
});

test("deployment routes GLM through OpenCode before NavyAI", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(
    config.vars?.ROLEPLAY_PROVIDER_ORDER,
    "nanogpt,opencode,linkapi,navyai",
  );
  assert.deepEqual(JSON.parse(config.vars?.ROLEPLAY_PROVIDER_FAMILIES), {
    nanogpt: ["glm"],
    opencode: ["glm", "kimi"],
    linkapi: ["kimi"],
    navyai: ["glm"],
  });
  assert.deepEqual(
    JSON.parse(config.vars?.ROLEPLAY_PROVIDER_MODELS).nanogpt.glm,
    [
      "z-ai/glm-5.3-flash",
      "zai-org/glm-5.3",
      "zai-org/glm-5.2:thinking",
      "z-ai/glm-5.3-flash-uncensored",
    ],
  );
  assert.deepEqual(
    JSON.parse(config.vars?.ROLEPLAY_PROVIDER_MODELS).opencode.glm,
    ["glm-5.3-flash", "glm-5.3", "glm-5.2"],
  );
  assert.equal(
    JSON.parse(config.vars?.ROLEPLAY_PROVIDER_MODELS).navyai.glm,
    "glm-5.2-venice",
  );
  assert.equal(config.vars?.ROLEPLAY_COMPACT_TRIGGER_TOKENS, "128000");
  assert.equal(config.vars?.ROLEPLAY_KEEP_RECENT_MESSAGES, "32");
  assert.equal(config.vars?.ROLEPLAY_MAX_STORED_BYTES, "640000");
  assert.equal(
    config.vars?.ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS,
    "1",
  );
  assert.equal(
    config.vars?.ROLEPLAY_QUALITY_LATENCY_PREMIUM_PERCENT,
    "20",
  );
  assert.equal(config.vars?.ROLEPLAY_QUALITY_MIN_SAMPLES, "3");
});
