import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import {
  buildConfiguredCandidates,
  getRoleplaySettings,
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

test("deployment keeps GLM away from OpenCode and omits OpenRouter", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(
    config.vars?.ROLEPLAY_PROVIDER_ORDER,
    "nanogpt,navyai,opencode,linkapi",
  );
  assert.deepEqual(JSON.parse(config.vars?.ROLEPLAY_PROVIDER_FAMILIES), {
    nanogpt: ["glm"],
    navyai: ["glm"],
    opencode: ["kimi"],
    linkapi: ["kimi"],
  });
  assert.equal(
    JSON.parse(config.vars?.ROLEPLAY_PROVIDER_MODELS).navyai.glm,
    "glm-5.2-venice",
  );
});
