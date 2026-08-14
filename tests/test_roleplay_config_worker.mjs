import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import {
  buildConfiguredCandidates,
  getRoleplaySettings,
} from "../worker/roleplay/config.mjs";

const { MultiLLMProxyContainer } = await loadWorkerModule();

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
