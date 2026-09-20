import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  buildConfiguredCandidates,
  getRoleplaySettings,
} from "../worker/roleplay/config.mjs";
import {
  buildCompactionPayload,
  buildUpstreamPayload,
} from "../worker/roleplay/memory.mjs";
import { prepareCompactionCandidates } from "../worker/roleplay/compaction-budget.mjs";

const BASE = {
  NANOGPT_API_KEY: "k",
  ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
};
const PLAN = { forced: true };
const STATE = { memory: null, messages: [] };

function candidateFor(env) {
  return buildConfiguredCandidates(env, getRoleplaySettings(env))[0];
}

test("compaction uses the configured model without touching generation", () => {
  const env = {
    ...BASE,
    ROLEPLAY_COMPACTION_MODELS: JSON.stringify({ nanogpt: "moonshotai/kimi-k2.6" }),
  };
  const settings = getRoleplaySettings(env);
  const candidate = candidateFor(env);

  assert.equal(
    buildCompactionPayload(STATE, PLAN, candidate, settings).model,
    "moonshotai/kimi-k2.6",
  );
  assert.equal(
    buildUpstreamPayload({ stream: false, forwarded: {} }, candidate, [], settings).model,
    candidate.model,
  );
});

test("an override only applies to its own provider", () => {
  const env = {
    ...BASE,
    ROLEPLAY_COMPACTION_MODELS: JSON.stringify({ navyai: "glm-5.2-venice" }),
  };
  const settings = getRoleplaySettings(env);
  const candidate = candidateFor(env);

  // A model name is only valid at the gateway that serves it, so a NavyAI
  // override must never be sent on a NanoGPT candidate's credential.
  assert.equal(
    buildCompactionPayload(STATE, PLAN, candidate, settings).model,
    candidate.model,
  );
});

test("unset or malformed config falls back to the candidate model", () => {
  for (const value of [undefined, "", "not json", "[]", JSON.stringify({ nanogpt: "" }),
                       JSON.stringify({ madeup: "x" })]) {
    const env = { ...BASE, ROLEPLAY_COMPACTION_MODELS: value };
    const settings = getRoleplaySettings(env);
    const candidate = candidateFor(env);
    assert.equal(
      buildCompactionPayload(STATE, PLAN, candidate, settings).model,
      candidate.model,
      `fallback failed for ${JSON.stringify(value)}`,
    );
  }
});

test("the deployment routes NanoGPT compaction to the latest Kimi", async () => {
  const config = JSON.parse(
    await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
  );
  assert.deepEqual(JSON.parse(config.vars?.ROLEPLAY_COMPACTION_MODELS), {
    nanogpt: "moonshotai/kimi-k2.6",
  });
  // Generation must stay on the GLM rotation.
  assert.equal(config.vars?.ROLEPLAY_GLM_MODEL, "glm-5.3-flash");
  assert.deepEqual(JSON.parse(config.vars?.ROLEPLAY_PROVIDER_MODELS).nanogpt.glm, [
    "z-ai/glm-5.3-flash",
    "z-ai/glm-5.3-flash-uncensored",
    "zai-org/glm-5.2:thinking",
    "z-ai/glm-5.3",
  ]);
});

test("the compaction budget and deadline ceilings admit the deployed values", async () => {
  const config = JSON.parse(
    await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
  );
  const settings = getRoleplaySettings(config.vars);

  // Values below the ceiling must survive verbatim, or the deployment is
  // silently running something other than what wrangler.jsonc says.
  assert.equal(settings.compactionMaxTokens, 16_000);
  assert.equal(settings.compactionTimeoutMs, 100_000);

  const clamped = getRoleplaySettings({
    ...config.vars,
    ROLEPLAY_COMPACTION_MAX_TOKENS: "999999",
    ROLEPLAY_COMPACTION_TIMEOUT_MS: "99999999",
  });
  assert.equal(clamped.compactionMaxTokens, 16_384);
  assert.equal(clamped.compactionTimeoutMs, 1_000_000);
});

test("a larger budget still leaves every candidate eligible to compact", async () => {
  const config = JSON.parse(
    await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
  );
  const env = { ...config.vars, NANOGPT_API_KEY: "k", LINKAPI_KEY: "k", NAVY_API_KEY: "k" };
  const settings = getRoleplaySettings(env);
  const candidates = buildConfiguredCandidates(env, settings);
  // prepareCompactionCandidates drops any candidate that cannot fund the
  // budget, so raising it too far would starve compaction entirely.
  const prepared = prepareCompactionCandidates(candidates, 4_000, settings);
  assert.equal(prepared.length, candidates.length);
  assert.ok(prepared.length > 0);
});
