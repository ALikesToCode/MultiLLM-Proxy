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
