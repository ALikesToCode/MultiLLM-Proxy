import assert from "node:assert/strict";
import test from "node:test";

import { roleplayCandidateMatchesPreference } from "../worker/roleplay/model-selection.mjs";
import { applyGlmQualityLatencyGuard } from "../worker/roleplay/quality-routing.mjs";
import { maximumReasoningProfile } from "../worker/roleplay/reasoning.mjs";

const flash = {
  provider: "opencode",
  credentialId: "primary",
  family: "glm",
  model: "glm-5.3-flash",
  modelRank: 0,
  key: "opencode:glm-5.3-flash",
};
const full = {
  provider: "opencode",
  credentialId: "primary",
  family: "glm",
  model: "glm-5.3",
  modelRank: 1,
  key: "opencode:glm-5.3",
};
const stable = {
  provider: "opencode",
  credentialId: "primary",
  family: "glm",
  model: "glm-5.2",
  modelRank: 2,
  key: "opencode:glm-5.2",
};

function stats(ttfbSamplesMs, totalSamplesMs) {
  return { ttfbSamplesMs, totalSamplesMs };
}

test("GLM-5.3-Flash stays first without enough full-model evidence", () => {
  const candidates = applyGlmQualityLatencyGuard(
    [flash, full, stable],
    {
      [flash.key]: stats([100, 100, 100], [1_000, 1_000, 1_000]),
      [full.key]: stats([105, 105], [1_050, 1_050]),
    },
    "glm",
  ).sort((left, right) => left.routingRank - right.routingRank);

  assert.deepEqual(
    candidates.map((candidate) => candidate.model),
    ["glm-5.3-flash", "glm-5.3", "glm-5.2"],
  );
  assert.equal(candidates[1].qualityPromoted, false);
});

test("full GLM-5.3 promotes only when both p95 latencies are within 20 percent", () => {
  const candidates = applyGlmQualityLatencyGuard(
    [flash, full, stable],
    {
      [flash.key]: stats([100, 105, 110], [1_000, 1_050, 1_100]),
      [full.key]: stats([105, 110, 120], [1_050, 1_100, 1_250]),
    },
    "glm",
    { premiumPercent: 20, minimumSamples: 3 },
  ).sort((left, right) => left.routingRank - right.routingRank);

  assert.equal(candidates[0].model, "glm-5.3");
  assert.equal(candidates[0].qualityPromoted, true);
});

test("full GLM-5.3 remains behind Flash when either p95 exceeds the guard", () => {
  const candidates = applyGlmQualityLatencyGuard(
    [flash, full, stable],
    {
      [flash.key]: stats([100, 100, 100], [1_000, 1_000, 1_000]),
      [full.key]: stats([119, 120, 121], [1_050, 1_050, 1_050]),
    },
    "glm",
    { premiumPercent: 20, minimumSamples: 3 },
  ).sort((left, right) => left.routingRank - right.routingRank);

  assert.equal(candidates[0].model, "glm-5.3-flash");
  assert.equal(candidates[1].qualityPromoted, false);
});

test("explicit full-model selection bypasses the adaptive guard", () => {
  const candidates = applyGlmQualityLatencyGuard(
    [full],
    {},
    "glm-5.3",
  );

  assert.equal(candidates[0].routingRank, full.modelRank);
});

test("uncensored routing is explicit and accepts the GLM-5.2 Venice fallback", () => {
  const nanoUncensored = {
    family: "glm",
    model: "z-ai/glm-5.3-flash-uncensored",
  };
  const navyVenice = { family: "glm", model: "glm-5.2-venice" };

  assert.equal(
    roleplayCandidateMatchesPreference(nanoUncensored, "uncensored"),
    true,
  );
  assert.equal(
    roleplayCandidateMatchesPreference(navyVenice, "uncensored"),
    true,
  );
  assert.equal(roleplayCandidateMatchesPreference(nanoUncensored, "glm"), false);
  assert.equal(roleplayCandidateMatchesPreference(navyVenice, "glm"), true);
  assert.equal(roleplayCandidateMatchesPreference(navyVenice, "glm-5.2"), true);
});

test("NanoGPT uncensored Flash respects its high reasoning ceiling", () => {
  assert.deepEqual(
    maximumReasoningProfile({
      provider: "nanogpt",
      family: "glm",
      model: "z-ai/glm-5.3-flash-uncensored",
    }),
    {
      mode: "max",
      effort: "high",
      fields: { reasoning_effort: "high" },
    },
  );
});
