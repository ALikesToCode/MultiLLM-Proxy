import assert from "node:assert/strict";
import test from "node:test";

import {
  parseRoleplayModelPreference,
  roleplayCandidateMatchesPreference,
} from "../worker/roleplay/model-selection.mjs";
import { rankRoleplayCandidates } from "../worker/roleplay/config.mjs";
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

test("GLM speed routing compares every eligible model in the provider tier", () => {
  const candidates = applyGlmQualityLatencyGuard(
    [flash, full, stable],
    {},
    "glm-speed",
  );

  assert.deepEqual(
    candidates.map((candidate) => candidate.routingRank),
    [0, 0, 0],
  );
});

test("GLM speed routing prefers measured generation throughput", () => {
  const candidates = [flash, stable].map((candidate) => ({
    ...candidate,
    providerRank: 0,
    familyRank: 0,
    credentialRank: 0,
    subscriptionOnly: true,
  }));
  const modelStats = {
    [flash.key]: {
      attempts: 2,
      successes: 2,
      ewmaTtfbMs: 100,
      ewmaTotalMs: 10_000,
      ewmaTokensPerSecond: 100,
    },
    [stable.key]: {
      attempts: 2,
      successes: 2,
      ewmaTtfbMs: 150,
      ewmaTotalMs: 8_000,
      ewmaTokensPerSecond: 200,
    },
  };

  const ranked = rankRoleplayCandidates(
    candidates,
    modelStats,
    "glm-speed",
    Date.now(),
    {},
    { referenceOutputTokens: 1_024 },
  );

  assert.equal(ranked[0].model, "glm-5.2");
});

test("subscription-safe GLM includes uncensored Flash but excludes full 5.3", () => {
  const nanoUncensored = {
    family: "glm",
    model: "z-ai/glm-5.3-flash-uncensored",
    subscriptionOnly: true,
  };
  const nanoFull = {
    family: "glm",
    model: "z-ai/glm-5.3",
    subscriptionOnly: true,
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
  assert.equal(roleplayCandidateMatchesPreference(nanoUncensored, "glm"), true);
  assert.equal(roleplayCandidateMatchesPreference(nanoFull, "glm"), false);
  assert.equal(
    roleplayCandidateMatchesPreference(nanoFull, "glm-5.3"),
    true,
  );
  assert.equal(
    roleplayCandidateMatchesPreference(
      nanoUncensored,
      "glm-5.3-flash-uncensored",
    ),
    true,
  );
  assert.equal(roleplayCandidateMatchesPreference(navyVenice, "glm"), true);
  assert.equal(roleplayCandidateMatchesPreference(navyVenice, "glm-5.2"), true);
  assert.equal(
    parseRoleplayModelPreference({
      model: "roleplay:5.3-flash-uncensored",
    }),
    "glm-5.3-flash-uncensored",
  );
  assert.equal(
    parseRoleplayModelPreference({
      model: "z-ai/glm-5.3-flash-uncensored",
    }),
    "glm-5.3-flash-uncensored",
  );
  assert.equal(
    parseRoleplayModelPreference({ model: "z-ai/glm-5.3" }),
    "glm-5.3",
  );
  assert.equal(
    parseRoleplayModelPreference({ model: "zai-org/glm-5.2:thinking" }),
    "glm-5.2",
  );
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
