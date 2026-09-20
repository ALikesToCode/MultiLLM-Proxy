import assert from "node:assert/strict";
import test from "node:test";

import {
  buildConfiguredCandidates,
  getRoleplaySettings,
} from "../worker/roleplay/config.mjs";
import { buildUpstreamPayload } from "../worker/roleplay/memory.mjs";

const BASE_ENV = {
  NANOGPT_API_KEY: "test-key",
  ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
};

function nanogptCandidate(speedRouting) {
  const env = { ...BASE_ENV, NANOGPT_SPEED_ROUTING: speedRouting };
  return buildConfiguredCandidates(env, getRoleplaySettings(env))[0];
}

test("roleplay keeps the subscription endpoint when speed routing is unset", () => {
  const candidate = nanogptCandidate("");

  assert.equal(candidate.billingMode, "subscription");
  assert.equal(candidate.subscriptionOnly, true);
  assert.match(candidate.endpoint, /\/api\/subscription\/v1\/chat\/completions$/);
  assert.equal(candidate.upstreamModel, candidate.model);
});

test("roleplay speed routing switches NanoGPT to the pay-as-you-go endpoint", () => {
  const candidate = nanogptCandidate("fast");

  assert.equal(candidate.billingMode, "standard");
  assert.equal(candidate.subscriptionOnly, false);
  assert.match(candidate.endpoint, /nano-gpt\.com\/api\/v1\/chat\/completions$/);
  assert.equal(candidate.upstreamModel, `${candidate.model}:fast`);
});

test("roleplay ignores an unsupported speed routing value", () => {
  const candidate = nanogptCandidate("turbo");

  assert.equal(candidate.subscriptionOnly, true);
  assert.equal(candidate.upstreamModel, candidate.model);
});

test("only the upstream body carries the speed suffix", () => {
  const candidate = nanogptCandidate("throughput");
  const payload = buildUpstreamPayload(
    { stream: false, forwarded: {} },
    candidate,
    [{ role: "user", content: "Continue." }],
    {},
  );

  assert.equal(payload.model, `${candidate.model}:throughput`);
  // Routing, stats keys and telemetry keep reading the plain model id.
  assert.equal(candidate.model.includes(":throughput"), false);
});

test("a candidate without upstreamModel falls back to the plain model id", () => {
  const payload = buildUpstreamPayload(
    { stream: false, forwarded: {} },
    { provider: "nanogpt", model: "glm-5.3" },
    [],
    {},
  );

  assert.equal(payload.model, "glm-5.3");
});
