import assert from "node:assert/strict";
import test from "node:test";

import {
  buildConfiguredCandidates,
  getRoleplaySettings,
  nanogptSpeedRoutingAllowed,
  noteNanogptPaygoRejection,
  resetNanogptPaygoBreaker,
} from "../worker/roleplay/config.mjs";
import { buildUpstreamPayload } from "../worker/roleplay/memory.mjs";
import { applyRoleplayPromptCache } from "../worker/roleplay/prompt-cache.mjs";
import {
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

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

test("a pay-as-you-go refusal pauses the suffix, then it resumes", () => {
  resetNanogptPaygoBreaker();
  try {
    assert.equal(nanogptSpeedRoutingAllowed(1_000), true);
    noteNanogptPaygoRejection(60_000, 1_000);
    assert.equal(nanogptSpeedRoutingAllowed(60_000), false);
    assert.equal(nanogptSpeedRoutingAllowed(61_001), true);
  } finally {
    resetNanogptPaygoBreaker();
  }
});

test("a paused breaker keeps the suffix off candidates", () => {
  resetNanogptPaygoBreaker();
  try {
    noteNanogptPaygoRejection(900_000);
    const candidate = nanogptCandidate("fast");
    assert.equal(candidate.upstreamModel, candidate.model);
    assert.equal(candidate.model.includes(":fast"), false);
  } finally {
    resetNanogptPaygoBreaker();
  }
});

test("the breaker never shortens an open window", () => {
  resetNanogptPaygoBreaker();
  try {
    noteNanogptPaygoRejection(600_000, 0);
    noteNanogptPaygoRejection(1_000, 1_000);
    assert.equal(nanogptSpeedRoutingAllowed(500_000), false);
  } finally {
    resetNanogptPaygoBreaker();
  }
});

test("the cooldown is configurable and bounded", () => {
  assert.equal(getRoleplaySettings({}).nanogptPaygoCooldownMs, 900_000);
  assert.equal(
    getRoleplaySettings({ NANOGPT_SPEED_ROUTING_COOLDOWN_SECONDS: "45" })
      .nanogptPaygoCooldownMs,
    45_000,
  );
  // Out-of-range values clamp to the bound, so the breaker cannot be disabled.
  assert.equal(
    getRoleplaySettings({ NANOGPT_SPEED_ROUTING_COOLDOWN_SECONDS: "0" })
      .nanogptPaygoCooldownMs,
    30_000,
  );
});

test("speed routing takes priority over cache selection without changing thinking", () => {
  for (const suffix of ["fast", "throughput", "latency"]) {
    for (const caching of [undefined, true, false]) {
      for (const [enabled, threshold, requestEnabled] of [
        [true, 1, true], [false, 1, true], [true, 1, false], [true, 1024, true],
      ]) {
        const payload = {
          model: `zai-org/glm-5.2:thinking:${suffix}`,
          messages: [{ role: "user", content: "Continue." }],
          thinking: { type: "enabled" },
          reasoning_effort: "max",
          ...(caching === undefined ? {} : { caching }),
        };
        const original = structuredClone(payload);
        const decision = applyRoleplayPromptCache(
          payload, { provider: "nanogpt" }, payload.messages,
          { promptCacheEnabled: enabled, promptCacheMinTokens: threshold },
          requestEnabled,
        );
        const expected = { ...payload };
        if (caching === true) delete expected.caching;
        assert.deepEqual(decision.payload, expected);
        assert.deepEqual(payload, original);
        assert.equal(decision.promptCache.status, "skipped");
        assert.equal(decision.promptCache.mode, "nanogpt-speed-routing");
      }
    }
  }
});

for (const path of ["/v1/roleplay", "/roleplay/v1/chat/completions"]) {
  test(`${path} keeps fast inference and thinking with automatic caching enabled`, async (t) => {
    for (const stream of [false, true]) {
      await t.test(`stream=${stream}`, async () => {
        const fixture = makeRoleplayEnv({
          ...BASE_ENV,
          NANOGPT_SPEED_ROUTING: "fast",
          PROMPT_CACHE_ENABLED: "true",
          PROMPT_CACHE_MIN_TOKENS: "1",
          ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
        });
        const sent = [];
        const reasoning = "Consider the clues before continuing.";
        const answer = "The scene continues.";
        const { response, body } = await withGlobalFetch(async (input, init) => {
          assert.equal(String(input), "https://nano-gpt.com/api/v1/chat/completions");
          const payload = JSON.parse(init.body);
          sent.push(payload);
          if (payload.caching === true) {
            return new Response(JSON.stringify({ error: {
              message: "Invalid provider selection: :fast cannot be combined with caching=true.",
            } }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          if (!stream) {
            return new Response(JSON.stringify({ choices: [{
              message: { role: "assistant", reasoning, content: answer },
              finish_reason: "stop",
            }] }), { headers: { "Content-Type": "application/json" } });
          }
          const frames = [
            { delta: { reasoning } },
            { delta: { content: answer }, finish_reason: "stop" },
          ].map((choice) => `data: ${JSON.stringify({ choices: [choice] })}\n\n`);
          return new Response(`${frames.join("")}data: [DONE]\n\n`, {
            headers: { "Content-Type": "text/event-stream" },
          });
        }, async () => {
          const response = await handleRoleplayEdgeRequest(roleplayRequest({
            model: "roleplay:5.3-flash", input: "Continue the scene.",
            reasoning_effort: "max", stream,
          }, {}, path), fixture.env);
          const body = await response.text();
          await fixture.waitForBackgroundWork();
          return { response, body };
        });
        assert.equal(response.status, 200, body);
        assert.equal(sent.length, 1);
        assert.equal(sent[0].model, "z-ai/glm-5.3-flash:fast");
        assert.equal(sent[0].reasoning_effort, "max");
        assert.equal(Object.hasOwn(sent[0], "caching"), false);
        assert.ok(body.includes(reasoning));
        assert.ok(body.includes(answer));
        assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache"), "skipped");
        assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache-Mode"), "nanogpt-speed-routing");
      });
    }
  });
}
