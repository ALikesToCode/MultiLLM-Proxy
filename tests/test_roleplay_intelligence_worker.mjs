import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";
import {
  buildConfiguredCandidates,
  buildIntelligenceCandidates,
  getRoleplaySettings,
  rankRoleplayCandidates,
} from "../worker/roleplay/config.mjs";
import { resolveRoleplayCandidateLimits } from "../worker/roleplay/capacity.mjs";
import { parseRoleplayPayload } from "../worker/roleplay/memory.mjs";
import { ROLEPLAY_PUBLIC_MODEL_ALIASES } from "../worker/roleplay/model-selection.mjs";
import { applyReasoningPolicy } from "../worker/roleplay/reasoning.mjs";
import { parseRoutingPolicy } from "../worker/roleplay/routing-policy.mjs";
import { unwrapClineEnvelope } from "../worker/roleplay/transport.mjs";

const KEYS = {
  NANOGPT_API_KEY: "nano-key",
  CLINE_API_KEY: "cline-key",
  OPENCODE_GO_API_KEY: "opencode-key",
  NAVYAI_API_KEY: "navy-key",
};

function chain(env) {
  const settings = getRoleplaySettings(env);
  return buildIntelligenceCandidates(env, settings);
}

function order(candidates) {
  return candidates.map((candidate) => `${candidate.provider}:${candidate.model}`);
}

test("roleplay:intelligence selects the fixed-order preference", () => {
  const parsed = parseRoleplayPayload({
    model: "roleplay:intelligence",
    messages: [{ role: "user", content: "Continue." }],
  });

  assert.equal(parsed.modelPreference, "intelligence");
  assert.match(ROLEPLAY_PUBLIC_MODEL_ALIASES["roleplay:intelligence"], /MiMo-V2\.6-Pro/);
});

test("the default chain is MiMo first, then GLM-5.3-Flash, 5.3 and 5.2", () => {
  assert.deepEqual(order(chain(KEYS)), [
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
  ]);
});

test("chain entries without a provider key are skipped", () => {
  assert.deepEqual(order(chain({ CLINE_API_KEY: "cline-key" })), [
    "cline-pass:cline-pass/mimo-v2.6-pro",
    "cline-pass:cline-pass/glm-5.3-flash",
    "cline-pass:cline-pass/glm-5.3",
  ]);
});

test("ROLEPLAY_INTELLIGENCE_MODELS replaces the chain and drops invalid entries", () => {
  const candidates = chain({
    ...KEYS,
    ROLEPLAY_INTELLIGENCE_MODELS: JSON.stringify([
      "openrouter:z-ai/glm-5.3",
      "unknown:model",
      "no-separator",
      "cline-pass:cline-pass/glm-5.3",
      "cline-pass:cline-pass/glm-5.3",
    ]),
  });

  // OpenRouter has no key here, so only the ClinePass entry remains.
  assert.deepEqual(order(candidates), ["cline-pass:cline-pass/glm-5.3"]);
  assert.equal(
    candidates[0].endpoint,
    "https://api.cline.bot/api/v1/chat/completions",
  );
});

test("NanoGPT keys rotate within an entry before the next entry", () => {
  const candidates = chain({
    NANOGPT_API_KEY_1: "nano-one",
    NANOGPT_API_KEY_2: "nano-two",
    CLINE_API_KEY: "cline-key",
    ROLEPLAY_INTELLIGENCE_MODELS:
      "nanogpt:xiaomi/mimo-v2.6-pro,cline-pass:cline-pass/mimo-v2.6-pro",
  });
  const ranked = rankRoleplayCandidates(candidates, {}, "intelligence", 1_000);

  assert.deepEqual(
    ranked.map((candidate) => `${candidate.provider}:${candidate.credentialId}`),
    ["nanogpt:key-1", "nanogpt:key-2", "cline-pass:primary"],
  );
});

test("a cooling chain entry moves behind the available ones", () => {
  const candidates = chain(KEYS);
  const now = 1_000;
  const ranked = rankRoleplayCandidates(
    candidates,
    { "nanogpt:xiaomi/mimo-v2.6-pro": { cooldownUntil: now + 60_000 } },
    "intelligence",
    now,
  );

  assert.equal(ranked[0].model, "cline-pass/mimo-v2.6-pro");
  assert.ok(!ranked.some((candidate) => candidate.model === "xiaomi/mimo-v2.6-pro"));
  assert.equal(ranked[0].key, "cline-pass:cline-pass/mimo-v2.6-pro");
});

test("other roleplay aliases never use the intelligence chain", () => {
  const settings = getRoleplaySettings(KEYS);
  const candidates = [
    ...buildConfiguredCandidates(KEYS, settings),
    ...buildIntelligenceCandidates(KEYS, settings),
  ];
  for (const preference of ["auto", "glm", "kimi", "glm-5.3"]) {
    const ranked = rankRoleplayCandidates(candidates, {}, preference, 1_000);
    assert.ok(ranked.length > 0, preference);
    assert.ok(
      ranked.every((candidate) => candidate.route !== "intelligence"),
      preference,
    );
  }
});

test("MiMo and ClinePass GLM carry their million-token limits", () => {
  assert.deepEqual(
    resolveRoleplayCandidateLimits({}, "nanogpt", "mimo", "xiaomi/mimo-v2.6-pro"),
    { contextWindow: 1_048_576, maxOutputTokens: 131_072, source: "model-family-default" },
  );
  assert.equal(
    resolveRoleplayCandidateLimits({}, "cline-pass", "glm", "cline-pass/glm-5.3").contextWindow,
    1_000_000,
  );
});

test("ClinePass receives Cline's reasoning object, capped at xhigh", () => {
  const candidate = { provider: "cline-pass", family: "mimo", model: "cline-pass/mimo-v2.6-pro" };

  assert.deepEqual(
    applyReasoningPolicy({ model: candidate.model }, candidate, { defaultEffort: "high" }).reasoning,
    { effort: "high" },
  );
  const maximum = applyReasoningPolicy(
    { model: candidate.model, reasoning_effort: "max" },
    candidate,
    { defaultEffort: "high" },
  );
  assert.deepEqual(maximum.reasoning, { effort: "xhigh" });
  assert.equal(maximum.reasoning_effort, undefined);
});

test("routing may pin ClinePass", () => {
  assert.equal(
    parseRoutingPolicy({ mode: "pinned", provider: "cline-pass", model: "cline-pass/glm-5.3" }).provider,
    "cline-pass",
  );
});

test("Cline's non-streaming envelope is unwrapped and streams pass through", async () => {
  const completion = { id: "gen-1", choices: [{ message: { content: "Hi" } }] };
  const wrapped = await unwrapClineEnvelope(
    new Response(JSON.stringify({ data: completion, success: true }), {
      headers: { "Content-Type": "application/json", "Content-Length": "999" },
    }),
  );
  assert.deepEqual(await wrapped.json(), completion);
  assert.equal(wrapped.headers.get("Content-Length"), null);

  const stream = new Response("data: [DONE]\n\n", {
    headers: { "Content-Type": "text/event-stream" },
  });
  assert.equal(await unwrapClineEnvelope(stream), stream);

  const failure = new Response('{"error":"nope","success":false}', {
    status: 429,
    headers: { "Content-Type": "application/json" },
  });
  assert.equal(await unwrapClineEnvelope(failure), failure);
});

test("a roleplay:intelligence turn falls back from NanoGPT MiMo to ClinePass MiMo", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    CLINE_API_KEY: "cline-key",
  });
  const calls = [];

  const response = await withGlobalFetch(async (input, init) => {
    const url = new URL(input);
    const payload = JSON.parse(init.body);
    calls.push({
      url: url.toString(),
      authorization: init.headers.get("Authorization"),
      model: payload.model,
      reasoning: payload.reasoning,
    });
    if (url.hostname === "nano-gpt.com") {
      return new Response('{"error":"rate limited"}', {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }
    const completion = await completionResponse(payload.model, "MiMo answers.").json();
    return new Response(JSON.stringify({ data: completion, success: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-intelligence-chain",
        input: "Continue.",
        model: "roleplay:intelligence",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.choices[0].message.content, "MiMo answers.");
  assert.equal(response.headers.get("X-Roleplay-Provider"), "cline-pass");
  assert.equal(response.headers.get("X-Roleplay-Model"), "cline-pass/mimo-v2.6-pro");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.deepEqual(
    calls.map((call) => call.model),
    ["xiaomi/mimo-v2.6-pro", "cline-pass/mimo-v2.6-pro"],
  );
  assert.equal(calls[1].url, "https://api.cline.bot/api/v1/chat/completions");
  assert.equal(calls[1].authorization, "Bearer cline-key");
  assert.ok(calls[1].reasoning?.effort);
});
