import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";
import { parseRoleplayPayload } from "../worker/roleplay/memory.mjs";

test("GLM 5.3 is accepted as a roleplay GLM family alias", () => {
  const parsed = parseRoleplayPayload({
    model: "glm-5.3",
    messages: [{ role: "user", content: "Continue." }],
  });

  assert.equal(parsed.modelPreference, "glm");
});

test("roleplay remembers failed GLM tiers and recovers through OpenCode", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    NAVYAI_API_KEY: "navy-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt,opencode,navyai",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({
      nanogpt: ["glm"],
      opencode: ["glm"],
      navyai: ["glm"],
    }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3", "glm-5.2"] },
      navyai: { glm: "glm-5.2-venice" },
    }),
  });
  const calls = [];

  const respond = (host, payload) => {
    calls.push({
      host,
      model: payload.model,
      reasoningEffort: payload.reasoning_effort,
    });
    if (payload.model === "zai-org/glm-5.2:thinking") {
      return new Response('{"error":"rate limited"}', {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (payload.model === "glm-5.3") {
      return new Response('{"error":"temporarily unavailable"}', {
        status: 503,
        headers: { "Content-Type": "application/json" },
      });
    }
    return completionResponse(payload.model, "The scene continues.");
  };
  fixture.env.MULTILLM_PROXY_CONTAINER = {
    getByName(name) {
      assert.equal(name, "primary");
      return {
        async fetch(request) {
          assert.equal(
            request.url,
            "https://roleplay.internal/opencode/v1/chat/completions",
          );
          assert.equal(
            request.headers.get("Authorization"),
            "Bearer opencode-roleplay-key",
          );
          return respond("roleplay.internal", await request.json());
        },
      };
    },
  };

  const responses = await withGlobalFetch(async (input, init) => {
    const payload = JSON.parse(init.body);
    return respond(new URL(input).hostname, payload);
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-glm-tier-recovery",
        input: "Continue.",
        model: "roleplay:glm",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-glm-tier-recovery",
        input: "Continue again.",
        model: "glm-5.3",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    );
    return [first, second];
  });

  assert.deepEqual(responses.map((response) => response.status), [200, 200]);
  assert.equal(responses[0].headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(responses[0].headers.get("X-Roleplay-Model"), "glm-5.2");
  assert.equal(responses[0].headers.get("X-Roleplay-Fallback-Count"), "2");
  assert.equal(responses[1].headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(responses[1].headers.get("X-Roleplay-Model"), "glm-5.2");
  assert.equal(responses[1].headers.get("X-Roleplay-Fallback-Count"), "0");
  assert.deepEqual(calls, [
    {
      host: "nano-gpt.com",
      model: "zai-org/glm-5.2:thinking",
      reasoningEffort: "max",
    },
    { host: "roleplay.internal", model: "glm-5.3", reasoningEffort: "max" },
    { host: "roleplay.internal", model: "glm-5.2", reasoningEffort: "max" },
    { host: "roleplay.internal", model: "glm-5.2", reasoningEffort: "max" },
  ]);
});
