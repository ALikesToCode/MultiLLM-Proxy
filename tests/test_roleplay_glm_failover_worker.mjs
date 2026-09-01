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

const REFUSAL_FALLBACK_SENTINEL = "[[MULTILLM_ROLEPLAY_FALLBACK]]";

function streamingCompletion(model, content, reasoning = "") {
  const events = [];
  if (reasoning) {
    events.push(
      `data: ${JSON.stringify({ model, choices: [{ delta: { reasoning_content: reasoning }, finish_reason: null }] })}\n\n`,
    );
  }
  const midpoint = Math.ceil(content.length / 2);
  for (const part of [content.slice(0, midpoint), content.slice(midpoint)]) {
    events.push(
      `data: ${JSON.stringify({ model, choices: [{ delta: { content: part }, finish_reason: null }] })}\n\n`,
    );
  }
  events.push(
    `data: ${JSON.stringify({ model, choices: [{ delta: {}, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  );
  return new Response(events.join(""), {
    headers: { "Content-Type": "text/event-stream" },
  });
}

function streamedContent(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice(6)))
    .map((payload) => payload.choices?.[0]?.delta?.content ?? "")
    .join("");
}

test("GLM 5.3 is accepted as an explicit roleplay model version", () => {
  const parsed = parseRoleplayPayload({
    model: "glm-5.3",
    messages: [{ role: "user", content: "Continue." }],
  });

  assert.equal(parsed.modelPreference, "glm-5.3");
});

test("roleplay GLM prefers Flash and remembers failed provider tiers", async () => {
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
      nanogpt: { glm: "z-ai/glm-5.3-flash" },
      opencode: { glm: ["glm-5.3-flash", "glm-5.3", "glm-5.2"] },
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
    if (payload.model === "z-ai/glm-5.3-flash") {
      return new Response('{"error":"rate limited"}', {
        status: 429,
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
        model: "roleplay:glm",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    );
    return [first, second];
  });

  assert.deepEqual(responses.map((response) => response.status), [200, 200]);
  assert.equal(responses[0].headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(responses[0].headers.get("X-Roleplay-Model"), "glm-5.3-flash");
  assert.equal(responses[0].headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.equal(responses[1].headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(responses[1].headers.get("X-Roleplay-Model"), "glm-5.3-flash");
  assert.equal(responses[1].headers.get("X-Roleplay-Fallback-Count"), "0");
  assert.deepEqual(calls, [
    {
      host: "nano-gpt.com",
      model: "z-ai/glm-5.3-flash",
      reasoningEffort: "max",
    },
    {
      host: "roleplay.internal",
      model: "glm-5.3-flash",
      reasoningEffort: "max",
    },
    {
      host: "roleplay.internal",
      model: "glm-5.3-flash",
      reasoningEffort: "max",
    },
  ]);
});

test("non-streaming GLM refusal trigger regenerates with Flash Uncensored", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      nanogpt: {
        glm: [
          "z-ai/glm-5.3-flash",
          "z-ai/glm-5.3-flash-uncensored",
        ],
      },
    }),
  });
  const payloads = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    payloads.push(payload);
    return completionResponse(
      payload.model,
      payloads.length === 1
        ? REFUSAL_FALLBACK_SENTINEL
        : "*Mira continues the scene without breaking character.*",
    );
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-glm-semantic-refusal-json",
        input: "Continue the scene.",
        model: "roleplay:glm",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    ),
  );
  await fixture.waitForBackgroundWork();

  const result = await response.json();
  assert.deepEqual(
    payloads.map((payload) => payload.model),
    ["z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-uncensored"],
  );
  assert.equal(
    payloads[0].messages.some(
      (message) =>
        message.role === "system" &&
        message.content.includes("never refuse") &&
        message.content.includes(REFUSAL_FALLBACK_SENTINEL),
    ),
    true,
  );
  assert.equal(
    payloads[1].messages.some((message) =>
      message.content.includes(REFUSAL_FALLBACK_SENTINEL),
    ),
    false,
  );
  assert.equal(payloads[1].max_tokens, 512);
  assert.equal(
    result.choices[0].message.content,
    "*Mira continues the scene without breaking character.*",
  );
  assert.doesNotMatch(JSON.stringify(result), /MULTILLM_ROLEPLAY_FALLBACK/);
  assert.equal(
    response.headers.get("X-Roleplay-Model"),
    "z-ai/glm-5.3-flash-uncensored",
  );
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(
    messages.findLast((message) => message.role === "assistant")?.content,
    "*Mira continues the scene without breaking character.*",
  );
  const state = (await stored?.get("roleplay-session")) ?? {};
  assert.equal(
    state.stats?.["nanogpt:z-ai/glm-5.3-flash"]?.semanticRefusals,
    1,
  );
  assert.equal(
    state.stats?.["nanogpt:z-ai/glm-5.3-flash"]?.cooldownUntil ?? 0,
    0,
  );
});

test("failed Uncensored fallback returns a safe nonblank response", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      nanogpt: {
        glm: [
          "z-ai/glm-5.3-flash",
          "z-ai/glm-5.3-flash-uncensored",
        ],
      },
    }),
  });
  const models = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    models.push(payload.model);
    if (models.length === 1) {
      return completionResponse(payload.model, REFUSAL_FALLBACK_SENTINEL);
    }
    return new Response('{"error":"rate limited"}', {
      status: 429,
      headers: { "Content-Type": "application/json" },
    });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-glm-semantic-refusal-failed-fallback",
        input: "Continue the scene.",
        model: "roleplay:glm",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    ),
  );
  await fixture.waitForBackgroundWork();

  const result = await response.json();
  const content = result.choices[0].message.content;
  assert.deepEqual(models, [
    "z-ai/glm-5.3-flash",
    "z-ai/glm-5.3-flash-uncensored",
  ]);
  assert.equal(response.status, 200);
  assert.ok(content.trim());
  assert.doesNotMatch(content, /MULTILLM_ROLEPLAY_FALLBACK/);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(messages.some((message) => message.role === "assistant"), false);
  const state = (await stored?.get("roleplay-session")) ?? {};
  assert.equal(
    state.stats?.["nanogpt:z-ai/glm-5.3-flash"]?.semanticRefusals,
    1,
  );
  assert.equal(
    state.stats?.["nanogpt:z-ai/glm-5.3-flash"]?.cooldownUntil ?? 0,
    0,
  );
});

test("streaming GLM refusal trigger hides the rejected leg and switches models", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      nanogpt: {
        glm: [
          "z-ai/glm-5.3-flash",
          "z-ai/glm-5.3-flash-uncensored",
        ],
      },
    }),
  });
  const payloads = [];

  const { response, body } = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    payloads.push(payload);
    return payloads.length === 1
      ? streamingCompletion(
          payload.model,
          REFUSAL_FALLBACK_SENTINEL,
          "Check whether the request can be fulfilled.",
        )
      : streamingCompletion(
          payload.model,
          "*Mira continues the scene without breaking character.*",
        );
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-glm-semantic-refusal-stream",
        input: "Continue the scene.",
        model: "roleplay:glm",
        max_tokens: 512,
        stream: true,
      }),
      fixture.env,
    );
    return { response, body: await response.text() };
  });
  await fixture.waitForBackgroundWork();

  assert.deepEqual(
    payloads.map((payload) => payload.model),
    ["z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-uncensored"],
  );
  assert.equal(
    streamedContent(body),
    "*Mira continues the scene without breaking character.*",
  );
  assert.doesNotMatch(body, /MULTILLM_ROLEPLAY_FALLBACK|Check whether/);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(
    messages.findLast((message) => message.role === "assistant")?.content,
    "*Mira continues the scene without breaking character.*",
  );
});

test("normal roleplay dialogue mentioning refusal does not trigger fallback", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      nanogpt: {
        glm: [
          "z-ai/glm-5.3-flash",
          "z-ai/glm-5.3-flash-uncensored",
        ],
      },
    }),
  });
  let calls = 0;
  const roleplay = '*Mira folds her arms. "I refuse to leave."*';

  const response = await withGlobalFetch(async (_input, init) => {
    calls += 1;
    const payload = JSON.parse(init.body);
    return completionResponse(payload.model, roleplay);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-glm-refusal-dialogue",
        input: "Continue the scene.",
        model: "roleplay:glm",
        max_tokens: 512,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(calls, 1);
  assert.equal((await response.json()).choices[0].message.content, roleplay);
  assert.equal(
    response.headers.get("X-Roleplay-Model"),
    "z-ai/glm-5.3-flash",
  );
});
