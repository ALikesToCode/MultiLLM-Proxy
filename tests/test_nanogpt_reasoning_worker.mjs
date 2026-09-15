import assert from "node:assert/strict";
import test from "node:test";
import { applyReasoningPolicy } from "../worker/roleplay/reasoning.mjs";
import { previewProfile } from "../worker/roleplay/profile-receipt.mjs";
import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const MODEL = "z-ai/glm-5.3-flash";
const REASONING = "Consider the clue and the possible routes. ".repeat(500);
const ANSWER = "Take the north path.";

function upstreamResponse(stream, reasoning) {
  const choices = [{ message: { role: "assistant", reasoning, content: ANSWER }, finish_reason: "stop" }];
  if (!stream) return new Response(JSON.stringify({ choices }), { headers: { "Content-Type": "application/json" } });
  const frames = [
    { delta: { reasoning } },
    { delta: { content: ANSWER }, finish_reason: "stop" },
  ].map((choice) => `data: ${JSON.stringify({ choices: [choice] })}\n\n`);
  return new Response(`${frames.join("")}data: [DONE]\n\n`, { headers: { "Content-Type": "text/event-stream" } });
}

function responseContent(body, stream) {
  if (!stream) return JSON.parse(body).choices[0].message.content;
  return body.split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice(6)).choices?.[0]?.delta?.content ?? "")
    .join("");
}

test("NanoGPT native defaults ignore the general roleplay effort setting", () => {
  for (const defaultEffort of [undefined, "high", "max"]) {
    for (const model of [MODEL, `${MODEL}-uncensored`, "zai-org/glm-5.2:thinking", "moonshotai/kimi-k2.6"]) {
      const payload = { model, messages: [] };
      assert.deepEqual(applyReasoningPolicy(payload, {
        provider: "nanogpt", model, family: model.includes("glm") ? "glm" : "kimi",
      }, { defaultEffort }), payload);
    }
  }
});

for (const path of ["/v1/roleplay", "/roleplay/v1/chat/completions"]) {
  test(`${path} preserves NanoGPT native thinking and caller overrides`, async (t) => {
    for (const stream of [false, true]) {
      for (const [options, expected] of [[{}, undefined], [{ reasoning_effort: "low" }, "low"],
        [{ reasoning_effort: "none" }, "none"], [{ reasoning_effort: "max" }, "xhigh"]]) {
        await t.test(`stream=${stream} options=${JSON.stringify(options)}`, async () => {
          const fixture = makeRoleplayEnv({
            NANOGPT_API_KEY: "nano-test-key",
            ROLEPLAY_PROVIDER_ORDER: "nanogpt",
            ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
            ROLEPLAY_DEFAULT_REASONING_EFFORT: "high",
            ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
          });
          const sent = [];
          const response = await withGlobalFetch(async (input, init) => {
            assert.equal(String(input), "https://nano-gpt.com/api/subscription/v1/chat/completions");
            sent.push(JSON.parse(init.body));
            return upstreamResponse(stream, expected === "none" ? "" : REASONING);
          }, async () => {
            const result = await handleRoleplayEdgeRequest(roleplayRequest({
              model: "roleplay:5.3-flash", messages: [{ role: "user", content: "Which path fits the clue?" }],
              stream, ...options,
            }, {}, path), fixture.env);
            const body = await result.text();
            await fixture.waitForBackgroundWork();
            assert.equal(result.status, 200);
            const content = responseContent(body, stream);
            assert.ok(content.includes(ANSWER));
            if (expected !== "none") assert.ok(content.includes(REASONING.trim()), "full upstream reasoning reaches the client");
            return result;
          });
          assert.equal(response.status, 200);
          assert.equal(sent.length, 1);
          assert.equal(sent[0].reasoning_effort, expected);
          assert.equal(Object.hasOwn(sent[0], "reasoning_effort"), expected !== undefined);
          assert.equal(Object.hasOwn(sent[0], "reasoning"), false);
          assert.equal(Object.hasOwn(sent[0], "thinking"), false);
        });
      }
    }
  });
}

test("NanoGPT profile receipts report native defaults and explicit mapped effort", () => {
  for (const [options, requested, wire] of [[{}, "native", "native"],
    [{ reasoning_effort: "low" }, "low", "low"], [{ reasoning_effort: "max" }, "max", "xhigh"]]) {
    const preview = previewProfile({
      routing: { mode: "pinned", provider: "nanogpt", model: MODEL, fallback: "none" }, ...options,
    }, { NANOGPT_API_KEY: "nano-test-key", ROLEPLAY_DEFAULT_REASONING_EFFORT: "high" });
    assert.equal(preview.selected.requestedEffort, requested);
    assert.equal(preview.selected.wireEffort, wire);
    assert.equal(preview.selected.providerAcknowledged, false);
  }
});

test("NanoGPT memory compaction also leaves effort unset", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-test-key", ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4", ROLEPLAY_DEFAULT_REASONING_EFFORT: "max",
  });
  const sent = [];
  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    sent.push(payload);
    const compacting = payload.messages[0].content.startsWith("You manage continuity for a long-running roleplay.");
    return completionResponse(payload.model, compacting ? JSON.stringify({
      compact: true, summary: "The characters are deciding which path to take.",
      character_facts: [], relationships: [], world_state: [], open_threads: [], tone_style: [],
    }) : ANSWER);
  }, () => handleRoleplayEdgeRequest(roleplayRequest({
    model_preference: "glm", stream: false, memory: { mode: "force" },
    messages: Array.from({ length: 8 }, (_, index) => ({
      role: index % 2 === 0 ? "user" : "assistant", content: `Scene event ${index}`,
    })),
  }), fixture.env));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "model_compacted");
  assert.equal(sent.length, 2);
  for (const payload of sent) {
    assert.equal(payload.model, MODEL);
    assert.equal(Object.hasOwn(payload, "reasoning_effort"), false);
    assert.equal(Object.hasOwn(payload, "reasoning"), false);
  }
  await response.text();
  await fixture.waitForBackgroundWork();
});
