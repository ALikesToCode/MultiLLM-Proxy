import assert from "node:assert/strict";
import test from "node:test";

import { parseRoleplayPayload } from "../worker/roleplay/memory.mjs";
import { sanitizeRoleplayMessages } from "../worker/roleplay/message-validation.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import {
  completionResponse,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const worker = (await loadWorkerModule()).default;
const paths = [
  "/v1/roleplay",
  "/roleplay/v1/chat/completions",
  "/v1/roleplay/chat/completions",
];

test("blank text placeholders are omitted without mutating incoming messages", () => {
  const messages = [
    { role: "system", content: "" },
    { role: "developer", content: "  Keep the setting consistent.  " },
    { role: "assistant", content: null },
    { role: "system" },
    { role: "user", content: "\n\t\u2003" },
    { role: "assistant", content: "Waiting.", name: " Mira " },
    { role: "user", content: "  Continue. " },
    { role: "tool", content: "Found the room.", tool_call_id: "call-1" },
  ];
  const original = structuredClone(messages);
  assert.deepEqual(sanitizeRoleplayMessages(messages, 1000), [
    { role: "developer", content: "Keep the setting consistent." },
    { role: "assistant", content: "Waiting.", name: "Mira" },
    { role: "user", content: "Continue." },
    { role: "tool", content: "Found the room.", tool_call_id: "call-1" },
  ]);
  assert.deepEqual(messages, original);
});

test("blank messages can accompany input but cannot form an empty request", () => {
  const messages = [{ role: "system", content: " " }];
  assert.throws(() => parseRoleplayPayload({ messages }), /Provide input/);
  assert.deepEqual(parseRoleplayPayload({ messages, input: "Continue." }).messages, [
    { role: "user", content: "Continue." },
  ]);
});

test("blank filtering retains validation and original message indexes", () => {
  const invalidMessages = [
    null,
    [],
    { role: "unknown", content: "" },
    { content: "" },
    { role: "user", content: [] },
    { role: "user", content: {} },
    { role: "user", content: 0 },
    { role: "user", content: false },
    { role: "tool", content: "", tool_call_id: "call-1" },
    { role: "assistant", content: null, tool_calls: [{ id: "call-1" }] },
    { role: "assistant", content: "", function_call: { name: "lookup" } },
    { role: "assistant", content: "", tool_call_id: "call-1" },
    { role: "assistant", content: "", refusal: "Unavailable." },
  ];
  for (const message of invalidMessages) {
    assert.throws(() => sanitizeRoleplayMessages([
      { role: "system", content: "" }, message,
    ], 1000), /messages\[1\]/);
  }
  assert.throws(() => sanitizeRoleplayMessages(
    Array.from({ length: 257 }, () => ({ role: "user", content: "" })), 1000,
  ), /at most 256/);
  assert.throws(() => sanitizeRoleplayMessages([
    { role: "system", content: "" }, { role: "user", content: "Too long" },
  ], 3), /messages\[1\].content must be at most 3/);
});

function makeNanoFixture() {
  return makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nano-roleplay-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      nanogpt: { glm: ["z-ai/glm-5.3-flash"] },
    }),
  });
}

function upstreamResponse(payload) {
  if (!payload.stream) return completionResponse(payload.model, "Mira listens.");
  const chunk = {
    id: "chatcmpl-blank-placeholder",
    model: payload.model,
    choices: [{ index: 0, delta: { content: "Mira listens." }, finish_reason: "stop" }],
  };
  return new Response(`data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`, {
    headers: { "Content-Type": "text/event-stream" },
  });
}

for (const pathname of paths) {
  for (const stream of [false, true]) {
    test(`${pathname} accepts blank incoming placeholders with stream=${stream}`, async () => {
      const fixture = makeNanoFixture();
      const upstreamPayloads = [];
      const response = await withGlobalFetch(async (_input, init) => {
        const payload = JSON.parse(init.body);
        upstreamPayloads.push(payload);
        return upstreamResponse(payload);
      }, () => worker.fetch(roleplayRequest({
        model: "roleplay:5.3-flash",
        messages: [
          { role: "system", content: "" },
          { role: "system", content: "Continue the scene." },
          { role: "assistant", content: "\n " },
          { role: "user", content: "Who is at the door?" },
        ],
        stream,
      }, { Origin: "https://janitorai.com" }, pathname), fixture.env));

      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://janitorai.com");
      const body = await response.text();
      assert.match(body, /Mira listens\./);
      if (stream) assert.match(body, /data: \[DONE\]/);
      assert.equal(upstreamPayloads.length, 1);
      assert.ok(upstreamPayloads[0].messages.every(message => message.content.trim()));
      assert.ok(upstreamPayloads[0].messages.some(message => message.content === "Continue the scene."));
      assert.ok(upstreamPayloads[0].messages.some(message => message.content === "Who is at the door?"));
      await fixture.waitForBackgroundWork();
    });
  }

  test(`${pathname} rejects an all-blank request without calling a provider`, async () => {
    const fixture = makeNanoFixture();
    const response = await withGlobalFetch(() => assert.fail("Unexpected provider request"),
      () => worker.fetch(roleplayRequest({
        model: "roleplay:5.3-flash",
        messages: [{ role: "system", content: "" }, { role: "assistant", content: null }],
      }, {}, pathname), fixture.env));
    assert.equal(response.status, 400);
    assert.match((await response.json()).error.message, /Provide input/);
  });
}
