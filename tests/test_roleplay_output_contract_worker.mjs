import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const IMAGE_CONTRACT = [
  "You are Celia, a private roleplay engine.",
  "A complete IMAGE PROMPT block is mandatory at the end of every story response.",
  "IMAGE PROMPT:",
  "Create a high-detail modern anime image.",
].join("\n");

const STORY_WITH_IMAGE_PROMPT = [
  "*Mira closes the library door and points toward the marked shelf.*",
  "",
  "IMAGE PROMPT:",
  "Create a high-detail modern anime image.",
  "Background/setting: old library at sunset, marked wooden shelf.",
  "Main character focus: young adult woman with dark hair and brown eyes.",
  "Outfit: fitted academy uniform with a loosened blue ribbon.",
  "Accessories: silver stud earrings and a thin silver pendant.",
  "Hair and makeup: shoulder-length dark hair, defined lashes, rose lips.",
  "Glamour read: polished uniform, jewelry catching amber light.",
  "Pose and expression: one hand on the shelf, focused gaze.",
  "Lighting: warm sunset through tall windows.",
  "Composition and camera: first-person medium shot, eye level.",
  "Mood: long shadows, dusty shelves, still posture.",
].join("\n");

function imageContractMessages(userContent = "Open the marked shelf.") {
  return [
    { role: "system", content: IMAGE_CONTRACT },
    { role: "assistant", content: "*Mira waits beside the shelf.*" },
    { role: "user", content: userContent },
  ];
}

test("roleplay reinforces a mandatory image prompt and reserves output budget", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_IMAGE_PROMPT_MIN_OUTPUT_TOKENS: "2048",
  });
  let upstreamPayload;

  const response = await withGlobalFetch(async (_input, init) => {
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(
      upstreamPayload.model,
      STORY_WITH_IMAGE_PROMPT,
    );
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-image-contract",
        messages: imageContractMessages(),
        max_tokens: 256,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(upstreamPayload.max_tokens, 2048);
  assert.deepEqual(upstreamPayload.messages[0], {
    role: "system",
    content: IMAGE_CONTRACT,
  });
  const reminderIndex = upstreamPayload.messages.findIndex((message) =>
    message.content.startsWith("[Caller-required final output contract]"),
  );
  const latestUserIndex = upstreamPayload.messages.findIndex(
    (message) => message.content === "Open the marked shelf.",
  );
  assert.ok(reminderIndex > 0);
  assert.equal(reminderIndex, latestUserIndex - 1);
  assert.match(
    upstreamPayload.messages[reminderIndex].content,
    /exactly one complete IMAGE PROMPT: block at the end/,
  );
  assert.equal(
    response.headers.get("X-Roleplay-Max-Output-Tokens"),
    "2048",
  );
  const responsePayload = await response.json();
  assert.equal(
    responsePayload.choices[0].message.content,
    STORY_WITH_IMAGE_PROMPT,
  );
});

test("an explicit no-image turn bypasses reinforcement and the budget floor", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_IMAGE_PROMPT_MIN_OUTPUT_TOKENS: "2048",
  });
  let upstreamPayload;

  const response = await withGlobalFetch(async (_input, init) => {
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(upstreamPayload.model, "*Mira nods once.*");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-no-image-command",
        messages: imageContractMessages("Continue. No image."),
        max_tokens: 256,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(upstreamPayload.max_tokens, 256);
  assert.equal(
    upstreamPayload.messages.some((message) =>
      message.content.startsWith("[Caller-required final output contract]"),
    ),
    false,
  );
});

test("retained image-prompt directives reinforce later delta-only turns", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_IMAGE_PROMPT_MIN_OUTPUT_TOKENS: "2048",
  });
  const upstreamPayloads = [];

  const responses = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    return completionResponse(payload.model, STORY_WITH_IMAGE_PROMPT);
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-retained-image-contract",
        messages: imageContractMessages(),
        max_tokens: 256,
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-retained-image-contract",
        input: "Continue from the open shelf.",
        max_tokens: 256,
        stream: false,
      }),
      fixture.env,
    );
    return [first, second];
  });

  assert.deepEqual(responses.map((response) => response.status), [200, 200]);
  assert.equal(upstreamPayloads.length, 2);
  assert.equal(upstreamPayloads[1].messages[0].content, IMAGE_CONTRACT);
  assert.equal(upstreamPayloads[1].max_tokens, 2048);
  assert.equal(
    upstreamPayloads[1].messages.some((message) =>
      message.content.startsWith("[Caller-required final output contract]"),
    ),
    true,
  );
});

test("streaming preserves the complete image prompt block byte for byte", async () => {
  const fixture = makeRoleplayEnv();
  const events = [
    `data: ${JSON.stringify({ choices: [{ delta: { content: "*Mira opens the shelf.*\n\n" } }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: { content: STORY_WITH_IMAGE_PROMPT.slice(STORY_WITH_IMAGE_PROMPT.indexOf("IMAGE PROMPT:")) }, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    assert.equal(payload.max_tokens, 2048);
    return new Response(events.join(""), {
      headers: { "Content-Type": "text/event-stream" },
    });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-streaming-image-contract",
        messages: imageContractMessages(),
        max_tokens: 512,
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(await response.text(), events.join(""));
  await fixture.waitForBackgroundWork();
});
