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
  "Background/setting: describe the visible room.",
  "Main character focus: describe visible identity and anatomy.",
  "Outfit: describe visible clothes and materials.",
  "Accessories: describe visible jewelry and props.",
  "Hair and makeup: describe styling and cosmetics.",
  "Glamour read: describe concrete presentation details.",
  "Pose and expression: describe posture and facial muscles.",
  "Lighting: describe source, direction, color, and shadow.",
  "Composition and camera: describe viewpoint, crop, and angle.",
  "Mood: describe only visible light, posture, and room details.",
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

const CURRENT_IMAGE_CONTRACT = [
  "Story responses must end with exactly one IMAGE PROMPT block.",
  "IMAGE PROMPT:",
  "Always include Camera, Primary subject, Setting, Lighting, and Composition.",
  "Camera:",
  "Primary subject:",
  "Expression:",
  "Hair and grooming:",
  "Clothing:",
  "Ear styling:",
  "Accessories:",
  "Pose:",
  "Setting:",
  "Lighting:",
  "Composition:",
  "Rendering:",
].join("\n");

const STORY_WITH_CURRENT_IMAGE_PROMPT = [
  "*Mira closes the library door and points toward the marked shelf.*",
  "",
  "IMAGE PROMPT:",
  "Create a high-detail modern anime image.",
  "Camera: first-person medium shot at eye level.",
  "Primary subject: young adult woman with dark hair and brown eyes.",
  "Setting: old library at sunset, marked wooden shelf.",
  "Lighting: warm sunset through tall windows.",
  "Composition: Mira centered beyond a foreground table, shallow depth of field.",
].join("\n");

function streamingStory(content, finishReason = "stop") {
  return new Response(
    [
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: finishReason }] })}\n\n`,
      "data: [DONE]\n\n",
    ].join(""),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function reasoningOnlyEof() {
  return new Response(
    [
      `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "internal planning that must stay hidden" }, finish_reason: null }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: "  " }, finish_reason: null }] })}\n\n`,
    ].join(""),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function streamedContent(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice(6)))
    .map((payload) => payload.choices?.[0]?.delta?.content ?? "")
    .join("");
}

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

test("streaming releases one validated complete image prompt block", async () => {
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
  const body = await response.text();
  assert.equal(
    streamedContent(body),
    `*Mira opens the shelf.*\n\n${STORY_WITH_IMAGE_PROMPT.slice(STORY_WITH_IMAGE_PROMPT.indexOf("IMAGE PROMPT:"))}`,
  );
  assert.equal(body.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
  await fixture.waitForBackgroundWork();
});

test("reasoning-only provider EOF retries once from a clean response boundary", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "8",
  });
  const upstreamPayloads = [];
  let body;

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    return upstreamPayloads.length === 1
      ? reasoningOnlyEof()
      : streamingStory(STORY_WITH_CURRENT_IMAGE_PROMPT);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-retry-reasoning-only-eof",
          messages: [
            { role: "system", content: CURRENT_IMAGE_CONTRACT },
            { role: "user", content: "Open the marked shelf." },
          ],
          stream: true,
          max_tokens: 0,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(upstreamPayloads.length, 2);
  assert.equal(
    upstreamPayloads[1].messages.some((message) => message.role === "assistant"),
    false,
  );
  assert.equal(
    upstreamPayloads[1].messages.some(
      (message) =>
        message.role === "system" &&
        message.content.includes("ended before any visible response"),
    ),
    true,
  );
  assert.equal(streamedContent(body), STORY_WITH_CURRENT_IMAGE_PROMPT);
  assert.doesNotMatch(body, /internal planning|<think>/i);
  assert.equal(body.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(
    messages.findLast((message) => message.role === "assistant")?.content,
    STORY_WITH_CURRENT_IMAGE_PROMPT,
  );
});

test("repeated empty provider EOF stops after one clean retry and stores nothing", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "8",
  });
  let calls = 0;
  let body;

  await withGlobalFetch(async () => {
    calls += 1;
    return reasoningOnlyEof();
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-exhaust-empty-eof-retry",
          messages: [
            { role: "system", content: CURRENT_IMAGE_CONTRACT },
            { role: "user", content: "Open the marked shelf." },
          ],
          stream: true,
          max_tokens: 0,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(calls, 2);
  assert.equal(streamedContent(body), "");
  assert.doesNotMatch(body, /internal planning|<think>/i);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(messages.some((message) => message.role === "assistant"), false);
});

test("Janitor unlimited stream repairs a provider stop before the required image prompt", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "2",
  });
  const upstreamPayloads = [];

  let response;
  let body;
  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    return upstreamPayloads.length === 1
      ? streamingStory(
          [
            "*Mira reaches toward the marked shelf.*",
            "",
            "IMAGE PROMPT:",
            "Create a high-detail modern anime image.",
            "Background/setting: old library at sunset.",
          ].join("\n"),
        )
      : streamingStory(
          STORY_WITH_IMAGE_PROMPT.slice(
            STORY_WITH_IMAGE_PROMPT.indexOf("\nMain character focus:"),
          ),
        );
  }, async () => {
    response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-repair-incomplete-stop",
          messages: imageContractMessages(),
          stream: true,
          max_tokens: 1_000_000,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(upstreamPayloads.length, 2);
  assert.ok(
    upstreamPayloads[1].messages.some(
      (message) =>
        message.role === "assistant" &&
        message.content.includes("Background/setting: old library"),
    ),
  );
  assert.ok(
    upstreamPayloads[1].messages.some(
      (message) =>
        message.role === "system" &&
        message.content.includes("Automatic repair of an incomplete final output contract"),
    ),
  );
  assert.match(body, /Mira reaches toward the marked shelf/);
  assert.match(body, /IMAGE PROMPT:/);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
});

test("Janitor unlimited stream accepts stop after the required image prompt is complete", async () => {
  const fixture = makeRoleplayEnv({ ROLEPLAY_PROVIDER_ORDER: "opencode" });
  let calls = 0;
  let body;

  await withGlobalFetch(async () => {
    calls += 1;
    return streamingStory(STORY_WITH_IMAGE_PROMPT);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-accept-complete-stop",
          messages: imageContractMessages(),
          stream: true,
          max_tokens: 1_000_000,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(calls, 1);
  assert.match(body, /Mood: long shadows/);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
});

test("current image schema remains complete when a legacy contract is retained", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "2",
  });
  let calls = 0;
  let body;

  await withGlobalFetch(async () => {
    calls += 1;
    return streamingStory(STORY_WITH_CURRENT_IMAGE_PROMPT);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-current-schema-with-retained-legacy",
          messages: [
            { role: "system", content: IMAGE_CONTRACT },
            { role: "system", content: CURRENT_IMAGE_CONTRACT },
            { role: "user", content: "Open the marked shelf." },
          ],
          stream: true,
          max_tokens: 0,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(calls, 1);
  assert.equal(body.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
});

test("no-progress contract repair is suppressed and never persisted", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "8",
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  const initial = [
    "*Mira points toward the marked shelf.*",
    "",
    "IMAGE PROMPT:",
    "Setting: old library at sunset.",
  ].join("\n");
  const meta =
    "The response above was already complete. No continuation is needed. The next story turn belongs to Mysterious.";
  let calls = 0;
  let body;

  await withGlobalFetch(async () => {
    calls += 1;
    return streamingStory(calls === 1 ? initial : meta);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-contract-no-progress",
          messages: [
            { role: "system", content: CURRENT_IMAGE_CONTRACT },
            { role: "user", content: "Open the marked shelf." },
          ],
          stream: true,
          max_tokens: 0,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(calls, 2);
  assert.equal(streamedContent(body), initial);
  assert.doesNotMatch(body, /already complete|No continuation|next story turn/i);
  assert.equal(body.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(
    messages.some((message) => /Automatic repair|already complete/i.test(message.content)),
    false,
  );
  assert.equal(messages.some((message) => message.role === "assistant"), false);
});
