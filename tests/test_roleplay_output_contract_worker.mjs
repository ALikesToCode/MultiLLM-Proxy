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

const CURRENT_IMAGE_PROMPT_ONLY = STORY_WITH_CURRENT_IMAGE_PROMPT.slice(
  STORY_WITH_CURRENT_IMAGE_PROMPT.indexOf("IMAGE PROMPT:"),
);

function streamingStory(content, finishReason = "stop") {
  return new Response(
    [
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: finishReason }] })}\n\n`,
      "data: [DONE]\n\n",
    ].join(""),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function streamingReasoningStory(reasoning, content, finishReason = "stop") {
  return new Response(
    [
      `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: reasoning }, finish_reason: null }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: finishReason }] })}\n\n`,
      "data: [DONE]\n\n",
    ].join(""),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function reasoningOnlyEof() {
  return new Response(
    `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "provider planning from the empty attempt" }, finish_reason: null }] })}\n\n`,
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

test("streaming releases reasoning and story before the image prompt is complete", async () => {
  const fixture = makeRoleplayEnv();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let releaseImagePrompt;
  const imagePromptGate = new Promise((resolve) => {
    releaseImagePrompt = resolve;
  });

  const response = await withGlobalFetch(
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(
              encoder.encode(
                `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "Plan the visible scene." }, finish_reason: null }] })}\n\n`,
              ),
            );
            controller.enqueue(
              encoder.encode(
                `data: ${JSON.stringify({ choices: [{ delta: { content: "*Mira opens the shelf.*\n\n" }, finish_reason: null }] })}\n\n`,
              ),
            );
            void imagePromptGate.then(() => {
              controller.enqueue(
                encoder.encode(
                  `data: ${JSON.stringify({ choices: [{ delta: { content: STORY_WITH_IMAGE_PROMPT.slice(STORY_WITH_IMAGE_PROMPT.indexOf("IMAGE PROMPT:")) }, finish_reason: "stop" }] })}\n\n` +
                    "data: [DONE]\n\n",
                ),
              );
              controller.close();
            });
          },
        }),
        { headers: { "Content-Type": "text/event-stream" } },
      ),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: "session-stream-story-before-image-validation",
          messages: imageContractMessages(),
          max_tokens: 512,
          stream: true,
        }),
        fixture.env,
      ),
  );

  const reader = response.body.getReader();
  let settledReads = 0;
  const firstReadPromise = reader.read().then((result) => {
    settledReads += 1;
    return result;
  });
  const secondReadPromise = reader.read().then((result) => {
    settledReads += 1;
    return result;
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  const liveChunksBeforeImagePrompt = settledReads;
  releaseImagePrompt();

  const earlyReads = await Promise.all([firstReadPromise, secondReadPromise]);
  let body = earlyReads
    .map((result) => decoder.decode(result.value ?? new Uint8Array()))
    .join("");
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) {
      break;
    }
    body += decoder.decode(chunk.value, { stream: true });
  }
  body += decoder.decode();
  await fixture.waitForBackgroundWork();

  assert.equal(
    liveChunksBeforeImagePrompt,
    2,
    "reasoning and story must not wait for final image-prompt validation",
  );
  assert.equal(
    streamedContent(body),
    [
      "<think>[provider: opencode | model: kimi-k2.6]\n",
      "Plan the visible scene.",
      "</think>\n\n",
      "*Mira opens the shelf.*\n\n",
      STORY_WITH_IMAGE_PROMPT.slice(STORY_WITH_IMAGE_PROMPT.indexOf("IMAGE PROMPT:")),
    ].join(""),
  );
  assert.equal(body.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
});

test("reasoning-only provider EOF streams immediately before a clean retry", async () => {
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
  assert.equal(
    streamedContent(body),
    [
      "<think>[provider: opencode | model: kimi-k2.6]\n",
      "provider planning from the empty attempt",
      "</think>\n\n",
      STORY_WITH_CURRENT_IMAGE_PROMPT,
    ].join(""),
  );
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

test("an image-only retry is discarded before regenerating the complete story", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "8",
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  const upstreamPayloads = [];
  let body;

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    if (upstreamPayloads.length === 1) {
      return reasoningOnlyEof();
    }
    return upstreamPayloads.length === 2
      ? streamingStory(CURRENT_IMAGE_PROMPT_ONLY)
      : streamingStory(STORY_WITH_CURRENT_IMAGE_PROMPT);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-retry-image-only-response",
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

  assert.equal(upstreamPayloads.length, 3);
  assert.equal(
    upstreamPayloads[2].messages.some(
      (message) => message.role === "assistant",
    ),
    false,
  );
  assert.equal(
    upstreamPayloads[2].messages.some(
      (message) =>
        message.role === "system" &&
        message.content.includes("no visible story content"),
    ),
    true,
  );
  assert.equal(
    streamedContent(body),
    [
      "<think>[provider: opencode | model: kimi-k2.6]\n",
      "provider planning from the empty attempt",
      "</think>\n\n",
      STORY_WITH_CURRENT_IMAGE_PROMPT,
    ].join(""),
  );
  assert.equal(body.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(body.match(/\"finish_reason\":\"stop\"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(
    messages.findLast((message) => message.role === "assistant")?.content,
    STORY_WITH_CURRENT_IMAGE_PROMPT,
  );
});

test("repeated empty provider EOF streams each attempt but stores nothing", async () => {
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
  assert.equal(streamedContent(body).match(/<think>/g)?.length, 2);
  assert.equal(streamedContent(body).match(/<\/think>/g)?.length, 2);
  assert.equal(streamedContent(body).match(/provider planning from the empty attempt/g)?.length, 2);
  assert.doesNotMatch(body, /IMAGE PROMPT:/i);
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

test("combined image labels complete without a repair continuation", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3-flash"] },
    }),
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  const combined = [
    "*Mira closes the book.*",
    "",
    "IMAGE PROMPT:",
    "Camera & Composition: first-person medium shot, subject centered.",
    "Primary subject: young adult woman with dark braids and a closed book.",
    "Setting: old library beside a tall window.",
    "Lighting and rendering: warm sunset with soft shadows.",
  ].join("\n");
  let calls = 0;
  let body;

  await withGlobalFetch(async () => {
    calls += 1;
    return streamingReasoningStory("Plan the visible scene.", combined);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-combined-image-labels",
          messages: [
            { role: "system", content: CURRENT_IMAGE_CONTRACT },
            { role: "user", content: "Close the book." },
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

  const content = streamedContent(body);
  assert.equal(calls, 1);
  assert.equal(content.match(/<think>/g)?.length, 1);
  assert.equal(content.match(/<\/think>/g)?.length, 1);
  assert.equal(content.match(/\[provider:/g)?.length, 1);
  assert.equal(content.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.match(content, /Camera & Composition:/);
  assert.match(content, /Lighting and rendering:/);
  assert.doesNotMatch(content, /\nCamera:|\nComposition:/);
});

test("contract repair hides second-leg reasoning and preserves the story", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3-flash"] },
    }),
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  const incomplete = [
    "*Mira closes the book.*",
    "",
    "IMAGE PROMPT:",
    "Camera: first-person medium shot.",
    "Primary subject: young adult woman with dark braids.",
    "Setting: old library beside a tall window.",
  ].join("\n");
  const repair = [
    "Lighting: warm sunset with soft shadows.",
    "Composition: Mira centered beyond a foreground table.",
  ].join("\n");
  let calls = 0;
  let body;

  await withGlobalFetch(async () => {
    calls += 1;
    return calls === 1
      ? streamingReasoningStory("Plan the visible scene.", incomplete)
      : streamingReasoningStory("Identify the missing fields.", repair);
  }, async () => {
    const response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-repair-hides-reasoning",
          messages: [
            { role: "system", content: CURRENT_IMAGE_CONTRACT },
            { role: "user", content: "Close the book." },
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

  const content = streamedContent(body);
  assert.equal(calls, 2);
  assert.equal(content.match(/<think>/g)?.length, 1);
  assert.equal(content.match(/<\/think>/g)?.length, 1);
  assert.equal(content.match(/\[provider:/g)?.length, 1);
  assert.doesNotMatch(content, /Identify the missing fields/);
  assert.equal(content.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.match(content, /\*Mira closes the book\.\*/);
  assert.match(content, /Lighting: warm sunset/);
  assert.match(content, /Composition: Mira centered/);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  const assistant = messages.findLast((message) => message.role === "assistant");
  assert.equal(assistant?.content, `${incomplete}\n${repair}`);
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
