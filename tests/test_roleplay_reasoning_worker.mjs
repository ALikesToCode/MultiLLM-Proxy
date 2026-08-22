import assert from "node:assert/strict";
import test from "node:test";

import {
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const JANITOR_PATH = "/roleplay/v1/chat/completions";

function visibleContent(streamBody) {
  return streamBody
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .flatMap((line) => {
      const payload = JSON.parse(line.slice("data: ".length));
      const content = payload?.choices?.[0]?.delta?.content;
      return typeof content === "string" ? [content] : [];
    })
    .join("");
}

async function normalizedReasoningContent({
  sessionId,
  reasoningChunks,
  visible,
  model = "glm-5.2",
}) {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: [model] },
    }),
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
  });
  const upstreamEvents = [
    ...reasoningChunks.map((reasoningContent) =>
      `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: reasoningContent }, finish_reason: null }] })}\n\n`,
    ),
    `data: ${JSON.stringify({ choices: [{ delta: { content: visible }, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("");

  const response = await withGlobalFetch(
    async () =>
      new Response(upstreamEvents, {
        headers: { "Content-Type": "text/event-stream" },
      }),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: sessionId,
            model: "roleplay:glm",
            messages: [{ role: "user", content: "Continue." }],
            max_tokens: 512,
            stream: true,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  const content = visibleContent(await response.text());
  await fixture.waitForBackgroundWork();
  return content;
}

test("roleplay keeps duplicated provider reasoning inside one labelled think block", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3"] },
    }),
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
  });

  const reasoningPrefix = "The user is playing as Mysterious. ";
  const reasoningSuffix = "I should write Holly's response.";
  const reasoning = `${reasoningPrefix}${reasoningSuffix}`;
  const leakedContent = [
    `<think>${reasoningPrefix}<think>${reasoningSuffix}</think>\n\n`,
    `${reasoningSuffix}</think>\n\n`,
    "*Holly turns in her seat.*",
  ].join("");
  const upstreamEvents = [
    `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: reasoning } }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: { content: leakedContent }, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("");

  const response = await withGlobalFetch(
    async () =>
      new Response(upstreamEvents, {
        headers: { "Content-Type": "text/event-stream" },
      }),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "session-reasoning-deduplication",
            model: "roleplay:5.3",
            messages: [{ role: "user", content: "Continue." }],
            max_tokens: 512,
            stream: true,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  const body = await response.text();
  const content = visibleContent(body);
  await fixture.waitForBackgroundWork();

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(response.headers.get("X-Roleplay-Model"), "glm-5.3");
  assert.equal(content.match(/<think>/g)?.length, 1);
  assert.equal(content.match(/<\/think>/g)?.length, 1);
  assert.equal(
    content,
    [
      "<think>[provider: opencode | model: glm-5.3]\n",
      reasoning,
      "</think>\n\n",
      "*Holly turns in her seat.*",
    ].join(""),
  );
  const [{ storage }] = [...fixture.storageBySession.values()];
  const storedMessages = storage.values.get("roleplay-messages");
  assert.equal(storedMessages.at(-1).role, "assistant");
  assert.equal(storedMessages.at(-1).content, "*Holly turns in her seat.*");
});

test("roleplay preserves leading spaces in visible stream chunks after reasoning", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3"] },
    }),
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
  });
  const visible = [
    "*There's",
    " just",
    " a",
    " blade",
    " in",
    " her",
    " hand.*\n\nIMAGE",
    " PROMPT:\nCreate",
    " a",
    " high-detail",
    " modern",
    " anime",
    " image.",
  ];
  const upstreamEvents = [
    `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "Plan the scene." }, finish_reason: null }] })}\n\n`,
    ...visible.map((content, index) =>
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: index === visible.length - 1 ? "stop" : null }] })}\n\n`,
    ),
    "data: [DONE]\n\n",
  ].join("");

  const response = await withGlobalFetch(
    async () =>
      new Response(upstreamEvents, {
        headers: { "Content-Type": "text/event-stream" },
      }),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "session-reasoning-visible-spacing",
            model: "roleplay:5.3",
            messages: [{ role: "user", content: "Continue." }],
            max_tokens: 512,
            stream: true,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  const content = visibleContent(await response.text());
  await fixture.waitForBackgroundWork();

  assert.equal(
    content,
    [
      "<think>[provider: opencode | model: glm-5.3]\n",
      "Plan the scene.",
      "</think>\n\n",
      visible.join(""),
    ].join(""),
  );
  assert.match(content, /There's just a blade in her hand/);
  assert.match(content, /IMAGE PROMPT:/);
});

test("roleplay preserves repeated GLM token deltas in reasoning", async () => {
  const reasoningChunks = [
    "The Human has",
    " M",
    "ysterious",
    " slap",
    " Ny",
    "la",
    " hard.",
    " ",
    "Let",
    " me",
    " think",
    ".",
  ];
  const content = await normalizedReasoningContent({
    sessionId: "session-reasoning-repeated-glm-deltas",
    reasoningChunks,
    visible: "*Nyla turns back.*",
  });

  assert.equal(
    content,
    [
      "<think>[provider: opencode | model: glm-5.2]\n",
      reasoningChunks.join(""),
      "</think>\n\n",
      "*Nyla turns back.*",
    ].join(""),
  );
});

test("roleplay collapses cumulative reasoning snapshots", async () => {
  const reasoning = "Plan the scene carefully. Keep Nyla in character.";
  const content = await normalizedReasoningContent({
    sessionId: "session-reasoning-cumulative-snapshots",
    reasoningChunks: ["Plan the scene carefully.", reasoning, reasoning],
    visible: "*Nyla stays silent.*",
  });

  assert.equal(
    content,
    [
      "<think>[provider: opencode | model: glm-5.2]\n",
      reasoning,
      "</think>\n\n",
      "*Nyla stays silent.*",
    ].join(""),
  );
});

test("roleplay continues a chunked post-reasoning image prompt to completion", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3"] },
    }),
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "2",
  });
  const calls = [];
  const firstLeg = [
    `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "Plan the scene." }, finish_reason: null }] })}\n\n`,
    ...[
      "*There's",
      " just",
      " a",
      " blade.*\n\nIMAGE",
      " PROMPT:\nComposition",
      " and",
      " camera: first-person",
      " view, viewer's",
      " glowing",
      " outline",
    ].map((content, index, chunks) =>
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: index === chunks.length - 1 ? "stop" : null }] })}\n\n`,
    ),
    "data: [DONE]\n\n",
  ].join("");
  const secondLeg = [
    `data: ${JSON.stringify({ choices: [{ delta: { content: [
      ".",
      "Primary subject: a young adult woman facing the viewer.",
      "Setting: frozen academy arena.",
      "Lighting: cold blue light across airborne dust.",
      "Mood: cold blue light and frozen dust.",
    ].join("\n") }, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("");

  let response;
  let body;
  await withGlobalFetch(
    async (_input, init) => {
      calls.push(JSON.parse(init.body));
      return new Response(calls.length === 1 ? firstLeg : secondLeg, {
        headers: { "Content-Type": "text/event-stream" },
      });
    },
    async () => {
      response = await handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "session-reasoning-image-continuation",
            model: "roleplay:5.3",
            messages: [
              {
                role: "system",
                content: [
                  "A complete IMAGE PROMPT block is mandatory.",
                  "IMAGE PROMPT:",
                  "Composition and camera:",
                  "Mood:",
                ].join("\n"),
              },
              { role: "user", content: "Continue." },
            ],
            max_tokens: 0,
            stream: true,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      );
      body = await response.text();
      await fixture.waitForBackgroundWork();
    },
  );

  const content = visibleContent(body);

  assert.equal(calls.length, 2);
  assert.match(content, /There's just a blade/);
  assert.match(content, /IMAGE PROMPT:/);
  assert.match(content, /viewer\'s glowing outline\.\nPrimary subject:/);
  assert.match(content, /Mood: cold blue light and frozen dust/);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
});

test("non-streaming roleplay removes duplicate reasoning fields and labels the selected route", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      opencode: { glm: ["glm-5.3"] },
    }),
  });
  const reasoning = "The user is playing as Mysterious. I should answer as Holly.";
  const malformed = [
    `<think>${reasoning}</think>\n\n`,
    `${reasoning}</think>\n\n`,
    "*Holly raises her hand.*",
  ].join("");

  const response = await withGlobalFetch(
    async () =>
      new Response(
        JSON.stringify({
          id: "chatcmpl-reasoning-non-stream",
          object: "chat.completion",
          model: "glm-5.3",
          choices: [
            {
              index: 0,
              message: {
                role: "assistant",
                content: malformed,
                reasoning_content: reasoning,
                reasoning,
                reasoning_details: [{ text: reasoning }],
              },
              finish_reason: "stop",
            },
          ],
        }),
        { headers: { "Content-Type": "application/json" } },
      ),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "session-reasoning-non-stream",
            model: "roleplay:5.3",
            messages: [{ role: "user", content: "Continue." }],
            stream: false,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  const payload = await response.json();
  const message = payload.choices[0].message;

  assert.equal(response.status, 200);
  assert.equal("reasoning_content" in message, false);
  assert.equal(message.content.match(/<think>/g)?.length, 1);
  assert.equal(message.content.match(/<\/think>/g)?.length, 1);
  assert.equal(
    message.content,
    [
      "<think>[provider: opencode | model: glm-5.3]\n",
      reasoning,
      "</think>\n\n",
      "*Holly raises her hand.*",
    ].join(""),
  );
});

test("roleplay repairs think tags split across provider stream frames", async () => {
  const fixture = makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
  });
  const upstreamEvents = [
    { content: "<thi" },
    { content: "nk>private analysis" },
    { content: "</thi" },
    { content: "nk>\n\n*Holly closes her notebook.*", finish: "stop" },
  ]
    .map(({ content, finish = null }) =>
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: finish }] })}\n\n`,
    )
    .concat("data: [DONE]\n\n")
    .join("");

  const response = await withGlobalFetch(
    async () =>
      new Response(upstreamEvents, {
        headers: { "Content-Type": "text/event-stream" },
      }),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "session-split-reasoning-tags",
            model: "roleplay:glm",
            messages: [{ role: "user", content: "Continue." }],
            stream: true,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  const content = visibleContent(await response.text());
  await fixture.waitForBackgroundWork();

  assert.equal(response.headers.get("X-Roleplay-Provider"), "nanogpt");
  assert.equal(
    content,
    [
      "<think>[provider: nanogpt | model: zai-org/glm-5.2:thinking]\n",
      "private analysis",
      "</think>\n\n",
      "*Holly closes her notebook.*",
    ].join(""),
  );
});

test("roleplay drops provider reasoning that arrives after visible story content", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
  });
  const upstreamEvents = [
    `data: ${JSON.stringify({ choices: [{ delta: { content: "Visible beginning." }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "late hidden analysis" }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: { content: "<think>also late</think> Visible end." }, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("");

  const response = await withGlobalFetch(
    async () =>
      new Response(upstreamEvents, {
        headers: { "Content-Type": "text/event-stream" },
      }),
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "session-late-reasoning",
            model: "roleplay:glm",
            messages: [{ role: "user", content: "Continue." }],
            stream: true,
          },
          { Origin: "https://janitorai.com" },
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  const content = visibleContent(await response.text());
  await fixture.waitForBackgroundWork();

  assert.equal(content, "Visible beginning. Visible end.");
  assert.doesNotMatch(content, /late hidden|also late|<\/?think>/);
});
