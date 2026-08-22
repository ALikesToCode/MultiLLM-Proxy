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
            model: "roleplay:glm",
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
