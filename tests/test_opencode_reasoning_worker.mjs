import assert from "node:assert/strict";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const worker = (await loadWorkerModule()).default;
const OPENCODE_CHAT_URL =
  "https://multillm-proxy.cserules.workers.dev/opencode/v1/chat/completions";

function makeContainerEnv(fetchImpl) {
  let calls = 0;
  return {
    getCalls() {
      return calls;
    },
    env: {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_GO_API_KEY: "opencode-go-key",
      OPENCODE_EDGE_FETCH: "false",
      MULTILLM_PROXY_CONTAINER: {
        getByName(name) {
          assert.equal(name, "primary");
          return {
            async fetch(request) {
              calls += 1;
              return fetchImpl(request);
            },
          };
        },
      },
    },
  };
}

function streamedContent(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .flatMap((line) => {
      const payload = JSON.parse(line.slice("data: ".length));
      const content = payload?.choices?.[0]?.delta?.content;
      return typeof content === "string" ? [content] : [];
    })
    .join("");
}

test("container-backed OpenCode chat emits one route-labelled reasoning block", async () => {
  const reasoning = "The user wants a concise philosophical reply.";
  const malformedContent = [
    `<think>${reasoning}<think>Draft Holly's response.</think>\n\n`,
    "Draft Holly's response.</think>\n\n",
    "*Holly closes her notebook.*",
  ].join("");
  const upstreamEvents = [
    `data: ${JSON.stringify({
      id: "chatcmpl-ox-reasoning",
      model: "ox-alpha-free",
      choices: [
        {
          index: 0,
          delta: { reasoning_content: reasoning },
          finish_reason: null,
        },
      ],
    })}\n\n`,
    `data: ${JSON.stringify({
      id: "chatcmpl-ox-reasoning",
      model: "ox-alpha-free",
      choices: [
        {
          index: 0,
          delta: { content: malformedContent },
          finish_reason: "stop",
        },
      ],
    })}\n\n`,
    "data: [DONE]\n\n",
  ].join("");
  const requestBody = JSON.stringify({
    model: "ox-alpha-free",
    messages: [{ role: "user", content: "Continue." }],
    stream: true,
  });
  const fixture = makeContainerEnv(async (request) => {
    assert.equal(request.url, OPENCODE_CHAT_URL);
    assert.equal(await request.text(), requestBody);
    return new Response(upstreamEvents, {
      headers: { "Content-Type": "text/event-stream" },
    });
  });

  const response = await worker.fetch(
    new Request(OPENCODE_CHAT_URL, {
      method: "POST",
      headers: {
        Authorization: "Bearer admin-live-key",
        "Content-Type": "application/json",
        Origin: "https://janitorai.com",
      },
      body: requestBody,
    }),
    fixture.env,
  );
  const content = streamedContent(await response.text());

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://janitorai.com");
  assert.equal(response.headers.get("X-MultiLLM-Provider"), "opencode");
  assert.equal(response.headers.get("X-MultiLLM-Model"), "ox-alpha-free");
  assert.equal(content.match(/<think>/g)?.length, 1);
  assert.equal(content.match(/<\/think>/g)?.length, 1);
  assert.equal(
    content,
    [
      "<think>[provider: opencode | model: ox-alpha-free]\n",
      `${reasoning}Draft Holly's response.`,
      "</think>\n\n",
      "*Holly closes her notebook.*",
    ].join(""),
  );
  assert.equal(fixture.getCalls(), 1);
});

test("container-backed non-stream OpenCode chat removes duplicate reasoning fields", async () => {
  const reasoning = "Plan the next visible story beat.";
  const requestBody = JSON.stringify({
    model: "ox-alpha-free",
    messages: [{ role: "user", content: "Continue." }],
    stream: false,
  });
  const fixture = makeContainerEnv(async () =>
    new Response(
      JSON.stringify({
        id: "chatcmpl-ox-json",
        model: "ox-alpha-free",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              reasoning_content: reasoning,
              content: [
                `<think>${reasoning}</think>\n\n`,
                `${reasoning}</think>\n\n`,
                "*Holly raises one eyebrow.*",
              ].join(""),
            },
            finish_reason: "stop",
          },
        ],
      }),
      {
        headers: {
          "Content-Type": "application/json",
          ETag: '"upstream-body"',
        },
      },
    ),
  );

  const response = await worker.fetch(
    new Request(OPENCODE_CHAT_URL, {
      method: "POST",
      headers: {
        Authorization: "Bearer admin-live-key",
        "Content-Type": "application/json",
      },
      body: requestBody,
    }),
    fixture.env,
  );
  const payload = await response.json();
  const message = payload.choices[0].message;

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-MultiLLM-Provider"), "opencode");
  assert.equal(response.headers.get("X-MultiLLM-Model"), "ox-alpha-free");
  assert.equal(response.headers.get("ETag"), null);
  assert.equal("reasoning_content" in message, false);
  assert.equal(message.content.match(/<think>/g)?.length, 1);
  assert.equal(message.content.match(/<\/think>/g)?.length, 1);
  assert.equal(
    message.content,
    [
      "<think>[provider: opencode | model: ox-alpha-free]\n",
      reasoning,
      "</think>\n\n",
      "*Holly raises one eyebrow.*",
    ].join(""),
  );
  assert.equal(fixture.getCalls(), 1);
});
