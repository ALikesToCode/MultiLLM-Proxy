import assert from "node:assert/strict";
import test from "node:test";

import {
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";
import { parseRoleplayOutputBudget } from "../worker/roleplay/output-budget.mjs";
import { createObservedStream } from "../worker/roleplay/streaming.mjs";

const JANITOR_PATH = "/roleplay/v1/chat/completions";

function streamingResponse(model, content, finishReason) {
  const encoder = new TextEncoder();
  const payload = JSON.stringify({
    id: `chatcmpl-${finishReason}`,
    object: "chat.completion.chunk",
    model,
    choices: [
      {
        index: 0,
        delta: { content },
        finish_reason: finishReason,
      },
    ],
  });
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(`data: ${payload}\n\n`));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      },
    }),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function chunkedBody(chunks) {
  const encoder = new TextEncoder();
  const remaining = [...chunks];
  return new ReadableStream({
    pull(controller) {
      const chunk = remaining.shift();
      if (chunk === undefined) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(chunk));
    },
  });
}

test("Janitor output is unlimited and transparently continues after length", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "4",
  });
  const upstreamPayloads = [];

  let response;
  let body;
  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    return upstreamPayloads.length === 1
      ? streamingResponse(payload.model, "First half ", "length")
      : streamingResponse(payload.model, "finishes naturally.", "stop");
  }, async () => {
    response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-unlimited",
          model: "roleplay:glm",
          messages: [{ role: "user", content: "Tell the whole story." }],
          stream: true,
          max_tokens: 2_048,
        },
        { Origin: "https://janitorai.com" },
        JANITOR_PATH,
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Max-Output-Tokens"), "131072");
  assert.match(body, /First half/);
  assert.match(body, /finishes naturally\./);
  assert.doesNotMatch(body, /"finish_reason":"length"/);
  assert.match(body, /"finish_reason":"stop"/);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  assert.equal(upstreamPayloads.length, 2);
  assert.equal(upstreamPayloads[0].max_tokens, 131_072);
  assert.equal(upstreamPayloads[1].max_tokens, 131_072);
  assert.ok(
    upstreamPayloads[1].messages.some(
      (message) =>
        message.role === "assistant" && message.content === "First half ",
    ),
  );
  assert.ok(
    upstreamPayloads[1].messages.some(
      (message) =>
        message.role === "system" &&
        message.content.includes("Automatic continuation"),
    ),
  );

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-unlimited",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal(metrics.status, 200);
  const metricsPayload = await metrics.json();
  assert.equal(metricsPayload.turns, 1);
  assert.equal(metricsPayload.stored_messages, 2);
});

test("finite non-Janitor output keeps the caller ceiling", async () => {
  const fixture = makeRoleplayEnv({ ROLEPLAY_PROVIDER_ORDER: "opencode" });
  let calls = 0;
  const response = await withGlobalFetch(async (_input, init) => {
    calls += 1;
    const payload = JSON.parse(init.body);
    assert.equal(payload.max_tokens, 2_048);
    return streamingResponse(payload.model, "Bounded reply", "length");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-bounded-output",
        model: "roleplay:glm",
        input: "Continue.",
        stream: true,
        max_tokens: 2_048,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.headers.get("X-Roleplay-Max-Output-Tokens"), "2048");
  assert.match(await response.text(), /"finish_reason":"length"/);
  assert.equal(calls, 1);
});

test("unlimited continuation safety bound retains the emitted partial reply", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "1",
  });
  let calls = 0;
  let response;
  let body;

  await withGlobalFetch(async (_input, init) => {
    calls += 1;
    const payload = JSON.parse(init.body);
    return streamingResponse(payload.model, `Part ${calls}. `, "length");
  }, async () => {
    response = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-unlimited-safety-bound",
          model: "roleplay:glm",
          input: "Keep going.",
          stream: true,
          max_tokens: 1_000_000,
        },
        { Origin: "https://janitorai.com" },
        JANITOR_PATH,
      ),
      fixture.env,
    );
    body = await response.text();
    await fixture.waitForBackgroundWork();
  });

  assert.equal(calls, 2);
  assert.match(body, /Part 1\./);
  assert.match(body, /Part 2\./);
  assert.equal(body.match(/"finish_reason":"length"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-unlimited-safety-bound",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const payload = await metrics.json();
  assert.equal(payload.turns, 1);
  assert.equal(payload.stored_messages, 2);
});

test("roleplay output budget recognizes provider max and unlimited sentinels", () => {
  assert.deepEqual(parseRoleplayOutputBudget({}), {
    maxTokens: null,
    mode: "provider_max",
    requestedMaxTokens: null,
  });
  assert.deepEqual(parseRoleplayOutputBudget({ max_tokens: 2_048 }), {
    maxTokens: 2_048,
    mode: "bounded",
    requestedMaxTokens: 2_048,
  });
  assert.deepEqual(parseRoleplayOutputBudget({ max_tokens: 1_000_000 }), {
    maxTokens: null,
    mode: "unlimited",
    requestedMaxTokens: 1_000_000,
  });
  assert.deepEqual(
    parseRoleplayOutputBudget(
      { max_tokens: 2_048 },
      { forceUnlimited: true },
    ),
    {
      maxTokens: null,
      mode: "unlimited",
      requestedMaxTokens: 2_048,
    },
  );
  assert.throws(
    () => parseRoleplayOutputBudget({ output_mode: "endless" }),
    /output_mode must be bounded or unlimited/,
  );
});

test("continuation parser handles terminal SSE frames split across chunks", async () => {
  const firstBody = chunkedBody([
    'data: {"choices":[{"delta":{"content":"Split ',
    'start. "},"finish_reason":"length"}]}\n\ndata: [DONE]\n\n',
  ]);
  const finalBody = chunkedBody([
    'data: {"choices":[{"delta":{"content":"Completed."},',
    '"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
  ]);
  const observed = createObservedStream({
    upstreamBody: firstBody,
    requestSignal: new AbortController().signal,
    upstreamController: new AbortController(),
    heartbeatMs: 1_000,
    maxContinuations: 1,
    openContinuation: async () => ({
      upstreamBody: finalBody,
      upstreamController: new AbortController(),
    }),
    onComplete() {},
  });

  const body = await new Response(observed.stream).text();
  const completion = await observed.completion;
  assert.match(body, /Split start\. /);
  assert.match(body, /Completed\./);
  assert.doesNotMatch(body, /"finish_reason":"length"/);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
  assert.equal(completion.success, true);
  assert.equal(completion.continuationCount, 1);
  assert.equal(completion.assistant, "Split start. Completed.");
});

test("unlimited stream keeps sending heartbeats while a continuation opens", async () => {
  const observed = createObservedStream({
    upstreamBody: chunkedBody([
      'data: {"choices":[{"delta":{"content":"Before pause. "},"finish_reason":"length"}]}\n\n',
      "data: [DONE]\n\n",
    ]),
    requestSignal: new AbortController().signal,
    upstreamController: new AbortController(),
    heartbeatMs: 2,
    maxContinuations: 1,
    openContinuation: async () => {
      await new Promise((resolve) => setTimeout(resolve, 12));
      return {
        upstreamBody: chunkedBody([
          'data: {"choices":[{"delta":{"content":"After pause."},"finish_reason":"stop"}]}\n\n',
          "data: [DONE]\n\n",
        ]),
        upstreamController: new AbortController(),
      };
    },
    onComplete() {},
  });

  const body = await new Response(observed.stream).text();
  const completion = await observed.completion;
  assert.match(body, /: roleplay-keepalive/);
  assert.match(body, /Before pause\./);
  assert.match(body, /After pause\./);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
  assert.equal(completion.success, true);
  assert.ok(completion.heartbeatCount >= 1);
});
