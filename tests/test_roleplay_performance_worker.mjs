import assert from "node:assert/strict";
import test from "node:test";

import {
  compactionPlan,
} from "../worker/roleplay/memory.mjs";
import { applyRoleplayPromptCache } from "../worker/roleplay/prompt-cache.mjs";
import { createSseAssistantCollector } from "../worker/roleplay/sse-collector.mjs";
import {
  modelThroughputMetrics,
  recordThroughputObservation,
} from "../worker/roleplay/model-performance.mjs";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

function opencodeOnlyFixture() {
  return makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
  });
}

test("roleplay throughput metrics retain bounded observed TPS", () => {
  const first = recordThroughputObservation(
    {},
    { completionTokens: 1_000, generationMs: 10_000 },
  );
  const second = {
    ...first,
    ...recordThroughputObservation(first, {
      completionTokens: 1_000,
      generationMs: 5_000,
    }),
  };
  const metrics = modelThroughputMetrics(second);

  assert.equal(metrics.sample_count, 2);
  assert.deepEqual(metrics.tokens_per_second, {
    ewma: 125,
    p50: 100,
    p95: 200,
  });
  assert.equal(metrics.last_completion_tokens, 1_000);
  assert.equal(metrics.last_generation_ms, 5_000);
});

test("roleplay captures completion tokens from a final usage-only SSE frame", () => {
  const collector = createSseAssistantCollector();
  collector.consume(
    'data: {"choices":[{"delta":{"content":"Measured."},"finish_reason":"stop"}]}\n\n',
  );
  const completed = collector.finish(
    'data: {"choices":[],"usage":{"completion_tokens":321}}\n\ndata: [DONE]\n\n',
  );

  assert.equal(completed.assistant, "Measured.");
  assert.equal(completed.completionTokens, 321);
  assert.equal(completed.terminated, true);
});

test("roleplay compaction planning exposes reusable hot-path analysis", () => {
  const state = {
    directives: [{ role: "system", content: "Keep continuity." }],
    memory: null,
  };
  const parsed = {
    character: {},
    lore: [],
    maxTokens: 8192,
    memory: { mode: "auto" },
    outputContract: null,
    responseLength: "balanced",
  };
  const conversation = [
    { role: "user", content: "Continue from the exact current scene." },
  ];
  const settings = {
    compactTriggerTokens: 128_000,
    hardInputTokens: 128_000,
    keepRecentMessages: 8,
    maxStoredBytes: 640_000,
  };

  const plan = compactionPlan(state, parsed, conversation, settings);

  assert.ok(Array.isArray(plan.roleplayMessages));
  assert.ok(plan.roleplayMessages.length > conversation.length);
  assert.ok(plan.estimatedTokens > 0);
  assert.ok(plan.projectedStoredBytes > 0);
});

test("prompt-cache policy reuses a precomputed input estimate", () => {
  const prepared = applyRoleplayPromptCache(
    { model: "glm-5.2", messages: [] },
    { provider: "opencode" },
    [],
    { promptCacheEnabled: true, promptCacheMinTokens: 1 },
    true,
    12_345,
  );

  assert.equal(prepared.promptCache.estimatedInputTokens, 12_345);
});

test("roleplay edge forwards the already-validated request body without reserializing it", async () => {
  const originalBody = JSON.stringify(
    {
      session_id: "session-body-reuse",
      model: "roleplay:5.2",
      stream: false,
      messages: [{ role: "user", content: "Preserve this body." }],
    },
    null,
    2,
  );
  let forwardedBody = "";
  const env = {
    ADMIN_API_KEY: "admin-roleplay-key",
    ROLEPLAY_API_KEY: "janitor-roleplay-key",
    ROLEPLAY_SESSION: {
      getByName() {
        return {
          async fetch(request) {
            forwardedBody = await request.text();
            return new Response("{}", {
              headers: { "Content-Type": "application/json" },
            });
          },
        };
      },
    },
  };

  const response = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay", {
      method: "POST",
      headers: {
        Authorization: "Bearer admin-roleplay-key",
        "Content-Type": "application/json",
      },
      body: originalBody,
    }),
    env,
  );

  assert.equal(response.status, 200);
  assert.equal(forwardedBody, originalBody);
});

test("warm roleplay turns avoid redundant durable storage operations", async () => {
  const fixture = opencodeOnlyFixture();
  const sessionId = "session-performance-storage";

  await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model, "First reply.");
    },
    async () => {
      const first = await handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: sessionId,
          model: "roleplay:5.2",
          stream: false,
          messages: [{ role: "user", content: "First turn." }],
        }),
        fixture.env,
      );
      assert.equal(first.status, 200);
    },
  );
  await fixture.waitForBackgroundWork();

  const [{ storage }] = [...fixture.storageBySession.values()];
  storage.resetOperations();

  await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model, "Second reply.");
    },
    async () => {
      const second = await handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: sessionId,
          model: "roleplay:5.2",
          stream: false,
          messages: [
            { role: "user", content: "First turn." },
            { role: "assistant", content: "First reply." },
            { role: "user", content: "Second turn." },
          ],
        }),
        fixture.env,
      );
      assert.equal(second.status, 200);
      assert.equal(second.headers.get("X-Roleplay-State-Cache"), "hit");
      assert.equal(
        second.headers.get("X-Roleplay-Credential-Check"),
        "skipped",
      );
      assert.match(
        second.headers.get("Server-Timing"),
        /roleplay_state_load;dur=/,
      );
      assert.match(
        second.headers.get("Server-Timing"),
        /roleplay_prepare;dur=/,
      );
    },
  );
  await fixture.waitForBackgroundWork();

  assert.deepEqual(storage.operations, {
    get: 0,
    put: 1,
    setAlarm: 0,
    deleteAll: 0,
  });

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      `https://proxy.example/v1/roleplay/metrics?session_id=${sessionId}`,
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const metricPayload = await metrics.json();
  const modelMetrics = metricPayload.models["opencode:glm-5.2"];
  assert.deepEqual(metricPayload.state_cache, {
    hits: 1,
    misses: 1,
    hit_rate: 0.5,
  });
  assert.equal(modelMetrics.latency.sample_count, 2);
  assert.ok(Number.isFinite(modelMetrics.latency.ttfb_ms.p50));
  assert.ok(Number.isFinite(modelMetrics.latency.total_ms.p95));
});

test("fresh NanoGPT sessions generate with the preferred key without a catalog probe", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-key-zero",
    NANOGPT_API_KEY_1: "nanogpt-key-one",
    NANOGPT_PREFERRED_KEY_INDEX: "1",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    requests.push({
      method: init.method,
      authorization: new Headers(init.headers).get("Authorization"),
    });
    const payload = JSON.parse(init.body);
    return completionResponse(payload.model, "Preferred key reply.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-performance-nanogpt",
        model: "roleplay:5.2",
        stream: false,
        input: "Begin.",
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(requests, [
    {
      method: "POST",
      authorization: "Bearer nanogpt-key-one",
    },
  ]);
});

test("roleplay SSE disables intermediary response transformation", async () => {
  const fixture = opencodeOnlyFixture();
  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    const chunk = JSON.stringify({
      id: "chatcmpl-performance-stream",
      model: payload.model,
      usage: { completion_tokens: 240 },
      choices: [
        {
          index: 0,
          delta: { content: "Immediate." },
          finish_reason: null,
        },
      ],
    });
    return new Response(`data: ${chunk}\n\ndata: [DONE]\n\n`, {
      headers: { "Content-Type": "text/event-stream" },
    });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-performance-streaming",
        model: "roleplay:5.2",
        stream: true,
        input: "Begin.",
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-cache, no-transform");
  const metrics = await Promise.race([
    handleRoleplayEdgeRequest(
      new Request(
        "https://proxy.example/v1/roleplay/metrics?session_id=session-performance-streaming",
        { headers: { Authorization: "Bearer admin-roleplay-key" } },
      ),
      fixture.env,
    ),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("metrics waited for the active stream")),
        50,
      ),
    ),
  ]);
  assert.equal(metrics.status, 200);
  assert.equal((await metrics.json()).pending_turns, 1);
  assert.match(await response.text(), /Immediate\./);
  await fixture.waitForBackgroundWork();
  const completedMetrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-performance-streaming",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const completedPayload = await completedMetrics.json();
  assert.equal(completedPayload.pending_turns, 0);
  const throughput =
    completedPayload.models["opencode:glm-5.2"].throughput;
  assert.equal(throughput.sample_count, 1);
  assert.equal(throughput.last_completion_tokens, 240);
  assert.ok(throughput.tokens_per_second.ewma > 0);
});

test("NanoGPT streaming requests ask for the final usage frame", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
  });
  let upstreamPayload;
  const response = await withGlobalFetch(async (_input, init) => {
    upstreamPayload = JSON.parse(init.body);
    return new Response(
      'data: {"choices":[{"delta":{"content":"Measured."},"finish_reason":"stop"}],"usage":{"completion_tokens":12}}\n\ndata: [DONE]\n\n',
      { headers: { "Content-Type": "text/event-stream" } },
    );
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-performance-nanogpt-usage",
        model: "roleplay:5.3-flash",
        stream: true,
        input: "Begin.",
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(upstreamPayload.stream_options, { include_usage: true });
  assert.match(await response.text(), /Measured\./);
  await fixture.waitForBackgroundWork();
});

test("roleplay accepts the exact NanoGPT uncensored Flash model ID", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"] }),
  });
  let requestedModel = "";
  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requestedModel = payload.model;
    return completionResponse(payload.model, "Pinned uncensored reply.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-exact-nanogpt-uncensored",
        model: "z-ai/glm-5.3-flash-uncensored",
        stream: false,
        input: "Begin.",
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(requestedModel, "z-ai/glm-5.3-flash-uncensored");
  assert.equal(
    response.headers.get("X-Roleplay-Model"),
    "z-ai/glm-5.3-flash-uncensored",
  );
});

test("roleplay streams story text before validating the final image prompt", async () => {
  const fixture = opencodeOnlyFixture();
  let releaseRemainder;
  const remainderReady = new Promise((resolve) => {
    releaseRemainder = resolve;
  });
  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    const frame = (content, finishReason = null) =>
      `data: ${JSON.stringify({
        id: "chatcmpl-performance-contract-stream",
        model: payload.model,
        choices: [
          {
            index: 0,
            delta: content === null ? {} : { content },
            finish_reason: finishReason,
          },
        ],
      })}\n\n`;
    let step = 0;
    return new Response(
      new ReadableStream({
        async pull(controller) {
          if (step === 0) {
            step += 1;
            controller.enqueue(
              new TextEncoder().encode(
                frame("🌅 Morning | Academy | Clear\n\n*Story begins.*\n"),
              ),
            );
            return;
          }
          await remainderReady;
          controller.enqueue(
            new TextEncoder().encode(
              frame(
                "\nIMAGE PROMPT:\nCamera: eye level.\nPrimary subject: adult woman.\nSetting: classroom.\nLighting: daylight.\nComposition: medium shot.",
              ) +
                frame(null, "stop") +
                "data: [DONE]\n\n",
            ),
          );
          controller.close();
        },
      }),
      { headers: { "Content-Type": "text/event-stream" } },
    );
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-performance-contract-streaming",
        model: "roleplay:5.2",
        stream: true,
        messages: [
          {
            role: "system",
            content:
              "Every story response must end with exactly one IMAGE PROMPT block. " +
              "Use Camera, Primary subject, Setting, Lighting, and Composition fields.",
          },
          { role: "user", content: "Begin." },
        ],
      }),
      fixture.env,
    ),
  );

  const reader = response.body.getReader();
  const first = await Promise.race([
    reader.read(),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("story text was buffered until validation")),
        50,
      ),
    ),
  ]);
  const firstText = new TextDecoder().decode(first.value);
  assert.match(firstText, /Story begins/);
  assert.doesNotMatch(firstText, /IMAGE PROMPT/);

  releaseRemainder();
  let remainder = "";
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) {
      break;
    }
    remainder += new TextDecoder().decode(chunk.value);
  }
  assert.match(remainder, /IMAGE PROMPT/);
  assert.equal((firstText + remainder).match(/IMAGE PROMPT:/g)?.length, 1);
  await fixture.waitForBackgroundWork();
});
