import assert from "node:assert/strict";
import test from "node:test";

import {
  loadRoleplayStreamingModule,
  loadWorkerModule,
} from "./helpers/load_cloudflare_worker.mjs";
import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const worker = (await loadWorkerModule()).default;
const { createObservedStream } =
  await loadRoleplayStreamingModule();

test("roleplay model catalog exposes configured adaptive tiers without secrets", async () => {
  const fixture = makeRoleplayEnv({
    NAVYAI_API_KEY: "navy-roleplay-key",
  });
  const response = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: { Authorization: "Bearer admin-roleplay-key" },
    }),
    fixture.env,
  );

  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.deepEqual(
    payload.data.slice(0, 4).map(({ provider, family, model }) => ({
      provider,
      family,
      model,
    })),
    [
      { provider: "opencode", family: "kimi", model: "kimi-k2.6" },
      { provider: "opencode", family: "glm", model: "glm-5.2" },
      { provider: "navyai", family: "kimi", model: "kimi-k2.6" },
      { provider: "navyai", family: "glm", model: "glm-5.2" },
    ],
  );
  assert.equal(payload.data[0].context_window, 262_144);
  assert.equal(payload.data[0].max_output_tokens, 262_144);
  assert.equal(payload.data[3].context_window, 1_048_576);
  assert.equal(payload.data[3].max_output_tokens, 131_072);
  assert.doesNotMatch(JSON.stringify(payload), /roleplay-key/);
});

test("worker routes roleplay natively without opening the container", async () => {
  const fixture = makeRoleplayEnv();
  fixture.env.MULTILLM_PROXY_CONTAINER = {
    getByName() {
      assert.fail("native roleplay routes must not wake the container");
    },
  };

  const response = await worker.fetch(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: {
        Authorization: "Bearer admin-roleplay-key",
        Origin: "https://client.example",
      },
    }),
    fixture.env,
  );

  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get("Access-Control-Allow-Origin"),
    "https://client.example",
  );
});

test("roleplay model catalog applies explicit provider limit overrides", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_LIMITS: JSON.stringify({
      opencode: {
        glm: {
          context_window: 524_288,
          max_output_tokens: 98_304,
        },
      },
    }),
  });
  const response = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: { Authorization: "Bearer admin-roleplay-key" },
    }),
    fixture.env,
  );
  const glm = (await response.json()).data.find(
    (model) => model.provider === "opencode" && model.family === "glm",
  );

  assert.equal(response.status, 200);
  assert.equal(glm.context_window, 524_288);
  assert.equal(glm.max_output_tokens, 98_304);
  assert.equal(glm.limits_source, "environment-override");
});

test("roleplay endpoint stores continuity and explores Kimi then GLM", async () => {
  const fixture = makeRoleplayEnv();
  const upstreamModels = [];

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamModels.push(payload.model);
    assert.match(
      payload.messages[0].content,
      /Preserve character voice/,
    );
    return completionResponse(payload.model, `Reply from ${payload.model}`);
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-adaptive",
        input: "Enter the moonlit hall.",
        character: {
          name: "Mira",
          persona: "A guarded court mage.",
        },
        stream: false,
      }),
      fixture.env,
    );
    assert.equal(first.status, 200);
    assert.equal(first.headers.get("X-Roleplay-Model"), "kimi-k2.6");
    assert.equal(first.headers.get("X-Roleplay-Selection"), "exploration");
    assert.equal(
      first.headers.get("X-Roleplay-Session-ID"),
      "session-adaptive",
    );

    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-adaptive",
        input: "Ask who followed us.",
        stream: false,
      }),
      fixture.env,
    );
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("X-Roleplay-Model"), "glm-5.2");
    await fixture.waitForBackgroundWork();
  });

  assert.deepEqual(upstreamModels, ["kimi-k2.6", "glm-5.2"]);
  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-adaptive",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const metricPayload = await metrics.json();
  assert.equal(metricPayload.turns, 2);
  assert.equal(metricPayload.stored_messages, 4);
  assert.equal(metricPayload.models["opencode:kimi-k2.6"].successes, 1);
  assert.equal(metricPayload.models["opencode:glm-5.2"].successes, 1);
});

test("roleplay defaults to maximum reasoning for every provider and model family", async () => {
  const disabledProviderKeys = {
    OPENCODE_GO_API_KEY: "",
    OPENCODE_API_KEY: "",
    NAVYAI_API_KEY: "",
    LINKAPI_KEY: "",
    LINKAPI_API_KEY: "",
    NANOGPT_API_KEY: "",
    OPENROUTER_API_KEY: "",
  };
  const cases = [
    ["opencode", "OPENCODE_GO_API_KEY", "kimi", "native", undefined],
    ["opencode", "OPENCODE_GO_API_KEY", "glm", "max", undefined],
    ["navyai", "NAVYAI_API_KEY", "kimi", "xhigh", undefined],
    ["navyai", "NAVYAI_API_KEY", "glm", "xhigh", undefined],
    ["linkapi", "LINKAPI_KEY", "kimi", "high", undefined],
    ["linkapi", "LINKAPI_KEY", "glm", "high", undefined],
    ["nanogpt", "NANOGPT_API_KEY", "kimi", "xhigh", undefined],
    ["nanogpt", "NANOGPT_API_KEY", "glm", "max", undefined],
    ["openrouter", "OPENROUTER_API_KEY", "kimi", undefined, "high"],
    ["openrouter", "OPENROUTER_API_KEY", "glm", undefined, "xhigh"],
  ];

  for (const [provider, keyName, family, effort, nestedEffort] of cases) {
    const fixture = makeRoleplayEnv({
      ...disabledProviderKeys,
      [keyName]: `${provider}-reasoning-key`,
      ROLEPLAY_PROVIDER_ORDER: provider,
    });
    let upstreamPayload;
    const response = await withGlobalFetch(async (_input, init) => {
      upstreamPayload = JSON.parse(init.body);
      return completionResponse(upstreamPayload.model);
    }, () =>
      handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: `session-reasoning-${provider}-${family}`,
          input: "Continue.",
          model_preference: family,
          stream: false,
        }),
        fixture.env,
      ),
    );

    assert.equal(response.status, 200, `${provider}:${family}`);
    if (effort === "native") {
      assert.equal(
        "reasoning_effort" in upstreamPayload,
        false,
        `${provider}:${family}`,
      );
    } else {
      assert.equal(
        upstreamPayload.reasoning_effort,
        effort,
        `${provider}:${family}`,
      );
    }
    if (nestedEffort) {
      assert.deepEqual(
        upstreamPayload.reasoning,
        { effort: nestedEffort },
        `${provider}:${family}`,
      );
      assert.equal(
        "reasoning_effort" in upstreamPayload,
        false,
        `${provider}:${family}`,
      );
    } else {
      assert.equal(
        "reasoning" in upstreamPayload,
        false,
        `${provider}:${family}`,
      );
    }
  }
});

test("roleplay preserves an explicit GLM reasoning override for every provider", async () => {
  const disabledProviderKeys = {
    OPENCODE_GO_API_KEY: "",
    OPENCODE_API_KEY: "",
    NAVYAI_API_KEY: "",
    LINKAPI_KEY: "",
    LINKAPI_API_KEY: "",
    NANOGPT_API_KEY: "",
    OPENROUTER_API_KEY: "",
  };
  const cases = [
    ["opencode", "OPENCODE_GO_API_KEY", "max", undefined],
    ["navyai", "NAVYAI_API_KEY", "xhigh", undefined],
    ["linkapi", "LINKAPI_KEY", "high", undefined],
    ["nanogpt", "NANOGPT_API_KEY", "max", undefined],
    ["openrouter", "OPENROUTER_API_KEY", undefined, "xhigh"],
  ];

  for (const [provider, keyName, maximumEffort, nestedMaximumEffort] of cases) {
    for (const requestedEffort of ["low", "max"]) {
      const fixture = makeRoleplayEnv({
        ...disabledProviderKeys,
        [keyName]: `${provider}-reasoning-key`,
        ROLEPLAY_PROVIDER_ORDER: provider,
      });
      let upstreamPayload;
      const response = await withGlobalFetch(async (_input, init) => {
        upstreamPayload = JSON.parse(init.body);
        return completionResponse(upstreamPayload.model);
      }, () =>
        handleRoleplayEdgeRequest(
          roleplayRequest({
            session_id: `session-reasoning-override-${provider}-${requestedEffort}`,
            input: "Continue.",
            model_preference: "glm",
            reasoning_effort: requestedEffort,
            stream: false,
          }),
          fixture.env,
        ),
      );

      assert.equal(response.status, 200, `${provider}:${requestedEffort}`);
      if (nestedMaximumEffort) {
        assert.deepEqual(upstreamPayload.reasoning, {
          effort:
            requestedEffort === "max"
              ? nestedMaximumEffort
              : requestedEffort,
        });
        assert.equal("reasoning_effort" in upstreamPayload, false);
      } else {
        assert.equal(
          upstreamPayload.reasoning_effort,
          requestedEffort === "max" ? maximumEffort : requestedEffort,
          `${provider}:${requestedEffort}`,
        );
        assert.equal("reasoning" in upstreamPayload, false);
      }
    }
  }
});

test("roleplay fallback advances only after a clear provider rejection", async () => {
  const fixture = makeRoleplayEnv({ NAVYAI_API_KEY: "navy-key" });
  const calls = [];

  const response = await withGlobalFetch(async (input, init) => {
    const payload = JSON.parse(init.body);
    calls.push({ url: String(input), model: payload.model });
    if (payload.model === "kimi-k2.6") {
      return new Response('{"error":"rate limited"}', {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }
    return completionResponse(payload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-fallback",
        input: "Continue.",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Model"), "glm-5.2");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.equal(calls.length, 2);
  assert.ok(calls.every((call) => call.url.includes("opencode.ai")));
});

test("roleplay sends OpenCode requests through Container egress", async () => {
  let containerCalls = 0;
  const fixture = makeRoleplayEnv({
    MULTILLM_PROXY_CONTAINER: {
      getByName(name) {
        assert.equal(name, "primary");
        return {
          async fetch(request) {
            containerCalls += 1;
            assert.equal(
              request.url,
              "https://roleplay.internal/opencode/v1/chat/completions",
            );
            assert.equal(
              request.headers.get("X-MultiLLM-Api-Key"),
              "admin-roleplay-key",
            );
            assert.equal(
              request.headers.get("Authorization"),
              "Bearer opencode-roleplay-key",
            );
            const payload = await request.json();
            assert.equal(payload.model, "kimi-k2.6");
            assert.equal("reasoning_effort" in payload, false);
            return completionResponse(payload.model, "Mira stays in character.");
          },
        };
      },
    },
  });

  const response = await withGlobalFetch(async () => {
    assert.fail("OpenCode roleplay must not use Worker-origin fetch");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-container-egress",
        input: "Continue the scene.",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(containerCalls, 1);
});

test("roleplay stops fallback on ambiguous upstream failure", async () => {
  const fixture = makeRoleplayEnv({ NAVYAI_API_KEY: "navy-key" });
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    return new Response('{"error":"upstream failed"}', {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-ambiguous",
        input: "Continue.",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 502);
  assert.equal(calls, 1);
});

test("roleplay streams SSE unchanged and records assistant continuity after EOF", async () => {
  const fixture = makeRoleplayEnv();
  const encoder = new TextEncoder();
  const chunks = [
    'data: {"choices":[{"delta":{"content":"Mira "}}]}\n\n',
    'data: {"choices":[{"delta":{"content":"listens."}}]}\n\n',
    "data: [DONE]\n\n",
  ];

  const response = await withGlobalFetch(async () =>
    new Response(
      new ReadableStream({
        pull(controller) {
          const chunk = chunks.shift();
          if (chunk === undefined) {
            controller.close();
            return;
          }
          controller.enqueue(encoder.encode(chunk));
        },
      }),
      { headers: { "Content-Type": "text/event-stream" } },
    ), () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-streaming",
        input: "Listen at the door.",
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Model"), "kimi-k2.6");
  assert.equal(
    await response.text(),
    'data: {"choices":[{"delta":{"content":"Mira "}}]}\n\n' +
      'data: {"choices":[{"delta":{"content":"listens."}}]}\n\n' +
      "data: [DONE]\n\n",
  );
  await fixture.waitForBackgroundWork();

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-streaming",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const payload = await metrics.json();
  assert.equal(payload.turns, 1);
  assert.equal(payload.stored_messages, 2);
  assert.equal(payload.models["opencode:kimi-k2.6"].successes, 1);
});

test("roleplay emits SSE heartbeats while a valid stream is thinking", async () => {
  const encoder = new TextEncoder();
  const upstreamController = new AbortController();
  const upstreamBody = new ReadableStream({
    start(controller) {
      setTimeout(() => {
        controller.enqueue(
          encoder.encode(
            'data: {"choices":[{"delta":{"content":"Mira answers."},"finish_reason":"stop"}]}\n\n',
          ),
        );
        controller.close();
      }, 35);
    },
  });
  const observed = createObservedStream({
    upstreamBody,
    requestSignal: new AbortController().signal,
    upstreamController,
    heartbeatMs: 10,
    onComplete() {},
  });

  const body = await new Response(observed.stream).text();
  const result = await observed.completion;

  assert.match(body, /: roleplay-keepalive\n\n/);
  assert.match(body, /Mira answers\./);
  assert.equal(result.success, true);
  assert.equal(result.reason, "complete");
  assert.ok(result.heartbeatCount >= 1);
  assert.equal(upstreamController.signal.aborted, false);
});

test("roleplay marks an unterminated SSE EOF as incomplete", async () => {
  const encoder = new TextEncoder();
  const upstreamBody = new ReadableStream({
    start(controller) {
      controller.enqueue(
        encoder.encode(
          'data: {"choices":[{"delta":{"content":"A partial reply"}}]}\n\n',
        ),
      );
      controller.close();
    },
  });
  const observed = createObservedStream({
    upstreamBody,
    requestSignal: new AbortController().signal,
    upstreamController: new AbortController(),
    heartbeatMs: 10,
    onComplete() {},
  });

  assert.match(
    await new Response(observed.stream).text(),
    /A partial reply/,
  );
  const result = await observed.completion;
  assert.equal(result.success, false);
  assert.equal(result.reason, "incomplete_eof");
  assert.equal(result.assistant, "A partial reply");
});

test("roleplay does not save a truncated stream as completed memory", async () => {
  const fixture = makeRoleplayEnv();
  const encoder = new TextEncoder();

  const response = await withGlobalFetch(async () =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(
            encoder.encode(
              'data: {"choices":[{"delta":{"content":"An unfinished reply"}}]}\n\n',
            ),
          );
          controller.close();
        },
      }),
      { headers: { "Content-Type": "text/event-stream" } },
    ), () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-incomplete-stream",
        input: "Continue.",
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.match(await response.text(), /An unfinished reply/);
  await fixture.waitForBackgroundWork();
  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-incomplete-stream",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const payload = await metrics.json();
  assert.equal(payload.stored_messages, 0);
  assert.equal(payload.models["opencode:kimi-k2.6"].successes, 0);
  assert.equal(payload.models["opencode:kimi-k2.6"].failures, 1);
});

test("roleplay exposes output-limited SSE without saving partial memory", async () => {
  const fixture = makeRoleplayEnv();
  const encoder = new TextEncoder();

  const response = await withGlobalFetch(async () =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(
            encoder.encode(
              'data: {"choices":[{"delta":{"content":"A capped reply"},"finish_reason":"length"}]}\n\n',
            ),
          );
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
        },
      }),
      { headers: { "Content-Type": "text/event-stream" } },
    ), () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-output-limited",
        input: "Continue.",
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.match(await response.text(), /"finish_reason":"length"/);
  await fixture.waitForBackgroundWork();
  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-output-limited",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const payload = await metrics.json();
  assert.equal(payload.stored_messages, 0);
  assert.equal(payload.models["opencode:kimi-k2.6"].successes, 1);
  assert.equal(payload.models["opencode:kimi-k2.6"].failures, 0);
});

test("roleplay does not retain an output-limited JSON completion", async () => {
  const fixture = makeRoleplayEnv();

  const response = await withGlobalFetch(async () =>
    new Response(
      JSON.stringify({
        choices: [
          {
            message: {
              role: "assistant",
              content: "A capped non-stream reply",
            },
            finish_reason: "length",
          },
        ],
      }),
      { headers: { "Content-Type": "application/json" } },
    ), () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-output-limited-json",
        input: "Continue.",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  await fixture.waitForBackgroundWork();
  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-output-limited-json",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).stored_messages, 0);
});

test("roleplay keeps a quiet upstream alive until it finishes", async () => {
  const encoder = new TextEncoder();
  const upstreamController = new AbortController();
  const upstreamBody = new ReadableStream({
    start(controller) {
      setTimeout(() => {
        controller.enqueue(
          encoder.encode(
            'data: {"choices":[{"delta":{"content":"Long thought completes."},"finish_reason":"stop"}]}\n\n',
          ),
        );
        controller.close();
      }, 75);
    },
  });
  const observed = createObservedStream({
    upstreamBody,
    requestSignal: new AbortController().signal,
    upstreamController,
    heartbeatMs: 10,
    onComplete() {},
  });

  const body = await new Response(observed.stream).text();
  const result = await observed.completion;
  assert.match(body, /Long thought completes\./);
  assert.equal(result.success, true);
  assert.equal(result.reason, "complete");
  assert.equal(upstreamController.signal.aborted, false);
  assert.ok(result.heartbeatCount >= 5);
});

test("roleplay idempotency key blocks duplicate paid generation", async () => {
  const fixture = makeRoleplayEnv();
  let calls = 0;

  await withGlobalFetch(async (_input, init) => {
    calls += 1;
    return completionResponse(JSON.parse(init.body).model);
  }, async () => {
    const body = {
      session_id: "session-idempotent",
      input: "Open the gate.",
      stream: false,
    };
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest(body, { "Idempotency-Key": "turn-0001" }),
      fixture.env,
    );
    const duplicate = await handleRoleplayEdgeRequest(
      roleplayRequest(body, { "Idempotency-Key": "turn-0001" }),
      fixture.env,
    );

    assert.equal(first.status, 200);
    assert.equal(duplicate.status, 409);
    assert.equal(calls, 1);
  });
});

test("roleplay validates provider options before upstream generation", async () => {
  const fixture = makeRoleplayEnv();
  const invalidPayloads = [
    { stream: "false" },
    { temperature: 3 },
    { stop: Array.from({ length: 9 }, () => "stop") },
    { response_format: { type: "xml" } },
    { seed: 1.5 },
    { prompt_cache: "yes" },
  ];

  await withGlobalFetch(async () => {
    assert.fail("invalid roleplay input must not reach a provider");
  }, async () => {
    for (const [index, invalid] of invalidPayloads.entries()) {
      const response = await handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: `session-invalid-${index}`,
          input: "Continue.",
          ...invalid,
        }),
        fixture.env,
      );
      assert.equal(response.status, 400);
    }
  });
});

test("roleplay response length changes pacing without shrinking capacity", async () => {
  const fixture = makeRoleplayEnv();
  const requests = [];

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return completionResponse(payload.model);
  }, async () => {
    for (const responseLength of ["compact", "immersive"]) {
      const response = await handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: `session-length-${responseLength}`,
          input: "Continue the scene.",
          response_length: responseLength,
          stream: false,
        }),
        fixture.env,
      );
      assert.equal(response.status, 200);
    }
  });

  assert.equal(requests.length, 2);
  assert.ok(
    Math.abs(requests[0].max_tokens - requests[1].max_tokens) <= 2,
  );
  assert.ok(requests[0].max_tokens > 20_000);
  assert.match(requests[0].messages[0].content, /Response length: compact/);
  assert.match(requests[1].messages[0].content, /Response length: immersive/);
});

test("roleplay removes the proxy-wide ceiling and clamps to model capacity", async () => {
  const fixture = makeRoleplayEnv();
  const budgets = [];

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    budgets.push(payload.max_tokens);
    return completionResponse(payload.model);
  }, async () => {
    const automatic = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-budget-automatic",
        input: "Continue the scene.",
        stream: false,
      }),
      fixture.env,
    );
    const explicit = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-budget-explicit",
        input: "Continue the scene.",
        max_tokens: 100_000,
        stream: false,
      }),
      fixture.env,
    );
    const tooLarge = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-budget-too-large",
        input: "Continue the scene.",
        model_preference: "glm",
        max_tokens: 200_000,
        stream: false,
      }),
      fixture.env,
    );

    assert.equal(automatic.status, 200);
    assert.equal(explicit.status, 200);
    assert.equal(tooLarge.status, 200);
  });

  assert.ok(budgets[0] > 20_000);
  assert.equal(budgets[1], 100_000);
  assert.equal(budgets[2], 131_072);
});

test("roleplay selects and retains a working NanoGPT key per session", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "",
    NANO_GPT_KEY: "nanogpt-rejected-key",
    NANO_GPT_KEY_1: "nanogpt-working-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  });
  const authorizationAttempts = [];
  const requestedModels = [];

  const catalogResponse = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: { Authorization: "Bearer admin-roleplay-key" },
    }),
    fixture.env,
  );
  const catalog = await catalogResponse.json();
  assert.deepEqual(
    catalog.data.map(({ provider, family }) => ({ provider, family })),
    [
      { provider: "nanogpt", family: "kimi" },
      { provider: "nanogpt", family: "glm" },
    ],
  );
  assert.deepEqual(
    catalog.data.map(({ billing_mode: billingMode }) => billingMode),
    ["subscription", "subscription"],
  );
  assert.doesNotMatch(JSON.stringify(catalog), /nanogpt-(?:rejected|working)-key/);

  const responses = await withGlobalFetch(async (_input, init) => {
    const authorization = new Headers(init.headers).get("Authorization");
    authorizationAttempts.push(authorization);
    if (init.method === "GET") {
      if (authorization === "Bearer nanogpt-rejected-key") {
        return new Response(
          JSON.stringify({ error: { message: "Invalid session" } }),
          {
            status: 401,
            headers: { "Content-Type": "application/json" },
          },
        );
      }
      return new Response(JSON.stringify({ data: [{ id: "kimi-k2.6" }] }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    if (authorization === "Bearer nanogpt-rejected-key") {
      return new Response(
        JSON.stringify({ error: { message: "Invalid session" } }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    assert.equal(authorization, "Bearer nanogpt-working-key");
    const payload = JSON.parse(init.body);
    requestedModels.push(payload.model);
    return completionResponse(payload.model, "Mira keeps the same thread.");
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-key-pool",
        input: "Continue.",
        model_preference: "kimi",
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-key-pool",
        input: "Continue again.",
        model_preference: "kimi",
        stream: false,
      }),
      fixture.env,
    );
    return [first, second];
  });

  assert.deepEqual(responses.map((response) => response.status), [200, 200]);
  assert.deepEqual(authorizationAttempts, [
    "Bearer nanogpt-rejected-key",
    "Bearer nanogpt-working-key",
    "Bearer nanogpt-working-key",
    "Bearer nanogpt-working-key",
  ]);
  assert.deepEqual(requestedModels, [
    "kimi-k2.6",
    "kimi-k2.6",
  ]);
});

test("roleplay advances to the next NanoGPT key after insufficient balance", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-empty-key",
    NANOGPT_API_KEY_1: "nanogpt-funded-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  });
  const authorizationAttempts = [];

  const responses = await withGlobalFetch(async (_input, init) => {
    const authorization = new Headers(init.headers).get("Authorization");
    authorizationAttempts.push(authorization);
    if (init.method === "GET") {
      return new Response(JSON.stringify({ data: [{ id: "kimi-k2.6" }] }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    if (authorization === "Bearer nanogpt-empty-key") {
      return new Response(
        JSON.stringify({
          error: "Insufficient balance",
          code: "insufficient_balance",
        }),
        {
          status: 402,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    assert.equal(authorization, "Bearer nanogpt-funded-key");
    const payload = JSON.parse(init.body);
    return completionResponse(payload.model, "Mira continues without resetting.");
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-balance-rotation",
        input: "Continue.",
        model_preference: "kimi",
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-balance-rotation",
        input: "Continue again.",
        model_preference: "kimi",
        stream: false,
      }),
      fixture.env,
    );
    return [first, second];
  });

  assert.deepEqual(responses.map((response) => response.status), [200, 200]);
  assert.equal(responses[0].headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.deepEqual(authorizationAttempts, [
    "Bearer nanogpt-empty-key",
    "Bearer nanogpt-empty-key",
    "Bearer nanogpt-funded-key",
    "Bearer nanogpt-funded-key",
  ]);
});

test("roleplay maps NanoGPT GLM to its exact thinking model", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-working-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
  });
  let requestedModel;
  let requestedMaxTokens;

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requestedModel = payload.model;
    requestedMaxTokens = payload.max_tokens;
    assert.equal(payload.reasoning_effort, "max");
    return completionResponse(payload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-glm-thinking",
        input: "Continue.",
        model_preference: "glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(requestedModel, "zai-org/glm-5.2:thinking");
  assert.equal(requestedMaxTokens, 131_072);
});

test("roleplay selects a larger provider context before compacting", async () => {
  const fixture = makeRoleplayEnv({
    NAVYAI_API_KEY: "navy-roleplay-key",
    ROLEPLAY_PROVIDER_ORDER: "opencode,navyai",
    ROLEPLAY_HARD_INPUT_TOKENS: "0",
    ROLEPLAY_COMPACT_TRIGGER_TOKENS: "0",
  });
  const requestedProviders = [];
  const longMessages = Array.from({ length: 9 }, (_, index) => ({
    role: index % 2 === 0 ? "user" : "assistant",
    content: `${index}:${"x".repeat(120_000)}`,
  }));

  const response = await withGlobalFetch(async (input, init) => {
    requestedProviders.push(new URL(input).hostname);
    const payload = JSON.parse(init.body);
    return completionResponse(payload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-provider-context",
        messages: longMessages,
        history_mode: "replace",
        memory: { mode: "off" },
        model_preference: "glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "navyai");
  assert.equal(response.headers.get("X-Roleplay-Memory"), "off");
  assert.deepEqual(requestedProviders, ["api.navy"]);
  assert.ok(
    Number(response.headers.get("X-Roleplay-Estimated-Input-Tokens")) >
      262_144,
  );
});

test("roleplay skips a provider that cannot honor explicit output", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-roleplay-key",
    NAVYAI_API_KEY: "navy-roleplay-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt,navyai",
  });
  const requestedProviders = [];

  const response = await withGlobalFetch(async (input, init) => {
    requestedProviders.push(new URL(input).hostname);
    const payload = JSON.parse(init.body);
    assert.equal(payload.max_tokens, 100_000);
    return completionResponse(payload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-provider-output",
        input: "Continue the scene.",
        model_preference: "kimi",
        max_tokens: 100_000,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "navyai");
  assert.deepEqual(requestedProviders, ["api.navy"]);
});

test("roleplay keeps NanoGPT subscription traffic free of PAYG cache hints", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-working-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    PROMPT_CACHE_MIN_TOKENS: "1",
  });
  let upstreamPayload;
  let upstreamUrl;

  const response = await withGlobalFetch(async (input, init) => {
    upstreamUrl = String(input);
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(upstreamPayload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-prompt-cache",
        input: "Continue.",
        model_preference: "glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(
    upstreamUrl,
    "https://nano-gpt.com/api/subscription/v1/chat/completions",
  );
  assert.equal("caching" in upstreamPayload, false);
  assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache"), "skipped");
  assert.equal(
    response.headers.get("X-MultiLLM-Prompt-Cache-Mode"),
    "nanogpt-subscription-only",
  );
});

test("roleplay standard NanoGPT mode retains explicit cache routing", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-working-key",
    NANOGPT_BILLING_MODE: "standard",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    PROMPT_CACHE_MIN_TOKENS: "1",
  });
  let upstreamPayload;
  let upstreamUrl;

  const response = await withGlobalFetch(async (input, init) => {
    upstreamUrl = String(input);
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(upstreamPayload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-standard-prompt-cache",
        input: "Continue.",
        model_preference: "glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(upstreamUrl, "https://nano-gpt.com/api/v1/chat/completions");
  assert.equal(upstreamPayload.caching, true);
  assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache"), "applied");
});

test("roleplay leaves implicit-cache providers schema-clean", async () => {
  const fixture = makeRoleplayEnv({ PROMPT_CACHE_MIN_TOKENS: "1" });
  let upstreamPayload;

  const response = await withGlobalFetch(async (_input, init) => {
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(upstreamPayload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-implicit-prompt-cache",
        input: "Continue.",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal("caching" in upstreamPayload, false);
  assert.equal("prompt_cache_key" in upstreamPayload, false);
  assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache"), "implicit");
  assert.equal(
    response.headers.get("X-MultiLLM-Prompt-Cache-Mode"),
    "implicit-prefix",
  );
});

test("roleplay request can disable automatic prompt caching", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-working-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    PROMPT_CACHE_MIN_TOKENS: "1",
  });
  let upstreamPayload;

  const response = await withGlobalFetch(async (_input, init) => {
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(upstreamPayload.model);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-disabled-prompt-cache",
        input: "Continue.",
        prompt_cache: false,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal("caching" in upstreamPayload, false);
  assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache"), "skipped");
  assert.equal(
    response.headers.get("X-MultiLLM-Prompt-Cache-Mode"),
    "request-disabled",
  );
});

test("roleplay revalidates the remembered NanoGPT key after the request interval", async () => {
  const fixture = makeRoleplayEnv({
    OPENCODE_GO_API_KEY: "",
    NANOGPT_API_KEY: "nanogpt-working-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt",
    NANOGPT_KEY_CHECK_EVERY_REQUESTS: "1",
  });
  const methods = [];
  const urls = [];

  const responses = await withGlobalFetch(async (input, init) => {
    methods.push(init.method);
    urls.push(String(input));
    if (init.method === "GET") {
      return new Response(JSON.stringify({ data: [{ id: "kimi-k2.6" }] }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    const payload = JSON.parse(init.body);
    return completionResponse(payload.model);
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-key-recheck",
        input: "Continue.",
        model_preference: "kimi",
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-nanogpt-key-recheck",
        input: "Continue again.",
        model_preference: "kimi",
        stream: false,
      }),
      fixture.env,
    );
    return [first, second];
  });

  assert.deepEqual(responses.map((response) => response.status), [200, 200]);
  assert.deepEqual(methods, ["POST", "GET", "POST"]);
  assert.deepEqual(urls, [
    "https://nano-gpt.com/api/subscription/v1/chat/completions",
    "https://nano-gpt.com/api/subscription/v1/models",
    "https://nano-gpt.com/api/subscription/v1/chat/completions",
  ]);
});
