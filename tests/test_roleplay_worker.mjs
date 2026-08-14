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

test("roleplay enforces maximum reasoning for every provider and model family", async () => {
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
    ["nanogpt", "NANOGPT_API_KEY", "glm", "xhigh", undefined],
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
          reasoning_effort: "none",
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

test("roleplay response length adjusts the smart output budget", async () => {
  const fixture = makeRoleplayEnv();
  const budgets = [];

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    budgets.push(payload.max_tokens);
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

  assert.equal(budgets.length, 2);
  assert.ok(budgets[0] < budgets[1]);
});

test("roleplay allows a 20000-token reply budget", async () => {
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
        max_tokens: 20_000,
        stream: false,
      }),
      fixture.env,
    );
    const tooLarge = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-budget-too-large",
        input: "Continue the scene.",
        max_tokens: 20_001,
        stream: false,
      }),
      fixture.env,
    );

    assert.equal(automatic.status, 200);
    assert.equal(explicit.status, 200);
    assert.equal(tooLarge.status, 400);
  });

  assert.deepEqual(budgets, [20_000, 20_000]);
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
  assert.doesNotMatch(JSON.stringify(catalog), /nanogpt-(?:rejected|working)-key/);

  const responses = await withGlobalFetch(async (_input, init) => {
    const authorization = new Headers(init.headers).get("Authorization");
    authorizationAttempts.push(authorization);
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
  ]);
});
