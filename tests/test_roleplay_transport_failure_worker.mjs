import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

function transportFallbackEnv(overrides = {}) {
  return makeRoleplayEnv({
    NANOGPT_API_KEY: "nano-key",
    ROLEPLAY_PROVIDER_ORDER: "nanogpt,opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({
      nanogpt: ["glm"],
      opencode: ["glm"],
    }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({
      nanogpt: { glm: "z-ai/glm-5.3-flash" },
      opencode: { glm: "glm-5.3-flash" },
    }),
    ...overrides,
  });
}

function streamingCompletionResponse(model, content) {
  return new Response(
    [
      `data: ${JSON.stringify({
        choices: [{ delta: { content }, finish_reason: null }],
        model,
      })}\n\n`,
      `data: ${JSON.stringify({
        choices: [{ delta: {}, finish_reason: "stop" }],
        model,
      })}\n\n`,
      "data: [DONE]\n\n",
    ].join(""),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function providerErrorResponse(status = 500) {
  return Response.json(
    {
      error: {
        message: "An unexpected provider error occurred",
        type: "provider_error",
        code: "provider_error",
      },
    },
    { status },
  );
}

test("roleplay advances after a pre-response transport rejection", async () => {
  const fixture = transportFallbackEnv();
  const calls = [];

  const response = await withGlobalFetch(async (input, init) => {
    const payload = JSON.parse(init.body);
    calls.push({ url: String(input), model: payload.model });
    if (calls.length === 1) {
      throw new TypeError("fetch failed");
    }
    return completionResponse(payload.model, "The scene continues.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-pre-response-rejection",
        input: "Continue.",
        model: "roleplay:glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.deepEqual(calls, [
    {
      url: "https://nano-gpt.com/api/subscription/v1/chat/completions",
      model: "z-ai/glm-5.3-flash",
    },
    {
      url: "https://opencode.ai/zen/go/v1/chat/completions",
      model: "glm-5.3-flash",
    },
  ]);
});

test("roleplay streaming advances before exposing response headers", async () => {
  const fixture = transportFallbackEnv();
  let calls = 0;

  const response = await withGlobalFetch(async (_input, init) => {
    calls += 1;
    if (calls === 1) {
      throw new TypeError("fetch failed");
    }
    const payload = JSON.parse(init.body);
    return streamingCompletionResponse(payload.model, "Immediate stream.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-stream-transport-rejection",
        input: "Continue.",
        model: "roleplay:glm",
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.match(await response.text(), /Immediate stream\./);
  assert.equal(calls, 2);
});

test("roleplay advances after an explicit upstream provider error", async () => {
  const fixture = transportFallbackEnv();
  let calls = 0;

  const response = await withGlobalFetch(async (_input, init) => {
    calls += 1;
    if (calls === 1) {
      return providerErrorResponse();
    }
    const payload = JSON.parse(init.body);
    return streamingCompletionResponse(payload.model, "Recovered stream.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-explicit-provider-error",
        input: "Continue.",
        model: "roleplay:glm",
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.match(await response.text(), /Recovered stream\./);
  assert.equal(calls, 2);
});

for (const status of [502, 504]) {
  test(`roleplay advances after an explicit upstream ${status}`, async () => {
    const fixture = transportFallbackEnv();
    let calls = 0;

    const response = await withGlobalFetch(async (_input, init) => {
      calls += 1;
      if (calls === 1) {
        return providerErrorResponse(status);
      }
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model, "Recovered response.");
    }, () =>
      handleRoleplayEdgeRequest(
        roleplayRequest({
          session_id: `session-explicit-provider-${status}`,
          input: "Continue.",
          model: "roleplay:glm",
          stream: false,
        }),
        fixture.env,
      ),
    );

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("X-Roleplay-Provider"), "opencode");
    assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
    assert.equal(calls, 2);
  });
}

test("roleplay keeps unknown upstream 500 responses fail-closed", async () => {
  const fixture = transportFallbackEnv();
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    return Response.json(
      {
        error: {
          message: "Unknown upstream failure",
          type: "server_error",
          code: "server_error",
        },
      },
      { status: 500 },
    );
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-unknown-provider-500",
        input: "Continue.",
        model: "roleplay:glm",
        stream: true,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 500);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "nanogpt");
  assert.equal(response.headers.get("X-Roleplay-Model"), "z-ai/glm-5.3-flash");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "0");
  assert.equal(response.headers.get("X-Roleplay-Failure-Kind"), "http_status");
  assert.equal((await response.json()).error.code, "server_error");
  assert.equal(calls, 1);
});

test("roleplay can disable explicit provider-error fallback", async () => {
  const fixture = transportFallbackEnv({
    ROLEPLAY_PROVIDER_ERROR_FALLBACK_ENABLED: "false",
  });
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    return providerErrorResponse();
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-provider-error-fail-closed",
        input: "Continue.",
        model: "roleplay:glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 500);
  assert.equal((await response.json()).error.code, "provider_error");
  assert.equal(calls, 1);
});

test("roleplay does not inspect oversized provider error bodies", async () => {
  const fixture = transportFallbackEnv();
  const oversizedBody = JSON.stringify({
    error: {
      message: "An unexpected provider error occurred",
      type: "provider_error",
      code: "provider_error",
      detail: "x".repeat(40 * 1024),
    },
  });
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    return new Response(oversizedBody, {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-oversized-provider-error",
        input: "Continue.",
        model: "roleplay:glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 500);
  assert.equal(await response.text(), oversizedBody);
  assert.equal(calls, 1);
});

test("roleplay can keep fail-closed transport behavior", async () => {
  const fixture = transportFallbackEnv({
    ROLEPLAY_PRE_RESPONSE_FALLBACK_ENABLED: "false",
  });
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    throw new TypeError("fetch failed");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-pre-response-fail-closed",
        input: "Continue.",
        model: "roleplay:glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 502);
  assert.equal(calls, 1);
  assert.equal(
    (await response.json()).error.code,
    "ambiguous_provider_failure",
  );
});

test("roleplay reports the final provider transport failure", async () => {
  const fixture = transportFallbackEnv();
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    throw new TypeError("fetch failed");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-all-transports-failed",
        input: "Continue.",
        model: "roleplay:glm",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 502);
  assert.equal(calls, 2);
  assert.equal(response.headers.get("X-Roleplay-Provider"), "opencode");
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "1");
  assert.equal(
    response.headers.get("X-Roleplay-Failure-Kind"),
    "transport_rejection",
  );
  assert.equal((await response.json()).error.code, "provider_transport_failure");
});

for (const status of [400, 404, 429, 503]) {
  for (const stream of [false, true]) {
    for (const candidateCount of [1, 2]) {
      test(`roleplay preserves final HTTP ${status}, stream=${stream}, candidates=${candidateCount}`, async () => {
        const fixture = transportFallbackEnv({
          ROLEPLAY_PROVIDER_ORDER:
            candidateCount === 1 ? "nanogpt" : "nanogpt,opencode",
        });
        let calls = 0;
        let finalBody;
        const response = await withGlobalFetch(async () => {
          calls += 1;
          finalBody = JSON.stringify({
            error: {
              message: `Rejected attempt ${calls}`,
              code: "upstream_rejection",
            },
          });
          return new Response(finalBody, {
            status,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": "17",
              "X-RateLimit-Remaining-Tokens": "0",
              "X-Request-ID": `upstream-${calls}`,
              "Set-Cookie": "upstream-private=value",
            },
          });
        }, () => handleRoleplayEdgeRequest(
          roleplayRequest({
            session_id: `session-http-${status}-${stream}-${candidateCount}`,
            input: "Continue.",
            model: "roleplay:glm",
            stream,
          }), fixture.env,
        ));

        assert.equal(response.status, status);
        assert.equal(await response.text(), finalBody);
        assert.equal(calls, candidateCount);
        assert.equal(response.headers.get("Retry-After"), "17");
        assert.equal(response.headers.get("X-RateLimit-Remaining-Tokens"), "0");
        assert.equal(response.headers.get("X-Request-ID"), `upstream-${calls}`);
        assert.equal(response.headers.get("Set-Cookie"), null);
        assert.equal(
          response.headers.get("X-Roleplay-Fallback-Count"),
          String(candidateCount - 1),
        );
        assert.equal(
          response.headers.get("X-Roleplay-Provider"),
          candidateCount === 1 ? "nanogpt" : "opencode",
        );
        assert.equal(response.headers.get("X-Roleplay-Failure-Kind"), "http_status");
      });
    }
  }
}

test("roleplay never advances after a client abort", async () => {
  const fixture = transportFallbackEnv();
  const controller = new AbortController();
  let calls = 0;
  let markFetchStarted;
  const fetchStarted = new Promise((resolve) => {
    markFetchStarted = resolve;
  });
  const baseRequest = roleplayRequest({
    session_id: "session-client-abort",
    input: "Continue.",
    model: "roleplay:glm",
    stream: false,
  });
  const request = new Request(baseRequest, { signal: controller.signal });

  const responsePromise = withGlobalFetch(async (_input, init) => {
    calls += 1;
    markFetchStarted();
    return new Promise((resolve, reject) => {
      const rejectAbort = () =>
        reject(new DOMException("Request aborted", "AbortError"));
      if (init.signal.aborted) {
        rejectAbort();
        return;
      }
      init.signal.addEventListener("abort", rejectAbort, { once: true });
    });
  }, () => handleRoleplayEdgeRequest(request, fixture.env));

  await fetchStarted;
  controller.abort("client_cancelled");
  const response = await responsePromise;

  assert.equal(response.status, 499);
  assert.equal(calls, 1);
  assert.equal((await response.json()).error.code, "request_aborted");
});
