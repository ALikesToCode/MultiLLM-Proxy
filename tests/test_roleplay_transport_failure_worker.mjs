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
      model: "zai-org/glm-5.2:thinking",
    },
    {
      url: "https://opencode.ai/zen/go/v1/chat/completions",
      model: "glm-5.2",
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
