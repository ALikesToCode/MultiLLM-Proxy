import assert from "node:assert/strict";
import test from "node:test";

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
  assert.equal((await completedMetrics.json()).pending_turns, 0);
});
