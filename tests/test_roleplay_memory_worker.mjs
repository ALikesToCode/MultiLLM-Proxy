import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

function compactionResponse(model, overrides = {}) {
  return completionResponse(
    model,
    JSON.stringify({
      compact: true,
      summary: "The prior scene remains active.",
      character_facts: [],
      relationships: [],
      world_state: [],
      open_threads: ["Continue the scene."],
      tone_style: [],
      ...overrides,
    }),
  );
}

test("roleplay asks the model to compact older memory before a forced turn", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return payload.response_format?.type === "json_object"
      ? compactionResponse(payload.model)
      : completionResponse(payload.model, "Mira turns toward the door.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction",
        messages: Array.from({ length: 8 }, (_, index) => ({
          role: index % 2 === 0 ? "user" : "assistant",
          content: `Roleplay event ${index}`,
        })),
        character: { name: "Mira" },
        memory: { mode: "force" },
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "model_compacted");
  assert.equal(requests.length, 2);
  assert.equal(requests[0].stream, false);
  assert.equal(
    requests[1].messages.some((message) =>
      message.content.includes("Untrusted roleplay continuity memory")),
    true,
  );

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-compaction",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).compactions, 1);
});

test("roleplay shrinks the recent window and compacts storage overflow", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_MAX_STORED_BYTES: "16000",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return payload.response_format?.type === "json_object"
      ? compactionResponse(payload.model)
      : completionResponse(payload.model, "The scene continues.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-storage-overflow",
        messages: Array.from({ length: 7 }, (_, index) => ({
          role: index % 2 === 0 ? "user" : "assistant",
          content: `Event ${index}: ${"x".repeat(2500)}`,
        })),
        max_tokens: 128,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "model_compacted");
  assert.equal(requests.length, 2);
  const compactedInput = JSON.parse(requests[0].messages[1].content);
  assert.ok(compactedInput.older_dialogue.length > 0);
  assert.ok(compactedInput.older_dialogue.length < 7);
});

test("roleplay compacts one oversized latest turn but sends it raw to generation", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_MAX_STORED_BYTES: "16000",
  });
  const latestTurn = `LATEST-OVERSIZED-TURN:${"x".repeat(15000)}`;
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return payload.response_format?.type === "json_object"
      ? compactionResponse(payload.model)
      : completionResponse(payload.model, "Handled without losing the turn.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-single-overflow",
        input: latestTurn,
        max_tokens: 128,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "model_compacted");
  assert.equal(requests.length, 2);
  const compactedInput = JSON.parse(requests[0].messages[1].content);
  assert.equal(compactedInput.older_dialogue[0].content, latestTurn);
  assert.equal(
    requests[1].messages.some((message) => message.content === latestTurn),
    true,
  );

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-single-overflow",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).stored_messages, 1);
});

test("roleplay fails closed when required overflow compaction is declined", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_MAX_STORED_BYTES: "16000",
  });
  let calls = 0;

  const response = await withGlobalFetch(async (_input, init) => {
    calls += 1;
    const payload = JSON.parse(init.body);
    return compactionResponse(payload.model, { compact: false });
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction-declined",
        input: "x".repeat(15000),
        max_tokens: 128,
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, "memory_compaction_failed");
  assert.equal(calls, 1);
});
