import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  scopePublicRoleplaySessionId,
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

function isCompactionPayload(payload) {
  return payload.messages?.[0]?.content?.startsWith(
    "You manage continuity for a long-running roleplay.",
  );
}

test("roleplay asks the model to compact older memory before a forced turn", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  const requests = [];
  const systemInstruction = "Remain Mira and never break character.";
  const developerInstruction =
    "Keep the west passage secret until Mira finds the latch.";

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return isCompactionPayload(payload)
      ? compactionResponse(payload.model)
      : completionResponse(payload.model, "Mira turns toward the door.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction",
        messages: [
          { role: "system", content: systemInstruction },
          { role: "developer", content: developerInstruction },
          ...Array.from({ length: 8 }, (_, index) => ({
            role: index % 2 === 0 ? "user" : "assistant",
            content: `Roleplay event ${index}`,
          })),
        ],
        character: { name: "Mira" },
        memory: { mode: "force" },
        model_preference: "glm",
        reasoning_effort: "none",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "model_compacted");
  assert.match(
    response.headers.get("Server-Timing"),
    /roleplay_compaction;dur=/,
  );
  assert.match(
    response.headers.get("Server-Timing"),
    /roleplay_total_to_headers;dur=/,
  );
  assert.equal(requests.length, 2);
  assert.equal(requests[0].model, "glm-5.2");
  assert.equal(requests[0].reasoning_effort, "max");
  assert.equal(requests[0].stream, false);
  assert.equal(requests[0].response_format, undefined);
  assert.equal(requests[1].model, "glm-5.2");
  assert.equal(requests[1].reasoning_effort, "none");
  const compactedInput = JSON.parse(requests[0].messages[1].content);
  assert.equal(
    compactedInput.older_dialogue.some((message) =>
      ["system", "developer"].includes(message.role),
    ),
    false,
  );
  assert.equal(
    requests[1].messages.some(
      (message) =>
        message.role === "system" &&
        message.content === systemInstruction,
    ),
    true,
  );
  assert.equal(
    requests[1].messages.some(
      (message) =>
        message.role === "developer" &&
        message.content === developerInstruction,
    ),
    true,
  );
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
  const metricPayload = await metrics.json();
  assert.equal(metricPayload.compactions, 1);
  assert.equal(metricPayload.protected_directives, 2);
});

test("roleplay shrinks the recent window and compacts storage overflow", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_MAX_STORED_BYTES: "16000",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return isCompactionPayload(payload)
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
  assert.equal(
    response.headers.get("X-MultiLLM-Optimization"),
    "skipped",
  );
  assert.equal(
    response.headers.get("X-MultiLLM-Estimated-Input-Before"),
    response.headers.get("X-MultiLLM-Estimated-Input-After"),
  );
  assert.equal(response.headers.get("X-MultiLLM-Messages-Summarized"), "0");
  assert.equal(requests.length, 2);
  const compactedInput = JSON.parse(requests[0].messages[1].content);
  assert.ok(compactedInput.older_dialogue.length > 0);
  assert.ok(compactedInput.older_dialogue.length < 7);
  for (let index = 0; index < 7; index += 1) {
    assert.equal(
      requests[1].messages.some((message) =>
        message.content.startsWith(`Event ${index}:`),
      ),
      true,
    );
  }

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-storage-overflow",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).estimated_input_tokens_saved, 0);
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
    return isCompactionPayload(payload)
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

test("roleplay uses local memory when required model compaction is declined", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_MAX_STORED_BYTES: "16000",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return isCompactionPayload(payload)
      ? compactionResponse(payload.model, { compact: false })
      : completionResponse(payload.model, "The scene continues safely.");
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

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "local_compacted");
  assert.equal(requests.length, 2);
  assert.equal(
    requests[1].messages.some((message) => message.content === "x".repeat(15000)),
    true,
  );

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-compaction-declined",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).local_compactions, 1);
});

test("roleplay accepts explanatory text around model compaction JSON", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    if (isCompactionPayload(payload)) {
      const compacted = JSON.stringify({
        compact: true,
        summary: "Mira promised to return.",
        character_facts: [],
        relationships: [],
        world_state: [],
        open_threads: ["Return before dawn."],
        tone_style: [],
      });
      return completionResponse(
        payload.model,
        `Memory follows:\n\`\`\`json\n${compacted}\n\`\`\``,
      );
    }
    return completionResponse(payload.model, "Mira keeps her promise.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction-prose",
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
  assert.equal(
    requests[1].messages.some((message) =>
      message.content.includes("Mira promised to return."),
    ),
    true,
  );
});

test("roleplay continues with local memory after compaction provider error", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    if (isCompactionPayload(payload)) {
      return new Response(
        JSON.stringify({ error: { message: "Unsupported JSON mode" } }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    return completionResponse(payload.model, "The story moves forward.");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction-error",
        messages: Array.from({ length: 8 }, (_, index) => ({
          role:
            index === 0
              ? "system"
              : index % 2 === 0
                ? "user"
                : "assistant",
          content: `Continuity marker ${index}`,
        })),
        memory: { mode: "force" },
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Memory"), "local_compacted");
  assert.equal(requests.length, 2);
  const memoryMessage = requests[1].messages.find((message) =>
    message.content.includes("Archived dialogue excerpts"),
  );
  const compactedInput = JSON.parse(requests[0].messages[1].content);
  assert.equal(
    compactedInput.older_dialogue.some((message) =>
      ["system", "developer"].includes(message.role),
    ),
    false,
  );
  assert.doesNotMatch(memoryMessage.content, /Continuity marker 0/);
  assert.match(memoryMessage.content, /Continuity marker 3/);
  assert.equal(
    requests[1].messages.some(
      (message) =>
        message.role === "system" &&
        message.content === "Continuity marker 0",
    ),
    true,
  );
});

test("roleplay backs off failed model compaction and keeps using local memory", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  let compactionCalls = 0;
  let generationCalls = 0;

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    if (isCompactionPayload(payload)) {
      compactionCalls += 1;
      return new Response(
        JSON.stringify({ error: { message: "Compaction unavailable" } }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    generationCalls += 1;
    return completionResponse(payload.model, "The scene advances.");
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction-backoff",
        messages: Array.from({ length: 8 }, (_, index) => ({
          role: index % 2 === 0 ? "user" : "assistant",
          content: `Backoff event ${index}`,
        })),
        character: { name: "Mira" },
        memory: { mode: "force" },
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-compaction-backoff",
        input: "Continue without retrying broken compaction.",
        memory: { mode: "force" },
        stream: false,
      }),
      fixture.env,
    );

    assert.equal(first.status, 200);
    assert.equal(first.headers.get("X-Roleplay-Memory"), "local_compacted");
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("X-Roleplay-Memory"), "local_compacted");
  });

  assert.equal(compactionCalls, 1);
  assert.equal(generationCalls, 2);
  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-compaction-backoff",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  const payload = await metrics.json();
  assert.equal(payload.compaction_failures, 1);
  assert.ok(payload.compaction_backoff_until > Date.now());
  assert.equal(payload.local_compactions, 2);
});

test("roleplay persists protected directives outside dialogue and clears them only on replace", async () => {
  const fixture = makeRoleplayEnv();
  const requests = [];
  const directives = [
    {
      role: "system",
      content: "Always portray Mira as guarded and observant.",
    },
    {
      role: "developer",
      content: "Keep replies in close third person.",
    },
  ];

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    return completionResponse(payload.model, "Mira watches the corridor.");
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-protected-directives",
        messages: [
          ...directives,
          { role: "user", content: "Listen at the door." },
        ],
        stream: false,
      }),
      fixture.env,
    );
    const second = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-protected-directives",
        input: "What do you hear?",
        stream: false,
      }),
      fixture.env,
    );
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);

    const storageSessionId = await scopePublicRoleplaySessionId(
      "session-protected-directives",
      "admin-roleplay-key",
    );
    const storage = fixture.storageBySession.get(storageSessionId).storage;
    assert.deepEqual(
      await storage.get("roleplay-directives"),
      directives,
    );
    assert.equal(
      (await storage.get("roleplay-messages")).some((message) =>
        ["system", "developer"].includes(message.role),
      ),
      false,
    );

    const replaced = await handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-protected-directives",
        input: "Start a clean scene.",
        history_mode: "replace",
        stream: false,
      }),
      fixture.env,
    );
    assert.equal(replaced.status, 200);
    assert.deepEqual(await storage.get("roleplay-directives"), []);
  });

  assert.equal(requests.length, 3);
  for (const request of requests.slice(0, 2)) {
    for (const directive of directives) {
      assert.equal(
        request.messages.some(
          (message) =>
            message.role === directive.role &&
            message.content === directive.content,
        ),
        true,
      );
    }
  }
  for (const directive of directives) {
    assert.equal(
      requests[2].messages.some(
        (message) => message.content === directive.content,
      ),
      false,
    );
  }
});

test("roleplay migrates protected directives out of legacy stored history", async () => {
  const fixture = makeRoleplayEnv();
  const sessionId = "session-legacy-directives";
  const legacyDirective = {
    role: "system",
    content: "Legacy Mira instructions remain authoritative.",
  };
  const storageSessionId = await scopePublicRoleplaySessionId(
    sessionId,
    "admin-roleplay-key",
  );
  fixture.env.ROLEPLAY_SESSION.getByName(storageSessionId);
  const storage = fixture.storageBySession.get(storageSessionId).storage;
  await storage.put("roleplay-session", { version: 1 });
  await storage.put("roleplay-messages", [
    legacyDirective,
    { role: "user", content: "The old scene begins." },
  ]);
  let upstreamPayload;

  const response = await withGlobalFetch(async (_input, init) => {
    upstreamPayload = JSON.parse(init.body);
    return completionResponse(
      upstreamPayload.model,
      "Mira remembers the scene.",
    );
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: sessionId,
        input: "Continue from there.",
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(
    upstreamPayload.messages.some(
      (message) =>
        message.role === legacyDirective.role &&
        message.content === legacyDirective.content,
    ),
    true,
  );
  assert.deepEqual(
    await storage.get("roleplay-directives"),
    [legacyDirective],
  );
  assert.equal(
    (await storage.get("roleplay-messages")).some((message) =>
      ["system", "developer"].includes(message.role),
    ),
    false,
  );
});

test("roleplay rejects oversized protected instructions instead of compacting them", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_HARD_INPUT_TOKENS: "2000",
  });
  let providerCalls = 0;

  const response = await withGlobalFetch(async () => {
    providerCalls += 1;
    return completionResponse("kimi-k2.6");
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest({
        session_id: "session-oversized-directive",
        messages: [
          { role: "system", content: "p".repeat(9_000) },
          { role: "user", content: "Continue." },
        ],
        stream: false,
      }),
      fixture.env,
    ),
  );

  assert.equal(response.status, 413);
  assert.equal(providerCalls, 0);
  assert.match(
    (await response.json()).error.message,
    /will not be compacted/,
  );
});
