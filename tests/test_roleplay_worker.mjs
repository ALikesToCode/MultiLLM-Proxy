import assert from "node:assert/strict";
import test from "node:test";

import {
  loadRoleplayModule,
  loadWorkerModule,
} from "./helpers/load_cloudflare_worker.mjs";

const {
  RoleplaySession,
  handleRoleplayEdgeRequest,
} = await loadRoleplayModule();
const worker = (await loadWorkerModule()).default;

class FakeStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
  }

  async get(key) {
    return structuredClone(this.values.get(key));
  }

  async put(key, value) {
    if (key && typeof key === "object" && !Array.isArray(key)) {
      for (const [entryKey, entryValue] of Object.entries(key)) {
        this.values.set(entryKey, structuredClone(entryValue));
      }
      return;
    }
    this.values.set(key, structuredClone(value));
  }

  async setAlarm(value) {
    this.alarm = value;
  }

  async deleteAll() {
    this.values.clear();
    this.alarm = null;
  }
}

function makeRoleplayEnv(overrides = {}) {
  const storageBySession = new Map();
  const waits = [];
  const env = {
    ADMIN_API_KEY: "admin-roleplay-key",
    OPENCODE_GO_API_KEY: "opencode-roleplay-key",
    ROLEPLAY_COMPACT_TRIGGER_TOKENS: "12000",
    ROLEPLAY_HARD_INPUT_TOKENS: "24000",
    ROLEPLAY_KEEP_RECENT_MESSAGES: "12",
    ...overrides,
  };

  env.ROLEPLAY_SESSION = {
    getByName(sessionId) {
      if (!storageBySession.has(sessionId)) {
        const storage = new FakeStorage();
        const ctx = {
          storage,
          waitUntil(promise) {
            waits.push(Promise.resolve(promise));
          },
        };
        storageBySession.set(sessionId, {
          instance: new RoleplaySession(ctx, env),
          storage,
        });
      }
      return {
        fetch(request) {
          return storageBySession.get(sessionId).instance.fetch(request);
        },
      };
    },
  };

  return {
    env,
    storageBySession,
    async waitForBackgroundWork() {
      await Promise.allSettled(waits.splice(0));
    },
  };
}

function roleplayRequest(body, headers = {}) {
  return new Request("https://proxy.example/v1/roleplay", {
    method: "POST",
    headers: {
      Authorization: "Bearer admin-roleplay-key",
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

async function withGlobalFetch(fetchImpl, operation) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await operation();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function completionResponse(model, content = "In character.") {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-roleplay",
      object: "chat.completion",
      model,
      choices: [
        {
          index: 0,
          message: { role: "assistant", content },
          finish_reason: "stop",
        },
      ],
    }),
    { headers: { "Content-Type": "application/json" } },
  );
}

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

test("roleplay asks model to compact older memory before forced turn", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  const requests = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    requests.push(payload);
    if (payload.response_format?.type === "json_object") {
      return completionResponse(
        payload.model,
        JSON.stringify({
          compact: true,
          summary: "Mira entered the moonlit hall and heard footsteps.",
          character_facts: ["Mira is a guarded court mage."],
          relationships: [],
          world_state: ["The party is inside the moonlit hall."],
          open_threads: ["Identify the follower."],
          tone_style: ["Tense gothic fantasy."],
        }),
      );
    }
    return completionResponse(payload.model, "Mira turns toward the door.");
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
  assert.equal(requests[1].messages.some((message) =>
    message.content.includes("Untrusted roleplay continuity memory")), true);

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      "https://proxy.example/v1/roleplay/metrics?session_id=session-compaction",
      { headers: { Authorization: "Bearer admin-roleplay-key" } },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).compactions, 1);
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
