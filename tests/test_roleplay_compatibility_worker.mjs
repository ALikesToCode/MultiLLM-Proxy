import assert from "node:assert/strict";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const JANITOR_PATH = "/roleplay/v1/chat/completions";
const OPENAI_ALIAS_PATH = "/v1/roleplay/chat/completions";
const worker = (await loadWorkerModule()).default;

function janitorHeaders(overrides = {}) {
  return {
    Authorization: "Bearer janitor-roleplay-key",
    ...overrides,
  };
}

function openingMessages(userContent = "Who followed us?") {
  return [
    {
      role: "system",
      content: "You are Mira, a guarded court mage in the palace library.",
    },
    {
      role: "assistant",
      content: "Mira quietly closes the library door.",
    },
    { role: "user", content: userContent },
  ];
}

function compactionResponse(model) {
  return completionResponse(
    model,
    JSON.stringify({
      compact: true,
      summary: "Mira is investigating the sealed palace passage.",
      character_facts: ["Mira is a guarded court mage."],
      relationships: [],
      world_state: ["The palace library door is closed."],
      open_threads: ["Identify who followed Mira."],
      tone_style: ["Tense gothic fantasy."],
    }),
  );
}

test("Janitor Chat Completions stays native and exposes session metadata", async () => {
  const fixture = makeRoleplayEnv();
  fixture.env.MULTILLM_PROXY_CONTAINER = {
    getByName() {
      assert.fail("Janitor roleplay must not wake the container");
    },
  };

  const response = await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model, "Mira listens.");
    },
    () =>
      worker.fetch(
        roleplayRequest(
          {
            model: "roleplay:auto",
            messages: openingMessages(),
            stream: false,
          },
          janitorHeaders({ Origin: "https://janitorai.com" }),
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get("Access-Control-Allow-Origin"),
    "https://janitorai.com",
  );
  assert.equal(
    response.headers.get("X-Roleplay-Session-Source"),
    "derived",
  );
  assert.match(
    response.headers.get("Access-Control-Expose-Headers") ?? "",
    /X-Roleplay-Session-Source/,
  );
});

test("both roleplay Chat Completions aliases reject invalid input at the edge", async () => {
  const fixture = makeRoleplayEnv();
  fixture.env.MULTILLM_PROXY_CONTAINER = {
    getByName() {
      assert.fail("roleplay aliases must not wake the container");
    },
  };

  for (const pathname of [JANITOR_PATH, OPENAI_ALIAS_PATH]) {
    const response = await worker.fetch(
      roleplayRequest(
        { model: "roleplay:auto", messages: [] },
        janitorHeaders(),
        pathname,
      ),
      fixture.env,
    );
    assert.equal(response.status, 400);
  }
});

test("invalid roleplay model aliases fail before provider generation", async () => {
  const fixture = makeRoleplayEnv();

  const response = await withGlobalFetch(
    async () => {
      assert.fail("invalid roleplay model must not reach a provider");
    },
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            model: "roleplay:unknown",
            messages: openingMessages(),
            stream: false,
          },
          janitorHeaders(),
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  assert.equal(response.status, 400);
});

test("dedicated roleplay key authorizes roleplay without replacing admin access", async () => {
  const fixture = makeRoleplayEnv();
  const roleplayOnlyFixture = makeRoleplayEnv({ ADMIN_API_KEY: "" });
  const roleplayResponse = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: janitorHeaders(),
    }),
    roleplayOnlyFixture.env,
  );
  const adminResponse = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: { Authorization: "Bearer admin-roleplay-key" },
    }),
    fixture.env,
  );
  const deniedResponse = await handleRoleplayEdgeRequest(
    new Request("https://proxy.example/v1/roleplay/models", {
      headers: { Authorization: "Bearer wrong-key" },
    }),
    fixture.env,
  );

  assert.equal(roleplayResponse.status, 200);
  assert.equal(adminResponse.status, 200);
  assert.equal(deniedResponse.status, 401);
});

test("Janitor full-history requests recover the same durable session", async () => {
  const fixture = makeRoleplayEnv();
  const firstMessages = openingMessages();
  let call = 0;

  const responses = await withGlobalFetch(
    async (_input, init) => {
      call += 1;
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model, `Reply ${call}`);
    },
    async () => {
      const first = await handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            model: "roleplay:auto",
            messages: firstMessages,
            stream: false,
          },
          janitorHeaders(),
          JANITOR_PATH,
        ),
        fixture.env,
      );
      const second = await handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            model: "roleplay:auto",
            messages: [
              ...firstMessages,
              { role: "assistant", content: "Reply 1" },
              { role: "user", content: "Open the sealed passage." },
            ],
            stream: false,
          },
          janitorHeaders(),
          JANITOR_PATH,
        ),
        fixture.env,
      );
      return [first, second];
    },
  );

  const [first, second] = responses;
  const sessionId = first.headers.get("X-Roleplay-Session-ID");
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(first.headers.get("X-Roleplay-Session-Source"), "derived");
  assert.equal(second.headers.get("X-Roleplay-Session-ID"), sessionId);
  assert.equal(fixture.storageBySession.size, 1);
  await fixture.waitForBackgroundWork();

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      `https://proxy.example/v1/roleplay/metrics?session_id=${sessionId}`,
      { headers: janitorHeaders() },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).turns, 2);
});

test("Janitor derived sessions retain compacted continuity on later turns", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_KEEP_RECENT_MESSAGES: "4",
  });
  const history = [
    ...openingMessages(),
    { role: "assistant", content: "A shadow crosses the shelves." },
    { role: "user", content: "Follow it." },
    { role: "assistant", content: "Mira reaches the west wall." },
    { role: "user", content: "Search for a hidden latch." },
    { role: "assistant", content: "Her fingers find a silver catch." },
  ];
  const upstreamPayloads = [];
  let sessionId;

  await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      upstreamPayloads.push(payload);
      return payload.response_format?.type === "json_object"
        ? compactionResponse(payload.model)
        : completionResponse(payload.model, "First reply");
    },
    async () => {
      const first = await handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            model: "roleplay:auto",
            messages: history,
            memory: { mode: "force" },
            stream: false,
          },
          janitorHeaders(),
          JANITOR_PATH,
        ),
        fixture.env,
      );
      const second = await handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            model: "roleplay:auto",
            messages: [
              ...history,
              { role: "assistant", content: "First reply" },
              { role: "user", content: "Open the passage." },
            ],
            stream: false,
          },
          janitorHeaders(),
          JANITOR_PATH,
        ),
        fixture.env,
      );
      assert.equal(first.status, 200);
      assert.equal(second.status, 200);
      assert.equal(
        second.headers.get("X-Roleplay-Session-ID"),
        first.headers.get("X-Roleplay-Session-ID"),
      );
      assert.equal(
        second.headers.get("X-Roleplay-Memory"),
        "checkpoint_reused",
      );
      sessionId = first.headers.get("X-Roleplay-Session-ID");
    },
  );

  assert.equal(upstreamPayloads.length, 3);
  assert.equal(
    upstreamPayloads[2].messages.some((message) =>
      message.content.includes("Untrusted roleplay continuity memory"),
    ),
    true,
  );
  assert.equal(
    upstreamPayloads[2].messages.some(
      (message) => message.content === "Who followed us?",
    ),
    false,
  );
  await fixture.waitForBackgroundWork();
  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      `https://proxy.example/v1/roleplay/metrics?session_id=${sessionId}`,
      { headers: janitorHeaders() },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).compacted_prefix_messages, 4);
});

test("derived sessions separate different openings", async () => {
  const fixture = makeRoleplayEnv();
  const sessionIds = [];

  await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model);
    },
    async () => {
      for (const opening of [
        "Who followed us?",
        "Why is the observatory locked?",
      ]) {
        const response = await handleRoleplayEdgeRequest(
          roleplayRequest(
            {
              model: "roleplay:auto",
              messages: openingMessages(opening),
              stream: false,
            },
            janitorHeaders(),
            JANITOR_PATH,
          ),
          fixture.env,
        );
        sessionIds.push(response.headers.get("X-Roleplay-Session-ID"));
      }
    },
  );

  assert.notEqual(sessionIds[0], sessionIds[1]);
});

test("derived sessions are isolated by the accepted credential", async () => {
  const fixture = makeRoleplayEnv();
  const sessionIds = [];

  await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model);
    },
    async () => {
      for (const authorization of [
        "Bearer janitor-roleplay-key",
        "Bearer admin-roleplay-key",
      ]) {
        const response = await handleRoleplayEdgeRequest(
          roleplayRequest(
            {
              model: "roleplay:auto",
              messages: openingMessages(),
              stream: false,
            },
            { Authorization: authorization },
            JANITOR_PATH,
          ),
          fixture.env,
        );
        sessionIds.push(response.headers.get("X-Roleplay-Session-ID"));
      }
    },
  );

  assert.notEqual(sessionIds[0], sessionIds[1]);
});

test("client conversation IDs override message-derived routing", async () => {
  const fixture = makeRoleplayEnv();
  const sessionIds = [];

  await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      return completionResponse(payload.model);
    },
    async () => {
      for (const userContent of ["First opening.", "Different history."]) {
        const response = await handleRoleplayEdgeRequest(
          roleplayRequest(
            {
              conversation_id: "janitor-chat-42",
              model: "roleplay:auto",
              messages: openingMessages(userContent),
              history_mode: "replace",
              stream: false,
            },
            janitorHeaders(),
            JANITOR_PATH,
          ),
          fixture.env,
        );
        assert.equal(
          response.headers.get("X-Roleplay-Session-Source"),
          "client",
        );
        sessionIds.push(response.headers.get("X-Roleplay-Session-ID"));
      }
    },
  );

  assert.equal(sessionIds[0], sessionIds[1]);
});

test("Janitor model field can pin GLM while explicit sessions remain exact", async () => {
  const fixture = makeRoleplayEnv();
  let upstreamModel;

  const response = await withGlobalFetch(
    async (_input, init) => {
      const payload = JSON.parse(init.body);
      upstreamModel = payload.model;
      return completionResponse(payload.model);
    },
    () =>
      handleRoleplayEdgeRequest(
        roleplayRequest(
          {
            session_id: "janitor-explicit-session",
            model: "roleplay:glm",
            messages: openingMessages(),
            stream: false,
          },
          janitorHeaders(),
          JANITOR_PATH,
        ),
        fixture.env,
      ),
  );

  assert.equal(response.status, 200);
  assert.equal(upstreamModel, "glm-5.2");
  assert.equal(
    response.headers.get("X-Roleplay-Session-ID"),
    "janitor-explicit-session",
  );
  assert.equal(
    response.headers.get("X-Roleplay-Session-Source"),
    "explicit",
  );
});
