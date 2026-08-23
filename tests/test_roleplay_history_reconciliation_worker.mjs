import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const JANITOR_PATH = "/roleplay/v1/chat/completions";

function janitorHeaders() {
  return { Authorization: "Bearer janitor-roleplay-key" };
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

function isCompactionPayload(payload) {
  return payload.messages?.[0]?.content?.startsWith(
    "You manage continuity for a long-running roleplay.",
  );
}

test("Janitor full-history rewind does not resurrect a deleted reply", async () => {
  const fixture = makeRoleplayEnv({ ROLEPLAY_PROVIDER_ORDER: "opencode" });
  const upstreamPayloads = [];
  let call = 0;

  const responses = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    call += 1;
    return completionResponse(
      payload.model,
      call === 1 ? "Deleted opening reply." : "Fresh opening reply.",
    );
  }, async () => {
    const requestBody = {
      model: "roleplay:auto",
      messages: openingMessages(),
      stream: false,
    };
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest(requestBody, janitorHeaders(), JANITOR_PATH),
      fixture.env,
    );
    await fixture.waitForBackgroundWork();
    const retried = await handleRoleplayEdgeRequest(
      roleplayRequest(requestBody, janitorHeaders(), JANITOR_PATH),
      fixture.env,
    );
    await fixture.waitForBackgroundWork();
    return [first, retried];
  });

  assert.equal(
    responses[0].headers.get("X-Roleplay-Session-ID"),
    responses[1].headers.get("X-Roleplay-Session-ID"),
  );
  assert.equal(upstreamPayloads.length, 2);
  assert.equal(
    upstreamPayloads[1].messages.some(
      (message) => message.content === "Deleted opening reply.",
    ),
    false,
  );
});

test("Janitor edited branch replaces deleted full-history messages", async () => {
  const fixture = makeRoleplayEnv({ ROLEPLAY_PROVIDER_ORDER: "opencode" });
  const upstreamPayloads = [];
  let call = 0;
  const oldAssistant = "Mira points toward the left passage.";

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    call += 1;
    const replies = [
      oldAssistant,
      "The left stair opens.",
      "The right stair opens.",
    ];
    return completionResponse(payload.model, replies[call - 1]);
  }, async () => {
    const first = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          model: "roleplay:auto",
          messages: openingMessages(),
          stream: false,
        },
        janitorHeaders(),
        JANITOR_PATH,
      ),
      fixture.env,
    );
    assert.equal(first.status, 200);
    await fixture.waitForBackgroundWork();

    const oldBranch = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          model: "roleplay:auto",
          messages: [
            ...openingMessages(),
            { role: "assistant", content: oldAssistant },
            { role: "user", content: "Take the left stair." },
          ],
          stream: false,
        },
        janitorHeaders(),
        JANITOR_PATH,
      ),
      fixture.env,
    );
    assert.equal(oldBranch.status, 200);
    await fixture.waitForBackgroundWork();

    const editedBranch = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          model: "roleplay:auto",
          messages: [
            ...openingMessages(),
            { role: "assistant", content: oldAssistant },
            { role: "user", content: "Take the right stair." },
          ],
          stream: false,
        },
        janitorHeaders(),
        JANITOR_PATH,
      ),
      fixture.env,
    );
    assert.equal(editedBranch.status, 200);
    await fixture.waitForBackgroundWork();
  });

  assert.equal(upstreamPayloads.length, 3);
  const editedPayload = upstreamPayloads[2];
  assert.equal(
    editedPayload.messages.some(
      (message) => message.content === "Take the left stair.",
    ),
    false,
  );
  assert.equal(
    editedPayload.messages.some(
      (message) => message.content === "The left stair opens.",
    ),
    false,
  );
  assert.equal(
    editedPayload.messages.some(
      (message) => message.content === "Take the right stair.",
    ),
    true,
  );
});

test("Janitor rewind clears compacted memory from the deleted branch", async () => {
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

  await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    upstreamPayloads.push(payload);
    return isCompactionPayload(payload)
      ? compactionResponse(payload.model)
      : completionResponse(payload.model, "Mira answers.");
  }, async () => {
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
    await fixture.waitForBackgroundWork();
    const rewound = await handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          model: "roleplay:auto",
          messages: openingMessages(),
          stream: false,
        },
        janitorHeaders(),
        JANITOR_PATH,
      ),
      fixture.env,
    );
    await fixture.waitForBackgroundWork();
    assert.equal(first.status, 200);
    assert.equal(rewound.status, 200);
    assert.equal(
      rewound.headers.get("X-Roleplay-Session-ID"),
      first.headers.get("X-Roleplay-Session-ID"),
    );
    sessionId = first.headers.get("X-Roleplay-Session-ID");
  });

  const rewoundPayload = upstreamPayloads.at(-1);
  assert.equal(
    rewoundPayload.messages.some((message) =>
      message.content.includes("Untrusted roleplay continuity memory"),
    ),
    false,
  );
  assert.equal(
    rewoundPayload.messages.some(
      (message) => message.content === "A shadow crosses the shelves.",
    ),
    false,
  );

  const metrics = await handleRoleplayEdgeRequest(
    new Request(
      `https://proxy.example/v1/roleplay/metrics?session_id=${sessionId}`,
      { headers: janitorHeaders() },
    ),
    fixture.env,
  );
  assert.equal((await metrics.json()).compacted_prefix_messages, 0);
});
