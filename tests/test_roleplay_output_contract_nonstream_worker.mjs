import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const CURRENT_CONTRACT = [
  "Story responses must end with exactly one IMAGE PROMPT block.",
  "IMAGE PROMPT:",
  "Always include Camera, Primary subject, Setting, Lighting, and Composition.",
  "Camera:",
  "Primary subject:",
  "Setting:",
  "Lighting:",
  "Composition:",
].join("\n");

function janitorJsonRequest(sessionId) {
  return roleplayRequest(
    {
      session_id: sessionId,
      messages: [
        { role: "system", content: CURRENT_CONTRACT },
        { role: "user", content: "Open the marked shelf." },
      ],
      stream: false,
      max_tokens: 0,
    },
    { Origin: "https://janitorai.com" },
    "/roleplay/v1/chat/completions",
  );
}

test("non-streaming completion repairs only missing canonical fields", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  const initial = [
    "*Mira points toward the marked shelf.*",
    "",
    "IMAGE PROMPT:",
    "Camera: first-person medium shot.",
    "Primary subject: young adult woman with dark hair.",
  ].join("\n");
  const repair = [
    "Setting: old library at sunset.",
    "Lighting: warm window light.",
    "Composition: Mira centered beyond a foreground table.",
  ].join("\n");
  const payloads = [];

  const response = await withGlobalFetch(async (_input, init) => {
    const payload = JSON.parse(init.body);
    payloads.push(payload);
    return completionResponse(
      payload.model,
      payloads.length === 1 ? initial : repair,
    );
  }, () =>
    handleRoleplayEdgeRequest(
      janitorJsonRequest("session-nonstream-contract-repair"),
      fixture.env,
    ),
  );
  await fixture.waitForBackgroundWork();

  const result = await response.json();
  const content = result.choices[0].message.content;
  assert.equal(response.status, 200);
  assert.equal(payloads.length, 2);
  assert.match(content, /Mira points toward the marked shelf/);
  assert.match(content, /Primary subject: young adult woman/);
  assert.match(content, /Setting: old library/);
  assert.match(content, /Composition: Mira centered/);
  assert.equal(content.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.equal(result.choices[0].finish_reason, "stop");
  assert.ok(
    payloads[1].messages.some(
      (message) =>
        message.role === "system" &&
        message.content.includes("Supply only these missing IMAGE PROMPT fields"),
    ),
  );
});

test("non-streaming no-progress repair is omitted from response and storage", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  const initial = [
    "*Mira points toward the marked shelf.*",
    "",
    "IMAGE PROMPT:",
    "Setting: old library at sunset.",
  ].join("\n");
  const meta =
    "The response above was already complete. No continuation is needed.";
  let calls = 0;

  const response = await withGlobalFetch(async (_input, init) => {
    calls += 1;
    const payload = JSON.parse(init.body);
    return completionResponse(payload.model, calls === 1 ? initial : meta);
  }, () =>
    handleRoleplayEdgeRequest(
      janitorJsonRequest("session-nonstream-contract-no-progress"),
      fixture.env,
    ),
  );
  await fixture.waitForBackgroundWork();

  const result = await response.json();
  const content = result.choices[0].message.content;
  assert.equal(calls, 2);
  assert.equal(content, initial);
  assert.doesNotMatch(content, /already complete|No continuation/i);
  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  assert.equal(messages.some((message) => message.role === "assistant"), false);
});
