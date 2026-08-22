import assert from "node:assert/strict";
import test from "node:test";

import {
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const CONTRACT = [
  "Story output order: story, exactly one IMAGE PROMPT, then end.",
  "IMAGE PROMPT:",
  "Camera:",
  "Primary subject:",
  "Setting:",
  "Lighting:",
  "Composition:",
].join("\n");

const FIRST_RESPONSE = [
  "*Holly grips her cross and answers the argument.*",
  "",
  "IMAGE PROMPT:",
  "Camera: first-person classroom view.",
  "Primary subject: young adult woman with chestnut hair.",
  "Setting: college philosophy classroom.",
  "Lighting: daylight and fluorescent panels.",
  "Composition: Holly centered beside her desk.",
].join("\n");

const CORRUPTED_TAIL = [
  "The response above was already complete. No continuation is needed.",
  "*Holly leaves for the hallway before anyone can answer.*",
  "",
  "IMAGE PROMPT:",
  "Camera: first-person hallway view.",
  "Primary subject: young adult woman walking away.",
  "Setting: college hallway.",
  "Lighting: fluorescent panels.",
  "Composition: receding corridor.",
].join("\n");

function stream(content) {
  return new Response(
    [
      `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason: "stop" }] })}\n\n`,
      "data: [DONE]\n\n",
    ].join(""),
    { headers: { "Content-Type": "text/event-stream" } },
  );
}

function visibleContent(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice(6)))
    .map((payload) => payload.choices?.[0]?.delta?.content ?? "")
    .join("");
}

test("mangled completed response is reduced to its first clean story and image block", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "8",
    ROLEPLAY_MAX_OUTPUT_CONTRACT_REPAIRS: "1",
  });
  let calls = 0;

  const response = await withGlobalFetch(async () => {
    calls += 1;
    return stream(`${FIRST_RESPONSE}${CORRUPTED_TAIL}`);
  }, () =>
    handleRoleplayEdgeRequest(
      roleplayRequest(
        {
          session_id: "session-clean-corrupted-contract-output",
          messages: [
            { role: "system", content: CONTRACT },
            { role: "user", content: "Continue the debate." },
          ],
          stream: true,
          max_tokens: 0,
        },
        { Origin: "https://janitorai.com" },
        "/roleplay/v1/chat/completions",
      ),
      fixture.env,
    ),
  );
  const body = await response.text();
  await fixture.waitForBackgroundWork();

  const visible = visibleContent(body);
  assert.equal(calls, 1);
  assert.equal(visible, FIRST_RESPONSE);
  assert.equal(visible.match(/IMAGE PROMPT:/g)?.length, 1);
  assert.doesNotMatch(visible, /already complete|No continuation|hallway/i);
  assert.equal(body.match(/"finish_reason":"stop"/g)?.length, 1);
  assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);

  const stored = [...fixture.storageBySession.values()][0]?.storage;
  const messages = (await stored?.get("roleplay-messages")) ?? [];
  const assistant = messages.find((message) => message.role === "assistant");
  assert.equal(assistant?.content, FIRST_RESPONSE);
});
