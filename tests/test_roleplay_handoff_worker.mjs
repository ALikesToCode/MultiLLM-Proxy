import assert from "node:assert/strict";
import test from "node:test";

import {
  completionResponse,
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";
import {
  ROLEPLAY_HANDOFF_TOOL_NAME,
  createRoleplayHandoffFrameFilter,
  isEmptyRoleplayReply,
  preferRoleplayHandoffTargets,
  roleplayHandoffCall,
  roleplayHandoffMessages,
} from "../worker/roleplay/handoff.mjs";
import { getRoleplaySettings } from "../worker/roleplay/config.mjs";

const SOURCE = "deepseek-v4.1-flash";
const TARGET = "glm-5.3";
const DRAFT = "*Isolde draws the pistol slowly.* \"You'll have neither of them, Commodore.\"";
const TARGET_REPLY = "*Isolde lets the silence stretch until the gun crews flinch.* \"No.\"";

function handoffEnv(overrides = {}) {
  return makeRoleplayEnv({
    ROLEPLAY_INTELLIGENCE_MODELS: `opencode:${SOURCE},opencode:${TARGET},opencode:mimo-v2.6-pro`,
    ROLEPLAY_HANDOFF_FROM: `opencode:${SOURCE}`,
    ROLEPLAY_HANDOFF_TO: `opencode:${TARGET}`,
    ROLEPLAY_DEFAULT_REASONING_EFFORT: "high",
    ...overrides,
  });
}

function frame(model, delta, finishReason = null) {
  return `data: ${JSON.stringify({ model, choices: [{ index: 0, delta, finish_reason: finishReason }] })}\n\n`;
}

function sse(frames) {
  return new Response([...frames, "data: [DONE]\n\n"].join(""), {
    headers: { "Content-Type": "text/event-stream" },
  });
}

function handoffCallFrames(model, args) {
  const text = JSON.stringify(args);
  return [
    frame(model, { reasoning_content: "This is the turning point of the story." }),
    frame(model, {
      tool_calls: [{
        index: 0,
        id: "call_handoff",
        type: "function",
        function: { name: ROLEPLAY_HANDOFF_TOOL_NAME, arguments: "" },
      }],
    }),
    frame(model, { tool_calls: [{ index: 0, function: { arguments: text.slice(0, 25) } }] }),
    frame(model, { tool_calls: [{ index: 0, function: { arguments: text.slice(25) } }] }),
    frame(model, {}, "tool_calls"),
  ];
}

function contentFrames(model, content) {
  const midpoint = Math.ceil(content.length / 2);
  return [
    frame(model, { content: content.slice(0, midpoint) }),
    frame(model, { content: content.slice(midpoint) }),
    frame(model, {}, "stop"),
  ];
}

function streamedPayloads(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice(6)));
}

function streamedContent(body) {
  return streamedPayloads(body)
    .map((payload) => payload.choices?.[0]?.delta?.content ?? "")
    .join("");
}

function visibleContent(body) {
  return streamedContent(body).replace(/<think>[\s\S]*?<\/think>/g, "").trim();
}

function turn(sessionId, overrides = {}) {
  return roleplayRequest({
    session_id: sessionId,
    input: "Harrow's frigate runs out its guns. He offers to spare the crew for Rook and the crate.",
    model: "roleplay:intelligence",
    max_tokens: 1024,
    stream: true,
    ...overrides,
  });
}

async function sessionState(fixture) {
  const stored = [...fixture.storageBySession.values()][0]?.storage;
  return {
    state: (await stored?.get("roleplay-session")) ?? {},
    messages: (await stored?.get("roleplay-messages")) ?? [],
  };
}

function recordingFetch(calls, respond) {
  return async (input, init) => {
    const payload = JSON.parse(init.body);
    calls.push(payload);
    return respond(payload, calls.length, new URL(input));
  };
}

test("a streamed source turn hands off to the target, which rewrites the draft", async () => {
  const fixture = handoffEnv();
  const calls = [];
  const response = await withGlobalFetch(recordingFetch(calls, (payload) =>
    payload.model === SOURCE
      ? sse(handoffCallFrames(SOURCE, {
          reason: "deeper_reasoning",
          notes: "Isolde must refuse without softening.",
          draft: DRAFT,
        }))
      : sse(contentFrames(TARGET, TARGET_REPLY)),
  ), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-handoff-stream"), fixture.env);
    return { status: result.status, body: await result.text() };
  });
  await fixture.waitForBackgroundWork();

  assert.equal(response.status, 200);
  assert.deepEqual(calls.map((call) => call.model), [SOURCE, TARGET]);
  assert.equal(calls[0].tools?.[0]?.function?.name, ROLEPLAY_HANDOFF_TOOL_NAME);
  assert.equal(calls[0].tool_choice, "auto");
  assert.equal(calls[1].tools, undefined);
  // The target keeps the configured effort: at max, GLM-5.3 spent a 4,096-token budget reasoning.
  assert.equal(calls[1].reasoning_effort, "high");
  const lastUser = calls[1].messages.findLastIndex((message) => message.role === "user");
  const note = calls[1].messages[lastUser - 1];
  assert.equal(note.role, "system");
  assert.match(note.content, /Private handoff note/);
  assert.match(note.content, /careful reasoning/);
  assert.ok(note.content.includes(DRAFT));
  assert.ok(note.content.includes("Isolde must refuse without softening."));

  assert.equal(visibleContent(response.body), TARGET_REPLY);
  assert.doesNotMatch(response.body, /tool_calls|multillm_hand_off_turn|turning point/);

  const { state, messages } = await sessionState(fixture);
  assert.equal(state.lastHandoffTurn, 0);
  assert.equal(state.handoffs, 1);
  assert.equal(messages.findLast((message) => message.role === "assistant")?.content, TARGET_REPLY);
});

// Production reaches OpenCode through the container, which turns reasoning into <think> content
// and drops the closing frame that carries only finish_reason.
function containerHandoffCallFrames(model, args) {
  return handoffCallFrames(model, args)
    .slice(0, -1)
    .flatMap((entry, index) => index === 0
      ? [
          frame(model, { content: "<think>" }),
          frame(model, { content: "This is the turning point of the story." }),
          entry,
        ]
      : [entry])
    .concat(frame(model, { content: "</think>\n\n" }));
}

test("a handoff still happens when the container rewrites reasoning and drops the finish frame", async () => {
  const fixture = handoffEnv();
  const calls = [];
  const response = await withGlobalFetch(recordingFetch(calls, (payload) =>
    payload.model === SOURCE
      ? sse(containerHandoffCallFrames(SOURCE, { reason: "stronger_prose", notes: "Make it land.", draft: DRAFT }))
      : sse(contentFrames(TARGET, TARGET_REPLY)),
  ), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-handoff-container"), fixture.env);
    return await result.text();
  });
  await fixture.waitForBackgroundWork();

  assert.deepEqual(calls.map((call) => call.model), [SOURCE, TARGET]);
  assert.equal(visibleContent(response), TARGET_REPLY);
  assert.doesNotMatch(response, /tool_calls|multillm_hand_off_turn/);
});

test("a target that writes nothing visible leaves the source's draft as the reply", async () => {
  const fixture = handoffEnv();
  const calls = [];
  const response = await withGlobalFetch(recordingFetch(calls, (payload) =>
    payload.model === SOURCE
      ? sse(handoffCallFrames(SOURCE, { reason: "deeper_reasoning", notes: "Plan.", draft: DRAFT }))
      : sse([frame(TARGET, { reasoning_content: "Weighing every faction." }), frame(TARGET, {}, "length")]),
  ), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-handoff-target-empty"), fixture.env);
    return await result.text();
  });
  await fixture.waitForBackgroundWork();

  assert.deepEqual(calls.map((call) => call.model), [SOURCE, TARGET]);
  assert.equal(visibleContent(response), DRAFT);
  const finishReasons = streamedPayloads(response)
    .map((payload) => payload.choices?.[0]?.finish_reason)
    .filter(Boolean);
  assert.deepEqual(finishReasons, ["stop"]);
  const { messages } = await sessionState(fixture);
  assert.equal(messages.findLast((message) => message.role === "assistant")?.content, DRAFT);
});

test("a source that writes the reply keeps it, and its stray handoff call is removed", async () => {
  const fixture = handoffEnv();
  const calls = [];
  const reply = "*Isolde laughs and turns the wheel hard to port.*";
  const response = await withGlobalFetch(recordingFetch(calls, () => sse([
    ...contentFrames(SOURCE, reply).slice(0, 2),
    frame(SOURCE, {
      tool_calls: [{
        index: 0,
        id: "call_late",
        type: "function",
        function: { name: ROLEPLAY_HANDOFF_TOOL_NAME, arguments: "{\"reason\":\"stronger_prose\",\"notes\":\"x\"}" },
      }],
    }),
    frame(SOURCE, {}, "tool_calls"),
  ])), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-handoff-late-call"), fixture.env);
    return await result.text();
  });
  await fixture.waitForBackgroundWork();

  assert.deepEqual(calls.map((call) => call.model), [SOURCE]);
  assert.equal(visibleContent(response), reply);
  assert.doesNotMatch(response, /tool_calls|multillm_hand_off_turn/);
  const finishReasons = streamedPayloads(response)
    .map((payload) => payload.choices?.[0]?.finish_reason)
    .filter(Boolean);
  assert.deepEqual(finishReasons, ["stop"]);
});

test("the next turn after a handoff withholds the tool until the turn gap passes", async () => {
  const fixture = handoffEnv();
  const calls = [];
  await withGlobalFetch(recordingFetch(calls, (payload) =>
    payload.model === SOURCE && calls.length === 1
      ? sse(handoffCallFrames(SOURCE, { reason: "stronger_prose", notes: "Pivotal." }))
      : sse(contentFrames(payload.model, "*The guns fall silent.*")),
  ), async () => {
    for (let index = 0; index < 3; index += 1) {
      const result = await handleRoleplayEdgeRequest(
        turn("session-handoff-gap", { input: `Turn ${index + 1}.` }),
        fixture.env,
      );
      await result.text();
      await fixture.waitForBackgroundWork();
    }
  });

  const sourceCalls = calls.filter((call) => call.model === SOURCE);
  assert.deepEqual(sourceCalls.map((call) => call.tool_choice), ["auto", "none", "auto"]);
  // The tool definition stays on every source call so the cached prompt prefix does not change.
  assert.ok(sourceCalls.every((call) => call.tools?.[0]?.function?.name === ROLEPLAY_HANDOFF_TOOL_NAME));
});

test("when every target fails, the source's draft becomes the reply", async () => {
  const fixture = handoffEnv();
  const calls = [];
  const response = await withGlobalFetch(recordingFetch(calls, (payload) =>
    payload.model === SOURCE
      ? sse(handoffCallFrames(SOURCE, { reason: "stronger_prose", notes: "Pivotal.", draft: DRAFT }))
      : new Response('{"error":"rate limited"}', { status: 429, headers: { "Content-Type": "application/json" } }),
  ), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-handoff-draft"), fixture.env);
    return await result.text();
  });
  await fixture.waitForBackgroundWork();

  assert.deepEqual(calls.map((call) => call.model), [SOURCE, TARGET]);
  assert.equal(visibleContent(response), DRAFT);
  const { messages } = await sessionState(fixture);
  assert.equal(messages.findLast((message) => message.role === "assistant")?.content, DRAFT);
});

test("a non-streamed handoff returns the target's reply without the tool call", async () => {
  const fixture = handoffEnv();
  const calls = [];
  const response = await withGlobalFetch(recordingFetch(calls, (payload) => {
    if (payload.model !== SOURCE) return completionResponse(payload.model, TARGET_REPLY);
    return new Response(JSON.stringify({
      id: "chatcmpl-source",
      object: "chat.completion",
      model: SOURCE,
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: "",
          tool_calls: [{
            id: "call_handoff",
            type: "function",
            function: {
              name: ROLEPLAY_HANDOFF_TOOL_NAME,
              arguments: JSON.stringify({ reason: "stronger_prose", notes: "Pivotal.", draft: DRAFT }),
            },
          }],
        },
        finish_reason: "tool_calls",
      }],
    }), { headers: { "Content-Type": "application/json" } });
  }), () => handleRoleplayEdgeRequest(turn("session-handoff-json", { stream: false }), fixture.env));
  await fixture.waitForBackgroundWork();

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(calls.map((call) => call.model), [SOURCE, TARGET]);
  assert.equal(body.choices[0].message.content, TARGET_REPLY);
  assert.equal(body.choices[0].message.tool_calls, undefined);
  assert.equal(body.choices[0].finish_reason, "stop");
  assert.equal(response.headers.get("X-Roleplay-Model"), TARGET);
});

test("callers asking for xhigh or max reasoning start on the target", async () => {
  const fixture = handoffEnv();
  const calls = [];
  await withGlobalFetch(recordingFetch(calls, (payload) => sse(contentFrames(payload.model, TARGET_REPLY))), async () => {
    const result = await handleRoleplayEdgeRequest(
      turn("session-handoff-xhigh", { reasoning_effort: "xhigh" }),
      fixture.env,
    );
    await result.text();
  });

  assert.deepEqual(calls.map((call) => call.model), [TARGET]);
  assert.equal(calls[0].tools, undefined);
});

test("without handoff settings no tool is offered", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_INTELLIGENCE_MODELS: `opencode:${SOURCE},opencode:${TARGET}`,
  });
  const calls = [];
  await withGlobalFetch(recordingFetch(calls, (payload) => sse(contentFrames(payload.model, TARGET_REPLY))), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-handoff-off"), fixture.env);
    await result.text();
  });

  assert.deepEqual(calls.map((call) => call.model), [SOURCE]);
  assert.equal(calls[0].tools, undefined);
  assert.equal(calls[0].tool_choice, undefined);
});

test("a streamed reply with only reasoning falls through to the next candidate", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_INTELLIGENCE_MODELS: `opencode:${SOURCE},opencode:mimo-v2.6-pro`,
  });
  const calls = [];
  const reply = "*Isolde finally answers.*";
  const response = await withGlobalFetch(recordingFetch(calls, (payload) =>
    calls.length === 1
      ? sse([frame(payload.model, { reasoning_content: "Thinking it over." }), frame(payload.model, {}, "stop")])
      : sse(contentFrames(payload.model, reply)),
  ), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-empty-stream"), fixture.env);
    return await result.text();
  });
  await fixture.waitForBackgroundWork();

  assert.deepEqual(calls.map((call) => call.model), [SOURCE, "mimo-v2.6-pro"]);
  assert.equal(visibleContent(response), reply);
  const finishReasons = streamedPayloads(response)
    .map((payload) => payload.choices?.[0]?.finish_reason)
    .filter(Boolean);
  assert.deepEqual(finishReasons, ["stop"]);
  const { messages } = await sessionState(fixture);
  assert.equal(messages.findLast((message) => message.role === "assistant")?.content, reply);
});

test("a non-streamed empty reply falls through, and an all-empty turn says so", async () => {
  const empty = (model) => new Response(JSON.stringify({
    id: "chatcmpl-empty",
    object: "chat.completion",
    model,
    choices: [{ index: 0, message: { role: "assistant", content: "", reasoning_content: "Hmm." }, finish_reason: "stop" }],
  }), { headers: { "Content-Type": "application/json" } });

  const fixture = makeRoleplayEnv({
    ROLEPLAY_INTELLIGENCE_MODELS: `opencode:${SOURCE},opencode:mimo-v2.6-pro`,
  });
  const calls = [];
  const response = await withGlobalFetch(recordingFetch(calls, (payload) =>
    calls.length === 1 ? empty(payload.model) : completionResponse(payload.model, "*Isolde answers.*"),
  ), () => handleRoleplayEdgeRequest(turn("session-empty-json", { stream: false }), fixture.env));
  assert.deepEqual(calls.map((call) => call.model), [SOURCE, "mimo-v2.6-pro"]);
  assert.equal((await response.json()).choices[0].message.content, "*Isolde answers.*");

  const allEmpty = makeRoleplayEnv({
    ROLEPLAY_INTELLIGENCE_MODELS: `opencode:${SOURCE},opencode:mimo-v2.6-pro`,
  });
  const failed = await withGlobalFetch(async (_input, init) => empty(JSON.parse(init.body).model), () =>
    handleRoleplayEdgeRequest(turn("session-empty-json-all", { stream: false }), allEmpty.env));
  const content = (await failed.json()).choices[0].message.content;
  assert.match(content, /could not complete this response/);
});

test("the empty-reply retry can be switched off", async () => {
  const fixture = makeRoleplayEnv({
    ROLEPLAY_INTELLIGENCE_MODELS: `opencode:${SOURCE},opencode:mimo-v2.6-pro`,
    ROLEPLAY_EMPTY_REPLY_FALLBACK_ENABLED: "false",
  });
  const calls = [];
  await withGlobalFetch(recordingFetch(calls, (payload) =>
    sse([frame(payload.model, { reasoning_content: "Thinking." }), frame(payload.model, {}, "stop")]),
  ), async () => {
    const result = await handleRoleplayEdgeRequest(turn("session-empty-off"), fixture.env);
    await result.text();
  });

  assert.deepEqual(calls.map((call) => call.model), [SOURCE]);
});

test("handoff helpers parse calls, place the note and order candidates", () => {
  assert.deepEqual(
    roleplayHandoffCall([{ function: { name: ROLEPLAY_HANDOFF_TOOL_NAME, arguments: "{not json" } }]),
    { reason: "stronger_prose", notes: "", draft: "" },
  );
  assert.equal(roleplayHandoffCall([{ function: { name: "other", arguments: "{}" } }]), null);

  const messages = roleplayHandoffMessages(
    [{ role: "system", content: "Card." }, { role: "user", content: "Go." }],
    { reason: "stronger_prose", notes: "", draft: "Draft text." },
  );
  assert.deepEqual(messages.map((message) => message.role), ["system", "system", "user"]);
  assert.match(messages[1].content, /Draft text\./);

  const settings = getRoleplaySettings({
    ROLEPLAY_HANDOFF_FROM: `opencode:${SOURCE}`,
    ROLEPLAY_HANDOFF_TO: `opencode:${TARGET},cline-pass:cline-pass/glm-5.3`,
  });
  const chain = [
    { provider: "opencode", model: SOURCE },
    { provider: "opencode", model: TARGET },
    { provider: "opencode", model: "mimo-v2.6-pro" },
    { provider: "cline-pass", model: "cline-pass/glm-5.3" },
  ];
  assert.deepEqual(
    preferRoleplayHandoffTargets(chain, { forwarded: { reasoning_effort: "max" } }, settings)
      .map((candidate) => candidate.model),
    [TARGET, "cline-pass/glm-5.3", SOURCE, "mimo-v2.6-pro"],
  );
  assert.equal(preferRoleplayHandoffTargets(chain, { forwarded: { reasoning_effort: "high" } }, settings), chain);

  assert.equal(isEmptyRoleplayReply({ assistant: "  ", finishReason: "stop" }), true);
  assert.equal(isEmptyRoleplayReply({ assistant: "", finishReason: "stop", toolCalls: [{ function: { name: "lookup" } }] }), false);
  assert.equal(isEmptyRoleplayReply({ assistant: "", finishReason: "stop", terminated: false }), false);
});

test("the frame filter drops the handoff call and keeps other tool calls", () => {
  const filter = createRoleplayHandoffFrameFilter();
  const output = filter.filter([
    frame("m", { tool_calls: [{ index: 0, function: { name: ROLEPLAY_HANDOFF_TOOL_NAME, arguments: "" } }] }),
    frame("m", { tool_calls: [{ index: 0, function: { arguments: "{\"reason\":" } }] }),
    frame("m", { tool_calls: [{ index: 1, function: { name: "lookup", arguments: "{}" } }] }),
    frame("m", {}, "tool_calls"),
  ]);
  const payloads = output.map((entry) => JSON.parse(entry.slice(6)));
  assert.equal(payloads.length, 2);
  assert.equal(payloads[0].choices[0].delta.tool_calls[0].function.name, "lookup");
  assert.equal(payloads[1].choices[0].finish_reason, "tool_calls");
});
