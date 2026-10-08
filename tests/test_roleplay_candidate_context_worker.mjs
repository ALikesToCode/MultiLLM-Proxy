import assert from "node:assert/strict";
import test from "node:test";
import { registerHooks } from "node:module";
import {
  parseCandidateContextMode,
  prepareCandidateContext,
} from "../worker/roleplay/candidate-context.mjs";
import { prepareRoleplayCandidates } from "../worker/roleplay/capacity.mjs";
import { estimateTokens } from "../worker/roleplay/memory.mjs";

// The shared fixture's fixed data-URL import map predates this module.
const fixtureImports = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (context.parentURL?.startsWith("data:") && specifier === "./candidate-context.mjs") {
      return nextResolve(new URL("../worker/roleplay/candidate-context.mjs", import.meta.url).href, context);
    }
    return nextResolve(specifier, context);
  },
});
const {
  completionResponse, handleRoleplayEdgeRequest, makeRoleplayEnv,
  roleplayRequest, withGlobalFetch,
} = await import("./helpers/roleplay_fixture.mjs");
fixtureImports.deregister();

const settings = { contextSafetyTokens: 10, contextReplyReserveTokens: 100 };
const history = [
  { role: "system", content: "Keep the scene consistent." },
  { role: "user", content: "Old scene. ".repeat(100) },
  { role: "assistant", content: "Old answer. ".repeat(100) },
  { role: "developer", content: "Preserve the exact latest request." },
  { role: "user", content: "Recent scene." },
  { role: "assistant", content: "Recent answer." },
  { role: "user", content: "Continue." },
];
const retained = [history[0], ...history.slice(3)];

function fit(messages, contextWindow, outputReserveTokens = 100, safetyTokens = 10, estimator = estimateTokens) {
  return prepareCandidateContext({ contextWindow, messages, outputReserveTokens, safetyTokens, estimateTokens: estimator });
}

test("context mode is opt-in and invalid values stay off", () => {
  for (const value of [undefined, null, "", "off", "true", 1, {}]) {
    assert.equal(parseCandidateContextMode(value), "off");
  }
  assert.equal(parseCandidateContextMode(" WINDOW "), "window");
});

test("exact input, output and safety boundary keeps the original view", () => {
  const budget = estimateTokens(history) + 110;
  const plan = fit(history, budget);
  assert.equal(plan.fit, true);
  assert.equal(plan.messages, history);
  assert.equal(plan.estimatedInputTokens, estimateTokens(history));
  assert.equal(plan.omittedGroups, 0);
  assert.equal(fit(history, budget - 1).omittedGroups, 1);
});

test("small windows omit only oldest complete groups and preserve directive ordering", () => {
  const plan = fit(history, estimateTokens(retained) + 110);
  assert.equal(plan.fit, true);
  assert.deepEqual(plan.messages, retained);
  assert.equal(plan.omittedGroups, 1);
  assert.equal(plan.estimatedInputTokens, estimateTokens(retained));
  const smallest = [history[0], history[3], history[6]];
  assert.deepEqual(fit(history, estimateTokens(smallest) + 110).messages, smallest);
});

test("protected context is never sliced to make output or safety fit", () => {
  const messages = [history[0], history[3], history[6]];
  const boundary = estimateTokens(messages) + 110;
  for (const plan of [fit(messages, boundary - 1), fit(messages, boundary, 101), fit(messages, boundary, 100, 11)]) {
    assert.equal(plan.fit, false);
    assert.deepEqual(plan.messages, messages);
    assert.equal(plan.reason, "protected_context_too_large");
  }
});

test("unknown windows leave the original context untouched", () => {
  for (const window of [undefined, null, NaN, 0]) {
    const plan = fit(history, window);
    assert.equal(plan.fit, true);
    assert.equal(plan.messages, history);
    assert.equal(plan.omittedGroups, 0);
    assert.equal(plan.reason, "unknown_window");
  }
});

test("tool calls and all results are kept or omitted together", () => {
  const exchange = [
    { role: "user", content: "Inspect the room." },
    { role: "assistant", content: null, tool_calls: [
      { id: "one", type: "function", function: { name: "inspect", arguments: "{}" } },
      { id: "two", type: "function", function: { name: "inventory", arguments: "{}" } },
    ] },
    { role: "tool", tool_call_id: "two", content: "Inventory." },
    { role: "developer", content: "Keep this directive." },
    { role: "tool", tool_call_id: "one", content: "Room." },
    { role: "assistant", content: "Both results confirmed." },
  ];
  const messages = [history[0], ...exchange, history[6]];
  assert.deepEqual(fit(messages, estimateTokens(messages) + 110).messages, messages);
  const minimal = [history[0], exchange[3], history[6]];
  const plan = fit(messages, estimateTokens(minimal) + 110);
  assert.deepEqual(plan.messages, minimal);
  assert.equal(plan.omittedGroups, 1);
});

test("incomplete tool exchanges and unanswered old users stay protected", () => {
  for (const exchange of [
    [{ role: "assistant", content: "Calling.", tool_calls: [{ id: "missing" }] }],
    [{ role: "tool", tool_call_id: "orphan", content: "Result." }, { role: "assistant", content: "Answer." }],
    [{ role: "user", content: "Unanswered." }],
  ]) {
    const messages = [history[0], ...exchange, history[6]];
    const plan = fit(messages, estimateTokens([history[0], history[6]]) + 110);
    assert.equal(plan.fit, false);
    assert.deepEqual(plan.messages, messages);
  }
});

test("latest image, user and subsequent exchange survive without mutation", () => {
  const image = { role: "user", content: [
    { type: "text", text: "Describe this exact image." },
    { type: "image_url", image_url: { url: "data:image/png;base64,c3ludGhldGlj" } },
  ] };
  const messages = [...history.slice(0, -1), image,
    { role: "assistant", content: "Looking.", tool_calls: [{ id: "image" }] },
    { role: "tool", tool_call_id: "image", content: "Visible objects." }];
  const before = structuredClone(messages);
  const minimal = [history[0], history[3], ...messages.slice(-3)];
  const plan = fit(messages, estimateTokens(minimal) + 110);
  assert.deepEqual(plan.messages, minimal);
  assert.equal(plan.messages[2], image);
  assert.deepEqual(messages, before);
});

test("fitting bounds estimator traversals with a binary search over complete groups", () => {
  const messages = Array.from({ length: 255 }, (_, index) => ({
    role: index % 2 === 0 ? "user" : "assistant", content: `Message ${index}`,
  }));
  let calls = 0;
  const plan = fit(messages, 3, 1, 0, view => { calls += 1; return view.length; });
  assert.equal(plan.fit, true);
  assert.equal(plan.messages.length, 1);
  assert.ok(calls <= 12, `estimator traversals: ${calls}`);
});

test("candidate plans reserve output before fitting and preserve output-priority ordering", () => {
  const candidates = [
    { key: "small", contextWindow: estimateTokens(retained) + 110, maxOutputTokens: 1000 },
    { key: "large", contextWindow: 128000, maxOutputTokens: 1000 },
    { key: "clamped", contextWindow: 32000, maxOutputTokens: 50 },
  ];
  const before = structuredClone(candidates);
  const legacy = prepareRoleplayCandidates(candidates, estimateTokens(history), 100, settings);
  assert.equal(legacy.find(candidate => candidate.key === "small"), undefined);
  const prepared = prepareRoleplayCandidates(candidates, estimateTokens(history), 100, settings,
    { messages: history, estimateTokens });
  assert.deepEqual(prepared.map(candidate => candidate.key), ["small", "large", "clamped"]);
  assert.equal(prepared[0].resolvedMaxOutputTokens, 100);
  assert.deepEqual(prepared[0].contextPlan.messages, retained);
  assert.equal(prepared[1].contextPlan.messages, history);
  assert.equal(prepared[2].resolvedMaxOutputTokens, 50);
  assert.deepEqual(candidates, before);
});

test("windowing reserves requested output rather than accepting a smaller legacy allowance", () => {
  const candidate = { contextWindow: estimateTokens(history) + 30, maxOutputTokens: 1000 };
  const [legacy] = prepareRoleplayCandidates([candidate], estimateTokens(history), 100, settings);
  assert.equal(legacy.resolvedMaxOutputTokens, 20);
  const [prepared] = prepareRoleplayCandidates([candidate], estimateTokens(history), 100, settings,
    { messages: history, estimateTokens });
  assert.equal(prepared.resolvedMaxOutputTokens, 100);
  assert.equal(prepared.contextPlan.omittedGroups, 1);
});

test("provider-max output reserves the configured reply budget and unknown capacity stays compatible", () => {
  const candidate = { contextWindow: estimateTokens(retained) + 110, maxOutputTokens: 1000 };
  const [prepared] = prepareRoleplayCandidates([candidate], estimateTokens(history), null, settings,
    { messages: history, estimateTokens });
  assert.deepEqual(prepared.contextPlan.messages, retained);
  assert.ok(prepared.resolvedMaxOutputTokens >= settings.contextReplyReserveTokens);
  const unknown = { maxOutputTokens: 1000 };
  const [legacy] = prepareRoleplayCandidates([unknown], estimateTokens(history), 100, settings);
  const [unchanged] = prepareRoleplayCandidates([unknown], estimateTokens(history), 100, settings,
    { messages: history, estimateTokens });
  assert.ok(Number.isNaN(legacy.resolvedMaxOutputTokens));
  assert.ok(Number.isNaN(unchanged.resolvedMaxOutputTokens));
  assert.equal(unchanged.contextPlan.messages, history);
});

function fixture(mode, overrides = {}) {
  return makeRoleplayEnv({
    NANOGPT_API_KEY: "synthetic-nano", NAVYAI_API_KEY: "synthetic-navy",
    OPENCODE_GO_API_KEY: "", ROLEPLAY_PROVIDER_ORDER: "nanogpt,navyai",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ nanogpt: ["glm"], navyai: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({ nanogpt: { glm: "z-ai/glm-5.3-flash" }, navyai: { glm: "glm-5.2" } }),
    ROLEPLAY_PROVIDER_LIMITS: JSON.stringify({
      nanogpt: { glm: { context_window: 12000, max_output_tokens: 1000 } },
      navyai: { glm: { context_window: 2500, max_output_tokens: 1000 } },
    }),
    ROLEPLAY_CONTEXT_SAFETY_TOKENS: "256", ROLEPLAY_CONTEXT_REPLY_RESERVE_TOKENS: "1024",
    ROLEPLAY_COMPACT_TRIGGER_PERCENT: "99", ROLEPLAY_REFUSAL_FALLBACK_ENABLED: "false",
    ROLEPLAY_CANDIDATE_CONTEXT_REFIT: mode, PROMPT_CACHE_MIN_TOKENS: "1500", ...overrides,
  });
}

const requestHistory = [
  { role: "system", content: "Keep these instructions exact." },
  { role: "user", content: "Ancient scene. ".repeat(1000).trim() },
  { role: "assistant", content: "Old response." },
  { role: "user", content: "Recent scene." },
  { role: "assistant", content: "Recent response." },
  { role: "user", content: "Continue exactly here." },
];

async function runTurn(mode, { failAll = false, stream = false, overrides = {}, outputMode, continuation = false } = {}) {
  const setup = fixture(mode, overrides);
  const calls = [];
  const response = await withGlobalFetch(async (url, init) => {
    const payload = JSON.parse(init.body);
    calls.push(payload);
    if (new URL(url).hostname === "nano-gpt.com" || failAll) {
      return new Response('{"error":"busy"}', { status: 429 });
    }
    if (stream) {
      return new Response(`data: ${JSON.stringify({ choices: [{ delta: { content: "The scene continues." }, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`,
        { headers: { "Content-Type": "text/event-stream" } });
    }
    const result = completionResponse(payload.model, "The scene continues.");
    if (continuation && calls.length === 2) {
      const body = await result.json();
      body.choices[0].finish_reason = "length";
      return Response.json(body);
    }
    return result;
  }, () => handleRoleplayEdgeRequest(roleplayRequest({
    session_id: "candidate-context", model: "roleplay:glm", messages: requestHistory,
    max_tokens: 512, stream, recovery_enabled: true, ...(outputMode ? { output_mode: outputMode } : {}),
  }), setup.env));
  await response.text();
  await setup.waitForBackgroundWork();
  return { ...setup, calls, response, storage: [...setup.storageBySession.values()][0].storage };
}

test("off and unset modes keep legacy payloads, estimates and fallback behavior", async () => {
  const unset = await runTurn(undefined);
  const off = await runTurn("off");
  assert.equal(off.response.status, 429);
  assert.deepEqual(off.calls, unset.calls);
  assert.equal(off.calls.length, 1);
  assert.equal(off.response.headers.get("X-MultiLLM-Context-Refit"), null);
});

test("smaller fallback uses its fitted payload, cache estimate and headers without extra calls", async () => {
  const { calls, response } = await runTurn("window");
  assert.equal(response.status, 200);
  assert.equal(calls.length, 2);
  assert.ok(calls[0].messages.some(message => message.content === requestHistory[1].content));
  assert.ok(!calls[1].messages.some(message => message.content === requestHistory[1].content));
  assert.ok(calls[1].messages.some(message => message.content === requestHistory[0].content));
  assert.ok(calls[1].messages.some(message => message.content === requestHistory.at(-1).content));
  const estimate = String(estimateTokens(calls[1].messages));
  assert.equal(response.headers.get("X-Roleplay-Estimated-Input-Tokens"), estimate);
  assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache-Estimated-Tokens"), estimate);
  assert.equal(response.headers.get("X-MultiLLM-Prompt-Cache-Mode"), "below-threshold");
  assert.equal(response.headers.get("X-MultiLLM-Context-Refit"), "window");
  assert.equal(response.headers.get("X-MultiLLM-Context-Refit-Omitted-Groups"), "1");
  assert.equal(calls[1].max_tokens, 512);
});

test("windowing keeps the durable original conversation complete", async () => {
  const { response, storage } = await runTurn("window");
  assert.equal(response.status, 200);
  const stored = await storage.get("roleplay-messages");
  assert.deepEqual(stored.slice(0, -1), requestHistory.slice(1));
  assert.equal(stored.at(-1).role, "assistant");
});

test("failed fitted dispatch retains original recovery messages", async () => {
  const { response, storage, calls } = await runTurn("window", { failAll: true });
  assert.equal(response.status, 429);
  assert.equal(calls.length, 2);
  const recovery = await storage.get("operator_recovery_v1");
  assert.deepEqual(recovery.payload.messages, calls[0].messages);
  assert.ok(recovery.payload.messages.some(message => message.content === requestHistory[1].content));
});

test("streamed selection uses the fitted estimates and retains full storage", async () => {
  const { response, calls, storage } = await runTurn("window", { stream: true });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Roleplay-Estimated-Input-Tokens"), String(estimateTokens(calls[1].messages)));
  assert.equal(response.headers.get("X-MultiLLM-Context-Refit"), "window");
  assert.deepEqual((await storage.get("roleplay-messages")).slice(0, -1), requestHistory.slice(1));
});

test("continuation starts with the selected window instead of the original history", async () => {
  const { response, calls } = await runTurn("window", { outputMode: "unlimited", continuation: true });
  assert.equal(response.status, 200);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[2].messages.slice(0, calls[1].messages.length), calls[1].messages);
  assert.ok(!calls[2].messages.some(message => message.content === requestHistory[1].content));
});

test("an unfit first candidate skips before dispatch and leaves a fitting view untouched", async () => {
  const setup = fixture("window", { ROLEPLAY_PROVIDER_LIMITS: JSON.stringify({
    nanogpt: { glm: { context_window: 600, max_output_tokens: 512 } },
    navyai: { glm: { context_window: 12000, max_output_tokens: 1000 } },
  }) });
  const calls = [];
  const response = await withGlobalFetch(async (url, init) => {
    assert.equal(new URL(url).hostname, "api.navy");
    const payload = JSON.parse(init.body);
    calls.push(payload);
    return completionResponse(payload.model);
  }, () => handleRoleplayEdgeRequest(roleplayRequest({ session_id: "skip-unfit-first", model: "roleplay:glm",
    messages: requestHistory, max_tokens: 512, stream: false,
  }), setup.env));
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].messages.some(message => message.content === requestHistory[1].content));
  assert.equal(response.headers.get("X-MultiLLM-Context-Refit"), null);
  assert.equal(response.headers.get("X-Roleplay-Fallback-Count"), "0");
});

test("all-unfit protected views return the existing 413 without generation calls", async () => {
  const setup = fixture("window", { ROLEPLAY_PROVIDER_LIMITS: JSON.stringify({
    nanogpt: { glm: { context_window: 600, max_output_tokens: 512 } },
    navyai: { glm: { context_window: 600, max_output_tokens: 512 } },
  }) });
  let calls = 0;
  const response = await withGlobalFetch(() => { calls += 1; throw new Error("Unexpected dispatch"); },
    () => handleRoleplayEdgeRequest(roleplayRequest({ session_id: "unfit-context", model: "roleplay:glm",
      messages: [{ role: "system", content: "Protected. ".repeat(500).trim() }, { role: "user", content: "Continue." }],
      max_tokens: 512, memory: { mode: "off" }, stream: false,
    }), setup.env));
  const result = await response.json();
  assert.equal(response.status, 413, JSON.stringify(result));
  assert.equal(result.error.code, "roleplay_context_too_large");
  assert.equal(calls, 0);
});
