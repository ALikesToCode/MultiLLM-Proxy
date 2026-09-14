import assert from "node:assert/strict";
import test from "node:test";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { previewProfile } from "../worker/roleplay/profile-receipt.mjs";
import { applyReasoningPolicy } from "../worker/roleplay/reasoning.mjs";
import { withOpencodeGlmReasoning } from "../worker/opencode/reasoning-request.mjs";
import {
  handleRoleplayEdgeRequest,
  makeRoleplayEnv,
  roleplayRequest,
  withGlobalFetch,
} from "./helpers/roleplay_fixture.mjs";

const worker = (await loadWorkerModule()).default;
const MODEL = "glm-5.3-flash";
const REPLY = "The answer is 42.";
const REASONING = "Check the arithmetic before answering.";

function upstreamResponse(stream) {
  const headers = { "Content-Type": stream ? "text/event-stream" : "application/json" };
  if (!stream) {
    return new Response(JSON.stringify({
      model: MODEL,
      choices: [{
        message: { role: "assistant", content: REPLY, reasoning_content: REASONING },
        finish_reason: "stop",
      }],
    }), { headers });
  }
  const events = [
    { delta: { reasoning_content: REASONING } },
    { delta: { content: REPLY }, finish_reason: "stop" },
  ].map((choice) => `data: ${JSON.stringify({ model: MODEL, choices: [choice] })}\n\n`);
  return new Response(`${events.join("")}data: [DONE]\n\n`, { headers });
}

async function captureRequest(path, options, stream) {
  const payload = {
    model: path.startsWith("/roleplay/") ? "roleplay:5.3-flash" : MODEL,
    messages: [{ role: "user", content: "What is six times seven?" }],
    stream,
    ...options,
  };
  const roleplay = makeRoleplayEnv({
    ROLEPLAY_DEFAULT_REASONING_EFFORT: "high",
    ROLEPLAY_PROVIDER_ORDER: "opencode",
    ROLEPLAY_PROVIDER_FAMILIES: JSON.stringify({ opencode: ["glm"] }),
    ROLEPLAY_PROVIDER_MODELS: JSON.stringify({ opencode: { glm: [MODEL] } }),
    ROLEPLAY_MAX_AUTO_CONTINUATIONS: "0",
  });
  const sent = [];
  const response = await withGlobalFetch(async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    assert.equal(request.url, "https://opencode.ai/zen/go/v1/chat/completions");
    sent.push(await request.json());
    return upstreamResponse(stream);
  }, () => path.startsWith("/roleplay/")
    ? handleRoleplayEdgeRequest(roleplayRequest(payload, {}, path), roleplay.env)
    : worker.fetch(new Request(`https://proxy.example${path}`, {
      method: "POST",
      headers: { Authorization: "Bearer admin-test-key", "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }), {
      ADMIN_API_KEY: "admin-test-key",
      OPENCODE_GO_API_KEY: "opencode-test-key",
      OPENCODE_EDGE_FETCH: "true",
    }));
  const output = await response.text();
  await roleplay.waitForBackgroundWork();
  assert.equal(response.status, 200);
  assert.equal(sent.length, 1);
  assert.ok(output.includes(REPLY), "visible answer survives reasoning normalization");
  assert.ok(output.includes(REASONING), "upstream reasoning reaches the client");
  return sent[0];
}

for (const path of [
  "/opencode/v1/chat/completions",
  "/opencode/chat/completions",
  "/roleplay/v1/chat/completions",
]) {
  test(`${path} enables GLM thinking by default and honors effort overrides`, async (t) => {
    for (const stream of [false, true]) {
      for (const [options, expected] of [
        [{}, "max"],
        [{ reasoning_effort: "max" }, "max"],
        [{ reasoning_effort: "high" }, "high"],
        [{ reasoning_effort: "low" }, "low"],
        [{ reasoning_effort: "xhigh" }, "max"],
      ]) {
        await t.test(`stream=${stream} options=${JSON.stringify(options)}`, async () => {
          const sent = await captureRequest(path, options, stream);
          assert.equal(sent.reasoning_effort, expected);
          assert.deepEqual(sent.thinking, { type: "enabled" });
        });
      }
    }
  });
}

test("native chat preserves nested effort and explicit thinking controls", async () => {
  const thinking = { type: "enabled", clear_thinking: false };
  const sent = await captureRequest("/opencode/v1/chat/completions", {
    reasoning: { effort: "low" }, thinking,
  }, false);
  assert.equal(sent.reasoning_effort, "low");
  assert.deepEqual(sent.thinking, thinking);
  assert.equal("reasoning" in sent, false);
});

test("profile previews report the same Flash default and explicit override as generation", () => {
  for (const [options, expected] of [[{}, "max"], [{ reasoning_effort: "low" }, "low"]]) {
    const preview = previewProfile({
      kind: "roleplay",
      routing: { mode: "pinned", provider: "opencode", model: MODEL, fallback: "none" },
      ...options,
    }, { OPENCODE_GO_API_KEY: "opencode-test-key", ROLEPLAY_DEFAULT_REASONING_EFFORT: "high" });
    assert.equal(preview.selected.requestedEffort, expected);
    assert.equal(preview.selected.wireEffort, expected);
    assert.equal(preview.selected.providerAcknowledged, false);
  }
});

test("other roleplay models retain the configured default", () => {
  for (const candidate of [
    { provider: "opencode", model: "glm-5.2", family: "glm" },
    { provider: "nanogpt", model: `z-ai/${MODEL}`, family: "glm" },
  ]) {
    assert.equal(applyReasoningPolicy({}, candidate, {
      defaultEffort: "high",
    }).reasoning_effort, "high");
  }
});

test("native request normalization preserves unsupported bodies and other protocols", async () => {
  for (const [path, body] of [
    ["/opencode/v1/chat/completions", "not json"],
    ["/opencode/v1/chat/completions", "[]"],
    ["/opencode/v1/chat/completions", '{ "model": "kimi-k3" }'],
    ["/opencode/v1/chat/completions", '{ "model": "glm-5.3-flash", "reasoning_effort": "turbo" }'],
    ["/opencode/v1/chat/completions", '{ "model": "glm-5.2", "reasoning_effort": "none" }'],
    ["/opencode/v1/chat/completions", '{ "model": "glm-5.3-flash", "reasoning_effort": "low", "thinking": {"type":"disabled"} }'],
    ["/opencode/v1/messages", '{ "model": "qwen3.8-flash" }'],
    ["/opencode/v1/responses", '{ "model": "gpt-5.6-luna" }'],
  ]) {
    const request = new Request(`https://proxy.example${path}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body,
    });
    const normalized = await withOpencodeGlmReasoning(request, path);
    assert.equal(normalized, request);
    assert.equal(await normalized.text(), body);
  }
});

test("rewriting a GLM body preserves request affinity and aborts without a stale content length", async () => {
  const controller = new AbortController();
  const body = JSON.stringify({ model: MODEL, messages: [] });
  const request = new Request("https://proxy.example/opencode/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json", "Content-Length": String(body.length),
      "X-Opencode-Session": "synthetic-session", "Idempotency-Key": "synthetic-request",
    },
    body, signal: controller.signal,
  });
  const normalized = await withOpencodeGlmReasoning(request, new URL(request.url).pathname);
  const normalizedBody = await normalized.clone().text();
  assert.equal(normalized.headers.get("Content-Length"), String(new TextEncoder().encode(normalizedBody).byteLength));
  assert.equal(normalized.headers.get("X-Opencode-Session"), "synthetic-session");
  assert.equal(normalized.headers.get("Idempotency-Key"), "synthetic-request");
  assert.equal((await normalized.json()).reasoning_effort, "max");
  controller.abort();
  assert.equal(normalized.signal.aborted, true);
});

test("chunked GLM requests honor an effort override arriving after the model", async () => {
  const encoder = new TextEncoder();
  const request = new Request("https://proxy.example/opencode/v1/chat/completions", {
    method: "POST", headers: { "Content-Type": "application/json" }, duplex: "half",
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('{"model":"glm-5.3-flash",'));
        queueMicrotask(() => {
          controller.enqueue(encoder.encode('"messages":[{"role":"user","content":"नमस्ते"}],"reasoning_effort":"low"}'));
          controller.close();
        });
      },
    }),
  });
  const normalized = await withOpencodeGlmReasoning(request, new URL(request.url).pathname);
  const payload = await normalized.json();
  assert.equal(payload.reasoning_effort, "low");
  assert.deepEqual(payload.thinking, { type: "enabled" });
  assert.equal(payload.messages[0].content, "नमस्ते");
});
