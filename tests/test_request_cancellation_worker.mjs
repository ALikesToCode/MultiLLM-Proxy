import assert from "node:assert/strict";
import test from "node:test";

import { UpstreamCancellation } from "../worker/upstream-cancellation.mjs";
import { attemptRoleplayCandidates, readBoundedBytes } from "../worker/roleplay/transport.mjs";

async function withGlobalFetch(fetchImpl, callback) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try { return await callback(); } finally { globalThis.fetch = previous; }
}

const candidate = {
  key: "synthetic", provider: "nanogpt", model: "synthetic",
  token: "synthetic", endpoint: "https://example.invalid",
};
const settings = { upstreamHeaderTimeoutMs: 100, preResponseFallbackEnabled: true };

function pendingBody() {
  let cancelled = 0;
  let streamController;
  const body = new ReadableStream({
    start(controller) { streamController = controller; },
    cancel() { cancelled += 1; },
  }, { highWaterMark: 0 });
  return { body, get cancelled() { return cancelled; }, get controller() { return streamController; } };
}

for (const started of [false, true]) {
  test(`abort after headers closes once, reader started=${started}`, async () => {
    const client = new AbortController();
    const outcomes = [];
    const owner = new UpstreamCancellation({ signal: client.signal, onOutcome: outcome => outcomes.push(outcome) });
    const upstream = pendingBody();
    owner.handoff();
    const response = owner.wrapResponse(new Response(upstream.body));
    const reader = response.body.getReader();
    const read = started ? reader.read() : null;
    client.abort("synthetic disconnect");
    if (read) await assert.rejects(read, { name: "AbortError" });
    await assert.rejects(reader.read(), { name: "AbortError" });
    owner.cleanup();
    await owner.close();
    assert.equal(upstream.cancelled, 1);
    assert.equal(owner.controller.signal.aborted, true);
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].ambiguous, true);
    assert.equal(outcomes[0].usage, null);
    assert.equal(outcomes[0].usageState, "unknown");
    assert.equal(outcomes[0].replayPermission, false);
  });
}

test("downstream body cancellation aborts fetch even without Request.signal", async () => {
  const owner = new UpstreamCancellation();
  owner.handoff();
  const upstream = pendingBody();
  const response = owner.wrapResponse(new Response(upstream.body));
  await response.body.cancel();
  await owner.close();
  assert.equal(upstream.cancelled, 1);
  assert.equal(owner.controller.signal.aborted, true);
  assert.equal(owner.outcome.ambiguous, true);
});

test("successful bytes and headers survive and late abort is inert", async () => {
  const client = new AbortController();
  const owner = new UpstreamCancellation({ signal: client.signal });
  const bytes = new Uint8Array([0, 255, 13, 10, 37]);
  owner.handoff();
  const response = owner.wrapResponse(new Response(bytes, { status: 201, headers: { "X-Request-ID": "synthetic" } }));
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("X-Request-ID"), "synthetic");
  owner.cleanup();
  client.abort();
  assert.equal(owner.controller.signal.aborted, false);
  assert.equal(owner.outcome.reason, "complete");
  assert.equal(owner.outcome.ambiguous, false);
});

test("bounded reader abort and size rejection close pending reads once", async () => {
  const client = new AbortController();
  const upstream = pendingBody();
  const reading = readBoundedBytes(upstream.body, 10, client.signal);
  client.abort();
  await assert.rejects(reading, { name: "AbortError" });
  assert.equal(upstream.cancelled, 1);
  assert.equal(upstream.body.locked, false);
  const oversized = pendingBody();
  oversized.controller.enqueue(new Uint8Array(11));
  await assert.rejects(readBoundedBytes(oversized.body, 10), /response limit/);
  assert.equal(oversized.cancelled, 1);
});

test("already aborted candidate dispatch does not call provider", async () => {
  const controller = new AbortController();
  controller.abort();
  const candidate = { key: "synthetic", provider: "nanogpt", model: "synthetic", endpoint: "https://example.invalid" };
  let calls = 0;
  const result = await withGlobalFetch(async () => { calls += 1; throw new Error("unexpected fetch"); }, () =>
    attemptRoleplayCandidates({ stats: {} }, [candidate], () => ({ model: "synthetic" }), {},
      { upstreamHeaderTimeoutMs: 100, preResponseFallbackEnabled: true }, controller.signal, ""));
  assert.equal(calls, 0);
  assert.equal(result.terminalResponse.status, 499);
});

test("roleplay abort racing HTTP rejection never falls back", async () => {
  const client = new AbortController();
  let calls = 0;
  const response = await withGlobalFetch(async () => {
    calls += 1;
    client.abort();
    return Response.json({ error: { code: "synthetic" } }, { status: 429 });
  }, () => attemptRoleplayCandidates({ stats: {} }, [candidate, candidate],
    () => ({ model: "synthetic" }), {}, settings, client.signal, ""));
  assert.equal(calls, 1);
  assert.equal(response.terminalResponse.status, 499);
});

test("header timeout aborts and is bounded without a body", async () => {
  const owner = new UpstreamCancellation({ headerTimeoutMs: 1 });
  owner.handoff();
  await new Promise(resolve => owner.controller.signal.addEventListener("abort", resolve, { once: true }));
  assert.equal(owner.controller.signal.reason, "upstream_header_timeout");
  assert.equal(owner.outcome.ambiguous, true);
  assert.equal(owner.outcome.replayPermission, false);
});

test("in-flight provider fetch sees client abort and never advances", async () => {
  const client = new AbortController();
  const outcomes = [];
  let calls = 0;
  let started;
  const connected = new Promise(resolve => { started = resolve; });
  const requesting = withGlobalFetch(async (_input, init) => {
    calls += 1;
    started();
    return new Promise((resolve, reject) => init.signal.addEventListener("abort", () => {
      assert.equal(init.signal.reason, "synthetic disconnect");
      reject(new DOMException("Aborted", "AbortError"));
    }, { once: true }));
  }, () => attemptRoleplayCandidates({ stats: {} }, [candidate, candidate],
    () => ({ model: "synthetic" }), {}, { ...settings, onCancellationOutcome: value => outcomes.push(value) }, client.signal, ""));
  await connected;
  client.abort("synthetic disconnect");
  const result = await requesting;
  assert.equal(result.terminalResponse.status, 499);
  assert.equal(calls, 1);
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].ambiguous, true);
  assert.equal(outcomes[0].usage, null);
  assert.equal(outcomes[0].replayPermission, false);
});

test("roleplay disconnect after first byte closes and preserves unknown usage", async () => {
  const client = new AbortController();
  const upstream = pendingBody();
  upstream.controller.enqueue(new Uint8Array([1, 2]));
  const outcomes = [];
  let calls = 0;
  const result = await withGlobalFetch(async () => {
    calls += 1;
    return new Response(upstream.body);
  }, () => attemptRoleplayCandidates({ stats: {} }, [candidate, candidate],
    () => ({ model: "synthetic" }), {}, { ...settings, onCancellationOutcome: value => outcomes.push(value) }, client.signal, ""));
  const reader = result.response.body.getReader();
  assert.deepEqual((await reader.read()).value, new Uint8Array([1, 2]));
  client.abort();
  await assert.rejects(reader.read(), { name: "AbortError" });
  result.cleanup();
  assert.equal(calls, 1);
  assert.equal(upstream.cancelled, 1);
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].usage, null);
  assert.equal(outcomes[0].ambiguous, true);
});

test("cancellation does not await a provider acknowledgement", async () => {
  const owner = new UpstreamCancellation();
  owner.handoff();
  let cancelled = 0;
  const response = owner.wrapResponse(new Response(new ReadableStream({
    cancel() { cancelled += 1; return new Promise(() => {}); },
  }, { highWaterMark: 0 })));
  await response.body.cancel();
  await owner.close();
  assert.equal(cancelled, 1);
});

test("terminal provider rejection keeps bytes and abort ownership", async () => {
  const client = new AbortController();
  const body = '{"error":{"code":"synthetic"}}';
  const result = await withGlobalFetch(async () => new Response(body, {
    status: 429, headers: { "Retry-After": "17" },
  }), () => attemptRoleplayCandidates({ stats: {} }, [candidate],
    () => ({ model: "synthetic" }), {}, settings, client.signal, ""));
  assert.equal(result.terminalResponse.status, 429);
  assert.equal(await result.terminalResponse.text(), body);
  assert.equal(result.terminalResponse.headers.get("Retry-After"), "17");
  client.abort();
});
