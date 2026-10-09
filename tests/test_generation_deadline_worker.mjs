import test from "node:test";
import assert from "node:assert/strict";
import { createGenerationDeadline, forwardedDeadlineHeaders, GenerationDeadlineExceeded,
  withGenerationDeadline, generationDeadlineHook } from "../worker/generation-deadline.mjs";
import { settlementInformation } from "../worker/generation-deadline.mjs";
import { UpstreamCancellation } from "../worker/upstream-cancellation.mjs";

test("absent deadline preserves response and timeout policy", async () => {
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Internal-Deadline-Ms": "1" } });
  assert.equal(createGenerationDeadline(request), null);
  const response = new Response("raw");
  assert.equal(await withGenerationDeadline(request, {}, () => response), response);
  assert.equal(forwardedDeadlineHeaders(request.headers, null).has("X-MultiLLM-Internal-Deadline-Ms"), false);
});

test("one local clock and trusted remaining budget use minimum limits", () => {
  let now = 100;
  const request = new Request("https://example.invalid", { headers: {
    "X-MultiLLM-Deadline-Ms": "1000", "X-MultiLLM-Internal-Deadline-Ms": "1" } });
  const deadline = createGenerationDeadline(request, {}, { now: () => now, limitsMs: [500] });
  now += 200;
  assert.equal(deadline.remainingMs(), 300);
  const headers = forwardedDeadlineHeaders(request.headers, deadline);
  const remote = createGenerationDeadline(new Request(request, { headers }), {}, { trustedInternal: true, now: () => 5000 });
  assert.equal(remote.remainingMs(), 300);
  now = 1000;
  assert.throws(() => deadline.check(), GenerationDeadlineExceeded);
});

test("invalid request rejects and malformed maximum disables", () => {
  for (const value of ["", "0", "-1", "1.5", "bad", "300001"]) {
    assert.throws(() => createGenerationDeadline(new Request("https://example.invalid", {
      headers: { "X-MultiLLM-Deadline-Ms": value } })), /Invalid generation deadline/);
  }
  assert.equal(createGenerationDeadline(new Request("https://example.invalid", {
    headers: { "X-MultiLLM-Deadline-Ms": "1000" } }), { GENERATION_DEADLINE_MAX_MS: "bad" }), null);
});

test("setup expiry returns 504 without provider replay", async () => {
  let now = 0;
  let calls = 0;
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "100" } });
  const result = await withGenerationDeadline(request, {}, () => { calls++; now = 101; return new Response("late"); }, { now: () => now });
  assert.equal(result.status, 504);
  assert.equal((await result.json()).error.code, "generation_deadline_exceeded");
  assert.equal(calls, 1);
});

test("midstream expiry emits error without DONE and retains unknown usage", async () => {
  let now = 0;
  let reads = 0;
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "100" } });
  const owner = new UpstreamCancellation();
  const body = new ReadableStream({ pull(controller) {
    if (++reads === 1) controller.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{"content":"a"}}]}\n\n'));
    else { now = 101; controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n")); }
  } }, { highWaterMark: 0 });
  const result = await withGenerationDeadline(request, {}, () => new Response(body, { headers: { "Content-Type": "text/event-stream" } }), { now: () => now, owner });
  const content = await result.text();
  assert.match(content, /generation_deadline_exceeded/);
  assert.doesNotMatch(content, /\[DONE\]/);
  assert.equal(owner.outcome.ambiguous, true);
  assert.equal(owner.outcome.usageState, "unknown");
  assert.equal(owner.outcome.replayPermission, false);
});

test("pending header/read aborts on one timer with ambiguous settlement", async () => {
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "10" } });
  const owner = new UpstreamCancellation();
  const result = await withGenerationDeadline(request, {}, () => new Promise(() => {}), { owner });
  assert.equal(result.status, 504);
  assert.equal(owner.outcome.ambiguous, true);
});

test("native lifecycle hook consumes setup and never resets at dispatch", async () => {
  let now = 0;
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "100" } });
  const hook = generationDeadlineHook(request, {}, { now: () => now });
  await hook.authorize({});
  now = 101;
  assert.throws(() => hook.before_dispatch({}), GenerationDeadlineExceeded);
  await hook.finalize({});
});

test("unknown final usage stays ambiguous even at EOF", () => {
  const owner = new UpstreamCancellation();
  owner.handoff();
  owner.complete();
  const settlement = settlementInformation(owner);
  assert.equal(settlement.ambiguous, true);
  assert.equal(settlement.usageState, "unknown");
  assert.equal(settlement.replayPermission, false);
});

test("caller cancellation aborts a pending call without hanging or replay", async () => {
  const controller = new AbortController();
  const request = new Request("https://example.invalid", { signal: controller.signal,
    headers: { "X-MultiLLM-Deadline-Ms": "1000" } });
  let calls = 0;
  const result = withGenerationDeadline(request, {}, () => { calls++; controller.abort("client_cancelled"); return new Promise(() => {}); });
  await assert.rejects(result, { name: "AbortError" });
  assert.equal(calls, 1);
});

test("preflight heartbeats consume budget before useful output", async () => {
  let now = 0;
  let reads = 0;
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "100" } });
  const source = new ReadableStream({ pull(controller) {
    if (++reads === 1) controller.enqueue(new TextEncoder().encode(": heartbeat\n\n"));
    else { now = 101; controller.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{"content":"late"}}]}\n\n')); }
  } }, { highWaterMark: 0 });
  const result = await withGenerationDeadline(request, {}, () => new Response(source, { headers: { "Content-Type": "text/event-stream" } }), { now: () => now });
  assert.equal(result.status, 504);
  assert.equal((await result.json()).error.code, "generation_deadline_exceeded");
});

test("allowed wait cannot exceed remaining generation time", async () => {
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "1000" } });
  const hook = generationDeadlineHook(request, {}, { now: () => 100 });
  hook.authorize({});
  let sleeps = 0;
  await assert.rejects(hook.deadline.wait(2000, () => { sleeps++; }), GenerationDeadlineExceeded);
  assert.equal(sleeps, 0);
  hook.finalize({});
});

for (const protocol of ["responses", "anthropic"]) {
  test(`${protocol} expiry emits a protocol error event`, async () => {
    let now = 0;
    let reads = 0;
    const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "100" } });
    const source = new ReadableStream({ pull(controller) {
      if (++reads === 1) controller.enqueue(new TextEncoder().encode('data: {"type":"content_block_delta","delta":{"text":"a"}}\n\n'));
      else { now = 101; controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n")); }
    } }, { highWaterMark: 0 });
    const result = await withGenerationDeadline(request, {}, () => new Response(source, { headers: { "Content-Type": "text/event-stream" } }),
      { now: () => now, protocol, preflight: false });
    const content = await result.text();
    assert.match(content, /"type":"error"/);
    assert.doesNotMatch(content, /\[DONE\]/);
    if (protocol === "anthropic") assert.match(content, /"type":"api_error"/);
  });
}

test("late header response is cancelled after deadline return", async () => {
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "10" } });
  let resolveFetch;
  let cancelled = 0;
  const source = new ReadableStream({ cancel() { cancelled++; } });
  const result = await withGenerationDeadline(request, {}, () => new Promise(resolve => { resolveFetch = resolve; }));
  assert.equal(result.status, 504);
  resolveFetch(new Response(source));
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(cancelled, 1);
});

test("prefix bound rejects heartbeats before committing success", async () => {
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "1000" } });
  const result = await withGenerationDeadline(request, {}, () => new Response(": heartbeat\n\n".repeat(6000), { headers: { "Content-Type": "text/event-stream" } }));
  assert.equal(result.status, 502);
  assert.equal((await result.json()).error.code, "upstream_stream_invalid");
});

test("DONE without useful output cannot pass preflight", async () => {
  const request = new Request("https://example.invalid", { headers: { "X-MultiLLM-Deadline-Ms": "1000" } });
  const result = await withGenerationDeadline(request, {}, () => new Response("data: [DONE]\n\n", { headers: { "Content-Type": "text/event-stream" } }));
  assert.equal(result.status, 502);
});
