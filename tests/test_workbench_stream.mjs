import assert from "node:assert/strict";
import test from "node:test";
import { consumeStream, VisibleText } from "../static/js/workbench/stream.mjs";

const frame = (content, finish_reason = null) => `data: ${JSON.stringify({ choices: [{ delta: { content }, finish_reason }] })}\n\n`;
function response(parts) {
  return new Response(new ReadableStream({ start(controller) {
    for (const part of parts) controller.enqueue(new TextEncoder().encode(part));
    controller.close();
  } }));
}

test("visible parser handles split nested thinking without rendering reasoning", () => {
  const collector = new VisibleText();
  const result = ["<thi", "nk>private <think>nested</think>still hidden</thi", "nk>Final <img src=x>"]
    .map((part) => collector.consume(part)).join("");
  assert.equal(result, "Final <img src=x>");
});

test("split SSE and usage yield final text, not thought tokens", async () => {
  const stream = frame("<think>private</think>Hello") + '\ndata: {"usage":{"completion_tokens":10}}\n\n' + frame(" world", "stop") + "data: [DONE]\n\n";
  const result = await consumeStream(response([...stream]));
  assert.equal(result.text, "Hello world");
  assert.equal(result.status, "completed");
  assert.equal(result.output_tokens, 10);
  assert.ok(result.ttft_ms >= 0);
});

test("missing terminal events preserve visible partials without inventing TPS", async () => {
  const result = await consumeStream(response([frame("Part of an answer")]));
  assert.equal(result.status, "interrupted");
  assert.equal(result.text, "Part of an answer");
  assert.equal(result.tps, null);
});

test("unclosed thoughts, length, and stream errors are not reported as success", async () => {
  for (const stream of [frame("<think>hidden") + "data: [DONE]\n\n", frame("Partial", "length") + "data: [DONE]\n\n", frame("Partial") + 'data: {"error":{"message":"secret upstream error"}}\n\n']) {
    const result = await consumeStream(response([stream]));
    assert.equal(result.status, "interrupted");
    assert.ok(!JSON.stringify(result).includes("secret upstream error"));
  }
});

test("explicit cancellation preserves received text and closes the stream", async () => {
  const controller = new AbortController();
  let cancelled = false;
  const source = new ReadableStream({ start(stream) { stream.enqueue(new TextEncoder().encode(frame("Received"))); }, cancel() { cancelled = true; } });
  const result = await consumeStream(new Response(source), { signal: controller.signal, onText() { controller.abort(); } });
  assert.equal(result.text, "Received");
  assert.equal(result.status, "cancelled");
  assert.equal(cancelled, true);
});
