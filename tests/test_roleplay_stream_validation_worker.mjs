import assert from "node:assert/strict";
import test from "node:test";
import { createRoleplayStreamValidationGate } from "../worker/roleplay/stream-validation-gate.mjs";
import { createObservedStream } from "../worker/roleplay/streaming.mjs";

const frame = (delta) => `data: ${JSON.stringify({ choices: [{ delta }] })}\n\n`;
const content = (frames) => frames.map((value) => JSON.parse(value.slice(5)).choices[0].delta.content ?? "").join("");

test("schema mentions inside thinking never hold subsequent story deltas", async () => {
  let source;
  const observed = createObservedStream({
    upstreamBody: new ReadableStream({ start(controller) { source = controller; } }),
    upstreamController: new AbortController(),
    heartbeatMs: 1000,
    idleTimeoutMs: 2000,
    bufferUntilValidated: true,
    reasoningMetadata: { provider: "opencode", model: "glm-5.3-flash" },
    onComplete() {},
  });
  const reader = observed.stream.getReader();
  const decoder = new TextDecoder();
  const send = async (delta, expected) => {
    source.enqueue(new TextEncoder().encode(frame(delta)));
    const { value } = await reader.read();
    assert.match(decoder.decode(value), expected);
  };
  try {
    await send({ reasoning_content: "Plan the library scene.\n" }, /Plan the library/);
    await send({ reasoning_content: "IMAGE PROMPT:\nSave the setting for the end.\n" }, /Save the setting/);
    await send({ content: "The librarian opened the door." }, /librarian opened/);
    await send({ content: " The teapot said hello." }, /teapot said hello/);
    source.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'));
    source.close();
    while (!(await reader.read()).done) {}
    assert.equal((await observed.completion).success, true);
  } finally {
    await reader.cancel();
  }
});

test("split thinking tags pass through while only the real final block is held", () => {
  const gate = createRoleplayStreamValidationGate(true);
  const fragments = ["<thi", "nk>Plan.\nIMAGE PRO", "MPT:\nExample.\n</thi", "nk>\nStory.", "\nIMA", "GE PROMPT:\nSetting: library."];
  const released = fragments.flatMap((text) => gate.consume([frame({ content: text })]));
  assert.equal(content(released), "<think>Plan.\nIMAGE PROMPT:\nExample.\n</think>\nStory.\n");
  assert.equal(gate.remaining(fragments.join("")), "IMAGE PROMPT:\nSetting: library.");
});

test("a marker in the middle of a story line does not become a boundary across chunks", () => {
  const gate = createRoleplayStreamValidationGate(true);
  const output = ["She said ", "IMAGE PROMPT:", " is a label."]
    .flatMap((text) => gate.consume([frame({ content: text })]));
  assert.equal(content(output), "She said IMAGE PROMPT: is a label.");
});

test("discarding a leg resets thinking and line state", () => {
  const gate = createRoleplayStreamValidationGate(true);
  gate.consume([frame({ content: "<think>Still planning" })]);
  gate.discardLeg();
  assert.deepEqual(gate.consume([frame({ content: "IMAGE PROMPT:\nSetting: room" })]), []);
});


test("validation boundary is independent of every two-chunk split", () => {
  const prefix = "<think>Plan.\n IMAGE PROMPT:\nExample.</think>\nStory.\n";
  const suffix = " IMAGE PROMPT:\nSetting: library.";
  const text = prefix + suffix;
  for (let split = 1; split < text.length; split += 1) {
    const gate = createRoleplayStreamValidationGate(true);
    const output = [text.slice(0, split), text.slice(split)]
      .flatMap((part) => gate.consume([frame({ content: part })]));
    assert.equal(content(output), prefix, `split ${split}`);
    assert.equal(gate.remaining(text), suffix, `split ${split}`);
  }
});
