import assert from "node:assert/strict";
import test from "node:test";

const email = "alice@school.org", route = "/v1/roleplay/chat/completions";
const config = (extra = {}) => ({ PII_REDACTION_ENABLED: "true", PII_REDACTION_POLICY_JSON:
  JSON.stringify({ routes: [route], detectors: ["email", "phone", "card"], mode: "required", ...extra }) });
const modules = () => Promise.all([import("../worker/pii-redaction.mjs"), import("../worker/pii-rehydration.mjs")]);
async function prepare(text = email, env = config(), options = {}) {
  const [redaction] = await modules();
  return redaction.preparePayload({ messages: [{ role: "user", content: text }] }, env, { route, ...options });
}

test("PII modules are available", async () => {
  const [redaction, stream] = await modules();
  assert.equal(typeof redaction.preparePayload, "function");
  assert.equal(typeof stream.rehydrateResponse, "function");
});

test("disabled, empty, raw and unscoped keep original object", async () => {
  const [redaction] = await modules();
  const payload = { content: email };
  for (const env of [{}, { PII_REDACTION_ENABLED: "" }, config({ routes: [] }),
    { PII_REDACTION_ENABLED: "true", PII_REDACTION_POLICY_JSON: "" }]) {
    const result = await redaction.preparePayload(payload, env, { route });
    assert.equal(result.payload, payload);
    assert.equal(result.context, null);
  }
  assert.equal((await prepare(email, config(), { raw: true })).context, null);
  assert.ok((await prepare(email, config({ routes: [], keys: ["key-7"] }), { keyScope: "key-7" })).context);
});

test("detectors, Luhn, authenticated tokens and concurrent maps", async () => {
  for (const value of [email, "+1 (415) 555-2671", "4111 1111 1111 1111"]) {
    const [a, b] = await Promise.all([prepare(value), prepare(value)]);
    const token = a.payload.messages[0].content;
    assert.match(token, /^__MLPII_[0-9a-f]{64}__$/);
    assert.equal(a.context.restore(token), value);
    assert.equal(b.context.restore(token), token);
    a.context.close();
    assert.equal(a.context.values.size, 0);
    assert.equal(a.context.restore(token), token);
  }
  for (const value of ["4111 1111 1111 1112", "123", "123456789012345678901", "bad@local", "x".repeat(65) + "@school.org"])
    assert.equal((await prepare(value)).payload.messages[0].content, value);
});

test("secret spans never enter PII map", async () => {
  const result = await prepare("postgres://owner:S3cur3Password42@school.org/db " + email,
    { ...config(), SECRET_SCAN_DEFAULT: "observe" });
  assert.deepEqual([...result.context.values.values()], [email]);
  const [redaction] = await modules();
  const fields = await redaction.preparePayload({ password: "A1ice42@school.org", content: email }, config(), { route });
  assert.deepEqual([...fields.context.values.values()], [email]);
});

test("bounds fail closed and best effort is atomic", async () => {
  for (const text of ["x".repeat(1024 * 1024 + 1), Array.from({ length: 513 }, (_, i) => `p${i}@school.org`).join(" ")]) {
    await assert.rejects(prepare(text), { name: "PIIRedactionError" });
    const result = await prepare(text, config({ mode: "best_effort" }));
    assert.equal(result.skipped, true);
    assert.equal(result.context, null);
    assert.equal(result.payload.messages[0].content, text);
  }
});

test("nonstream JSON restores and drops map", async () => {
  const [, stream] = await modules(), result = await prepare();
  const token = result.payload.messages[0].content;
  const response = await stream.rehydrateResponse(Response.json({ content: "é " + token }), result.context);
  assert.deepEqual(await response.json(), { content: "é " + email });
  assert.equal(result.context.values.size, 0);
  const partial = await prepare();
  const error = await stream.rehydrateResponse(Response.json({ content: "__MLPII_" }), partial.context);
  assert.equal(error.status, 502);
  assert.equal(stream.isPIIFailure(error), true);
  assert.equal(partial.context.values.size, 0);
});

test("every chunk split including UTF8 and JSON escapes", async () => {
  const [, stream] = await modules();
  const sample = await prepare(), token = sample.payload.messages[0].content;
  const wire = `data: ${JSON.stringify({ choices: [{ delta: { content: "é " + token + "\n" } }] }).replaceAll("_", "\\u005f")}\r\n\r\ndata: [DONE]\r\n\r\n`;
  for (let split = 1; split < new TextEncoder().encode(wire).length; split += 1) {
    const result = await prepare();
    const bytes = new TextEncoder().encode(wire.replaceAll(token.replaceAll("_", "\\u005f"), result.payload.messages[0].content.replaceAll("_", "\\u005f")));
    const body = new ReadableStream({ start(c) { c.enqueue(bytes.slice(0, split)); c.enqueue(bytes.slice(split)); c.close(); } });
    const response = await stream.rehydrateResponse(new Response(body, { headers: { "Content-Type": "text/event-stream" } }), result.context);
    const text = await response.text();
    assert.equal(JSON.parse(text.split("\n")[0].slice(6)).choices[0].delta.content, "é " + email + "\n");
    assert.equal(result.context.values.size, 0);
  }
});

test("event fragments, terminal prefixes, bounds and cancellation", async () => {
  const [, stream] = await modules(), result = await prepare();
  const token = result.payload.messages[0].content;
  const frames = [token.slice(0, 13), token.slice(13, 60), token.slice(60)].map(content =>
    `data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`).join("");
  const response = await stream.rehydrateResponse(new Response(frames, { headers: { "Content-Type": "text/event-stream" } }), result.context);
  const text = await response.text();
  assert.deepEqual(text.split("\n").filter(line => line.startsWith("data:")).map(line => JSON.parse(line.slice(6)).choices[0].delta.content), ["", "", email]);
  for (const wire of ['data: {"content":"__MLPII_"}\n\ndata: [DONE]\n\n', "data: " + "x".repeat(65537)]) {
    const item = await prepare();
    const output = await stream.rehydrateResponse(new Response(wire, { headers: { "Content-Type": "text/event-stream" } }), item.context);
    await assert.rejects(output.text(), { name: "PIIStreamError" });
    assert.equal(item.context.values.size, 0);
  }
  let cancelled = false;
  const item = await prepare();
  const upstream = new ReadableStream({ cancel() { cancelled = true; } }, { highWaterMark: 0 });
  const output = await stream.rehydrateResponse(new Response(upstream, { headers: { "Content-Type": "text/event-stream" } }), item.context);
  await output.body.cancel();
  assert.equal(cancelled, true);
  assert.equal(item.context.values.size, 0);
});

test("native roleplay transport redacts after firewall and restores", async () => {
  const { attemptRoleplayCandidates } = await import("../worker/roleplay/transport.mjs");
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (_url, init) => {
    const payload = JSON.parse(init.body);
    calls.push(payload);
    return Response.json({ choices: [{ message: { content: payload.messages[0].content }, finish_reason: "stop" }] });
  };
  try {
    const candidate = { key: "synthetic", provider: "nanogpt", model: "synthetic", token: "synthetic", endpoint: "https://example.invalid" };
    const decisions = [];
    const result = await attemptRoleplayCandidates({ stats: {} }, [candidate], () => ({ model: "synthetic", messages: [{ role: "user", content: email }] }),
      { ...config({ routes: [], keys: ["key-7"] }), SECRET_SCAN_DEFAULT: "off" },
      { upstreamHeaderTimeoutMs: 1000, piiKeyScope: "key-7", onPIIDecision: decision => decisions.push(decision) }, undefined, "");
    assert.equal((await result.response.json()).choices[0].message.content, email);
    assert.ok(!JSON.stringify(calls).includes(email));
    assert.deepEqual(decisions, [{ redacted: true, skipped: false, cacheable: false, replayable: false }]);
    result.cleanup();
  } finally { globalThis.fetch = previous; }
});

test("required failure never dispatches or falls back; best effort preserves payload", async () => {
  const { attemptRoleplayCandidates } = await import("../worker/roleplay/transport.mjs");
  const previous = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (_url, init) => { calls += 1; return Response.json({ content: JSON.parse(init.body).messages.map(message => message.content).join("") }); };
  const candidate = { key: "synthetic", provider: "nanogpt", model: "synthetic", token: "synthetic", endpoint: "https://example.invalid" };
  const payload = { model: "synthetic", messages: [{ content: "x".repeat(1024 * 1024 + 1) }] };
  try {
    const result = await attemptRoleplayCandidates({ stats: {} }, [candidate, candidate], () => payload,
      { ...config(), SECRET_SCAN_DEFAULT: "off" }, { upstreamHeaderTimeoutMs: 1000, preResponseFallbackEnabled: true }, undefined, "");
    assert.equal(result.terminalResponse.status, 422);
    assert.equal(calls, 0);
    const fallback = await attemptRoleplayCandidates({ stats: {} }, [candidate], () => payload,
      { ...config({ mode: "best_effort" }), SECRET_SCAN_DEFAULT: "off" }, { upstreamHeaderTimeoutMs: 1000 }, undefined, "");
    assert.equal((await fallback.response.json()).content, payload.messages[0].content);
    assert.equal(calls, 1); fallback.cleanup();
  } finally { globalThis.fetch = previous; }
});

test("abort during nonstream restoration clears state and cancels pending reader", async () => {
  const [, stream] = await modules(), result = await prepare();
  let cancelled = false;
  const controller = new AbortController();
  const body = new ReadableStream({ cancel() { cancelled = true; } }, { highWaterMark: 0 });
  const restoring = stream.rehydrateResponse(new Response(body, { headers: { "Content-Type": "application/json" } }), result.context, { signal: controller.signal });
  controller.abort();
  await assert.rejects(restoring, { name: "AbortError" });
  assert.equal(result.context.values.size, 0);
  assert.equal(cancelled, true);
});

test("restoration failure after output cannot authorize another provider", async () => {
  const { attemptRoleplayCandidates } = await import("../worker/roleplay/transport.mjs");
  const previous = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return Response.json({ content: "__MLPII_" }); };
  const candidate = { key: "synthetic", provider: "nanogpt", model: "synthetic", token: "synthetic", endpoint: "https://example.invalid" };
  try {
    const result = await attemptRoleplayCandidates({ stats: {} }, [candidate, candidate],
      () => ({ model: "synthetic", messages: [{ content: email }] }),
      { ...config(), SECRET_SCAN_DEFAULT: "off" }, { upstreamHeaderTimeoutMs: 1000, preResponseFallbackEnabled: true }, undefined, "");
    assert.equal(calls, 1);
    assert.equal(result.terminalResponse.status, 502);
    assert.equal((await result.terminalResponse.json()).error.code, "pii_rehydration_failed");
  } finally { globalThis.fetch = previous; }
});

test("parser output batches are bounded", async () => {
  const [, stream] = await modules(), result = await prepare();
  const parser = new stream.PIIStreamParser(result.context);
  const wire = new TextEncoder().encode(('data: {"content":"' + "x".repeat(1000) + '"}\n\n').repeat(1100));
  assert.throws(() => parser.feed(wire), { name: "PIIStreamError" });
  parser.close();
  assert.equal(result.context.values.size, 0);
});

test("JSON escaping, unknown tokens and carry limits", async () => {
  const [redaction, stream] = await modules();
  const context = new redaction.PIIContext(), value = 'é "quoted"\\path\n';
  const token = await context.issue(value), unknown = "__MLPII_" + "0".repeat(64) + "__";
  const response = await stream.rehydrateResponse(Response.json({ content: token + unknown }), context);
  assert.deepEqual(await response.json(), { content: value + unknown });
  const result = await prepare(), parser = new stream.PIIStreamParser(result.context);
  const partial = result.payload.messages[0].content.slice(0, 65);
  assert.throws(() => parser.feed(new TextEncoder().encode(`data: ${JSON.stringify({ choices: [0, 1].map(() => ({ delta: { content: partial } })) })}\n\n`)), { name: "PIIStreamError" });
  parser.close();
});

test("malformed policy warns once without its value", async () => {
  const [redaction] = await modules(), previous = console.warn, warnings = [];
  console.warn = message => warnings.push(message);
  try {
    const invalid = { PII_REDACTION_ENABLED: "true", PII_REDACTION_POLICY_JSON: "private-invalid-value" };
    assert.equal((await prepare(email, invalid)).context, null);
    assert.equal((await prepare(email, invalid)).context, null);
    assert.equal(warnings.length, 1);
    assert.ok(!warnings[0].includes("private-invalid-value"));
  } finally { console.warn = previous; }
});

test("secret creation and HMAC collisions obey atomic policy", async () => {
  const original = globalThis.crypto;
  try {
    Object.defineProperty(globalThis, "crypto", { configurable: true, value: {
      getRandomValues: values => original.getRandomValues(values),
      subtle: { importKey: async () => ({}), sign: async () => new Uint8Array(32).buffer },
    } });
    await assert.rejects(prepare(email + " bob@school.org"), { name: "PIIRedactionError" });
    assert.equal((await prepare(email + " bob@school.org", config({ mode: "best_effort" }))).skipped, true);
    Object.defineProperty(globalThis, "crypto", { configurable: true, value: {
      getRandomValues() { throw new Error("synthetic entropy failure"); },
    } });
    await assert.rejects(prepare(), { name: "PIIRedactionError" });
    assert.equal((await prepare(email, config({ mode: "best_effort" }))).skipped, true);
  } finally { Object.defineProperty(globalThis, "crypto", { configurable: true, value: original }); }
});

test("off, unscoped and raw transport preserves request and response identity", async () => {
  const [, stream] = await modules();
  for (const [env, options] of [[{}, { route }], [config({ routes: [] }), { route }], [config(), { route, raw: true }]]) {
    const request = new Request("https://example.invalid", { method: "POST", body: "{ invalid JSON }" });
    const response = new Response("unchanged é bytes", { headers: { "X-Synthetic": "unchanged" } });
    const output = await stream.piiFetch(request, env, options, async upstream => {
      assert.equal(upstream, request);
      assert.equal(await upstream.text(), "{ invalid JSON }");
      return response;
    });
    assert.equal(output, response);
    assert.equal(await output.text(), "unchanged é bytes");
  }
});

test("custom JSON text also withholds terminal prefixes", async () => {
  const [, stream] = await modules(), result = await prepare();
  const response = await stream.rehydrateResponse(Response.json({ custom: ["__MLPII_"] }), result.context);
  assert.equal(response.status, 502);
  assert.ok(!(await response.text()).includes("__MLPII_"));
});
