import assert from "node:assert/strict";
import test from "node:test";
import { prepareRequest, resolvePolicy, finalizeResponse, CanarySSEParser } from "../worker/context-canary.mjs";
import { TurnTraceJournal } from "../worker/roleplay/turn-trace.mjs";

const route = "/v1/roleplay/chat/completions";
const env = (mode = "log", policy = { routes: [route] }) => ({ CONTEXT_CANARY_MODE: mode,
  CONTEXT_CANARY_POLICY_JSON: JSON.stringify(policy) });
const payload = () => ({ messages: [{ role: "user", content: "fixture" }] });
const prepare = (mode = "log", options = {}) => prepareRequest(payload(), env(mode), { route, ...options });
const encoder = new TextEncoder(), decoder = new TextDecoder();
const frame = content => `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content } }] })}\n\n`;
const contents = wire => wire.split("\n").filter(line => line.startsWith("data: {")).map(line =>
  JSON.parse(line.slice(6)).choices?.[0]?.delta?.content ?? "").join("");

test("default, empty, no opt-in and raw preserve payload and response identity", async () => {
  for (const settings of [{}, env("off"), env(""), env("log", {}), env("log", { keys: ["other"] })]) {
    const body = payload(), item = await prepareRequest(body, settings, { route });
    assert.equal(item.payload, body); assert.equal(item.context, null);
    const response = new Response("fixture");
    assert.equal(await finalizeResponse(response, item.context), response);
  }
  const body = payload();
  assert.equal((await prepareRequest(body, env(), { route, raw: true })).payload, body);
});

test("strict settings disable once without disclosing their values", () => {
  for (const policy of [[], null, { routes: route }, { keys: [2] }, { routes: [""] }, { default: true }]) {
    const warnings = [], warn = value => warnings.push(value);
    for (let i = 0; i < 2; i++) assert.equal(resolvePolicy(env("log", policy), { route, warn }), null);
    assert.ok(warnings.length <= 1);
    assert.ok(!warnings.join().includes(JSON.stringify(policy)));
  }
  assert.equal(resolvePolicy(env("private-invalid"), { route, warn: () => {} }), null);
  assert.equal(resolvePolicy({ CONTEXT_CANARY_MODE: "log", CONTEXT_CANARY_POLICY_JSON: "" }, { route }), null);
});

test("per-key opt-in and concurrent request-specific HMAC markers", async () => {
  const body = payload();
  const a = await prepareRequest(body, env("log", { keys: ["key-7"] }), { keyScope: "key-7" });
  const b = await prepare();
  assert.match(a.context.marker, /^[0-9a-f]{32}$/); assert.notEqual(a.context.marker, b.context.marker);
  assert.equal(body.messages.length, 1); assert.equal(a.payload.messages[0].role, "system");
  assert.match(a.payload.messages[0].content, /Gateway context canary/);
  assert.equal(a.context.scanner().feed(b.context.marker, true), b.context.marker);
});

test("every marker split, bounded carry, one digest-only event and false prefixes", async () => {
  const events = [], item = await prepare("log", { traceId: "trace-7", record: e => events.push(e) });
  for (let split = 0; split <= 32; split++) {
    const scan = item.context.scanner();
    const before = scan.feed("é before " + item.context.marker.slice(0, split));
    assert.ok(scan.carry.length < 32);
    assert.equal(before + scan.feed(item.context.marker.slice(split) + " after", true), "é before  after");
  }
  assert.deepEqual(events, [{ digest: item.context.digest, rule: "context_canary_leak", traceId: "trace-7" }]);
  assert.ok(!JSON.stringify(events).includes(item.context.marker));
  assert.equal(item.context.scanner().feed(item.context.marker.repeat(5), true), "");
  const scan = item.context.scanner(); scan.feed(item.context.marker.slice(0, 12));
  assert.equal(scan.feed("!", true), item.context.marker.slice(0, 12) + "!");
});

test("nonstream log strips JSON-escaped marker; block cancels and keeps cost hold", async () => {
  for (const mode of ["log", "block"]) {
    const item = await prepare(mode), accounting = { ambiguous: false }, controller = new AbortController();
    let cancelled = 0;
    const response = await finalizeResponse(Response.json({ content: "before " + item.context.marker + " after" }),
      item.context, { controller, accounting, cancel: () => cancelled++ });
    assert.equal(response.status, mode === "block" ? 502 : 200);
    const data = await response.text(); assert.ok(!data.includes(item.context.marker));
    if (mode === "block") {
      assert.equal(JSON.parse(data).error.code, "context_canary_leak");
      assert.ok(controller.signal.aborted && accounting.ambiguous); assert.equal(cancelled, 1);
    } else assert.equal(JSON.parse(data).content, "before  after");
    assert.ok(item.context.closed);
  }
});

test("every SSE read, event and UTF8 split removes the marker", async () => {
  const item = await prepare();
  for (let split = 1; split < 32; split++) {
    const bytes = encoder.encode(frame("é " + item.context.marker.slice(0, split)) +
      frame(item.context.marker.slice(split) + " tail") + "data: [DONE]\n\n");
    for (let cut = 1; cut < bytes.length; cut++) {
      const parser = new CanarySSEParser(item.context);
      const output = decoder.decode(parser.feed(bytes.slice(0, cut))) + decoder.decode(parser.feed(bytes.slice(cut), true));
      assert.equal(contents(output), "é  tail"); assert.ok(!output.includes(item.context.marker));
    }
  }
});

test("terminal false prefix flushes before DONE and structure/frame limits fail closed", async () => {
  const item = await prepare();
  const output = decoder.decode(new CanarySSEParser(item.context).feed(encoder.encode(
    frame(item.context.marker.slice(0, 9)) + "data: [DONE]\n\n"), true));
  assert.equal(contents(output), item.context.marker.slice(0, 9)); assert.ok(output.endsWith("data: [DONE]\n\n"));
  assert.throws(() => new CanarySSEParser(item.context).feed(encoder.encode("data: " + "x".repeat(65537))));
});

test("precommit block returns 502, late block sends a real error without DONE", async () => {
  for (const late of [false, true]) {
    const item = await prepare("block"), accounting = { ambiguous: false }, controller = new AbortController();
    const chunks = [...(late ? [frame("safe first")] : []), frame(item.context.marker)];
    let cancelled = 0;
    const body = new ReadableStream({ pull(c) { c.enqueue(encoder.encode(chunks.shift())); }, cancel() { cancelled++; } }, { highWaterMark: 0 });
    const result = await finalizeResponse(new Response(body, { headers: { "Content-Type": "text/event-stream" } }),
      item.context, { controller, accounting });
    assert.equal(result.status, late ? 200 : 502);
    const text = await result.text(); assert.ok(!text.includes(item.context.marker));
    assert.ok(text.includes('"code":"context_canary_leak"')); assert.ok(!text.includes("[DONE]"));
    if (late) assert.ok(text.includes("safe first"));
    assert.ok(accounting.ambiguous && controller.signal.aborted); assert.equal(cancelled, 1);
  }
});

test("abort and client cancellation close upstream and keep ambiguous spend", async () => {
  const item = await prepare(), accounting = { ambiguous: false }, signal = new AbortController();
  let cancelled = 0;
  const body = new ReadableStream({ cancel() { cancelled++; } }, { highWaterMark: 0 });
  const work = finalizeResponse(new Response(body), item.context, { signal: signal.signal, accounting });
  signal.abort(); await assert.rejects(work, { name: "AbortError" });
  assert.equal(cancelled, 1); assert.ok(item.context.closed && accounting.ambiguous);
});

test("zero-retention traces keep only validated digest, rule and trace ID", async () => {
  const writes = [], journal = new TurnTraceJournal({ get: async () => [], put: async (...args) => writes.push(args) });
  await journal.ready;
  const trace = journal.begin({ enabled: true, mode: "zero" });
  const item = await prepare("log", { traceId: trace.id, record: event => trace.canary(event) });
  item.context.scanner().feed(item.context.marker, true);
  trace.canary({ digest: "unsafe marker", rule: "content", traceId: trace.id });
  await trace.finish(true, "complete");
  assert.deepEqual(journal.snapshot().records[0].canary, { digest: item.context.digest,
    rule: "context_canary_leak", traceId: trace.id });
  assert.ok(!JSON.stringify(writes).includes(item.context.marker));
  assert.equal(writes[0][0], "zero-turn-traces-v1");
});

test("marker completion in a terminal delta cannot release the held prefix", async () => {
  const item = await prepare();
  const end = `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: item.context.marker.slice(10) + " tail" }, finish_reason: "stop" }] })}\n\n`;
  const parser = new CanarySSEParser(item.context);
  const wire = decoder.decode(parser.feed(encoder.encode(frame("head " + item.context.marker.slice(0, 10)) + end + "data: [DONE]\n\n"), true));
  assert.equal(contents(wire), "head  tail"); assert.ok(!wire.includes(item.context.marker));
});

// Map the owned module in memory; the shared test-loader registration is separate.
async function roleplayFixture() {
  const { readFile } = await import("node:fs/promises");
  const helperUrl = new URL("./helpers/load_cloudflare_worker.mjs", import.meta.url);
  const moduleUrl = new URL("../worker/context-canary.mjs", import.meta.url).href;
  const helper = (await readFile(helperUrl, "utf8")).replaceAll("import.meta.url", JSON.stringify(helperUrl.href))
    .replace("const patchedEndpoint = endpointSource", `const patchedEndpoint = endpointSource.replace('from "../context-canary.mjs";', 'from "${moduleUrl}";')`);
  const dataUrl = "data:text/javascript;base64," + Buffer.from(helper).toString("base64");
  const fixture = (await readFile(new URL("./helpers/roleplay_fixture.mjs", import.meta.url), "utf8"))
    .replace('from "./load_cloudflare_worker.mjs";', `from "${dataUrl}";`);
  return import("data:text/javascript;base64," + Buffer.from(fixture).toString("base64"));
}

test("managed roleplay dispatch strips reflected marker, blocks without retry, and retains no annotation", async () => {
  const { makeRoleplayEnv, roleplayRequest, withGlobalFetch, handleRoleplayEdgeRequest } = await roleplayFixture();
  for (const mode of ["off", "log", "block"]) {
    const fixture = makeRoleplayEnv({ ...env(mode), CONTENT_RETENTION_ENABLED: "true",
      CONTENT_RETENTION_POLICY_JSON: '{"default":"zero"}', SECRET_SCAN_DEFAULT: "off" });
    let calls = 0, marker = "", annotation = "";
    await withGlobalFetch(async (_url, init) => {
      calls++;
      const body = JSON.parse(init.body);
      annotation = body.messages.find(message => message.content?.startsWith("[Gateway context canary]"))?.content ?? "";
      marker = /marker: ([0-9a-f]{32})/.exec(annotation)?.[1] ?? "";
      assert.equal(Boolean(marker), mode !== "off");
      return Response.json({ choices: [{ message: { role: "assistant", content: "safe " + marker + " tail" }, finish_reason: "stop" }] });
    }, async () => {
      const response = await handleRoleplayEdgeRequest(roleplayRequest({ session_id: "canary-" + mode,
        model: "roleplay:glm", stream: false, messages: [{ role: "user", content: "fixture" }], memory: { mode: "off" } }), fixture.env);
      assert.equal(response.status, mode === "block" ? 502 : 200);
      const text = await response.text();
      if (mode === "block") assert.equal(JSON.parse(text).error.code, "context_canary_leak");
      if (marker) assert.ok(!text.includes(marker));
      await fixture.waitForBackgroundWork();
      for (const { storage } of fixture.storageBySession.values()) {
        const stored = JSON.stringify([...storage.values]);
        if (marker) assert.ok(!stored.includes(marker));
        if (annotation) assert.ok(!stored.includes(annotation));
      }
    });
    assert.equal(calls, 1);
  }
});

test("roleplay stream detects early and late leakage before content storage", async () => {
  const { makeRoleplayEnv, roleplayRequest, withGlobalFetch, handleRoleplayEdgeRequest } = await roleplayFixture();
  for (const late of [false, true]) {
    const fixture = makeRoleplayEnv({ ...env("block"), SECRET_SCAN_DEFAULT: "off", ROLEPLAY_STREAM_HEARTBEAT_MS: "5000" });
    let marker, cancelCount = 0, calls = 0;
    await withGlobalFetch(async (_url, init) => {
      calls++;
      const annotation = JSON.parse(init.body).messages.find(message => message.content?.startsWith("[Gateway context canary]")).content;
      marker = /marker: ([0-9a-f]{32})/.exec(annotation)[1];
      const chunks = [...(late ? [frame("safe first")] : []), frame(marker)];
      const body = new ReadableStream({ pull(c) {
        if (chunks.length) c.enqueue(encoder.encode(chunks.shift())); else c.close();
      }, cancel() { cancelCount++; } }, { highWaterMark: 0 });
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    }, async () => {
      const response = await handleRoleplayEdgeRequest(roleplayRequest({ session_id: "canary-stream-" + late,
        model: "roleplay:glm", stream: true, messages: [{ role: "user", content: "fixture" }] }), fixture.env);
      assert.equal(response.status, late ? 200 : 502);
      const text = await response.text();
      assert.ok(text.includes('"code":"context_canary_leak"')); assert.ok(!text.includes(marker));
      if (late) assert.ok(text.includes("safe first"));
      assert.ok(!text.includes("[DONE]")); await fixture.waitForBackgroundWork();
      for (const { storage } of fixture.storageBySession.values()) assert.ok(!JSON.stringify([...storage.values]).includes(marker));
    });
    assert.equal(calls, 1); assert.equal(cancelCount, 1);
  }
});

test("protocol-specific system annotations preserve supplied instructions", async () => {
  for (const [protocol, body, field] of [["messages", { system: "original", messages: [] }, "system"],
    ["responses", { instructions: "original", input: "fixture" }, "instructions"]]) {
    const item = await prepareRequest(body, env(), { route, protocol });
    assert.ok(item.payload[field].endsWith("\noriginal")); assert.equal(body[field], "original");
  }
});

test("interleaved choices and tool lanes retain independent bounded prefixes", async () => {
  const item = await prepare(), parser = new CanarySSEParser(item.context);
  const choice = (index, content) => `data: ${JSON.stringify({ choices: [{ index, delta: { content } }] })}\n\n`;
  const wire = choice(0, "head " + item.context.marker.slice(0, 12)) + choice(1, "other choice") +
    choice(0, item.context.marker.slice(12) + " tail") + "data: [DONE]\n\n";
  const text = decoder.decode(parser.feed(encoder.encode(wire), true));
  const values = text.split("\n").filter(line => line.startsWith("data: {")).map(line => JSON.parse(line.slice(6)).choices[0]);
  assert.equal(values.filter(choice => choice.index === 0).map(choice => choice.delta.content).join(""), "head  tail");
  assert.equal(values.filter(choice => choice.index === 1).map(choice => choice.delta.content).join(""), "other choice");
});

test("JSON unicode escapes and multiple SSE data lines are decoded before scanning", async () => {
  const item = await prepare();
  const escaped = [...item.context.marker].map(char => "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0")).join("");
  const output = await finalizeResponse(new Response('{"content":"' + escaped + '"}',
    { headers: { "content-type": "application/json" } }), item.context);
  assert.equal((await output.json()).content, "");
  const stream = await prepare();
  const wire = `event: message\ndata: {"choices":\ndata: [{"index":0,"delta":{"content":"${stream.context.marker}"}}]}\n\ndata: [DONE]\n\n`;
  assert.ok(!decoder.decode(new CanarySSEParser(stream.context).feed(encoder.encode(wire), true)).includes(stream.context.marker));
});

test("annotation capacity is checked for candidate paging and refit views", async () => {
  const { prepareCanaryCandidates, protectRoleplayContinuation } = await import("../worker/context-canary.mjs");
  const item = await prepare("block"), candidate = { contextWindow: 8, resolvedMaxOutputTokens: 4,
    contextPlan: { messages: payload().messages, estimatedInputTokens: 1, pages: [] } };
  const estimate = value => Math.ceil(encoder.encode(JSON.stringify(value)).length / 4);
  assert.deepEqual(prepareCanaryCandidates([candidate], item.context, [], estimate, { contextSafetyTokens: 0 }), []);
  assert.equal(item.context.messages(item.payload.messages).length, item.payload.messages.length);
  let cancelled = 0;
  const continuation = { openResponse: async () => ({ response: Response.json({ content: item.context.marker }),
    controller: new AbortController(), cleanup: () => cancelled++ }) };
  protectRoleplayContinuation(continuation, item.context);
  await assert.rejects(continuation.openResponse({}), { code: "context_canary_leak" });
  assert.equal(cancelled, 1);
});

test("SSE comments and event labels cannot disclose a complete marker", async () => {
  const item = await prepare();
  const wire = `event: ${item.context.marker}\n: ${item.context.marker}\n` + frame("safe");
  const result = decoder.decode(new CanarySSEParser(item.context).feed(encoder.encode(wire), true));
  assert.ok(!result.includes(item.context.marker)); assert.equal(contents(result), "safe");
});


test("DONE comments are scanned and a different choice finish retains its prefix", async () => {
  const item = await prepare();
  const done = `: ${item.context.marker}\ndata: [DONE]\n\n`;
  assert.ok(!decoder.decode(new CanarySSEParser(item.context).feed(encoder.encode(done), true)).includes(item.context.marker));
  const next = await prepare();
  const events = [{ choices: [{ index: 1, delta: { content: next.context.marker.slice(0, 12) } }] },
    { choices: [{ index: 0, delta: { content: "safe" }, finish_reason: "stop" }] },
    { choices: [{ index: 1, delta: { content: next.context.marker.slice(12) }, finish_reason: "stop" }] }];
  const wire = events.map(event => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n";
  const result = decoder.decode(new CanarySSEParser(next.context).feed(encoder.encode(wire), true));
  const values = result.split("\n").filter(line => line.startsWith("data: {")).map(line => JSON.parse(line.slice(6)).choices[0]);
  assert.equal(values.filter(choice => choice.index === 1).map(choice => choice.delta.content).join(""), "");
});
