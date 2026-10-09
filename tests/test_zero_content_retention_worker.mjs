import assert from "node:assert/strict";
import test from "node:test";
import { resolveRetentionPolicy, retentionAllowsContent, retentionKnowledgeOptions } from "../worker/retention-policy.mjs";
import { createInitialRoleplayState, saveRoleplayState, createRetentionStateRepository } from "../worker/roleplay/session-storage.mjs";
import { recoveryTemplate, preserveRecovery, handleRecoverySnapshot } from "../worker/roleplay/recovery.mjs";
import { TurnTraceJournal } from "../worker/roleplay/turn-trace.mjs";
import { memoSession } from "../worker/knowledge/memos.mjs";
import { HandoffStore } from "../worker/knowledge/handoff-store.mjs";
import { makeRoleplayEnv, completionResponse, handleRoleplayEdgeRequest, roleplayRequest, withGlobalFetch } from "./helpers/roleplay_fixture.mjs";

const enabled = { CONTENT_RETENTION_ENABLED: "true" };
const zero = resolveRetentionPolicy(enabled, { header: "zero" });
const normal = resolveRetentionPolicy({});
const storage = () => ({ rows: new Map(), writes: [], async get(key) { return this.rows.get(key); },
  async put(key, value) { this.writes.push(structuredClone([key, value])); }, async delete() { assert.fail("deletion"); } });

test("disabled and invalid settings ignore header without retaining configuration values in logs", () => {
  for (const flag of [undefined, "", "false", "nonsense"]) {
    assert.equal(resolveRetentionPolicy({ CONTENT_RETENTION_ENABLED: flag }, { header: "zero" }).mode, "inherit");
  }
  const warn = console.warn; const warnings = []; console.warn = value => warnings.push(value);
  try {
    for (const raw of ["{", "[]", '{"default":"bad"}', '{"keys":[]}', '{"routes":{"/chat":5}}']) {
      assert.equal(resolveRetentionPolicy({ ...enabled, CONTENT_RETENTION_POLICY_JSON: raw }, { header: "zero" }).enabled, false);
    }
  } finally { console.warn = warn; }
  assert.ok(warnings.length <= 1);
});

test("key and route restrictions cannot be loosened and captured policy is immutable", () => {
  const env = { ...enabled, CONTENT_RETENTION_POLICY_JSON: JSON.stringify({ keys: { reader: "zero" }, routes: { "/private": "zero" } }) };
  for (const identity of [{ keyId: "reader", route: "/chat" }, { keyId: "other", route: "/private" }]) {
    assert.equal(resolveRetentionPolicy(env, { ...identity, header: "inherit" }).mode, "zero");
  }
  assert.equal(retentionAllowsContent(zero), false);
  assert.equal(retentionAllowsContent(normal), true);
  assert.throws(() => { zero.mode = "inherit"; }, TypeError);
});

test("zero state writes contain only counters and preserve previous content without using the content cache", async () => {
  const s = storage(); s.rows.set("roleplay-messages", [{ content: "old content" }]);
  const state = { ...createInitialRoleplayState(), messages: [{ content: "private prompt" }], memory: "private memory", profile: { name: "private name" }, turns: 4 };
  const repo = createRetentionStateRepository(s, { load() { assert.fail("content cache"); }, save() { assert.fail("content cache"); } }, zero);
  assert.deepEqual((await repo.load()).messages, []);
  await repo.save(state, { private: "private trace" });
  await saveRoleplayState(s, state, null, { private: "private metadata" }, zero);
  assert.equal(s.rows.get("roleplay-messages")[0].content, "old content");
  assert.doesNotMatch(JSON.stringify(s.writes), /private|old content/);
  assert.match(JSON.stringify(s.writes), /"turns":4/);
});

test("zero retains numeric model and security counts under hashed identities", async () => {
  const s = storage();
  s.put = async (key, value) => { s.writes.push([key, structuredClone(value)]); s.rows.set(key, structuredClone(value)); };
  const candidates = [{ key: "private candidate identity", provider: "fixture", model: "fixture-model", family: "fixture" }];
  const repo = createRetentionStateRepository(s, null, zero, candidates);
  await repo.save({ ...createInitialRoleplayState(), stats: { "private candidate identity": {
    attempts: 4, successes: 3, failures: 1, completionTokens: 10, consecutiveFailures: 1,
    cooldownUntil: 1000, private: "private response", ttfbSamplesMs: [5, "private sample"],
  } } });
  assert.doesNotMatch(JSON.stringify(s.writes), /private|completionTokens/);
  assert.match(JSON.stringify(s.writes), /"attempts":4/);
  const loaded = await repo.load();
  assert.equal(loaded.stats[candidates[0].key].attempts, 4);
  assert.deepEqual(loaded.stats[candidates[0].key].ttfbSamplesMs, [5]);
});

test("zero trace keeps numeric metrics but excludes parameter content before queuing", async () => {
  const s = storage(); const journal = new TurnTraceJournal(s); await journal.ready;
  const trace = journal.begin(zero);
  trace.selected({ provider: "fixture", model: "fixture-model" }, { private: "private parameters" });
  trace.metrics({ completionTokens: 3 });
  await trace.finish(true, "completed", () => assert.fail("content persistence callback"));
  assert.doesNotMatch(JSON.stringify(s.writes), /private/);
  assert.doesNotMatch(JSON.stringify(s.writes), /fixture-model|"provider"|"model"/);
  assert.match(JSON.stringify(s.writes), /completionTokens/);
});

test("zero recovery rejects before reads, construction or writes and preserves old snapshots", async () => {
  const s = storage(); s.rows.set("operator_recovery_v1", { partial: "old content" });
  assert.equal(recoveryTemplate({ recovery_enabled: true }, [{ content: "private prompt" }], zero), null);
  await preserveRecovery(s, { private: "private template" }, { success: false, assistant: "private answer" }, "fixture", zero);
  const response = await handleRecoverySnapshot({ ctx: { storage: s } }, new Request("https://roleplay.internal/operator/recovery", { method: "POST" }), zero);
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error.code, "recovery_unavailable");
  assert.equal(s.writes.length, 0);
  assert.equal(s.rows.get("operator_recovery_v1").partial, "old content");
});

test("zero Knowledge blocks memo construction, embedding and queue registration; usage survives", async () => {
  const usage = [{ provider: "fixture", bound_units: 1 }];
  const options = { retentionPolicy: zero, memos: { call() { assert.fail("memo persistence"); } },
    embed() { assert.fail("embedding"); }, waitUntil() { assert.fail("queued content"); } };
  const session = memoSession(enabled, { call() { assert.fail("validation"); } }, { query: "private prompt" }, {}, options, performance.now(), usage);
  assert.deepEqual(await session.lookup(), {});
  await session.write({ status: "ok", excerpts: [{ text: "private answer" }] });
  await session.storeBundle({ private: "private answer" });
  assert.deepEqual(session.finish({}).usage, usage);
  const isolated = retentionKnowledgeOptions(zero, options);
  assert.equal(await isolated.cache.match("fixture"), undefined);
  await isolated.cache.put("fixture", new Response("private answer"));
  assert.equal(retentionKnowledgeOptions(normal, options), options);
});

test("zero handoff refuses before parse or SQL mutation without fake saved IDs", () => {
  const s = { sql: { exec() { return []; } }, transactionSync() { assert.fail("persistence"); } };
  const store = new HandoffStore(s);
  assert.throws(() => store.call("save", { private: "private input" }, Date.now(), zero), error => error.code === "retention_forbidden");
  assert.throws(() => store.save({ private: "private input" }, Date.now(), zero), error => error.code === "retention_forbidden");
});

const turn = { model: "roleplay:auto", messages: [{ role: "user", content: "private scene" }],
  memory: { mode: "off" }, history_mode: "replace", recovery_enabled: true, stream: false };

test("native public roleplay global zero preserves old records and exposes unavailable recovery", async () => {
  const f = makeRoleplayEnv({ ...enabled, CONTENT_RETENTION_POLICY_JSON: '{"default":"zero"}' });
  const reply = await withGlobalFetch(async () => completionResponse("fixture", "private reply"),
    () => handleRoleplayEdgeRequest(roleplayRequest(turn), f.env));
  assert.equal(reply.status, 200);
  assert.equal(reply.headers.get("X-MultiLLM-Retention"), "zero");
  assert.equal(reply.headers.get("X-MultiLLM-Roleplay-Recovery"), "unavailable");
  assert.match(await reply.text(), /private reply/);
  await f.waitForBackgroundWork();
  const entry = [...f.storageBySession.values()][0];
  assert.equal(entry.instance.stateRepository.loaded, false);
  assert.doesNotMatch(JSON.stringify([...entry.storage.values]), /private scene|private reply/);
  assert.equal(entry.storage.operations.setAlarm, 0);
});

test("internal zero header survives streaming completion after config changes without persisting content", async () => {
  const f = makeRoleplayEnv(enabled);
  const stub = f.env.ROLEPLAY_SESSION.getByName("fixture");
  const entry = f.storageBySession.get("fixture");
  entry.storage.values.set("roleplay-messages", [{ role: "user", content: "old content" }]);
  entry.storage.values.set("operator_recovery_v1", { partial: "old partial" });
  const frames = 'data: {"choices":[{"delta":{"content":"private reply"}}]}\n\n'
    + 'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"completion_tokens":3}}\n\n'
    + 'data: [DONE]\n\n';
  const reply = await withGlobalFetch(async () => new Response(frames, { headers: { "content-type": "text/event-stream" } }),
    () => stub.fetch(new Request("https://roleplay.internal/turn", { method: "POST",
      headers: { "X-MultiLLM-Retention": "zero", "Idempotency-Key": "private request identity" },
      body: JSON.stringify({ ...turn, stream: true }) })));
  assert.equal(reply.status, 200);
  f.env.CONTENT_RETENTION_ENABLED = "false";
  assert.match(await reply.text(), /private reply/);
  await f.waitForBackgroundWork();
  assert.deepEqual(entry.storage.values.get("roleplay-messages"), [{ role: "user", content: "old content" }]);
  assert.equal(entry.storage.values.get("operator_recovery_v1").partial, "old partial");
  const retained = [...entry.storage.values].filter(([key]) => key !== "roleplay-messages" && key !== "operator_recovery_v1");
  assert.doesNotMatch(JSON.stringify(retained), /private scene|private reply|private request identity/);
  assert.match(JSON.stringify(retained), /completionTokens/);
  assert.equal(entry.instance.stateRepository.loaded, false);
});

test("zero provider failure and aborted requests never make conversation or recovery writes", async () => {
  const f = makeRoleplayEnv({ ...enabled, CONTENT_RETENTION_POLICY_JSON: '{"default":"zero"}' });
  const stub = f.env.ROLEPLAY_SESSION.getByName("fixture");
  const response = await withGlobalFetch(async () => Response.json({ error: "private failure" }, { status: 400 }),
    () => stub.fetch(new Request("https://roleplay.internal/turn", { method: "POST", body: JSON.stringify(turn) })));
  assert.equal(response.status, 400);
  const controller = new AbortController(); controller.abort();
  const cancelled = await stub.fetch(new Request("https://roleplay.internal/turn", {
    method: "POST", body: JSON.stringify(turn), signal: controller.signal }));
  assert.equal(cancelled.status, 499);
  await f.waitForBackgroundWork();
  assert.doesNotMatch(JSON.stringify([...f.storageBySession.get("fixture").storage.values]), /private scene|private failure/);
});

test("queued normal and zero turns keep independent policies and conversation state", async () => {
  const f = makeRoleplayEnv(enabled);
  const stub = f.env.ROLEPLAY_SESSION.getByName("fixture");
  const seen = [];
  await withGlobalFetch(async (_url, init) => {
    const payload = JSON.parse(init.body); seen.push(payload.messages);
    if (payload.stream) return new Response('data: {"choices":[{"delta":{"content":"private reply"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
      { headers: { "content-type": "text/event-stream" } });
    return completionResponse("fixture", "ordinary reply");
  }, async () => {
    const privateReply = await stub.fetch(new Request("https://roleplay.internal/turn", { method: "POST",
      headers: { "X-MultiLLM-Retention": "zero" }, body: JSON.stringify({ ...turn, stream: true }) }));
    const ordinary = stub.fetch(new Request("https://roleplay.internal/turn", { method: "POST",
      headers: { "X-MultiLLM-Retention": "inherit" }, body: JSON.stringify({ ...turn, memory: { mode: "auto" },
        messages: [{ role: "user", content: "ordinary scene" }] }) }));
    await privateReply.text();
    const reply = await ordinary;
    assert.equal(reply.headers.get("X-MultiLLM-Retention"), null);
    assert.equal(reply.status, 200);
    await reply.text();
    await f.waitForBackgroundWork();
  });
  assert.equal(seen.length, 2);
  assert.doesNotMatch(JSON.stringify(seen[1]), /private scene|private reply/);
  const stored = [...f.storageBySession.get("fixture").storage.values];
  assert.doesNotMatch(JSON.stringify(stored), /private scene|private reply/);
  assert.match(JSON.stringify(stored), /ordinary scene|ordinary reply/);
});

test("zero repeated request identities remain hashed and cannot silently replay", async () => {
  const f = makeRoleplayEnv({ ...enabled, CONTENT_RETENTION_POLICY_JSON: '{"default":"zero"}' });
  const stub = f.env.ROLEPLAY_SESSION.getByName("fixture");
  let dispatched = 0;
  const request = () => new Request("https://roleplay.internal/turn", { method: "POST",
    headers: { "Idempotency-Key": "private identity" }, body: JSON.stringify(turn) });
  await withGlobalFetch(async () => { dispatched++; return completionResponse("fixture"); }, async () => {
    assert.equal((await stub.fetch(request())).status, 200);
    assert.equal((await stub.fetch(request())).status, 409);
  });
  assert.equal(dispatched, 1);
  assert.doesNotMatch(JSON.stringify([...f.storageBySession.get("fixture").storage.values]), /private identity|private scene/);
});

test("zero operator memory rejects before storage and disabled requests keep durable state", async () => {
  const f = makeRoleplayEnv({ ...enabled, CONTENT_RETENTION_POLICY_JSON: '{"default":"zero"}' });
  const stub = f.env.ROLEPLAY_SESSION.getByName("fixture");
  const blocked = await stub.fetch(new Request("https://roleplay.internal/operator/import-branch", {
    method: "POST", body: JSON.stringify({ content: "private branch" }) }));
  assert.equal(blocked.status, 409);
  assert.equal(f.storageBySession.get("fixture").storage.operations.put, 0);
  f.env.CONTENT_RETENTION_ENABLED = "false";
  const reply = await withGlobalFetch(async () => completionResponse("fixture", "ordinary reply"),
    () => stub.fetch(new Request("https://roleplay.internal/turn", { method: "POST", headers: { "X-MultiLLM-Retention": "zero" },
      body: JSON.stringify({ ...turn, memory: { mode: "auto" }, messages: [{ role: "user", content: "ordinary scene" }] }) })));
  assert.equal(reply.status, 200);
  assert.equal(reply.headers.get("X-MultiLLM-Retention"), null);
  assert.equal(reply.headers.get("X-MultiLLM-Roleplay-Recovery"), null);
  assert.match(JSON.stringify([...f.storageBySession.get("fixture").storage.values]), /ordinary scene|ordinary reply/);
});
