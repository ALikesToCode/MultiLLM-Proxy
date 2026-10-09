import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { SessionTierPolicy, sessionTierSettings, parseSessionTier } from "../worker/roleplay/session-tier-policy.mjs";
import { parseRoutingPolicy } from "../worker/roleplay/routing-policy.mjs";
import { completionResponse, makeRoleplayEnv, roleplayRequest, handleRoleplayEdgeRequest,
  withGlobalFetch } from "./helpers/roleplay_fixture.mjs";

const MIGRATION = "0021_session_tiers.sql";
const a = { provider: "opencode", model: "a", key: "opencode:a" };
const b = { provider: "opencode", model: "b", key: "opencode:b" };
const f = { provider: "other", model: "a", key: "other:a" };
const user = [{ role: "user", content: "private prompt" }];
function fixture() {
  const rows = new Map();
  const storage = { async get(k) { return structuredClone(rows.get(k)); },
    async put(k, v) { rows.set(k, structuredClone(v)); }, async delete(k) { rows.delete(k); } };
  const policy = new SessionTierPolicy(storage, { enabled: true, ttlSeconds: 1800 }, () => 100);
  return { policy, rows };
}
function start(policy, options = {}) {
  return policy.begin({ lane: "main", approved_model: "opencode:a", approved_tier: 1 }, [a, b, f], user, "r1", options);
}

test("default, empty and malformed settings disable without content logging", () => {
  for (const value of [undefined, "", "off", "private"]) assert.equal(sessionTierSettings({ SESSION_TIER_MODE: value }).enabled, false);
  assert.equal(sessionTierSettings({ SESSION_TIER_MODE: "sticky", SESSION_TIER_TTL_SECONDS: "" }).ttlSeconds, 1800);
  assert.equal(sessionTierSettings({ SESSION_TIER_MODE: "sticky", SESSION_TIER_TTL_SECONDS: "0" }).enabled, false);
});

test("routing defaults unchanged and explicit metadata validated only when enabled", () => {
  assert.deepEqual(parseRoutingPolicy(), { mode: "provider-priority", provider: "", model: "", billing: "configured", fallback: "safe" });
  assert.throws(() => parseRoutingPolicy({ session_tier: {} }));
  const tier = { lane: "main", approved_model: "opencode:a", approved_tier: 1 };
  assert.deepEqual(parseRoutingPolicy({ session_tier: tier }, { sessionTierEnabled: true }).session_tier, tier);
  for (const value of [{ ...tier, lane: "unknown" }, { ...tier, approved_tier: true }, { ...tier, extra: "private" }]) assert.throws(() => parseSessionTier(value));
});

test("role lanes isolated and tool loop changes only after complete matching results", async () => {
  const { policy } = fixture();
  let t = await start(policy);
  await t.finish(a, { success: true, toolCalls: [{ id: "one" }, { id: "two" }] });
  const delegation = await policy.begin({ lane: "delegation", approved_model: "opencode:b", approved_tier: 2 }, [a, b], user, "r1");
  assert.deepEqual(delegation.candidates, [b]);
  const changed = { lane: "main", approved_model: "opencode:b", approved_tier: 2 };
  t = await policy.begin(changed, [b, a], [{ role: "tool", tool_call_id: "one", content: "result" }, ...user], "r1");
  assert.deepEqual(t.candidates, [a]);
  await t.finish(a, { success: true });
  t = await policy.begin(changed, [b, a], [{ role: "tool", tool_call_id: "wrong", content: "result" }, ...user], "r1");
  assert.deepEqual(t.candidates, [a]);
  await t.finish(a, { success: true });
  t = await policy.begin(changed, [b, a], [{ role: "tool", tool_call_id: "two", content: "result" }, ...user], "r1");
  assert.deepEqual(t.candidates, [b]);
});

test("honest fallback keeps approved tier and model; cooldown and grants win", async () => {
  const { policy, rows } = fixture();
  let t = await start(policy);
  await t.finish(f, { success: true });
  assert.equal([...rows.values()][0].actual_model, "other:a");
  t = await start(policy);
  assert.deepEqual(t.candidates, [f, a]);
  await t.finish(f, { success: true });
  t = await policy.begin({ lane: "main", approved_model: "opencode:a", approved_tier: 1 }, [a, b, f], user, "r1", { unavailable: c => c === a });
  assert.deepEqual(t.candidates, [f]);
  await t.finish(f, { success: true });
  await assert.rejects(policy.begin({ lane: "main", approved_model: "opencode:a", approved_tier: 1 }, [b], user, "r1"), e => e.status === 503);
});

test("expiry, revision and credential failure invalidate narrowly; no content retained", async () => {
  const { policy, rows } = fixture();
  let t = await start(policy);
  await t.finish(a, { success: true, toolCalls: [{ id: "private call", function: { arguments: "private args" } }] });
  assert.doesNotMatch(JSON.stringify([...rows]), /private/);
  policy.clock = () => 1900;
  t = await start(policy);
  assert.deepEqual(t.row.pending_tools, []);
  await t.finish(a, { success: true });
  t = await policy.begin({ lane: "main", approved_model: "opencode:b", approved_tier: 2 }, [b], user, "r2");
  assert.deepEqual(t.candidates, [b]);
  await t.finish(null, { success: false, credentialFailed: true });
  assert.equal(rows.size, 0);
});

test("concurrent or aborted turns cannot create a safe turn or overwrite newer lease", async () => {
  const { policy, rows } = fixture();
  const t = await start(policy);
  await assert.rejects(start(policy), e => e.code === "session_tier_busy");
  policy.clock = () => 1900;
  const newer = await start(policy);
  await t.finish(f, { success: true });
  assert.equal([...rows.values()][0].lease, newer.row.lease);
  await newer.finish(a, { success: false });
  const changed = await policy.begin({ lane: "main", approved_model: "opencode:b", approved_tier: 2 }, [a, b], user, "r1");
  assert.deepEqual(changed.candidates, [a]);
});

test("disabled storage untouched; enabled unavailable storage fails closed", async () => {
  const storage = { async get() { throw new Error("private storage failure"); } };
  const disabled = new SessionTierPolicy(storage, { enabled: false });
  assert.equal(await start(disabled), null);
  const enabled = new SessionTierPolicy(storage, { enabled: true, ttlSeconds: 1800 });
  await assert.rejects(start(enabled), e => e.code === "session_tier_storage_unavailable" && e.status === 503 && !e.message.includes("private"));
  assert.match(readFileSync(new URL(`../intelligence-migrations/${MIGRATION}`, import.meta.url), "utf8"), /CREATE TABLE IF NOT EXISTS session_tiers/);
});

const approval = (model = "glm-5.3", lane = "main", tier = 2) => ({
  lane, approved_model: `opencode:${model}`, approved_tier: tier,
});
const body = (session_tier, messages = user) => ({ model: "roleplay:intelligence",
  session_id: "session-tier-test", messages, stream: false, memory: { mode: "off" },
  ...(session_tier ? { routing: { session_tier } } : {}) });
async function turn(f, payload, headers) {
  const response = await handleRoleplayEdgeRequest(roleplayRequest(payload, headers), f.env);
  const value = await response.json();
  await f.waitForBackgroundWork();
  return { response, value };
}

test("public roleplay tool loop keeps model until matching results and isolates authenticated callers", async () => {
  const f = makeRoleplayEnv({ SESSION_TIER_MODE: "sticky", CONTENT_RETENTION_ENABLED: "true" });
  const models = [];
  let emitTool = true;
  await withGlobalFetch(async (_url, options) => {
    const payload = JSON.parse(options.body); models.push(payload.model);
    assert.equal(payload.session_tier, undefined);
    const response = completionResponse(payload.model, "A tool is required.");
    if (!emitTool) return response;
    emitTool = false;
    const data = await response.json();
    data.choices[0].message.tool_calls = [{ id: "private-tool-id", type: "function", function: { name: "lookup", arguments: "private args" } }];
    data.choices[0].finish_reason = "tool_calls";
    return Response.json(data);
  }, async () => {
    const headers = { "X-MultiLLM-Retention": "zero" };
    const first = await turn(f, body(approval()), headers);
    assert.equal(first.response.status, 200);
    assert.equal(first.response.headers.get("X-MultiLLM-Retention"), "zero");
    const second = await turn(f, body(approval("glm-5.3-flash", "main", 1)), headers);
    assert.equal(second.response.status, 200);
    await turn(f, body(approval("glm-5.3-flash", "main", 1), [{ role: "tool", tool_call_id: "private-tool-id", content: "private result" }, ...user]), headers);
    assert.deepEqual(models, ["glm-5.3", "glm-5.3", "glm-5.3-flash"]);
    await turn(f, body(approval("glm-5.3-flash", "main", 1)), { ...headers, Authorization: "Bearer janitor-roleplay-key" });
    assert.equal(f.storageBySession.size, 2);
    const tierRows = [...f.storageBySession.values()].flatMap(v => [...v.storage.values].filter(([k]) => k.startsWith("session-tier:")));
    assert.doesNotMatch(JSON.stringify(tierRows), /private|session-tier-test|arguments|content/);
    assert.doesNotMatch(JSON.stringify([...f.storageBySession.values()].flatMap(v => [...v.storage.values])), /private prompt|private args|private result/);
  });
});

test("default and unopted requests keep provider response and add no tier storage or headers", async () => {
  for (const mode of [undefined, "", "off", "invalid", "sticky"]) {
    const f = makeRoleplayEnv({ SESSION_TIER_MODE: mode });
    await withGlobalFetch(async (_url, options) => completionResponse(JSON.parse(options.body).model), async () => {
      const result = await turn(f, body(null));
      assert.equal(result.response.status, 200);
      assert.equal(result.value.choices[0].message.content, "In character.");
      assert.equal([...result.response.headers.keys()].some(k => k.includes("session-tier")), false);
      assert.equal([...f.storageBySession.values()].some(v => [...v.storage.values.keys()].some(k => k.startsWith("session-tier:"))), false);
    });
  }
});

test("public roleplay storage failures return clear 503 before upstream generation", async () => {
  const f = makeRoleplayEnv({ SESSION_TIER_MODE: "sticky" });
  await withGlobalFetch(async (_url, options) => completionResponse(JSON.parse(options.body).model), async () => {
    await turn(f, body(null));
  });
  const { storage } = [...f.storageBySession.values()][0];
  const original = storage.get.bind(storage);
  storage.get = async key => {
    if (key.startsWith("session-tier:")) throw new Error("private unavailable table");
    return original(key);
  };
  await withGlobalFetch(() => assert.fail("upstream dispatch"), async () => {
    const result = await turn(f, body(approval()));
    assert.equal(result.response.status, 503);
    assert.equal(result.value.error.code, "session_tier_storage_unavailable");
    assert.doesNotMatch(JSON.stringify(result.value), /private/);
  });
});

test("public pinned route remains caller-selected and writes no tier binding", async () => {
  const f = makeRoleplayEnv({ SESSION_TIER_MODE: "sticky" });
  await withGlobalFetch(async (_url, options) => {
    assert.equal(JSON.parse(options.body).model, "glm-5.3-flash");
    return completionResponse("glm-5.3-flash");
  }, async () => {
    const payload = body(approval());
    payload.routing = { ...payload.routing, mode: "pinned", provider: "opencode", model: "glm-5.3-flash" };
    const result = await turn(f, payload);
    assert.equal(result.response.status, 200);
    assert.equal([...f.storageBySession.values()].some(v => [...v.storage.values.keys()].some(k => k.startsWith("session-tier:"))), false);
  });
});

test("stream tool identifiers are observed without changing bytes", async () => {
  const { policy } = fixture();
  const t = await start(policy);
  const data = 'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-"}]}}]}\n\n' +
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"one"}]},"finish_reason":"tool_calls"}]}\n\n' +
    'data: [DONE]\n\n';
  assert.equal(await t.observe(new Response(data, { headers: { "content-type": "text/event-stream" } })).text(), data);
  await t.finish(a, { success: true, finishReason: "tool_calls" });
  const next = await policy.begin({ lane: "main", approved_model: "opencode:b", approved_tier: 2 }, [a, b], user, "r1");
  assert.deepEqual(next.candidates, [a]);
});

test("public roleplay fallback records the actual eligible provider", async () => {
  const f = makeRoleplayEnv({ SESSION_TIER_MODE: "sticky", NAVYAI_API_KEY: "fixture-navy-key" });
  const calls = [];
  await withGlobalFetch(async (url, options) => {
    calls.push(String(url));
    if (String(url).includes("opencode")) return Response.json({ error: { message: "unavailable" } }, { status: 503 });
    return completionResponse(JSON.parse(options.body).model);
  }, async () => {
    const result = await turn(f, body(approval()));
    assert.equal(result.response.status, 200);
    const saved = [...f.storageBySession.values()][0].storage.values;
    const row = [...saved].find(([key]) => key.startsWith("session-tier:"))[1];
    assert.equal(row.approved_model, "opencode:glm-5.3");
    assert.equal(row.actual_model, "navyai:glm-5.3");
    await turn(f, body(approval()));
    assert.equal(calls.filter(url => url.includes("opencode")).length, 1);
  });
});

test("public streaming completion persists matching tool markers", async () => {
  const f = makeRoleplayEnv({ SESSION_TIER_MODE: "sticky" });
  await withGlobalFetch(async () => new Response(
    'data: {"id":"stream-test","choices":[{"index":0,"delta":{"content":"Using the tool.","tool_calls":[{"index":0,"id":"stream-call"}]},"finish_reason":null}]}\n\n' +
    'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n' +
    'data: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } }), async () => {
    const response = await handleRoleplayEdgeRequest(roleplayRequest({ ...body(approval()), stream: true }), f.env);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /\[DONE\]/);
    await f.waitForBackgroundWork();
    const row = [...[...f.storageBySession.values()][0].storage.values].find(([key]) => key.startsWith("session-tier:"))[1];
    assert.equal(row.pending_tools.length, 1);
    assert.equal(row.lease, "");
  });
});

test("simultaneous same-lane starts acquire exactly one lease", async () => {
  const { policy } = fixture();
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => start(policy)));
  assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
  assert.ok(results.filter(r => r.status === "rejected").every(r => r.reason.code === "session_tier_busy"));
});

test("cancelling a queued request cannot release the active request's tier lease", async () => {
  const f = makeRoleplayEnv({ SESSION_TIER_MODE: "sticky" });
  let release, entered;
  const upstreamStarted = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  await withGlobalFetch(async (_url, options) => {
    entered(); await gate;
    return completionResponse(JSON.parse(options.body).model);
  }, async () => {
    const first = handleRoleplayEdgeRequest(roleplayRequest(body(approval())), f.env);
    await upstreamStarted;
    const { instance, storage } = [...f.storageBySession.values()][0];
    const saved = () => [...storage.values].find(([key]) => key.startsWith("session-tier:"))[1];
    const lease = saved().lease;
    let queued;
    const queuedRequest = new Promise(resolve => { queued = resolve; });
    const acquire = instance.turnQueue.acquire.bind(instance.turnQueue);
    instance.turnQueue.acquire = (...args) => { const result = acquire(...args); queued(); return result; };
    const controller = new AbortController();
    const second = handleRoleplayEdgeRequest(new Request(roleplayRequest(body(approval())), { signal: controller.signal }), f.env);
    await queuedRequest;
    controller.abort();
    assert.equal((await second).status, 499);
    assert.equal(saved().lease, lease);
    release();
    const response = await first;
    assert.equal(response.status, 200);
    await response.text();
    await f.waitForBackgroundWork();
    assert.equal(saved().lease, "");
  });
});

test("unknown streamed tool state stays unresolved until expiry or revision", async () => {
  const { policy } = fixture();
  let t = await start(policy);
  const data = 'data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n';
  await t.observe(new Response(data, { headers: { "content-type": "text/event-stream" } })).text();
  await t.finish(a, { success: true, finishReason: "tool_calls" });
  t = await start(policy);
  await t.finish(a, { success: true });
  t = await policy.begin({ lane: "main", approved_model: "opencode:b", approved_tier: 2 }, [a, b], user, "r1");
  assert.deepEqual(t.candidates, [a]);
});
