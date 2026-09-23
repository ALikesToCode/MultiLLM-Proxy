import assert from "node:assert/strict";
import test from "node:test";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
import { KnowledgeAuthority } from "../worker/knowledge/authority.mjs";
import { defaultPolicy, validatePolicy } from "../worker/knowledge/policy.mjs";
import { retrieve } from "../worker/knowledge/providers/index.mjs";
import { fixture, principal } from "./knowledge_fixture.mjs";

// Matches the public Firecrawl SDK v4.40.0 tools contract; no live provider calls.
const tool = { provider: "particle", capability: "podcasts/episodes/search", name: "Episode search", description: "Find episodes",
  creditsCost: 15, perRecord: false, options: [{ name: "semantic_search", type: "string", required: true }, { name: "limit", type: "number" }],
  response: { about: "Episodes", fields: [] } };
const search = tools => ({ success: true, data: { tools } });
const scraped = (credits = 15, item = {}) => ({ success: true, scrape_id: "scrape-1", data: { creditsCost: credits,
  alexandria: [{ provider: tool.provider, capability: tool.capability, creditsCost: credits, data: { episodes: [{ title: "AI agents" }] }, ...item }] } });

async function setup({ enabled = true, limit = 100, tools = [tool], reply = () => Response.json(scraped()) } = {}) {
  const f = await fixture();
  f.env.FIRECRAWL_API_KEY = "synthetic-firecrawl-key";
  Object.assign(f.policy.providers.alexandria, { enabled, limit, hard_limit_confirmed: true, retention_allowed: true });
  await f.storage.put("policy", f.policy);
  const calls = [];
  const fetchImpl = async (url, options) => {
    const body = JSON.parse(options.body);
    calls.push({ url, options, body });
    if (url.endsWith("/search")) return Response.json(search(body.toolDetail === "full" ? tools
      : tools.map(({ provider, capability, description }) => ({ provider, capability, description }))));
    if (body.alexandria.capability === "find-tools") return Response.json(scraped(0, {
      provider: "firecrawl", capability: "find-tools", data: { level: "tools", items: [tool], total: 1, next: null },
    }));
    return reply(url, options);
  };
  return { ...f, calls,
    run(operation, payload, user = principal) {
      return dispatchKnowledge(f.env, { version: 1, operation: `alexandria.${operation}`, principal: user, payload },
        { authority: f.authority, fetchImpl });
    },
  };
}

async function requestFor(f, changes = {}) {
  const found = await f.run("search", { query: "podcast episodes" });
  return { quote_id: found.tools[0].quote_id, options: { semantic_search: "AI agents", limit: 2 }, reserve_credits: 15,
    request_id: crypto.randomUUID(), ...changes };
}
const usage = async f => (await f.authority.call("snapshot")).usage.find(row => row.provider === "alexandria");

test("discovery and exact capability inspection are free even when spending is disabled", async () => {
  const f = await setup({ enabled: false });
  f.policy.enabled = false;
  await f.storage.put("policy", f.policy);
  const found = await f.run("search", { query: "podcasts", limit: 2 });
  assert.deepEqual(f.calls[0].body, { query: "podcasts", limit: 2, sources: ["alexandria"], toolDetail: "full" });
  assert.deepEqual(found.cost, { credits: 0, state: "confirmed" });
  assert.equal(found.tools[0].creditsCost, 15);
  assert.ok(found.tools[0].quote_id);
  const details = await f.run("inspect", { quote_id: found.tools[0].quote_id });
  assert.deepEqual(details.cost, found.cost);
  assert.equal(details.details.level, "tools");
  assert.deepEqual(f.calls[1].body.alexandria, { provider: "firecrawl", capability: "find-tools",
    options: { providers: ["particle"], capabilities: [tool.capability], level: "tools", expand: ["options", "response", "examples"], limit: 1 } });
  assert.equal((await usage(f)).total, 0);
  assert.equal(f.calls[0].options.redirect, "error");
  assert.equal(f.calls[0].options.headers.Authorization, "Bearer synthetic-firecrawl-key");
  assert.ok(!JSON.stringify(found).includes("synthetic-firecrawl-key"));
});

test("execution returns the record and actual credits, with a persistent retry fence", async () => {
  const f = await setup();
  const payload = await requestFor(f, { reserve_credits: 20 });
  const result = await f.run("execute", payload);
  assert.equal(result.data.episodes[0].title, "AI agents");
  assert.deepEqual(result.cost, { credits: 15, state: "confirmed" });
  assert.equal(result.reserved_credits, 20);
  assert.equal((await usage(f)).confirmed, 15);
  const sent = f.calls.at(-1);
  assert.equal(sent.url, "https://api.firecrawl.dev/v2/scrape");
  assert.deepEqual(sent.body.alexandria, { provider: tool.provider, capability: tool.capability, options: payload.options });
  assert.match(sent.options.headers["x-request-id"], /^alexandria:[a-f0-9]{64}$/);
  assert.equal(result.upstream_request_id, sent.options.headers["x-request-id"]);
  const replay = await f.run("execute", { ...payload, options: { limit: 2, semantic_search: "AI agents" }, accept_variable_cost: false });
  assert.equal(replay.replay, true);
  assert.equal(replay.data_retained, false);
  assert.deepEqual(replay.call_cost, { credits: 0, state: "confirmed" });
  assert.equal(f.calls.length, 2);
  const receipt = await f.run("receipt", { request_id: payload.request_id });
  assert.equal(receipt.cost.credits, 15);
  assert.deepEqual(receipt.call_cost, { credits: 0, state: "confirmed" });
  assert.ok(!("fingerprint" in receipt) && !("principal_id" in receipt));
  await assert.rejects(f.run("execute", { ...payload, options: { semantic_search: "different" } }), { code: "request_conflict" });
});

test("Alexandria switches only rejected keys, reports one charge and shares Firecrawl key state", async () => {
  const f = await setup({ reply: (_url, options) => options.headers.Authorization === "Bearer synthetic-firecrawl-key"
    ? Response.json({ success: false, code: "insufficient_credits", error: "No provider was executed." }, { status: 402 })
    : Response.json(scraped()) });
  f.env.FIRECRAWL_API_KEY_1 = "synthetic-next";
  const payload = await requestFor(f);
  const result = await f.run("execute", payload);
  assert.deepEqual(result.cost, { credits: 15, state: "confirmed" });
  assert.equal((await usage(f)).total, 15);
  const attempts = f.calls.slice(1);
  assert.deepEqual(attempts.map(row => row.options.headers.Authorization), ["Bearer synthetic-firecrawl-key", "Bearer synthetic-next"]);
  assert.equal(attempts[0].options.headers["x-request-id"], attempts[1].options.headers["x-request-id"]);
  assert.deepEqual(attempts[0].body, attempts[1].body);
  await f.run("execute", payload);
  assert.equal(f.calls.length, 3, "receipt replay never repeats either attempt");
  await retrieve("firecrawl", { source_url: f.source.url, allowed_hosts: ["flask.palletsprojects.com"] }, {
    env: f.env, authority: f.authority, invoke: (_provider, _operation, callback) => callback(),
    fetchImpl: async (_url, options) => {
      assert.equal(options.headers.Authorization, "Bearer synthetic-next");
      return Response.json({ success: true, data: { markdown: f.text, metadata: { sourceURL: f.source.url } } });
    },
  });
});

test("definitive Alexandria credit rejections settle at zero after every configured key is exhausted", async () => {
  const f = await setup({ reply: () => Response.json({ success: false, code: "insufficient_credits" }, { status: 402 }) });
  f.env.FIRECRAWL_API_KEY_1 = "synthetic-next";
  const payload = await requestFor(f);
  const result = await f.run("execute", payload);
  assert.equal(result.status, "failed");
  assert.deepEqual(result.cost, { credits: 0, state: "confirmed" });
  assert.equal(result.error.code, "provider_keys_exhausted");
  assert.equal((await usage(f)).total, 0);
  await f.run("execute", payload);
  assert.equal(f.calls.length, 3);
});

test("ambiguous paid Alexandria failures never advance to another configured key", async () => {
  for (const [status, body] of [[402, { code: "insufficient_credits", chargeId: "accepted-charge" }],
    [503, { code: "request_unresolved", creditsCost: 2 }], [429, { error: "capability quota exceeded" }]]) {
    const f = await setup({ reply: () => Response.json(body, { status }) });
    f.env.FIRECRAWL_API_KEY_1 = "synthetic-next";
    const payload = await requestFor(f);
    const result = await f.run("execute", payload);
    assert.deepEqual(result.cost, { credits: null, state: "unknown" });
    assert.equal((await usage(f)).unknown, 15);
    await f.run("execute", payload);
    assert.equal(f.calls.length, 2);
  }
});

test("replays remain readable after discovery expires without another network request", async () => {
  const f = await setup();
  const payload = await requestFor(f);
  await f.run("execute", payload);
  f.authority.now = () => Date.now() + 11 * 60000;
  await f.authority.call("maintenance");
  const replay = await f.run("execute", payload);
  assert.equal(replay.replay, true);
  assert.equal(f.calls.length, 2);
});

test("unknown, stale, cross-principal and arbitrary capabilities cannot execute", async () => {
  const f = await setup();
  const payload = await requestFor(f);
  await assert.rejects(f.run("execute", { ...payload, provider: "forged", capability: "unknown" }), { code: "invalid_request" });
  await assert.rejects(f.run("execute", { ...payload, quote_id: "unknown" }), { code: "discovery_required" });
  await assert.rejects(f.run("execute", payload, { ...principal, id: "someone-else" }), { code: "discovery_required" });
  const other = await f.run("inspect", { quote_id: payload.quote_id }, { ...principal, id: "someone-else" });
  assert.equal(other.error.code, "discovery_required");
  f.authority.now = () => Date.now() + 11 * 60000;
  await assert.rejects(f.run("execute", payload), { code: "discovery_required" });
  assert.equal(f.calls.length, 1);
});

test("policy, input contracts and reservations reject before provider dispatch", async () => {
  const f = await setup({ enabled: false });
  const payload = await requestFor(f);
  await assert.rejects(f.run("execute", payload), { code: "provider_disabled" });
  await assert.rejects(f.run("execute", { ...payload, options: {} }), { code: "invalid_options" });
  await assert.rejects(f.run("execute", { ...payload, options: { ...payload.options, injected: true } }), { code: "invalid_options" });
  await assert.rejects(f.run("execute", { ...payload, reserve_credits: 14 }), { code: "insufficient_reservation" });
  await assert.rejects(f.run("execute", { ...payload, reserve_credits: true }), { code: "invalid_request" });
  assert.equal((await usage(f)).total, 0);
  assert.equal(f.calls.length, 1);
});

test("concurrent paid calls respect the credit allowance and request identity", async () => {
  const f = await setup({ limit: 20 });
  const payload = await requestFor(f);
  const attempts = await Promise.allSettled(Array.from({ length: 10 }, () => f.run("execute", { ...payload, request_id: crypto.randomUUID() })));
  assert.equal(attempts.filter(item => item.status === "fulfilled").length, 1);
  assert.ok(attempts.filter(item => item.status === "rejected").every(item => item.reason.code === "allowance_exhausted"));
  assert.equal(f.calls.length, 2);
  const same = await setup();
  const repeat = await requestFor(same);
  await Promise.all([same.run("execute", repeat), same.run("execute", repeat)]);
  assert.equal(same.calls.length, 2);
});

test("per-record pricing needs acknowledgement and accounts for the actual charge", async () => {
  const f = await setup({ tools: [{ ...tool, perRecord: true }], reply: () => Response.json(scraped(45)) });
  const payload = await requestFor(f, { reserve_credits: 30 });
  await assert.rejects(f.run("execute", payload), { code: "variable_cost_acknowledgement" });
  const result = await f.run("execute", { ...payload, accept_variable_cost: true });
  assert.equal(result.cost.credits, 45);
  assert.equal(result.reservation_exceeded, true);
  assert.equal((await usage(f)).confirmed, 45);
});

test("timeouts and malformed receipts stay unknown, with no retry or allowance refund", async () => {
  for (const reply of [() => { throw new Error("timeout with secret"); },
    () => Response.json(scraped(15, { provider: "wrong" })),
    () => Response.json({ success: true, data: { alexandria: [] } }),
    () => new Response("secret body", { status: 500 })]) {
    const f = await setup({ reply });
    const payload = await requestFor(f);
    const result = await f.run("execute", payload);
    assert.deepEqual(result.cost, { credits: null, state: "unknown" });
    assert.equal((await usage(f)).unknown, 15);
    assert.ok(!JSON.stringify(result).includes("secret"));
    await f.run("execute", payload);
    assert.equal(f.calls.length, 2);
    f.authority.now = () => Date.now() + 35 * 86400000;
    await f.authority.call("maintenance");
    assert.equal((await usage(f)).unknown, 15);
  }
});

test("reported capability failures retain their actual cost; terms never auto-accept", async () => {
  const f = await setup({ reply: () => Response.json(scraped(5, { error: { code: "failed", message: "untrusted provider detail" } })) });
  const result = await f.run("execute", await requestFor(f));
  assert.equal(result.status, "failed");
  assert.equal(result.cost.credits, 5);
  assert.ok(!JSON.stringify(result).includes("untrusted provider detail"));
  const terms = await setup({ reply: () => Response.json({ success: false, code: "THIRD_PARTY_DATA_TERMS_REQUIRED",
    requiresAction: { url: "https://evil.example/" } }, { status: 403 }) });
  const denied = await terms.run("execute", await requestFor(terms));
  assert.equal(denied.error.code, "provider_terms_required");
  assert.equal(denied.cost.credits, null);
  assert.equal(denied.error.requires_action.url, "https://www.firecrawl.dev/app/settings?tab=data-sources");
  assert.equal(terms.calls.length, 2);
});

test("catalogue and receipt operations require read scope and credentials remain private", async () => {
  const f = await setup();
  await assert.rejects(f.run("search", { query: "x" }, { ...principal, scopes: ["knowledge:manage"] }), { code: "insufficient_scope" });
  delete f.env.FIRECRAWL_API_KEY;
  await assert.rejects(f.run("search", { query: "x" }), { code: "provider_not_configured" });
  assert.equal(f.calls.length, 0);
});

test("stored six-provider policies gain a disabled Alexandria allowance without migration", async () => {
  const f = await fixture();
  const old = defaultPolicy();
  delete old.providers.alexandria;
  await f.storage.put("policy", old);
  const authority = new KnowledgeAuthority(f.storage);
  assert.deepEqual((await authority.call("snapshot")).policy.providers.alexandria, defaultPolicy().providers.alexandria);
  const { revision, ...body } = old;
  assert.equal(validatePolicy({ ...body, expected_revision: revision }).providers.alexandria.enabled, false);
});
