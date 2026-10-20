import assert from "node:assert/strict";
import test from "node:test";
import { configuredKeys, MAX_KEYS } from "../worker/knowledge/providers/keys.mjs";
import { upstreamError } from "../worker/knowledge/providers/errors.mjs";
import { requestJSON } from "../worker/knowledge/providers/transport.mjs";
import { providerStatus, retrieve } from "../worker/knowledge/providers/index.mjs";
import { metered } from "../worker/knowledge/operations.mjs";
import { fixture } from "./knowledge_fixture.mjs";

async function pool(env, reply) {
  const f = await fixture();
  f.policy.providers.context7 = { ...f.policy.providers.exa };
  await f.storage.put("policy", f.policy);
  let now = Date.now();
  f.authority.now = () => now;
  const calls = [];
  const context = { env, authority: f.authority,
    invoke: (provider, operation, callback) => metered(f.authority, {
      provider, operation_id: `${crypto.randomUUID()}:${operation}`, background: false,
    }, callback),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return reply(url, options);
    },
  };
  return { ...f, calls, context,
    advance(ms) { now += ms; },
    usage: async provider => (await f.authority.call("snapshot")).usage.find(row => row.provider === provider),
    request: (provider = "exa", extra = {}) => requestJSON(provider, "search",
      provider === "exa" ? "https://api.exa.ai/search" : "https://context7.com/api/v2/libs/search", {}, { ...context, ...extra }),
  };
}

test("numbered credentials follow numeric order, with gaps, blanks and duplicates handled", () => {
  const env = { CONTEXT7_API_KEY: " base ", CONTEXT7_API_KEY_10: "ten", CONTEXT7_API_KEY_2: "two",
    CONTEXT7_API_KEY_1: "one", CONTEXT7_API_KEY_3: " ", CONTEXT7_API_KEY_4: "base",
    CONTEXT7_API_KEY_backup: "ignored", CONTEXT7_API_KEY_2_EXTRA: "ignored", CONTEXT7_API_KEY_x: "ignored" };
  assert.deepEqual(configuredKeys("context7", env).map(row => row.name), [
    "CONTEXT7_API_KEY", "CONTEXT7_API_KEY_1", "CONTEXT7_API_KEY_2", "CONTEXT7_API_KEY_10",
  ]);
  delete env.CONTEXT7_API_KEY;
  assert.equal(configuredKeys("context7", env)[0].name, "CONTEXT7_API_KEY_1");
  assert.deepEqual(configuredKeys("mintlify", env), []);
  const status = providerStatus(env).find(row => row.id === "context7");
  assert.equal(status.configured, true);
  assert.equal(status.configured_key_count, 4);
  assert.ok(!JSON.stringify(status).includes('"one"'));
});

test("Context7 advances on quota exhaustion and keeps the selected key across both API stages", async () => {
  const env = { CONTEXT7_API_KEY: "synthetic-base", CONTEXT7_API_KEY_10: "synthetic-ten",
    CONTEXT7_API_KEY_2: "synthetic-two", CONTEXT7_API_KEY_1: "synthetic-one" };
  const exhausted = new Set(["Bearer synthetic-base"]);
  const f = await pool(env, (url, options) => {
    if (exhausted.has(options.headers.Authorization)) return Response.json({ error: "quota_exceeded", message: "Monthly quota exhausted" }, { status: 429 });
    return Response.json(url.includes("/libs/search") ? { results: [{ id: "/pallets/flask", title: "Flask" }] }
      : { codeSnippets: [], infoSnippets: [{ pageId: f.source.url, breadcrumb: "Limits" }] });
  });
  const intent = { query: "request limits", product: "flask", allowed_hosts: ["flask.palletsprojects.com"] };
  const run = () => retrieve("context7", intent, f.context);
  assert.equal((await run()).observations[0].url, f.source.url);
  await run();
  assert.deepEqual(f.calls.map(row => row.options.headers.Authorization), [
    "Bearer synthetic-base", "Bearer synthetic-one", "Bearer synthetic-one", "Bearer synthetic-one", "Bearer synthetic-one",
  ]);
  exhausted.add("Bearer synthetic-one");
  await run();
  assert.deepEqual(f.calls.slice(-3).map(row => row.options.headers.Authorization), ["Bearer synthetic-one", "Bearer synthetic-two", "Bearer synthetic-two"]);
  assert.equal((await f.usage("context7")).confirmed, 6, "each completed API stage is metered once");
  const state = await f.storage.get("credentials:context7");
  assert.match(state.active, /^[a-f0-9]{64}$/);
  assert.equal(Object.keys(state.blocked).length, 2);
  assert.ok(!JSON.stringify(state).includes("synthetic"));
  assert.ok(!JSON.stringify(await f.authority.call("snapshot")).includes(state.active));
});

test("all exhausted keys stop dispatch until reset and release unused allowance", async () => {
  const f = await pool({ EXA_API_KEY_10: "synthetic-ten", EXA_API_KEY_2: "synthetic-two", EXA_API_KEY_3: "synthetic-two" },
    () => Response.json({ error: "Insufficient credits" }, { status: 402, headers: { "Retry-After": "120" } }));
  await assert.rejects(f.request(), { code: "provider_keys_exhausted" });
  assert.deepEqual(f.calls.map(row => row.options.headers["x-api-key"]), ["synthetic-two", "synthetic-ten"]);
  await assert.rejects(f.request(), { code: "provider_keys_exhausted" });
  assert.equal(f.calls.length, 2, "cooling keys are not probed again by the next request");
  assert.equal((await f.usage("exa")).total, 0);
  f.advance(121000);
  await assert.rejects(f.request(), { code: "provider_keys_exhausted" });
  assert.equal(f.calls.length, 4);
  f.context.env.EXA_API_KEY_2 = "synthetic-replacement";
  await assert.rejects(f.request(), { code: "provider_keys_exhausted" });
  assert.equal(f.calls.length, 5, "a replaced secret has its own quota state");
  assert.equal(f.calls.at(-1).options.headers["x-api-key"], "synthetic-replacement");
});

test("rate limits respect provider retry and reset headers without short retry loops", () => {
  const now = Date.parse("2026-09-23T00:00:00Z");
  const rejection = headers => upstreamError("context7", 429, new Headers(headers), { error: "rate_limit_exceeded" }, now).key_rejection;
  assert.deepEqual(rejection({ "Retry-After": "15" }), { reason: "rate_limit", cooldown_seconds: 15 });
  assert.equal(rejection({ "Retry-After": new Date(now + 30000).toUTCString() }).cooldown_seconds, 30);
  assert.equal(rejection({ "RateLimit-Reset": String(now / 1000 + 300) }).cooldown_seconds, 300);
  assert.equal(rejection({}).cooldown_seconds, 60);
  assert.equal(upstreamError("context7", 429, new Headers(), { error: "Monthly quota exhausted" }, now).key_rejection.cooldown_seconds, 86400);
});

test("authentication, server failures, unstructured limits and accepted work never switch keys", async t => {
  for (const [name, response] of [
    ["authentication", () => Response.json({ error: "invalid key" }, { status: 401 })],
    ["access", () => Response.json({ error: "permission denied" }, { status: 403 })],
    ["server", () => Response.json({ error: "quota" }, { status: 500 })],
    ["unstructured", () => new Response("quota exceeded with private detail", { status: 429 })],
    ["unrecognized", () => Response.json({ error: "unknown failure" }, { status: 429 })],
    ...[{ success: true }, { chargeId: "charge-1" }, { scrape_id: "scrape-1" }, { data: {} }, { results: [] },
      { executed: true }, { creditsCost: 1 }, { creditsUsed: 1 }, { code: "request_unresolved" }].map(body => [
      Object.keys(body)[0], () => Response.json({ error: "insufficient credits", ...body }, { status: 402 }),
    ]),
  ]) await t.test(name, async () => {
    const f = await pool({ EXA_API_KEY: "synthetic-base", EXA_API_KEY_1: "synthetic-one" }, response);
    await assert.rejects(f.request(), error => {
      assert.ok(!error.no_charge);
      assert.ok(!error.message.includes("private detail"));
      return true;
    });
    assert.equal(f.calls.length, 1);
    assert.equal((await f.usage("exa")).unknown, 1);
    assert.deepEqual((await f.storage.get("credentials:exa")).blocked, {});
  });
});

test("network errors and timeouts keep their uncertain charge and never try another key", async () => {
  for (const abort of [false, true]) {
    const controller = new AbortController();
    const f = await pool({ EXA_API_KEY: "synthetic-base", EXA_API_KEY_1: "synthetic-one" }, () => {
      if (abort) controller.abort();
      throw new Error("private network detail");
    });
    await assert.rejects(f.request("exa", { signal: controller.signal }), { code: abort ? "provider_timeout" : "provider_network_error" });
    assert.equal(f.calls.length, 1);
    assert.equal((await f.usage("exa")).unknown, 1);
  }
});

test("cancellation while selecting a key cannot dispatch late provider work", async () => {
  const f = await pool({ EXA_API_KEY: "synthetic-base", EXA_API_KEY_1: "synthetic-one" }, () => assert.fail("late dispatch"));
  const controller = new AbortController();
  const call = f.authority.call.bind(f.authority);
  f.authority.call = async (operation, payload) => {
    const result = await call(operation, payload);
    if (operation === "credentials.select") controller.abort();
    return result;
  };
  await assert.rejects(f.request("exa", { signal: controller.signal }), { code: "provider_timeout" });
  assert.equal(f.calls.length, 0);
});

test("key pools reject excessive keys and missing durable state before HTTP dispatch", async () => {
  const env = Object.fromEntries(Array.from({ length: MAX_KEYS + 1 }, (_, i) => [`EXA_API_KEY_${i}`, `synthetic-${i}`]));
  const f = await pool(env, () => assert.fail("unexpected dispatch"));
  await assert.rejects(f.request(), { code: "provider_key_limit" });
  delete env.EXA_API_KEY_32;
  await assert.rejects(f.request("exa", { authority: undefined }), { code: "provider_key_state_required" });
  assert.equal(f.calls.length, 0);
});
