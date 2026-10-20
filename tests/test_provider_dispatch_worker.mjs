import assert from "node:assert/strict";
import { providerBinding } from "./helpers/provider_binding.mjs";
import test from "node:test";
import { providerFetch, providerOperation, withDispatchPrincipal } from "../worker/provider-dispatch.mjs";
import { verifyDataPolicy } from "../worker/dispatch-policy.mjs";
import { handleAiOutbound } from "../worker/ai-outbound.mjs";
import { policyStore } from "./helpers/dispatch_fixture.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { makeRoleplayEnv, roleplayRequest, withGlobalFetch } from "./helpers/roleplay_fixture.mjs";

const worker = (await loadWorkerModule()).default;
const authority = { authenticated: true, keyId: "synthetic-reader" };
const input = (provider = "openrouter") => new Request((provider === "gemini" ? "https://generativelanguage.googleapis.com" : "https://openrouter.ai") + "/v1/chat/completions", {
  method: "POST", headers: { "content-type": "application/json", authorization: "Bearer synthetic-cached" },
  body: JSON.stringify({ provider: { data_collection: "allow", sort: "price" }, messages: [] }),
});
const controls = () => ({ official_only: null, forced_provider_preferences: null });

for (const row of [null, {}, { official_only: null }, { forced_provider_preferences: null },
  { official_only: 1, forced_provider_preferences: "[]" }]) {
  test(`an incomplete or malformed durable policy refuses HTTP and SDK dispatch: ${JSON.stringify(row)}`, async () => {
    const env = { INTELLIGENCE_DB: policyStore(row) };
    await assert.rejects(providerFetch("openai", input(), {}, { env, authority, send: () => assert.fail("HTTP dispatch") }),
      { code: "key_data_controls_unavailable", status: 503 });
    await assert.rejects(withDispatchPrincipal(env, authority, () => providerOperation("cloudflare", () => assert.fail("SDK dispatch"))),
      { code: "key_data_controls_unavailable", status: 503 });
  });
}

test("a versioned envelope requires both explicit fields and the supported version", () => {
  for (const value of [null, {}, { version: 0, ...controls() }, { version: true, ...controls() },
    { version: 1, official_only: null }, { version: 1, ...controls(), extra: null }]) {
    assert.throws(() => verifyDataPolicy(value));
  }
  assert.deepEqual(verifyDataPolicy({ version: 1, ...controls() }), { version: 1, ...controls() });
});

test("each retry, poll and fallback rereads current controls rather than a captured policy", async () => {
  const row = controls(), env = { INTELLIGENCE_DB: policyStore(row) };
  let calls = 0;
  const send = () => { calls++; return new Response("{}"); };
  await providerFetch("linkapi", input(), {}, { env, authority, send });
  row.official_only = 1;
  for (const provider of ["linkapi", "nanogpt", "opencode", "free", "unknown"]) {
    await assert.rejects(providerFetch(provider, input(), {}, { env, authority, send }), { code: "provider_class_not_allowed", status: 403 });
  }
  assert.equal(calls, 1);
});

test("forced routing preferences and current attested credentials replace cached headers at dispatch", async () => {
  const env = { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: '{"data_collection":"deny"}' }),
    OPENROUTER_API_KEY: "synthetic-current" };
  await providerFetch("openrouter", input(), {}, { env, authority, send: async request => {
    assert.equal(request.headers.get("authorization"), "Bearer synthetic-current");
    assert.deepEqual((await request.json()).provider, { data_collection: "deny", sort: "price" });
    assert.equal(request.redirect, "manual");
    return new Response("{}");
  } });
  await assert.rejects(providerFetch("openrouter", input(), {}, { env, authority, realtime: true }),
    { code: "forced_provider_preferences_not_supported", status: 403 });
  delete env.OPENROUTER_API_KEY;
  await assert.rejects(providerFetch("openrouter", input(), {}, { env, authority }), { code: "attested_credential_unavailable", status: 503 });
});

test("Gemini never uses cached or query credentials for a restricted principal", async () => {
  const env = { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: null }), GEMINI_DATA_TIER: "paid" };
  await assert.rejects(providerFetch("gemini", input("gemini"), {}, { env, authority }), { code: "attested_credential_unavailable" });
  env.GEMINI_API_KEY = "synthetic-attested";
  await assert.rejects(providerFetch("gemini", "https://provider.example/generate?key=synthetic-caller", {}, { env, authority }),
    { code: "provider_credential_not_allowed", status: 403 });
  await providerFetch("gemini", input("gemini"), {}, { env, authority, send: request => {
    assert.equal(request.headers.get("authorization"), null);
    assert.equal(request.headers.get("x-goog-api-key"), "synthetic-attested");
    return new Response("{}");
  } });
});

test("private inference bindings refuse missing identity and unavailable current authority before SDK calls", async () => {
  let calls = 0;
  const env = { AI: providerBinding({ run() { calls++; assert.fail("SDK dispatch"); } }) };
  for (const headers of [{}, { "X-MultiLLM-Dispatch-Principal": '{"version":0,"username":"synthetic-reader"}' },
    { "X-MultiLLM-Dispatch-Principal": '{"version":1,"username":"synthetic-reader"}' }]) {
    const result = await handleAiOutbound(new Request("http://ai.internal/v1/embeddings", { method: "POST", headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify({ model: "@cf/baai/bge-m3", input: "Synthetic" }) }), env);
    assert.equal(result.status, 503);
  }
  assert.equal(calls, 0);
});

for (const [name, row, expected] of [["official", { official_only: 1, forced_provider_preferences: null }, 403],
  ["forced", { official_only: null, forced_provider_preferences: '{"data_collection":"deny"}' }, 403],
  ["old schema", {}, 503], ["missing account", null, 503]]) {
  test(`registered roleplay refuses ${name} controls before generation, compaction or fallback`, async () => {
    const fixture = makeRoleplayEnv({ INTELLIGENCE_DB: policyStore(row) });
    let calls = 0;
    const response = await withGlobalFetch(() => { calls++; assert.fail("Roleplay upstream dispatch"); }, () => worker.fetch(
      roleplayRequest({ messages: [{ role: "user", content: "Synthetic turn" }], stream: false, model: "roleplay:glm" }),
      fixture.env, { waitUntil() {} }));
    assert.equal(response.status, expected, await response.clone().text());
    assert.equal(calls, 0);
  });
}

test("registered roleplay refuses an unreadable control store even with an administrator credential", async () => {
  const fixture = makeRoleplayEnv({ INTELLIGENCE_DB: { prepare() { throw Error("Synthetic outage"); } } });
  await withGlobalFetch(() => assert.fail("Roleplay upstream dispatch"), async () => {
    const response = await worker.fetch(roleplayRequest({ messages: [{ role: "user", content: "Synthetic turn" }],
      model: "roleplay:glm", stream: false }), fixture.env, { waitUntil() {} });
    assert.equal(response.status, 503, await response.clone().text());
  });
});


test("index polling rereads current controls before every SDK call", async () => {
  const { KnowledgeCorpus } = await import("../worker/knowledge/corpus.mjs");
  let controls = { official_only: null, forced_provider_preferences: null }, calls = 0;
  const env = { INTELLIGENCE_DB: { prepare(query) {
    return { bind() { return this; }, async first() { return controls; } };
  } }, KNOWLEDGE_INDEX: providerBinding({ search() { assert.fail("Unexpected search"); }, items: { get() { return { async info() {
    calls++; return { id: "synthetic-item", key: "revisions/synthetic.txt", status: "completed" };
  } }; } } }) };
  const corpus = new KnowledgeCorpus(env);
  const artifact = { snapshot_key: "snapshots/synthetic.txt", index_key: "revisions/synthetic.txt",
    content_hash: "a".repeat(64), byte_length: 1 };
  await withDispatchPrincipal(env, { authenticated: true, keyId: "synthetic" }, async () => {
    assert.equal((await corpus.reconcileRevision(artifact, "synthetic-item")).status, "completed");
    controls = { official_only: 1 };
    await assert.rejects(() => corpus.reconcileRevision(artifact, "synthetic-item"), { code: "key_data_controls_unavailable" });
    controls = null;
    await assert.rejects(() => corpus.reconcileRevision(artifact, "synthetic-item"), { code: "key_data_controls_unavailable" });
  });
  assert.equal(calls, 1);
});


test("import watches use the source account instead of the scheduler and refuse legacy ownerless imports", async () => {
  const { checkImports } = await import("../worker/knowledge/skills-import.mjs");
  const env = { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: null }) };
  const source = { source: "github", repository: "example/synthetic", path: "", ref: "HEAD", commit: "a".repeat(40) };
  for (const dispatch_principal of [undefined, { authenticated: true, keyId: "source-key" }]) {
    let checked = 0, calls = 0;
    const store = { async call(name, body) {
      if (name === "imports.due") return [{ skill_id: "synthetic", origin: { ...source, dispatch_principal } }];
      assert.equal(name, "imports.checked"); assert.equal(body.result.status, "error"); checked++;
    } };
    await withDispatchPrincipal({ INTELLIGENCE_DB: policyStore() }, { authenticated: true, keyId: "admin" }, async () => {
      assert.equal(await checkImports(env, store, { fetch() { calls++; assert.fail("Watch dispatch"); } }), 1);
    });
    assert.equal(calls, 0); assert.equal(checked, 1);
  }
});
