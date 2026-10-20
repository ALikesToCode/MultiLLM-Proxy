import { policyStore } from "./helpers/dispatch_fixture.mjs";
import { dataPolicy } from "../worker/dispatch-policy.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "./helpers/local_miniflare.mjs";
import { guardNativeRequest, mergePreferences, providerDataClass, validDataControls } from "../worker/key-data-guards.mjs";
import { nativeGenerationFetch } from "../worker/gateway-extensions.mjs";
import { handleControlUsersRequest } from "../worker/control-users-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

const request = (provider = "openrouter", preferences = { data_collection: "allow" }) => new Request(`https://example.test/${provider}/v1/chat/completions`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ model: "example/model", provider: preferences, messages: [{ role: "user", content: "example" }] }),
});
const authority = (provider, principal) => ({ authenticated: true, provider, principal, keyId: principal.id ?? "example",
  route: `/${provider}/v1/chat/completions` });

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true,
    script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  return { INTELLIGENCE_DB: db };
}

test("provider classes and explicit tier choices exclude unverified endpoints", () => {
  assert.equal(providerDataClass("openai"), "official");
  assert.equal(providerDataClass("opencode"), "subscription");
  assert.equal(providerDataClass("nanogpt"), "reseller");
  assert.equal(providerDataClass("free"), "free");
  assert.equal(providerDataClass("custom"), "reseller");
  assert.equal(providerDataClass("ce-custom"), "subscription");
  assert.equal(providerDataClass("gemini"), "free");
  assert.equal(providerDataClass("gemini", { GEMINI_DATA_TIER: "paid" }), "official");
  assert.equal(providerDataClass("gemini", { GEMINI_DATA_TIER: "paid", FREE_ROUTE_FREE_TIER_PROVIDERS: "gemini" }), "free");
  for (const value of [2, true, "true"]) assert.equal(validDataControls({ official_only: value }), false);
  assert.equal(validDataControls({ forced_provider_preferences: "[]" }), false);
  assert.equal(validDataControls({ forced_provider_preferences: '{"data_collection":"invalid"}' }), false);
});

test("native direct requests refuse before calling any upstream", async () => {
  for (const provider of ["opencode", "nanogpt", "gemini", "ce-gpt-pro", "free"]) {
    const response = await nativeGenerationFetch(request(provider), { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: null }) }, {},
      authority(provider, { official_only: 1 }), () => assert.fail("Must not dispatch"));
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error.code, "provider_class_not_allowed");
  }
  let calls = 0;
  const response = await nativeGenerationFetch(new Request("https://api.openai.com/v1/chat/completions", request("openai")), { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: null }), OPENAI_API_KEY: "synthetic-operator" }, {},
    authority("openai", { official_only: 1 }), async () => { calls++; return new Response("{}"); });
  assert.equal(response.status, 200);
  assert.equal(calls, 1);
});

test("forced preferences override caller allow and preserve caller deny", async () => {
  const principal = { forced_provider_preferences: '{"data_collection":"deny","max_price":{"prompt":1}}' };
  const guarded = await guardNativeRequest(request("openrouter", { data_collection: "allow", sort: "price", max_price: { completion: 2 } }), { INTELLIGENCE_DB: policyStore({ official_only: null, forced_provider_preferences: principal.forced_provider_preferences }) }, authority("openrouter", principal));
  assert.deepEqual((await guarded.request.json()).provider,
    { data_collection: "deny", sort: "price", max_price: { completion: 2, prompt: 1 } });
  assert.deepEqual(mergePreferences({ data_collection: "deny" }, { data_collection: "allow" }), { data_collection: "deny" });
  const pollution = mergePreferences({}, JSON.parse('{"__proto__":{"polluted":true}}'));
  assert.equal({}.polluted, undefined);
  assert.equal(Object.hasOwn(pollution, "__proto__"), true);
});

test("durable key controls round-trip and native dispatch reads them", async t => {
  const env = await database(t);
  const user = { username: "example", api_key_hash: "synthetic-hash", api_key_prefix: "mllm_example", scopes: "chat,models",
    is_admin: 0, created_at: "2026-10-20T00:00:00Z", last_login: null, last_used_at: null, last_used_ip: null,
    created_by: null, rotated_at: null, revoked_at: null, daily_budget_usd: null, monthly_budget_usd: null,
    allowed_models: null, allowed_ips: null, expires_at: null, secret_scan_mode: null, shadow_eval_rate: null,
    official_only: 1, forced_provider_preferences: '{"data_collection":"deny"}' };
  const call = body => handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
  }), env);
  assert.equal((await call({ operation: "upsert", user })).status, 200);
  assert.deepEqual((await (await call({ operation: "get", username: user.username })).json()).user, { ...user, data_policy: dataPolicy(user) });
  const denied = await guardNativeRequest(request("opencode"), env, authority("opencode", { id: user.username }));
  assert.equal(denied.response.status, 403);
  const guarded = await guardNativeRequest(request(), env, authority("openrouter", { id: user.username }));
  assert.equal((await guarded.request.json()).provider.data_collection, "deny");
  const unavailable = await guardNativeRequest(request(), { INTELLIGENCE_DB: { prepare() { throw new Error(); } } }, authority("openrouter", { id: user.username }));
  assert.equal(unavailable.response.status, 503);
});
