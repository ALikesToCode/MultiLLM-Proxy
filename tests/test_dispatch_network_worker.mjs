import assert from "node:assert/strict";
import test from "node:test";
import net from "node:net";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { networkAdmitted } from "../worker/dispatch-network.mjs";
import { providerFetch, providerOperation } from "../worker/provider-dispatch.mjs";
import { policyStore, dispatchEnv } from "./helpers/dispatch_fixture.mjs";
import { providerBinding } from "./helpers/provider_binding.mjs";

const authority = { authenticated: true, keyId: "synthetic" };

test("SDK fixtures guard every method, nested handle and later replacement by default", async () => {
  let calls = 0;
  const binding = providerBinding({ run() { calls++; }, items: { get() { return { info() { calls++; } }; } } });
  assert.throws(() => binding.run(), /outside provider chokepoint/);
  assert.throws(() => binding.items.get("synthetic"), /outside provider chokepoint/);
  let handle;
  await providerOperation("cloudflare", () => { binding.run(); handle = binding.items.get("synthetic"); handle.info(); },
    { env: dispatchEnv(), authority });
  assert.equal(calls, 2);
  assert.throws(() => handle.info(), /outside provider chokepoint/);
  binding.run = () => { calls++; };
  assert.throws(() => binding.run(), /outside provider chokepoint/);
  assert.equal(calls, 2);
});

test("removing AI admission wrappers in memory fails before either SDK dispatch", async () => {
  const url = new URL("../worker/ai-outbound.mjs", import.meta.url);
  const source = await readFile(url, "utf8");
  let mutations = 0;
  const mutated = source.replace(/providerOperation\("cloudflare", \(\) => (env\.AI\.run\([^\n]+\))\)/g,
    (_, call) => { mutations++; return call; })
    .replace(/from (["'])(\.[^"']+)\1/g, (_, quote, path) => `from ${JSON.stringify(new URL(path, url).href)}`);
  assert.equal(mutations, 2, "mutate both shared AI and speech dispatches");
  const { handleAiOutbound } = await import(`data:text/javascript,${encodeURIComponent(mutated)}`);
  for (const [path, body] of [["embeddings", { model: "@cf/baai/bge-m3", input: "synthetic" }],
    ["audio/speech", { model: "@cf/deepgram/aura-2-en", input: "synthetic" }]]) {
    let calls = 0;
    const env = { INTELLIGENCE_DB: policyStore(), AI: providerBinding({ run() { calls++; return {}; } }) };
    const response = await handleAiOutbound(new Request(`http://ai.internal/v1/${path}`, {
      method: "POST", headers: { "content-type": "application/json",
        "X-MultiLLM-Dispatch-Principal": '{"version":1,"username":"synthetic"}' }, body: JSON.stringify(body),
    }), env);
    assert.equal(response.status, 502, "an unadmitted SDK call cannot return success");
    assert.equal(calls, 0, "the provider double must reject before running its implementation");
    assert.equal(networkAdmitted(), false);
  }
});

test("an unlisted axios-style adapter cannot bypass the global fetch guard", async t => {
  const previous = globalThis.fetch;
  t.after(() => { globalThis.fetch = previous; });
  let sends = 0;
  globalThis.fetch = () => { sends++; return Response.json({}); };
  const source = "export default { get: url => fetch(url), request: config => fetch(config.url) };";
  const { default: axios } = await import(`data:text/javascript,${encodeURIComponent(source)}`);
  assert.throws(() => axios.get("https://unrelated.example"), /outside provider chokepoint/);
  assert.throws(() => axios.request({ url: "https://unrelated.example" }), /outside provider chokepoint/);
  assert.equal(sends, 0);
  await providerFetch("xai", "https://api.x.ai/v1/models", {}, { env: dispatchEnv(), authority });
  assert.equal(sends, 1);
  assert.equal(networkAdmitted(), false);
});

test("axios-style node HTTP and direct socket adapters are guarded too", () => {
  assert.throws(() => http.get("http://127.0.0.1:9"), /outside provider chokepoint/);
  const socket = new net.Socket();
  try { assert.throws(() => socket.connect(9, "127.0.0.1"), /outside provider chokepoint/); }
  finally { socket.destroy(); }
});

test("capability ends after failed HTTP and SDK transports", async () => {
  const options = { env: dispatchEnv(), authority };
  await assert.rejects(providerFetch("xai", "https://api.x.ai/v1/models", {}, { ...options, send() {
    assert.equal(networkAdmitted(), true); throw Error("synthetic transport failure");
  } }), /synthetic transport failure/);
  assert.equal(networkAdmitted(), false);
  await assert.rejects(providerOperation("cloudflare", async () => {
    assert.equal(networkAdmitted(), true); throw Error("synthetic SDK failure");
  }, options), /synthetic SDK failure/);
  assert.equal(networkAdmitted(), false);
});

test("public assets strip every credential header even with restricted controls", async () => {
  const env = { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: null }), XAI_API_KEY: "synthetic-current" };
  await providerFetch("xai", "https://unrelated-cdn.example/asset.mp4", { headers: {
    authorization: "Bearer synthetic-cached", "x-api-key": "synthetic", cookie: "synthetic",
  } }, { env, authority, publicAsset: true, send(request) {
    for (const name of ["authorization", "x-api-key", "cookie"]) assert.equal(request.headers.get(name), null);
    return new Response("synthetic");
  } });
});


test("an API operation cannot inject operator secrets into another origin", async () => {
  const env = { INTELLIGENCE_DB: policyStore({ official_only: 1, forced_provider_preferences: null }), XAI_API_KEY: "synthetic-current" };
  await assert.rejects(providerFetch("xai", "https://api.x.ai.unrelated.example/v1/videos", {}, { env, authority,
    send() { assert.fail("Unapproved API destination"); } }), { code: "attested_credential_unavailable" });
});

test("asynchronous work cannot retain a capability after its admitted call ends", async () => {
  let release, delayed;
  await providerOperation("cloudflare", async () => {
    delayed = new Promise(resolve => { release = resolve; }).then(() => networkAdmitted());
  }, { env: dispatchEnv(), authority });
  release();
  assert.equal(await delayed, false);
});
