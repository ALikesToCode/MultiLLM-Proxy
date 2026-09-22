import assert from "node:assert/strict";
import test from "node:test";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

test("the container selects D1 only when the Worker holds its binding", () => {
  assert.equal(collectContainerEnv({}).INTELLIGENCE_STORAGE_BACKEND, undefined);
  assert.equal(collectContainerEnv({ INTELLIGENCE_STORAGE_BACKEND: "d1" }).INTELLIGENCE_STORAGE_BACKEND, undefined);
  const env = collectContainerEnv({ INTELLIGENCE_DB: { prepare() {} } });
  assert.equal(env.INTELLIGENCE_STORAGE_BACKEND, "d1");
  assert.equal(env.INTELLIGENCE_REQUIRE_DURABLE_STORAGE, "true");
  assert.equal(env.INTELLIGENCE_DB, undefined);
});

test("the Worker exports the private container egress entrypoint", async () => {
  const module = await loadWorkerModule();
  assert.equal(typeof module.ContainerProxy, "function");
  assert.deepEqual(Object.keys(module.MultiLLMProxyContainer.outboundByHost), ["intelligence.internal"]);
  assert.equal(module.MultiLLMProxyContainer.outboundByHost["intelligence.internal"], handleIntelligenceOutbound);
});

test("private storage rejects other targets, paths and methods before accessing D1", async () => {
  let calls = 0;
  const env = { INTELLIGENCE_DB: { prepare() { calls += 1; throw new Error("Unexpected database access"); } } };
  for (const [url, method, expected] of [
    ["https://public.example/v1/store", "POST", 400],
    ["http://intelligence.internal/v1/store?sql=select", "POST", 400],
    ["http://intelligence.internal/sql", "POST", 404],
    ["http://intelligence.internal/v1/store", "GET", 405],
  ]) {
    const response = await handleIntelligenceOutbound(new Request(url, { method }), env);
    assert.equal(response.status, expected);
  }
  assert.equal(calls, 0);
});

test("public requests cannot invoke the private D1 domain handler", async () => {
  const { default: worker } = await loadWorkerModule();
  let forwarded = 0;
  const env = {
    INTELLIGENCE_DB: { prepare() { throw new Error("Public request reached D1"); } },
    MULTILLM_PROXY_CONTAINER: { getByName() { return { async fetch() {
      forwarded += 1;
      return Response.json({ error: "not_found" }, { status: 404 });
    } }; } },
  };
  const response = await worker.fetch(new Request("https://proxy.example/v1/store", {
    method: "POST", body: JSON.stringify({ version: 1, operation: "policy" }),
  }), env);
  assert.equal(response.status, 404);
  assert.equal(forwarded, 1);
});
