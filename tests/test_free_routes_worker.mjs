import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";

const worker = (await loadWorkerModule()).default;
const origin = "https://example.test";

test("deployments preserve operator-owned free-tier settings", async () => {
  const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.equal(config.keep_vars, true);
  assert.equal(config.vars.FREE_ROUTE_FREE_TIER_PROVIDERS, undefined);
});

function environment(fetch) {
  return { MULTILLM_PROXY_CONTAINER: { getByName: () => ({ fetch }) } };
}

test("free pool preflight is answered at the edge without starting a container", async () => {
  const response = await worker.fetch(new Request(
    "https://proxy.example/v1/free/vision/chat/completions", {
      method: "OPTIONS", headers: { Origin: origin,
        "Access-Control-Request-Headers": "authorization,content-type" },
    },
  ), environment(() => { throw new Error("Unexpected container call"); }));
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(response.headers.get("Access-Control-Expose-Headers"), /X-MultiLLM-Auto-Selected-Model/i);
});

test("free pool image request reaches the container unchanged with quota metadata exposed", async () => {
  const payload = { model: "free:vision", messages: [{ role: "user", content: [
    { type: "text", text: "Read the label" },
    { type: "image_url", image_url: { url: "data:image/png;base64,aGVsbG8=" } },
  ] }] };
  let calls = 0;
  const response = await worker.fetch(new Request(
    "https://proxy.example/v1/free/vision/chat/completions", {
      method: "POST", headers: { Origin: origin, Authorization: "Bearer test-proxy-key",
        "Content-Type": "application/json" }, body: JSON.stringify(payload),
    },
  ), environment(async (request) => {
    calls += 1;
    assert.equal(new URL(request.url).pathname, "/v1/free/vision/chat/completions");
    assert.deepEqual(await request.json(), payload);
    return Response.json({ error: { code: "free_pool_exhausted" } }, {
      status: 429, headers: { "Retry-After": "60",
        "X-MultiLLM-Auto-Selected-Model": "openrouter:openrouter/free" },
    });
  }));
  assert.equal(calls, 1);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("Retry-After"), "60");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal((await response.json()).error.code, "free_pool_exhausted");
});

test("free pool startup failure remains a readable CORS API error", async () => {
  const response = await worker.fetch(new Request("https://proxy.example/v1/free/models", {
    headers: { Origin: origin },
  }), environment(() => { throw new Error("Unavailable"); }));
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(response.headers.get("Content-Type"), /application\/json/);
});

test("free provider settings and inference keys reach the container, not unrelated secrets", () => {
  const settings = {
    FREE_ROUTE_EXTRA_PROVIDERS: "mistral,workersai,zai,orcarouter,bazaarlink,llm7",
    FREE_ROUTE_FREE_TIER_PROVIDERS: "groq,gemini,mistral,workersai,llm7",
    FREE_ROUTE_PROVIDER_ORDER: "mistral,groq",
    FREE_ROUTE_WORKERSAI_ACCOUNT_ID: "a".repeat(32),
    GROQ_API_KEY: "test-groq",
    MISTRAL_API_KEY: "test-mistral",
    WORKERSAI_API_KEY: "test-workersai",
    ZAI_API_KEY: "test-zai",
    ORCAROUTER_API_KEY: "test-orcarouter",
    BAZAARLINK_API_KEY: "test-bazaarlink",
    LLM7_API_KEY: "test-llm7",
  };
  const forwarded = collectContainerEnv({ ...settings, CLOUDFLARE_API_TOKEN: "test-deployment-only" });
  for (const [key, value] of Object.entries(settings)) assert.equal(forwarded[key], value);
  assert.equal(forwarded.CLOUDFLARE_API_TOKEN, undefined);
});

test("free provider setup discovery reaches the authenticated container path", async () => {
  const response = await worker.fetch(new Request("https://proxy.example/v1/free/providers", {
    headers: { Origin: origin, Authorization: "Bearer test-proxy-key" },
  }), environment(async (request) => {
    assert.equal(new URL(request.url).pathname, "/v1/free/providers");
    assert.equal(request.headers.get("Authorization"), "Bearer test-proxy-key");
    return Response.json({ object: "list", data: [] });
  }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
});

test("standard endpoint forwards free vision and JSON schema without provider rewriting", async () => {
  const payload = { model: "free:vision", messages: [{ role: "user", content: [
    { type: "text", text: "Read the color" },
    { type: "image_url", image_url: { url: "data:image/png;base64,aGVsbG8=" } },
  ] }], response_format: { type: "json_schema", json_schema: {
    name: "color", strict: true, schema: { type: "object",
      properties: { color: { type: "string" } }, required: ["color"], additionalProperties: false },
  } } };
  const response = await worker.fetch(new Request("https://proxy.example/v1/chat/completions", {
    method: "POST", headers: { Origin: origin, Authorization: "Bearer test-proxy-key",
      "Content-Type": "application/json" }, body: JSON.stringify(payload),
  }), environment(async (request) => {
    assert.equal(new URL(request.url).pathname, "/v1/chat/completions");
    assert.equal(request.headers.get("Authorization"), "Bearer test-proxy-key");
    assert.deepEqual(await request.json(), payload);
    return Response.json({ choices: [{ message: { content: '{"color":"red"}' } }] }, {
      headers: { "X-MultiLLM-Auto-Route": "free:vision", "X-MultiLLM-Auto-Selected-Model": "groq:qwen/qwen3.8-27b" },
    });
  }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(response.headers.get("X-MultiLLM-Auto-Route"), "free:vision");
  assert.equal((await response.json()).choices[0].message.content, '{"color":"red"}');
});

test("standard model discovery preserves free aliases from the container", async () => {
  const payload = { object: "list", data: [{ id: "free:text", supports_vision: false },
    { id: "free:vision", supports_vision: true }] };
  const response = await worker.fetch(new Request("https://proxy.example/v1/models", {
    headers: { Origin: origin, Authorization: "Bearer test-proxy-key" },
  }), environment(async (request) => {
    assert.equal(new URL(request.url).pathname, "/v1/models");
    assert.equal(request.headers.get("Authorization"), "Bearer test-proxy-key");
    return Response.json(payload);
  }));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), payload);
});
