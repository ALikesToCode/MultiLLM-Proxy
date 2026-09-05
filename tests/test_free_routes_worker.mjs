import assert from "node:assert/strict";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const worker = (await loadWorkerModule()).default;
const origin = "https://example.test";

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
