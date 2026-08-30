import assert from "node:assert/strict";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const worker = (await loadWorkerModule()).default;

async function withGlobalFetch(fetchImpl, operation) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await operation();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function directEnv(overrides) {
  return {
    ADMIN_API_KEY: "admin-test-key",
    MULTILLM_PROXY_CONTAINER: {
      getByName() {
        throw new Error("direct image requests must not reach the container");
      },
    },
    ...overrides,
  };
}

for (const directCase of [
  {
    name: "LinkAPI",
    route: "/linkapi/v1/images/generations",
    upstream: "https://api.linkapi.ai/v1/images/generations",
    model: "gpt-image-2-c",
    env: { LINKAPI_KEY: "linkapi-provider-key" },
  },
  {
    name: "Codex Everywhere",
    route: "/codex-easy/v1/images/generations",
    upstream: "https://codex-easy.ai/v1/images/generations",
    model: "gpt-image-2",
    env: { CODEX_EASY_API_KEY: "codex-provider-key" },
  },
]) {
  test(`${directCase.name} fast path defaults GPT Image moderation to low`, async () => {
    let upstreamPayload;
    const response = await withGlobalFetch(
      async (upstreamRequest) => {
        assert.equal(upstreamRequest.url, directCase.upstream);
        upstreamPayload = await upstreamRequest.json();
        return Response.json({ data: [{ url: "https://images.example/result.png" }] });
      },
      () =>
        worker.fetch(
          new Request(`https://proxy.example${directCase.route}`, {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-test-key",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              model: directCase.model,
              prompt: "A green triangle",
            }),
          }),
          directEnv(directCase.env),
        ),
    );

    assert.equal(response.status, 200);
    assert.equal(upstreamPayload.moderation, "low");
  });
}

test("LinkAPI fast path preserves explicit auto moderation", async () => {
  let upstreamPayload;
  const response = await withGlobalFetch(
    async (upstreamRequest) => {
      upstreamPayload = await upstreamRequest.json();
      return Response.json({ data: [{ url: "https://images.example/result.png" }] });
    },
    () =>
      worker.fetch(
        new Request("https://proxy.example/linkapi/v1/images/generations", {
          method: "POST",
          headers: {
            Authorization: "Bearer admin-test-key",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "gpt-image-2-c",
            prompt: "A green triangle",
            moderation: "auto",
          }),
        }),
        directEnv({ LINKAPI_KEY: "linkapi-provider-key" }),
      ),
  );

  assert.equal(response.status, 200);
  assert.equal(upstreamPayload.moderation, "auto");
});

test("LinkAPI fast path rejects unknown GPT Image moderation", async () => {
  let upstreamCalls = 0;
  const response = await withGlobalFetch(
    async () => {
      upstreamCalls += 1;
      return Response.json({ data: [] });
    },
    () =>
      worker.fetch(
        new Request("https://proxy.example/linkapi/v1/images/generations", {
          method: "POST",
          headers: {
            Authorization: "Bearer admin-test-key",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "gpt-image-2-c",
            prompt: "A green triangle",
            moderation: "disabled",
          }),
        }),
        directEnv({ LINKAPI_KEY: "linkapi-provider-key" }),
      ),
  );

  assert.equal(response.status, 400);
  assert.equal(upstreamCalls, 0);
  assert.match((await response.json()).message, /auto, low/);
});
