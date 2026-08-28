import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const workerModule = await loadWorkerModule();
const worker = workerModule.default;
const { MultiLLMProxyContainer } = workerModule;

function makeEnv(fetchImpl, envOverrides = {}) {
  let calls = 0;
  return {
    getCalls: () => calls,
    env: {
      ADMIN_API_KEY: "admin-test-key",
      MULTILLM_PROXY_CONTAINER: {
        getByName(name) {
          assert.equal(name, "primary");
          return {
            async startAndWaitForPorts() {},
            async containerFetch(input, init) {
              calls += 1;
              const resolved =
                typeof input === "string" && input.startsWith("/")
                  ? `http://container${input}`
                  : input;
              return fetchImpl(
                resolved instanceof Request
                  ? resolved
                  : new Request(resolved, {
                      ...init,
                      ...(init?.body !== undefined ? { duplex: "half" } : {}),
                    }),
              );
            },
            async fetch(request) {
              calls += 1;
              return fetchImpl(request);
            },
          };
        },
      },
      ...envOverrides,
    },
  };
}

test("worker treats AIHubMix routes as API paths for CORS preflight", async () => {
  const origin = "https://image-studio.example";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });

  const response = await worker.fetch(
    new Request(
      "https://multillm-proxy.cserules.workers.dev/aihubmix/v1/images/generations",
      {
        method: "OPTIONS",
        headers: {
          Origin: origin,
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers":
            "Authorization, Content-Type, Idempotency-Key",
        },
      },
    ),
    stub.env,
  );

  assert.equal(response.status, 204);
  assert.equal(stub.getCalls(), 0);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
});

test("container receives AIHubMix secret and both configured origins", () => {
  const container = new MultiLLMProxyContainer(
    {},
    {
      AIHUBMIX_API_KEY: "aihubmix-live-key",
      AIHUBMIX_BASE_URL: "https://aihubmix.com",
      AIHUBMIX_BACKUP_BASE_URL: "https://api.inferera.com",
    },
  );

  assert.equal(container.envVars.AIHUBMIX_API_KEY, "aihubmix-live-key");
  assert.equal(container.envVars.AIHUBMIX_BASE_URL, "https://aihubmix.com");
  assert.equal(
    container.envVars.AIHUBMIX_BACKUP_BASE_URL,
    "https://api.inferera.com",
  );
});

test("wrangler config declares only non-secret AIHubMix origins", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(config.vars.AIHUBMIX_BASE_URL, "https://aihubmix.com");
  assert.equal(
    config.vars.AIHUBMIX_BACKUP_BASE_URL,
    "https://api.inferera.com",
  );
  assert.equal(config.vars.AIHUBMIX_API_KEY, undefined);
});
