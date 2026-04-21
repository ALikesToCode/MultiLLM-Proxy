import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function loadWorkerModule() {
  const workerUrl = new URL("./cloudflare-worker.mjs", import.meta.url);
  const source = await readFile(workerUrl, "utf8");
  const patchedSource = source.replace(
    /import\s+\{[^}]+\}\s+from\s+"@cloudflare\/containers";/,
    "class Container {}\nconst getContainer = (binding, name) => binding.getByName(name);",
  );

  return import(
    `data:text/javascript;base64,${Buffer.from(patchedSource, "utf8").toString("base64")}`
  );
}

const workerModule = await loadWorkerModule();
const worker = workerModule.default;

function makeEnv(fetchImpl) {
  let calls = 0;

  return {
    getCalls() {
      return calls;
    },
    env: {
      MULTILLM_PROXY_CONTAINER: {
        getByName(name) {
          assert.equal(name, "primary");

          return {
            async fetch(request) {
              calls += 1;
              return fetchImpl(request);
            },
          };
        },
      },
    },
  };
}

test("worker answers API CORS preflight without forwarding to the container", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
      },
    }),
    stub.env,
  );

  assert.equal(response.status, 204);
  assert.equal(stub.getCalls(), 0);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(response.headers.get("Access-Control-Allow-Methods") ?? "", /POST/);
  assert.equal(
    response.headers.get("Access-Control-Allow-Headers"),
    "Authorization, Content-Type",
  );
});

test("worker adds CORS headers to proxied API responses", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
      method: "POST",
      headers: {
        Origin: origin,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model: "kimi-k2.5" }),
    }),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(stub.getCalls(), 1);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.deepEqual(await response.json(), { ok: true });
});

test("worker returns a CORS-safe API error when the container fetch fails", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    throw new Error("container unavailable");
  });

  const originalConsoleError = console.error;
  console.error = () => {};

  let response;
  try {
    response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Origin: origin,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5" }),
      }),
      stub.env,
    );
  } finally {
    console.error = originalConsoleError;
  }

  assert.equal(response.status, 502);
  assert.equal(stub.getCalls(), 1);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.deepEqual(await response.json(), {
    error: "Proxy unavailable",
    message: "The proxy container could not handle the request.",
  });
});
