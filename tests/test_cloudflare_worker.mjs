import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function loadWorkerModule() {
  const workerUrl = new URL("../cloudflare-worker.mjs", import.meta.url);
  const source = await readFile(workerUrl, "utf8");
  const patchedSource = source.replace(
    /import\s+\{[^}]+\}\s+from\s+"@cloudflare\/containers";/,
    "class Container {}\nconst getContainer = (binding, name) => binding.getByName(name);\nconst switchPort = (request) => request;",
  );

  return import(
    `data:text/javascript;base64,${Buffer.from(patchedSource, "utf8").toString("base64")}`
  );
}

const workerModule = await loadWorkerModule();
const worker = workerModule.default;
const { MultiLLMProxyContainer } = workerModule;

function makeEnv(fetchImpl, envOverrides = {}) {
  let calls = 0;
  let startCalls = 0;

  return {
    getCalls() {
      return calls;
    },
    getStartCalls() {
      return startCalls;
    },
    env: {
      MULTILLM_PROXY_CONTAINER: {
        getByName(name) {
          assert.equal(name, "primary");

          return {
            async startAndWaitForPorts() {
              startCalls += 1;
              return undefined;
            },
            async containerFetch(input, init) {
              calls += 1;
              const resolvedInput =
                typeof input === "string" && input.startsWith("/")
                  ? `http://container${input}`
                  : input;
              const forwardedRequest =
                resolvedInput instanceof Request
                  ? resolvedInput
                  : new Request(resolvedInput, {
                      ...init,
                      ...(init?.body !== undefined ? { duplex: "half" } : {}),
                    });
              return fetchImpl(forwardedRequest);
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

function makeChunkedBody(chunks) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      controller.close();
    },
  });
}

async function withGlobalFetch(fetchImpl, operation) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await operation();
  } finally {
    globalThis.fetch = originalFetch;
  }
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

test("worker deploy config allows arbitrary API CORS preflight", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));
  const origin = "https://client.example";
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
  assert.equal(config.vars?.ALLOWED_ORIGINS, undefined);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
});

test("worker treats unified v1 routes as API paths for CORS preflight", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/v1/chat/completions", {
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
});

test("worker treats optimized chat as a CORS-safe Container API route", async () => {
  const origin = "https://client.example";
  const stub = makeEnv(async (request) => {
    const url = new URL(request.url);
    assert.equal(url.pathname, "/optimize/v1/chat/completions");
    assert.equal(url.search, "?trace=one&trace=two");
    assert.equal(request.method, "POST");
    assert.equal(request.headers.get("Authorization"), "Bearer admin-live-key");
    assert.deepEqual(await request.json(), {
      model: "kimi-code:k3",
      messages: [{ role: "user", content: "hello" }],
      optimization: { mode: "deterministic", trigger_input_tokens: 0 },
    });
    return new Response('{"ok":true}', {
      headers: {
        "Content-Type": "application/json",
        "X-MultiLLM-Optimization": "applied",
      },
    });
  });

  const preflight = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/optimize/v1/chat/completions", {
      method: "OPTIONS",
      headers: { Origin: origin },
    }),
    stub.env,
  );
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(
    preflight.headers.get("Access-Control-Expose-Headers") ?? "",
    /X-MultiLLM-Optimization/,
  );
  assert.equal(stub.getCalls(), 0);

  const response = await worker.fetch(
    new Request(
      "https://multillm-proxy.cserules.workers.dev/optimize/v1/chat/completions?trace=one&trace=two",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: origin,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "kimi-code:k3",
          messages: [{ role: "user", content: "hello" }],
          optimization: { mode: "deterministic", trigger_input_tokens: 0 },
        }),
      },
    ),
    stub.env,
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(response.headers.get("X-MultiLLM-Optimization"), "applied");
  assert.match(
    response.headers.get("Access-Control-Expose-Headers") ?? "",
    /X-MultiLLM-Summary/,
  );
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(stub.getCalls(), 1);
});

test("worker treats mimo provider routes as API paths for CORS preflight", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/mimo/chat/completions", {
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
});

test("worker treats nanogpt provider routes as API paths for CORS preflight", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/nanogpt/v1/chat/completions", {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers":
          "Authorization, Content-Type, X-MultiLLM-Api-Key, X-PAYMENT",
      },
    }),
    stub.env,
  );

  assert.equal(response.status, 204);
  assert.equal(stub.getCalls(), 0);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(
    response.headers.get("Access-Control-Allow-Headers") ?? "",
    /X-MultiLLM-Api-Key/i,
  );
  assert.match(
    response.headers.get("Access-Control-Allow-Headers") ?? "",
    /X-PAYMENT/i,
  );
  assert.match(
    response.headers.get("Access-Control-Expose-Headers") ?? "",
    /X-PAYMENT-RESPONSE/i,
  );
});

test("worker treats navyai provider routes as API paths for CORS preflight", async () => {
  const origin = "https://client.example";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/navyai/v1/messages", {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers":
          "X-MultiLLM-Api-Key, Authorization, X-Api-Key, Anthropic-Version",
      },
    }),
    stub.env,
  );

  assert.equal(response.status, 204);
  assert.equal(stub.getCalls(), 0);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(
    response.headers.get("Access-Control-Allow-Headers"),
    "X-MultiLLM-Api-Key, Authorization, X-Api-Key, Anthropic-Version",
  );
});

test("worker returns CORS-safe v1 API errors when the container fetch fails", async () => {
  const origin = "https://janitorai.com";
  const stub = makeEnv(async () => {
    throw new Error("container unavailable");
  });

  const originalConsoleError = console.error;
  console.error = () => {};

  let response;
  try {
    response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/v1/chat/completions", {
        method: "POST",
        headers: {
          Origin: origin,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "opencode:kimi-k2.5" }),
      }),
      stub.env,
    );
  } finally {
    console.error = originalConsoleError;
  }

  assert.equal(response.status, 502);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.deepEqual(await response.json(), {
    error: "Proxy unavailable",
    message: "The proxy container could not handle the request.",
  });
});

test("worker allows arbitrary API CORS preflight without forwarding", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("preflight should not reach the container");
    },
    { ALLOWED_ORIGINS: "https://allowed.example" },
  );

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
      method: "OPTIONS",
      headers: {
        Origin: "https://client.example",
        "Access-Control-Request-Method": "POST",
      },
    }),
    stub.env,
  );

  assert.equal(response.status, 204);
  assert.equal(stub.getCalls(), 0);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://client.example");
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
    new Request("https://multillm-proxy.cserules.workers.dev/openai/chat/completions", {
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

test("worker adds CORS headers for arbitrary proxied origins", async () => {
  const stub = makeEnv(
    async () => {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
        },
      });
    },
    { ALLOWED_ORIGINS: "https://allowed.example" },
  );

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/openai/chat/completions", {
      method: "POST",
      headers: {
        Origin: "https://client.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model: "kimi-k2.5" }),
    }),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(stub.getCalls(), 1);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://client.example");
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
      new Request("https://multillm-proxy.cserules.workers.dev/openai/chat/completions", {
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

test("container envVars are derived from the live Durable Object env", () => {
  const container = new MultiLLMProxyContainer(
    {},
    {
      ADMIN_API_KEY: "admin-live-key",
      FLASK_SECRET_KEY: "flask-live-secret",
      JWT_SECRET: "jwt-live-secret",
      OPENCODE_GO_API_KEY: "opencode-go-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
      OPENCODE_GO_BASE_URL: "https://opencode.ai/zen/go/v1",
      MIMO_API_KEY: "mimo-live-key",
      NANOGPT_API_KEY: "nanogpt-live-key",
      NANOGPT_BASE_URL: "https://cake.nano-gpt.com/api",
      NANOGPT_BATCH_BASE_URL: "https://api.nano-gpt.com/api/v1",
      NANOGPT_ORIGIN_URL: "https://cake.nano-gpt.com",
      NAVYAI_API_KEY: "navyai-live-key",
      NAVYAI_BASE_URL: "https://api.navy",
      LINKAPI_KEY: "linkapi-live-key",
      LINKAPI_API_KEY: "linkapi-alias-key",
      LINKAPI_BASE_URL: "https://hk.linkapi.ai",
      CODEX_EASY_API_KEY: "codex-easy-live-key",
      CODEX_API_KEY: "codex-easy-alias-key",
      KIMI_CODE_API_KEY: "kimi-code-live-key",
      MIMO_MAX_PROMPT_TOKENS: "1048576",
      MIMO_MAX_OUTPUT_TOKENS: "131072",
      MIMO_MAX_REQUEST_BYTES: "16777216",
      MIMO_RATE_LIMIT_TPM: "1200000",
      NANOGPT_RATE_LIMIT_RPM: "60",
      NANOGPT_MAX_REQUEST_BYTES: "16777216",
      NAVYAI_MAX_REQUEST_BYTES: "33554432",
      LINKAPI_MAX_REQUEST_BYTES: "33554432",
      LINKAPI_RATE_LIMIT_RPM: "120",
      CODEX_EASY_MAX_REQUEST_BYTES: "67108864",
      CODEX_EASY_RATE_LIMIT_RPM: "180",
      KIMI_CODE_MAX_REQUEST_BYTES: "33554432",
      KIMI_CODE_RATE_LIMIT_RPM: "90",
      OPTIMIZER_MAX_REQUEST_BYTES: "8388608",
      OPTIMIZER_SUMMARY_TIMEOUT_SECONDS: "30",
      RATE_LIMIT_ENABLED: "true",
      GUNICORN_GRACEFUL_TIMEOUT: "45",
      GUNICORN_ACCESS_LOG: "-",
    },
  );

  assert.equal(container.envVars.ADMIN_API_KEY, "admin-live-key");
  assert.equal(container.envVars.FLASK_SECRET_KEY, "flask-live-secret");
  assert.equal(container.envVars.JWT_SECRET, "jwt-live-secret");
  assert.equal(container.envVars.OPENCODE_GO_API_KEY, "opencode-go-live-key");
  assert.equal(container.envVars.OPENCODE_API_KEY, "opencode-live-key");
  assert.equal(
    container.envVars.OPENCODE_GO_BASE_URL,
    "https://opencode.ai/zen/go/v1",
  );
  assert.equal(container.envVars.MIMO_API_KEY, "mimo-live-key");
  assert.equal(container.envVars.NANOGPT_API_KEY, "nanogpt-live-key");
  assert.equal(
    container.envVars.NANOGPT_BASE_URL,
    "https://cake.nano-gpt.com/api",
  );
  assert.equal(
    container.envVars.NANOGPT_BATCH_BASE_URL,
    "https://api.nano-gpt.com/api/v1",
  );
  assert.equal(
    container.envVars.NANOGPT_ORIGIN_URL,
    "https://cake.nano-gpt.com",
  );
  assert.equal(container.envVars.NAVYAI_API_KEY, "navyai-live-key");
  assert.equal(container.envVars.NAVYAI_BASE_URL, "https://api.navy");
  assert.equal(container.envVars.LINKAPI_KEY, "linkapi-live-key");
  assert.equal(container.envVars.LINKAPI_API_KEY, "linkapi-alias-key");
  assert.equal(container.envVars.LINKAPI_BASE_URL, "https://hk.linkapi.ai");
  assert.equal(container.envVars.CODEX_EASY_API_KEY, "codex-easy-live-key");
  assert.equal(container.envVars.CODEX_API_KEY, "codex-easy-alias-key");
  assert.equal(container.envVars.KIMI_CODE_API_KEY, "kimi-code-live-key");
  assert.equal(container.envVars.MIMO_MAX_PROMPT_TOKENS, "1048576");
  assert.equal(container.envVars.MIMO_MAX_OUTPUT_TOKENS, "131072");
  assert.equal(container.envVars.MIMO_MAX_REQUEST_BYTES, "16777216");
  assert.equal(container.envVars.MIMO_RATE_LIMIT_TPM, "1200000");
  assert.equal(container.envVars.NANOGPT_RATE_LIMIT_RPM, "60");
  assert.equal(container.envVars.NANOGPT_MAX_REQUEST_BYTES, "16777216");
  assert.equal(container.envVars.NAVYAI_MAX_REQUEST_BYTES, "33554432");
  assert.equal(container.envVars.LINKAPI_MAX_REQUEST_BYTES, "33554432");
  assert.equal(container.envVars.LINKAPI_RATE_LIMIT_RPM, "120");
  assert.equal(container.envVars.CODEX_EASY_MAX_REQUEST_BYTES, "67108864");
  assert.equal(container.envVars.CODEX_EASY_RATE_LIMIT_RPM, "180");
  assert.equal(container.envVars.KIMI_CODE_MAX_REQUEST_BYTES, "33554432");
  assert.equal(container.envVars.KIMI_CODE_RATE_LIMIT_RPM, "90");
  assert.equal(container.envVars.OPTIMIZER_MAX_REQUEST_BYTES, "8388608");
  assert.equal(container.envVars.OPTIMIZER_SUMMARY_TIMEOUT_SECONDS, "30");
  assert.equal(container.envVars.RATE_LIMIT_ENABLED, "true");
  assert.equal(container.envVars.GUNICORN_GRACEFUL_TIMEOUT, "45");
  assert.equal(container.envVars.GUNICORN_ACCESS_LOG, "-");
  assert.equal(container.envVars.AUTH_DB_PATH, "/tmp/auth.sqlite3");
  assert.equal(container.envVars.RATE_LIMIT_DB_PATH, "/tmp/rate_limits.sqlite3");
  assert.equal(container.envVars.MODEL_REGISTRY_DB_PATH, "/tmp/model_registry.sqlite3");
  assert.equal(container.envVars.GUNICORN_WORKERS, "1");
  assert.equal(container.envVars.HOME, "/tmp");
  assert.equal(container.envVars.SERVER_PORT, "8080");
});

test("worker accepts every native LinkAPI caller auth style without reaching the container", async () => {
  const cases = [
    {
      name: "bearer",
      headers: { Authorization: "Bearer admin-live-key" },
      query: "cursor=one&cursor=two",
    },
    {
      name: "Claude x-api-key",
      headers: { "x-api-key": "admin-live-key" },
      query: "cursor=one&cursor=two",
    },
    {
      name: "Gemini x-goog-api-key",
      headers: { "x-goog-api-key": "admin-live-key" },
      query: "cursor=one&cursor=two",
    },
    {
      name: "Gemini query key",
      headers: {},
      query: "key=admin-live-key&cursor=one&cursor=two",
    },
  ];
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async (input) => {
      fetchCalls += 1;
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      const upstreamUrl = new URL(upstreamRequest.url);
      assert.equal(upstreamUrl.origin, "https://api.linkapi.ai");
      assert.equal(upstreamUrl.pathname, "/v1/models");
      assert.deepEqual(upstreamUrl.searchParams.getAll("cursor"), ["one", "two"]);
      assert.equal(upstreamUrl.searchParams.has("key"), false);
      assert.equal(upstreamRequest.headers.get("Authorization"), "Bearer linkapi-live-key");
      assert.equal(upstreamRequest.headers.has("x-api-key"), false);
      assert.equal(upstreamRequest.headers.has("x-goog-api-key"), false);
      return new Response(JSON.stringify({ data: [] }), {
        headers: { "Content-Type": "application/json" },
      });
    },
    async () => {
      for (const authCase of cases) {
        const response = await worker.fetch(
          new Request(
            `https://multillm-proxy.cserules.workers.dev/linkapi/v1/models?${authCase.query}`,
            { headers: authCase.headers },
          ),
          stub.env,
        );
        assert.equal(response.status, 200, authCase.name);
        assert.deepEqual(await response.json(), { data: [] }, authCase.name);
      }
    },
  );

  assert.equal(fetchCalls, cases.length);
  assert.equal(stub.getCalls(), 0);
});

test("worker uses the Workers timing-safe primitive for fixed-length token digests", async () => {
  const originalTimingSafeEqual = crypto.subtle.timingSafeEqual;
  let timingSafeCalls = 0;
  let fetchCalls = 0;
  Object.defineProperty(crypto.subtle, "timingSafeEqual", {
    configurable: true,
    value(left, right) {
      timingSafeCalls += 1;
      const leftBytes = new Uint8Array(left.buffer ?? left, left.byteOffset ?? 0, left.byteLength);
      const rightBytes = new Uint8Array(right.buffer ?? right, right.byteOffset ?? 0, right.byteLength);
      assert.equal(leftBytes.byteLength, 32);
      assert.equal(rightBytes.byteLength, 32);
      return leftBytes.every((value, index) => value === rightBytes[index]);
    },
  });
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );

  try {
    await withGlobalFetch(
      async () => {
        fetchCalls += 1;
        return new Response(null, { status: 204 });
      },
      async () => {
        const accepted = await worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/models", {
            headers: { Authorization: "Bearer admin-live-key" },
          }),
          stub.env,
        );
        const rejected = await worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/models", {
            headers: { Authorization: "Bearer wrong-key" },
          }),
          stub.env,
        );

        assert.equal(accepted.status, 204);
        assert.equal(rejected.status, 401);
      },
    );
  } finally {
    if (originalTimingSafeEqual === undefined) {
      delete crypto.subtle.timingSafeEqual;
    } else {
      Object.defineProperty(crypto.subtle, "timingSafeEqual", {
        configurable: true,
        value: originalTimingSafeEqual,
      });
    }
  }

  assert.equal(timingSafeCalls, 2);
  assert.equal(fetchCalls, 1);
  assert.equal(stub.getCalls(), 0);
});

test("worker preserves native LinkAPI request and SSE bytes for OpenAI, Claude, and Gemini", async () => {
  const scenarios = [
    {
      name: "OpenAI Responses",
      path: "/linkapi/v1/responses?include=usage&include=metadata",
      headers: {
        Authorization: "Bearer admin-live-key",
        "Content-Type": "application/json",
        "Idempotency-Key": "request-123",
        "OpenAI-Beta": "responses=v1",
        "X-Grok-Conv-Id": "must-not-cross-endpoints",
        Cookie: "must-not-leak=yes",
      },
      expectedUrl: "https://api.linkapi.ai/v1/responses?include=usage&include=metadata",
      assertAuth(request) {
        assert.equal(request.headers.get("Authorization"), "Bearer linkapi-live-key");
        assert.equal(request.headers.has("x-api-key"), false);
        assert.equal(request.headers.has("x-goog-api-key"), false);
        assert.equal(request.headers.get("Idempotency-Key"), "request-123");
        assert.equal(request.headers.get("OpenAI-Beta"), "responses=v1");
        assert.equal(request.headers.has("X-Grok-Conv-Id"), false);
      },
      bodyChunks: ['{"model":"gpt-5.5",', '"input":"café"}'],
      responseChunks: ["event: response.created\n", 'data: {"type":"response.created"}\n\n'],
    },
    {
      name: "Claude Messages",
      path: "/linkapi/v1/messages?beta=true",
      headers: {
        "x-api-key": "admin-live-key",
        "Content-Type": "application/json",
        "Anthropic-Beta": "tools-2025-04-04",
        "X-Grok-Conv-Id": "must-not-cross-protocols",
        Cookie: "must-not-leak=yes",
      },
      expectedUrl: "https://api.linkapi.ai/v1/messages?beta=true",
      assertAuth(request) {
        assert.equal(request.headers.has("Authorization"), false);
        assert.equal(request.headers.get("x-api-key"), "linkapi-live-key");
        assert.equal(request.headers.has("x-goog-api-key"), false);
        assert.equal(request.headers.get("anthropic-version"), "2023-06-01");
        assert.equal(request.headers.get("Anthropic-Beta"), "tools-2025-04-04");
        assert.equal(request.headers.has("X-Grok-Conv-Id"), false);
      },
      bodyChunks: ['{"model":"claude-opus-4-7",', '"stream":true}'],
      responseChunks: ["event: message_start\n", 'data: {"type":"message_start"}\n\n'],
    },
    {
      name: "Gemini generateContent",
      path: "/linkapi/v1beta/models/gemini-3.5-flash:streamGenerateContent?alt=sse&alt=json&key=admin-live-key",
      headers: {
        "x-goog-api-key": "admin-live-key",
        "Content-Type": "application/json",
        "x-goog-api-client": "gl-node/22.0.0",
        "X-Grok-Conv-Id": "must-not-cross-protocols",
        Cookie: "must-not-leak=yes",
      },
      expectedUrl:
        "https://api.linkapi.ai/v1beta/models/gemini-3.5-flash:streamGenerateContent?alt=sse&alt=json",
      assertAuth(request) {
        assert.equal(request.headers.has("Authorization"), false);
        assert.equal(request.headers.has("x-api-key"), false);
        assert.equal(request.headers.get("x-goog-api-key"), "linkapi-live-key");
        assert.equal(request.headers.get("x-goog-api-client"), "gl-node/22.0.0");
        assert.equal(request.headers.has("X-Grok-Conv-Id"), false);
      },
      bodyChunks: ['{"contents":[{"parts":[', '{"text":"hello"}]}]}'],
      responseChunks: ["data: {\"candidates\":[", '{"index":0}]}\n\n'],
    },
  ];
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );
  let scenarioIndex = 0;

  await withGlobalFetch(
    async (input) => {
      const scenario = scenarios[scenarioIndex];
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      assert.equal(upstreamRequest.url, scenario.expectedUrl, scenario.name);
      assert.equal(upstreamRequest.method, "POST", scenario.name);
      assert.equal(await upstreamRequest.text(), scenario.bodyChunks.join(""), scenario.name);
      assert.equal(upstreamRequest.headers.has("Cookie"), false, scenario.name);
      scenario.assertAuth(upstreamRequest);

      return new Response(makeChunkedBody(scenario.responseChunks), {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "X-Request-Id": `request-${scenarioIndex}`,
          "Set-Cookie": "must-not-leak=yes",
        },
      });
    },
    async () => {
      for (scenarioIndex = 0; scenarioIndex < scenarios.length; scenarioIndex += 1) {
        const scenario = scenarios[scenarioIndex];
        const response = await worker.fetch(
          new Request(`https://multillm-proxy.cserules.workers.dev${scenario.path}`, {
            method: "POST",
            headers: {
              ...scenario.headers,
              Origin: "https://client.example",
            },
            body: makeChunkedBody(scenario.bodyChunks),
            duplex: "half",
          }),
          stub.env,
        );
        const actualBytes = new Uint8Array(await response.arrayBuffer());
        const expectedBytes = new TextEncoder().encode(scenario.responseChunks.join(""));
        assert.deepEqual(actualBytes, expectedBytes, scenario.name);
        assert.equal(response.headers.get("Content-Type"), "text/event-stream", scenario.name);
        assert.equal(response.headers.get("X-Request-Id"), `request-${scenarioIndex}`, scenario.name);
        assert.equal(response.headers.has("Set-Cookie"), false, scenario.name);
        assert.equal(
          response.headers.get("Access-Control-Allow-Origin"),
          "https://client.example",
          scenario.name,
        );
      }
    },
  );

  assert.equal(stub.getCalls(), 0);
});

test("worker preserves LinkAPI Grok Chat cache affinity on the OpenAI protocol only", async () => {
  const requestBytes =
    '{"model":"grok-4.5","reasoning_effort":"high","messages":[{"role":"user","content":"ping"}],"stream":true}';
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI Grok fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async (input) => {
      fetchCalls += 1;
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      assert.equal(upstreamRequest.url, "https://api.linkapi.ai/v1/chat/completions");
      assert.equal(upstreamRequest.redirect, "manual");
      assert.equal(upstreamRequest.headers.get("Authorization"), "Bearer linkapi-live-key");
      assert.equal(upstreamRequest.headers.get("X-Grok-Conv-Id"), "conversation-123");
      assert.equal(upstreamRequest.headers.has("x-api-key"), false);
      assert.equal(upstreamRequest.headers.has("x-goog-api-key"), false);
      assert.equal(await upstreamRequest.text(), requestBytes);
      return new Response("data: [DONE]\n\n", {
        headers: { "Content-Type": "text/event-stream" },
      });
    },
    async () => {
      const response = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/linkapi/v1/chat/completions",
          {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
              "X-Grok-Conv-Id": "conversation-123",
              "x-api-key": "caller-key-must-not-leak",
              "x-goog-api-key": "caller-key-must-not-leak",
            },
            body: requestBytes,
          },
        ),
        stub.env,
      );

      assert.equal(response.status, 200);
      assert.equal(await response.text(), "data: [DONE]\n\n");
    },
  );

  assert.equal(fetchCalls, 1);
  assert.equal(stub.getCalls(), 0);
});

test("worker never exposes the Gemini upstream key through redirect headers", async () => {
  const upstreamKey = "linkapi-upstream-secret";
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: upstreamKey,
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async (input) => {
      fetchCalls += 1;
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      const upstreamUrl = new URL(upstreamRequest.url);
      assert.equal(upstreamRequest.method, "POST");
      assert.equal(upstreamUrl.searchParams.has("key"), false);
      assert.equal(upstreamRequest.headers.get("x-goog-api-key"), upstreamKey);
      assert.doesNotMatch(upstreamRequest.url, new RegExp(upstreamKey, "i"));
      return new Response("redirect refused", {
        status: 302,
        headers: {
          Location: `https://api.linkapi.ai/redirect?key=${upstreamKey}`,
          "X-Request-Id": "request-redirect",
        },
      });
    },
    async () => {
      const response = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/linkapi/v1beta/models/gemini-3.5-flash:generateContent?key=admin-live-key",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: '{"contents":[{"parts":[{"text":"hello"}]}]}',
          },
        ),
        stub.env,
      );
      const body = await response.text();
      const downstreamSurface = `${JSON.stringify([...response.headers.entries()])}\n${body}`;

      assert.equal(response.status, 302);
      assert.equal(response.headers.get("Location"), null);
      assert.equal(response.headers.get("X-Request-Id"), "request-redirect");
      assert.doesNotMatch(downstreamSurface, new RegExp(upstreamKey, "i"));
    },
  );

  assert.equal(fetchCalls, 1);
  assert.equal(stub.getCalls(), 0);
});

test("worker keeps Gemini provider secrets out of upstream URLs and failure logs", async () => {
  const upstreamKey = "linkapi-upstream-secret";
  const errorCalls = [];
  const originalConsoleError = console.error;
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: upstreamKey,
    },
  );

  console.error = (...args) => errorCalls.push(args);
  try {
    await withGlobalFetch(
      async (input) => {
        const upstreamRequest = input instanceof Request ? input : new Request(input);
        const upstreamUrl = new URL(upstreamRequest.url);
        assert.deepEqual(upstreamUrl.searchParams.getAll("alt"), ["sse", "json"]);
        assert.equal(upstreamUrl.searchParams.has("key"), false);
        assert.equal(upstreamRequest.headers.get("x-goog-api-key"), upstreamKey);
        assert.doesNotMatch(upstreamRequest.url, new RegExp(upstreamKey, "i"));
        throw new Error(`Gemini transport failed while using ${upstreamKey}`);
      },
      async () => {
        const response = await worker.fetch(
          new Request(
            "https://multillm-proxy.cserules.workers.dev/linkapi/v1beta/models/gemini-3.5-flash:generateContent?alt=sse&key=admin-live-key&alt=json",
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: '{"contents":[{"parts":[{"text":"hello"}]}]}',
            },
          ),
          stub.env,
        );

        assert.equal(response.status, 502);
      },
    );
  } finally {
    console.error = originalConsoleError;
  }

  assert.deepEqual(errorCalls, [[{
    event: "direct_linkapi_fetch_failed",
    errorName: "Error",
  }]]);
  assert.doesNotMatch(JSON.stringify(errorCalls), new RegExp(upstreamKey, "i"));
  assert.equal(stub.getCalls(), 0);
});

test("worker streams gated LinkAPI request and response bodies without retrying the generation POST", async () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let releaseRequest;
  let releaseResponse;
  let resolveUpstreamFirstChunk;
  const requestGate = new Promise((resolve) => {
    releaseRequest = resolve;
  });
  const responseGate = new Promise((resolve) => {
    releaseResponse = resolve;
  });
  const upstreamFirstChunk = new Promise((resolve) => {
    resolveUpstreamFirstChunk = resolve;
  });
  const requestBody = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('{"model":"gpt-5.5",'));
      requestGate.then(() => {
        controller.enqueue(encoder.encode('"input":"hello"}'));
        controller.close();
      });
    },
  });
  const responseBody = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode("event: response.created\n\n"));
      responseGate.then(() => {
        controller.enqueue(encoder.encode("event: response.completed\n\n"));
        controller.close();
      });
    },
  });
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );
  let fetchCalls = 0;

  const withDeadline = async (promise, label) => {
    let timeout;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error(`${label} was buffered`)), 500);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  };

  try {
    await withGlobalFetch(
      async (input) => {
        fetchCalls += 1;
        const upstreamRequest = input instanceof Request ? input : new Request(input);
        const reader = upstreamRequest.body.getReader();
        const first = await reader.read();
        assert.equal(decoder.decode(first.value), '{"model":"gpt-5.5",');
        assert.equal(first.done, false);
        resolveUpstreamFirstChunk();

        await requestGate;
        const second = await reader.read();
        assert.equal(decoder.decode(second.value), '"input":"hello"}');
        assert.equal(second.done, false);
        assert.equal((await reader.read()).done, true);
        return new Response(responseBody, {
          headers: { "Content-Type": "text/event-stream" },
        });
      },
      async () => {
        const pendingResponse = worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/responses", {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
            },
            body: requestBody,
            duplex: "half",
          }),
          stub.env,
        );

        await withDeadline(upstreamFirstChunk, "LinkAPI request body");
        assert.equal(fetchCalls, 1);
        releaseRequest();

        const response = await withDeadline(pendingResponse, "LinkAPI response headers");
        const responseReader = response.body.getReader();
        const first = await withDeadline(responseReader.read(), "LinkAPI first response chunk");
        assert.equal(decoder.decode(first.value), "event: response.created\n\n");
        assert.equal(first.done, false);
        assert.equal(fetchCalls, 1);

        releaseResponse();
        const second = await responseReader.read();
        assert.equal(decoder.decode(second.value), "event: response.completed\n\n");
        assert.equal(second.done, false);
        assert.equal((await responseReader.read()).done, true);
      },
    );
  } finally {
    releaseRequest();
    releaseResponse();
  }

  assert.equal(fetchCalls, 1);
  assert.equal(stub.getCalls(), 0);
});

test("worker propagates caller aborts to the direct LinkAPI fetch", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("LinkAPI fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );
  const controller = new AbortController();
  let upstreamSawAbort = false;

  await withGlobalFetch(
    async (input) => {
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      await new Promise((resolve) => {
        if (upstreamRequest.signal.aborted) {
          upstreamSawAbort = true;
          resolve();
          return;
        }
        upstreamRequest.signal.addEventListener(
          "abort",
          () => {
            upstreamSawAbort = true;
            resolve();
          },
          { once: true },
        );
      });
      return new Response(null, { status: 204 });
    },
    async () => {
      const pendingResponse = worker.fetch(
        new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/models", {
          headers: { Authorization: "Bearer admin-live-key" },
          signal: controller.signal,
        }),
        stub.env,
      );
      await Promise.resolve();
      controller.abort();
      assert.equal((await pendingResponse).status, 204);
    },
  );

  assert.equal(upstreamSawAbort, true);
  assert.equal(stub.getCalls(), 0);
});

test("worker constrains LinkAPI base URL overrides to HTTPS origins", async () => {
  const cases = [
    ["https://linkapi.ai", "https://linkapi.ai/v1/models"],
    ["https://api.linkapi.ai", "https://api.linkapi.ai/v1/models"],
    ["https://hk.linkapi.ai/", "https://hk.linkapi.ai/v1/models"],
    ["https://jp.linkapi.ai", "https://jp.linkapi.ai/v1/models"],
    ["https://linkapi.cc", "https://linkapi.cc/v1/models"],
    ["https://linkapi.pro", "https://linkapi.pro/v1/models"],
    ["https://proxy.example", "https://api.linkapi.ai/v1/models"],
    ["http://internal.example", "https://api.linkapi.ai/v1/models"],
    ["https://user:password@api.linkapi.ai", "https://api.linkapi.ai/v1/models"],
    ["https://api.linkapi.ai:8443", "https://api.linkapi.ai/v1/models"],
    ["https://api.linkapi.ai/proxy", "https://api.linkapi.ai/v1/models"],
    ["https://api.linkapi.ai?region=hk", "https://api.linkapi.ai/v1/models"],
    ["https://api.linkapi.ai#fragment", "https://api.linkapi.ai/v1/models"],
    ["not a URL", "https://api.linkapi.ai/v1/models"],
  ];
  let caseIndex = 0;

  await withGlobalFetch(
    async (input) => {
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      assert.equal(upstreamRequest.url, cases[caseIndex][1]);
      return new Response(null, { status: 204 });
    },
    async () => {
      for (caseIndex = 0; caseIndex < cases.length; caseIndex += 1) {
        const [baseUrl] = cases[caseIndex];
        const stub = makeEnv(
          async () => {
            throw new Error("LinkAPI fast path should bypass the container");
          },
          {
            ADMIN_API_KEY: "admin-live-key",
            LINKAPI_KEY: "linkapi-live-key",
            LINKAPI_BASE_URL: baseUrl,
          },
        );
        const response = await worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/models", {
            headers: { Authorization: "Bearer admin-live-key" },
          }),
          stub.env,
        );
        assert.equal(response.status, 204);
        assert.equal(stub.getCalls(), 0);
      }
    },
  );
});

test("worker returns sanitized CORS-safe LinkAPI auth and configuration errors", async () => {
  const origin = "https://client.example";
  const invalidAuthStub = makeEnv(
    async () => {
      throw new Error("invalid auth must not call the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      LINKAPI_KEY: "linkapi-live-key",
    },
  );
  const invalidAuthResponse = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/models", {
      headers: { Authorization: "Bearer wrong-key", Origin: origin },
    }),
    invalidAuthStub.env,
  );
  assert.equal(invalidAuthResponse.status, 401);
  assert.equal(invalidAuthResponse.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(invalidAuthStub.getCalls(), 0);

  const missingKeyStub = makeEnv(
    async () => {
      throw new Error("missing key must not call the container");
    },
    { ADMIN_API_KEY: "admin-live-key" },
  );
  const missingKeyResponse = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/models", {
      headers: { "x-api-key": "admin-live-key", Origin: origin },
    }),
    missingKeyStub.env,
  );
  const missingKeyBody = await missingKeyResponse.text();
  assert.equal(missingKeyResponse.status, 500);
  assert.equal(missingKeyResponse.headers.get("Access-Control-Allow-Origin"), origin);
  assert.doesNotMatch(missingKeyBody, /LINKAPI|API_KEY|linkapi-live-key/i);
  assert.equal(missingKeyStub.getCalls(), 0);
});

test("worker answers LinkAPI CORS preflight with native SDK headers", async () => {
  const origin = "https://client.example";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });
  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/linkapi/v1/messages", {
      method: "OPTIONS",
      headers: { Origin: origin },
    }),
    stub.env,
  );

  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(response.headers.get("Access-Control-Allow-Headers") ?? "", /X-Api-Key/i);
  assert.match(response.headers.get("Access-Control-Allow-Headers") ?? "", /X-Goog-Api-Key/i);
  assert.match(response.headers.get("Access-Control-Allow-Headers") ?? "", /Anthropic-Version/i);
  assert.equal(stub.getCalls(), 0);
});

test("worker deploy config keeps LinkAPI secrets private and samples observability", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(config.vars?.LINKAPI_BASE_URL, "https://api.linkapi.ai");
  assert.equal(config.vars?.LINKAPI_KEY, undefined);
  assert.equal(config.vars?.LINKAPI_API_KEY, undefined);
  assert.equal(config.compatibility_flags?.includes("enable_request_signal"), true);
  assert.equal(config.compatibility_flags?.includes("request_signal_passthrough"), true);
  assert.equal(config.compatibility_date, "2026-07-10");
  assert.equal(config.observability?.enabled, true);
  assert.equal(config.observability?.logs?.enabled, true);
  assert.equal(config.observability?.logs?.head_sampling_rate, 0.05);
  assert.equal(config.observability?.logs?.invocation_logs, false);
  assert.equal(config.observability?.traces?.enabled, false);
});

test("worker proxies Codex Everywhere Responses and Chat SSE bytes without rewriting Grok reasoning", async () => {
  const scenarios = [
    {
      path: "/codex-easy/v1/responses?include=usage&KEY=caller-secret&include=metadata&key=second-secret",
      expectedUrl: "https://codex-easy.ai/v1/responses?include=usage&include=metadata",
      requestBytes:
        '{"model":"grok-4.5","reasoning":{"effort":"high"},"prompt_cache_key":"conversation-123","input":"café","stream":true}',
      conversationHeader: null,
      responseChunks: [
        "event: response.created\n",
        'data: {"type":"response.created","response":{"id":"resp_1"}}\n\n',
      ],
    },
    {
      path: "/codex-easy/v1/chat/completions?trace=one&trace=two",
      expectedUrl: "https://codex-easy.ai/v1/chat/completions?trace=one&trace=two",
      requestBytes:
        '{"model":"grok-4.5","reasoning_effort":"high","messages":[{"role":"user","content":"ping"}],"stream":true}',
      conversationHeader: "conversation-123",
      responseChunks: [
        'data: {"id":"chatcmpl_1","choices":[{"delta":{"content":"pong"}}]}\n\n',
        "data: [DONE]\n\n",
      ],
    },
  ];
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      CODEX_EASY_API_KEY: "codex-easy-primary-key",
      CODEX_API_KEY: "codex-easy-alias-key",
    },
  );
  let scenarioIndex = 0;
  let fetchCalls = 0;

  await withGlobalFetch(
    async (input) => {
      fetchCalls += 1;
      const scenario = scenarios[scenarioIndex];
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      assert.equal(upstreamRequest.url, scenario.expectedUrl);
      assert.equal(upstreamRequest.method, "POST");
      assert.equal(upstreamRequest.redirect, "manual");
      assert.equal(await upstreamRequest.text(), scenario.requestBytes);
      assert.equal(
        upstreamRequest.headers.get("Authorization"),
        "Bearer codex-easy-primary-key",
      );
      assert.equal(upstreamRequest.headers.get("OpenAI-Beta"), "responses=v1");
      assert.equal(upstreamRequest.headers.get("OpenAI-Organization"), "org_123");
      assert.equal(upstreamRequest.headers.get("OpenAI-Project"), "proj_123");
      assert.equal(upstreamRequest.headers.get("Idempotency-Key"), "idempotent-123");
      assert.equal(upstreamRequest.headers.get("X-Client-Request-ID"), "client-request-123");
      assert.equal(upstreamRequest.headers.get("x-stainless-lang"), "js");
      assert.equal(upstreamRequest.headers.get("x-grok-conv-id"), scenario.conversationHeader);
      assert.equal(upstreamRequest.headers.has("x-api-key"), false);
      assert.equal(upstreamRequest.headers.has("x-goog-api-key"), false);
      assert.equal(upstreamRequest.headers.has("Cookie"), false);

      return new Response(makeChunkedBody(scenario.responseChunks), {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-store",
          "OpenAI-Processing-Ms": "42",
          "X-Request-Id": `request-${scenarioIndex}`,
          "X-RateLimit-Remaining-Requests": "9",
          "Set-Cookie": "must-not-leak=yes",
          Location: "https://untrusted.example/redirect",
          "Content-Encoding": "gzip",
          "Content-Length": "999",
        },
      });
    },
    async () => {
      for (scenarioIndex = 0; scenarioIndex < scenarios.length; scenarioIndex += 1) {
        const scenario = scenarios[scenarioIndex];
        const response = await worker.fetch(
          new Request(`https://multillm-proxy.cserules.workers.dev${scenario.path}`, {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
              "OpenAI-Beta": "responses=v1",
              "OpenAI-Organization": "org_123",
              "OpenAI-Project": "proj_123",
              "Idempotency-Key": "idempotent-123",
              "X-Client-Request-ID": "client-request-123",
              "x-stainless-lang": "js",
              ...(scenario.conversationHeader
                ? { "x-grok-conv-id": scenario.conversationHeader }
                : {}),
              "x-api-key": "must-not-leak",
              "x-goog-api-key": "must-not-leak",
              Cookie: "must-not-leak=yes",
              Origin: "https://client.example",
            },
            body: makeChunkedBody([scenario.requestBytes]),
            duplex: "half",
          }),
          stub.env,
        );

        assert.equal(response.status, 200);
        assert.equal(await response.text(), scenario.responseChunks.join(""));
        assert.equal(response.headers.get("Content-Type"), "text/event-stream");
        assert.equal(response.headers.get("Cache-Control"), "no-store");
        assert.equal(response.headers.get("OpenAI-Processing-Ms"), "42");
        assert.equal(response.headers.get("X-Request-Id"), `request-${scenarioIndex}`);
        assert.equal(response.headers.get("X-RateLimit-Remaining-Requests"), "9");
        assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://client.example");
        assert.equal(response.headers.has("Set-Cookie"), false);
        assert.equal(response.headers.has("Location"), false);
        assert.equal(response.headers.has("Content-Encoding"), false);
        assert.equal(response.headers.has("Content-Length"), false);
      }
    },
  );

  assert.equal(fetchCalls, scenarios.length);
  assert.equal(stub.getCalls(), 0);
});

test("worker uses the Codex Everywhere key alias for the model catalog", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      CODEX_API_KEY: "codex-easy-alias-key",
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async (input) => {
      fetchCalls += 1;
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      assert.equal(upstreamRequest.url, "https://codex-easy.ai/v1/models?after=one&after=two");
      assert.equal(upstreamRequest.method, "GET");
      assert.equal(upstreamRequest.body, null);
      assert.equal(upstreamRequest.headers.get("Authorization"), "Bearer codex-easy-alias-key");
      return new Response('{"object":"list","data":[]}', {
        headers: { "Content-Type": "application/json" },
      });
    },
    async () => {
      const response = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/codex-easy/v1/models?after=one&key=caller&after=two&KeY=caller-two",
          { headers: { Authorization: "Bearer admin-live-key" } },
        ),
        stub.env,
      );
      assert.deepEqual(await response.json(), { object: "list", data: [] });
    },
  );

  assert.equal(fetchCalls, 1);
  assert.equal(stub.getCalls(), 0);
});

test("worker authenticates Codex Everywhere callers before reporting configuration", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere auth failures must bypass the container");
    },
    { ADMIN_API_KEY: "admin-live-key" },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async () => {
      fetchCalls += 1;
      return new Response(null, { status: 204 });
    },
    async () => {
      for (const headers of [
        {},
        { Authorization: "Basic admin-live-key" },
        { Authorization: "Bearer wrong-key" },
        { "x-api-key": "admin-live-key" },
        { "x-goog-api-key": "admin-live-key" },
      ]) {
        const response = await worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/codex-easy/v1/models", {
            headers,
          }),
          stub.env,
        );
        assert.equal(response.status, 401);
      }

      const missingKey = await worker.fetch(
        new Request("https://multillm-proxy.cserules.workers.dev/codex-easy/v1/models", {
          headers: { Authorization: "Bearer admin-live-key" },
        }),
        stub.env,
      );
      const missingKeyBody = await missingKey.text();
      assert.equal(missingKey.status, 500);
      assert.doesNotMatch(missingKeyBody, /CODEX|API_KEY|codex-easy/i);
    },
  );

  assert.equal(fetchCalls, 0);
  assert.equal(stub.getCalls(), 0);
});

test("worker restricts Codex Everywhere to canonical documented paths", async () => {
  const allowedPaths = [
    ["GET", "/codex-easy/v1/models"],
    ["POST", "/codex-easy/v1/responses"],
    ["POST", "/codex-easy/v1/chat/completions"],
    ["POST", "/codex-easy/v1/images"],
    ["POST", "/codex-easy/v1/images/generations"],
    ["POST", "/codex-easy/v1/images/edits/async"],
  ];
  const rejectedPaths = [
    "/codex-easy",
    "/codex-easy/",
    "/codex-easy/v1/models/",
    "/codex-easy/v1/files",
    "/codex-easy/v1/chat/completions/extra",
    "/codex-easy/v1%2Fmodels",
    "/codex-easy/v1%5Cmodels",
    "/codex-easy%2Fv1/models",
    "/codex-easy%252Fv1/models",
    "/cod%65x-easy%252Fv1/models",
    "/codex-easy/v1/images/%2Fadmin",
    "/codex-easy/v1/images//generations",
  ];
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere route validation must bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      CODEX_EASY_API_KEY: "codex-easy-live-key",
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async () => {
      fetchCalls += 1;
      return new Response(null, { status: 204 });
    },
    async () => {
      for (const [method, path] of allowedPaths) {
        const bodyAllowed = method !== "GET";
        const response = await worker.fetch(
          new Request(`https://multillm-proxy.cserules.workers.dev${path}`, {
            method,
            headers: {
              Authorization: "Bearer admin-live-key",
              ...(bodyAllowed ? { "Content-Type": "application/json" } : {}),
            },
            ...(bodyAllowed ? { body: "{}" } : {}),
          }),
          stub.env,
        );
        assert.equal(response.status, 204, path);
      }

      for (const path of rejectedPaths) {
        const response = await worker.fetch(
          new Request(`https://multillm-proxy.cserules.workers.dev${path}`, {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
            },
            body: "{}",
          }),
          stub.env,
        );
        assert.equal(response.status, 404, path);
      }
    },
  );

  assert.equal(fetchCalls, allowedPaths.length);
  assert.equal(stub.getCalls(), 0);
});

test("worker preserves Codex Everywhere multipart uploads and binary image responses", async () => {
  const boundary = "----multillm-boundary";
  const requestBytes = new TextEncoder().encode(
    `--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\ngrok-image\r\n` +
      `--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="input.png"\r\n` +
      "Content-Type: image/png\r\n\r\nPNG-BYTES\r\n" +
      `--${boundary}--\r\n`,
  );
  const responseBytes = Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3]);
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere image fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      CODEX_EASY_API_KEY: "codex-easy-live-key",
    },
  );

  await withGlobalFetch(
    async (input) => {
      const upstreamRequest = input instanceof Request ? input : new Request(input);
      assert.equal(upstreamRequest.url, "https://codex-easy.ai/v1/images/edits");
      assert.equal(
        upstreamRequest.headers.get("Content-Type"),
        `multipart/form-data; boundary=${boundary}`,
      );
      assert.deepEqual(new Uint8Array(await upstreamRequest.arrayBuffer()), requestBytes);
      return new Response(responseBytes, {
        headers: {
          "Content-Type": "image/png",
          "Content-Disposition": 'attachment; filename="result.png"',
          "Request-Id": "image-request-1",
          "Content-Length": String(responseBytes.byteLength),
          "Set-Cookie": "must-not-leak=yes",
        },
      });
    },
    async () => {
      const response = await worker.fetch(
        new Request("https://multillm-proxy.cserules.workers.dev/codex-easy/v1/images/edits", {
          method: "POST",
          headers: {
            Authorization: "Bearer admin-live-key",
            "Content-Type": `multipart/form-data; boundary=${boundary}`,
          },
          body: requestBytes,
        }),
        stub.env,
      );

      assert.deepEqual(new Uint8Array(await response.arrayBuffer()), responseBytes);
      assert.equal(response.headers.get("Content-Type"), "image/png");
      assert.equal(response.headers.get("Content-Disposition"), 'attachment; filename="result.png"');
      assert.equal(response.headers.get("Request-Id"), "image-request-1");
      assert.equal(response.headers.has("Content-Length"), false);
      assert.equal(response.headers.has("Set-Cookie"), false);
    },
  );

  assert.equal(stub.getCalls(), 0);
});

test("worker streams gated Codex Everywhere bodies, propagates aborts, and fetches once", async () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let releaseRequest;
  let releaseResponse;
  let resolveFirstRequestChunk;
  const requestGate = new Promise((resolve) => {
    releaseRequest = resolve;
  });
  const responseGate = new Promise((resolve) => {
    releaseResponse = resolve;
  });
  const firstRequestChunk = new Promise((resolve) => {
    resolveFirstRequestChunk = resolve;
  });
  const requestBody = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('{"model":"grok-4.5",'));
      requestGate.then(() => {
        controller.enqueue(encoder.encode('"reasoning":{"effort":"high"}}'));
        controller.close();
      });
    },
  });
  const responseBody = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode("event: response.created\n\n"));
      responseGate.then(() => {
        controller.enqueue(encoder.encode("event: response.completed\n\n"));
        controller.close();
      });
    },
  });
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere streaming must bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      CODEX_EASY_API_KEY: "codex-easy-live-key",
    },
  );
  const controller = new AbortController();
  let fetchCalls = 0;
  let upstreamSawAbort = false;

  const withDeadline = async (promise, label) => {
    let timeout;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error(`${label} was buffered`)), 500);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  };

  try {
    await withGlobalFetch(
      async (input) => {
        fetchCalls += 1;
        const upstreamRequest = input instanceof Request ? input : new Request(input);
        upstreamRequest.signal.addEventListener(
          "abort",
          () => {
            upstreamSawAbort = true;
          },
          { once: true },
        );
        const reader = upstreamRequest.body.getReader();
        const first = await reader.read();
        assert.equal(decoder.decode(first.value), '{"model":"grok-4.5",');
        resolveFirstRequestChunk();
        await requestGate;
        const second = await reader.read();
        assert.equal(decoder.decode(second.value), '"reasoning":{"effort":"high"}}');
        assert.equal((await reader.read()).done, true);
        return new Response(responseBody, {
          headers: { "Content-Type": "text/event-stream" },
        });
      },
      async () => {
        const pendingResponse = worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/codex-easy/v1/responses", {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
            },
            body: requestBody,
            duplex: "half",
            signal: controller.signal,
          }),
          stub.env,
        );

        await withDeadline(firstRequestChunk, "Codex Everywhere request body");
        assert.equal(fetchCalls, 1);
        releaseRequest();
        const response = await withDeadline(pendingResponse, "Codex Everywhere response headers");
        const reader = response.body.getReader();
        const first = await withDeadline(reader.read(), "Codex Everywhere response body");
        assert.equal(decoder.decode(first.value), "event: response.created\n\n");
        controller.abort();
        await Promise.resolve();
        assert.equal(upstreamSawAbort, true);
        releaseResponse();
        const second = await reader.read();
        assert.equal(decoder.decode(second.value), "event: response.completed\n\n");
        assert.equal((await reader.read()).done, true);
      },
    );
  } finally {
    releaseRequest();
    releaseResponse();
  }

  assert.equal(fetchCalls, 1);
  assert.equal(stub.getCalls(), 0);
});

test("worker never retries, follows redirects, or accesses Cache for Codex Everywhere", async () => {
  const originalCaches = globalThis.caches;
  let cacheReads = 0;
  Object.defineProperty(globalThis, "caches", {
    configurable: true,
    get() {
      cacheReads += 1;
      throw new Error("Cache API must not be accessed");
    },
  });
  const cases = [429, 503, 307];
  let caseIndex = 0;
  let fetchCalls = 0;
  const stub = makeEnv(
    async () => {
      throw new Error("Codex Everywhere fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      CODEX_EASY_API_KEY: "codex-easy-live-key",
    },
  );

  try {
    await withGlobalFetch(
      async (input) => {
        fetchCalls += 1;
        const upstreamRequest = input instanceof Request ? input : new Request(input);
        assert.equal(upstreamRequest.redirect, "manual");
        const status = cases[caseIndex];
        return new Response(status === 307 ? "redirect refused" : "upstream unavailable", {
          status,
          headers: {
            "Content-Type": "text/plain",
            "Retry-After": "5",
            Location: "https://untrusted.example/redirect",
          },
        });
      },
      async () => {
        for (caseIndex = 0; caseIndex < cases.length; caseIndex += 1) {
          const callsBefore = fetchCalls;
          const response = await worker.fetch(
            new Request("https://multillm-proxy.cserules.workers.dev/codex-easy/v1/responses", {
              method: "POST",
              headers: {
                Authorization: "Bearer admin-live-key",
                "Content-Type": "application/json",
              },
              body: '{"model":"grok-4.5","reasoning":{"effort":"high"}}',
            }),
            stub.env,
          );
          assert.equal(response.status, cases[caseIndex]);
          assert.equal(fetchCalls - callsBefore, 1);
          assert.equal(response.headers.get("Retry-After"), "5");
          assert.equal(response.headers.has("Location"), false);
        }
      },
    );
  } finally {
    if (originalCaches === undefined) {
      delete globalThis.caches;
    } else {
      Object.defineProperty(globalThis, "caches", {
        configurable: true,
        value: originalCaches,
        writable: true,
      });
    }
  }

  assert.equal(fetchCalls, cases.length);
  assert.equal(cacheReads, 0);
  assert.equal(stub.getCalls(), 0);
});

test("worker answers Codex Everywhere CORS preflight with OpenAI SDK headers", async () => {
  const origin = "https://client.example";
  const stub = makeEnv(async () => {
    throw new Error("preflight should not reach the container");
  });
  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/codex-easy/v1/responses", {
      method: "OPTIONS",
      headers: { Origin: origin },
    }),
    stub.env,
  );

  const allowedHeaders = response.headers.get("Access-Control-Allow-Headers") ?? "";
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(allowedHeaders, /OpenAI-Beta/i);
  assert.match(allowedHeaders, /OpenAI-Organization/i);
  assert.match(allowedHeaders, /OpenAI-Project/i);
  assert.match(allowedHeaders, /Idempotency-Key/i);
  assert.match(allowedHeaders, /X-Client-Request-ID/i);
  assert.equal(stub.getCalls(), 0);
});

test("worker deploy config never stores Codex Everywhere secrets in plaintext", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(config.vars?.CODEX_EASY_API_KEY, undefined);
  assert.equal(config.vars?.CODEX_API_KEY, undefined);
});

test("worker authenticates Kimi Code at the edge and streams chat through the container", async () => {
  const requestBytes =
    '{"model":"k3","messages":[{"role":"assistant","content":"","reasoning_content":"thinking","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"ok"}],"reasoning_effort":"max","prompt_cache_key":"session-123","stream":true}';
  const responseChunks = [
    'data: {"id":"chatcmpl_1","choices":[{"delta":{"reasoning_content":"work"}}]}\n\n',
    'data: {"id":"chatcmpl_1","choices":[{"delta":{"content":"done"}}]}\n\n',
    "data: [DONE]\n\n",
  ];
  const stub = makeEnv(
    async (containerRequest) => {
      assert.equal(
        containerRequest.url,
        "https://multillm-proxy.cserules.workers.dev/kimi-code/v1/chat/completions?trace=one&key=caller-secret&trace=two&KEY=caller-two",
      );
      assert.equal(containerRequest.method, "POST");
      assert.equal(await containerRequest.text(), requestBytes);
      assert.equal(containerRequest.headers.get("Authorization"), "Bearer admin-live-key");
      assert.equal(containerRequest.headers.get("User-Agent"), "KimiCLI/1.2.3");
      return new Response(makeChunkedBody(responseChunks), {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-store",
          "X-Request-Id": "request-kimi-1",
          "X-RateLimit-Remaining-Requests": "9",
        },
      });
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      KIMI_CODE_API_KEY: "kimi-code-live-key",
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async () => {
      fetchCalls += 1;
      throw new Error("Kimi Code chat must not use Worker egress");
    },
    async () => {
      const response = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/kimi-code/v1/chat/completions?trace=one&key=caller-secret&trace=two&KEY=caller-two",
          {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
              "User-Agent": "KimiCLI/1.2.3",
              "Accept-Language": "en-US",
              "OpenAI-Beta": "chat=v1",
              "OpenAI-Project": "proj_123",
              "Idempotency-Key": "idempotent-123",
              "X-Client-Request-ID": "client-request-123",
              "x-stainless-lang": "js",
              "x-api-key": "must-not-leak",
              "x-goog-api-key": "must-not-leak",
              Cookie: "must-not-leak=yes",
              Origin: "https://client.example",
            },
            body: makeChunkedBody([requestBytes]),
            duplex: "half",
          },
        ),
        stub.env,
      );

      assert.equal(response.status, 200);
      assert.equal(await response.text(), responseChunks.join(""));
      assert.equal(response.headers.get("Content-Type"), "text/event-stream");
      assert.equal(response.headers.get("Cache-Control"), "no-store");
      assert.equal(response.headers.get("X-Request-Id"), "request-kimi-1");
      assert.equal(response.headers.get("X-RateLimit-Remaining-Requests"), "9");
      assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://client.example");
    },
  );

  assert.equal(fetchCalls, 0);
  assert.equal(stub.getCalls(), 1);
});

test("worker serves the configured Kimi Code model catalog without upstream or container I/O", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("Kimi Code catalog should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      KIMI_CODE_API_KEY: "kimi-code-live-key",
    },
  );
  let fetchCalls = 0;

  await withGlobalFetch(
    async () => {
      fetchCalls += 1;
      throw new Error("Kimi Code catalog must not use Worker egress");
    },
    async () => {
      const response = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/kimi-code/v1/models?after=one&key=caller&after=two&KeY=caller-two",
          { headers: { Authorization: "Bearer admin-live-key" } },
        ),
        stub.env,
      );
      assert.deepEqual(await response.json(), {
        object: "list",
        data: [{ id: "k3", object: "model", owned_by: "kimi" }],
      });
    },
  );

  assert.equal(fetchCalls, 0);
  assert.equal(stub.getCalls(), 0);
});

test("worker authenticates Kimi Code before configuration and restricts exact methods and paths", async () => {
  const configuredStub = makeEnv(
    async () => {
      throw new Error("invalid Kimi Code paths must bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      KIMI_CODE_API_KEY: "kimi-code-live-key",
    },
  );
  const missingSecretStub = makeEnv(
    async () => {
      throw new Error("Kimi Code auth failures must bypass the container");
    },
    { ADMIN_API_KEY: "admin-live-key" },
  );
  const rejectedCases = [
    ["GET", "/kimi-code"],
    ["GET", "/kimi-code/"],
    ["POST", "/kimi-code/v1/models"],
    ["GET", "/kimi-code/v1/chat/completions"],
    ["POST", "/kimi-code/v1/responses"],
    ["POST", "/kimi-code/v1/chat/completions/extra"],
    ["GET", "/kimi-code/v1/models/"],
    ["GET", "/kimi-code/v1%2Fmodels"],
    ["GET", "/kimi-code%2Fv1/models"],
    ["GET", "/kimi-code%252Fv1/models"],
    ["GET", "/k%69mi-code%252Fv1/models"],
    ["GET", "/kimi-code/v1/models%253Fkey%253Dsecret"],
  ];
  let fetchCalls = 0;

  await withGlobalFetch(
    async () => {
      fetchCalls += 1;
      return new Response(null, { status: 204 });
    },
    async () => {
      const unauthorized = await worker.fetch(
        new Request("https://multillm-proxy.cserules.workers.dev/kimi-code/v1/models"),
        missingSecretStub.env,
      );
      assert.equal(unauthorized.status, 401);

      const missingSecret = await worker.fetch(
        new Request("https://multillm-proxy.cserules.workers.dev/kimi-code/v1/models", {
          headers: { Authorization: "Bearer admin-live-key" },
        }),
        missingSecretStub.env,
      );
      const missingBody = await missingSecret.text();
      assert.equal(missingSecret.status, 500);
      assert.doesNotMatch(missingBody, /KIMI|API_KEY|kimi-code/i);

      for (const [method, path] of rejectedCases) {
        const hasBody = method === "POST";
        const response = await worker.fetch(
          new Request(`https://multillm-proxy.cserules.workers.dev${path}`, {
            method,
            headers: {
              Authorization: "Bearer admin-live-key",
              ...(hasBody ? { "Content-Type": "application/json" } : {}),
            },
            ...(hasBody ? { body: "{}" } : {}),
          }),
          configuredStub.env,
        );
        assert.equal(response.status, 404, `${method} ${path}`);
      }
    },
  );

  assert.equal(fetchCalls, 0);
  assert.equal(configuredStub.getCalls(), 0);
  assert.equal(missingSecretStub.getCalls(), 0);
});

test("worker returns one Kimi Code container failure with strict CORS and no Cache use", async () => {
  const originalCaches = globalThis.caches;
  let cacheReads = 0;
  Object.defineProperty(globalThis, "caches", {
    configurable: true,
    get() {
      cacheReads += 1;
      throw new Error("Cache API must not be accessed");
    },
  });
  const stub = makeEnv(
    async () =>
      new Response("upstream unavailable", {
        status: 503,
        headers: {
          "Content-Type": "text/plain",
          "Retry-After": "5",
        },
      }),
    {
      ADMIN_API_KEY: "admin-live-key",
      KIMI_CODE_API_KEY: "kimi-code-live-key",
    },
  );
  let fetchCalls = 0;

  try {
    await withGlobalFetch(
      async () => {
        fetchCalls += 1;
        throw new Error("Kimi Code chat must not use Worker egress");
      },
      async () => {
        const origin = "https://client.example";
        const preflight = await worker.fetch(
          new Request(
            "https://multillm-proxy.cserules.workers.dev/kimi-code/v1/chat/completions",
            { method: "OPTIONS", headers: { Origin: origin } },
          ),
          stub.env,
        );
        assert.equal(preflight.status, 204);
        assert.equal(preflight.headers.get("Access-Control-Allow-Origin"), origin);
        assert.match(preflight.headers.get("Access-Control-Allow-Headers") ?? "", /OpenAI-Project/i);

        const invalidPreflight = await worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/kimi-code/v1/responses", {
            method: "OPTIONS",
            headers: { Origin: origin },
          }),
          stub.env,
        );
        assert.equal(invalidPreflight.status, 404);

        const response = await worker.fetch(
          new Request(
            "https://multillm-proxy.cserules.workers.dev/kimi-code/v1/chat/completions",
            {
              method: "POST",
              headers: {
                Authorization: "Bearer admin-live-key",
                "Content-Type": "application/json",
              },
              body: '{"model":"k3","reasoning_effort":"max"}',
            },
          ),
          stub.env,
        );
        assert.equal(response.status, 503);
        assert.equal(response.headers.get("Retry-After"), "5");
      },
    );
  } finally {
    if (originalCaches === undefined) {
      delete globalThis.caches;
    } else {
      Object.defineProperty(globalThis, "caches", {
        configurable: true,
        value: originalCaches,
        writable: true,
      });
    }
  }

  assert.equal(fetchCalls, 0);
  assert.equal(cacheReads, 0);
  assert.equal(stub.getCalls(), 1);
});

test("worker deploy config never stores the Kimi Code secret in plaintext", async () => {
  const configUrl = new URL("../wrangler.jsonc", import.meta.url);
  const config = JSON.parse(await readFile(configUrl, "utf8"));

  assert.equal(config.vars?.KIMI_CODE_API_KEY, undefined);
});

test("worker answers /health directly without touching the container", async () => {
  const stub = makeEnv(async () => {
    throw new Error("health container unavailable");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/health"),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(stub.getCalls(), 0);
  assert.deepEqual(await response.json(), {
    status: "healthy",
    mode: "worker-fallback",
  });
});

test("worker checks application readiness through the container health endpoint", async () => {
  const origin = "https://client.example";
  const stub = makeEnv(async (request) => {
    const forwardedUrl = new URL(request.url);
    assert.equal(forwardedUrl.pathname, "/healthz");
    assert.equal(request.method, "GET");
    assert.equal(request.redirect, "manual");
    return new Response(JSON.stringify({ status: "ready", database: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/ready", {
      headers: { Origin: origin },
    }),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(stub.getCalls(), 1);
  assert.equal(stub.getStartCalls(), 0);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.deepEqual(await response.json(), { status: "ready", database: "ok" });
});

test("worker relies on container.fetch for startup and readiness", async () => {
  const stub = makeEnv(async () => new Response("container ready", { status: 200 }));

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/dashboard"),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "container ready");
  assert.equal(stub.getCalls(), 1);
  assert.equal(stub.getStartCalls(), 0);
});

test("worker streams ordinary request bodies into the container without buffering", async () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let releaseTail;
  let resolveFirstChunk;
  const tailGate = new Promise((resolve) => {
    releaseTail = resolve;
  });
  const firstChunkSeen = new Promise((resolve) => {
    resolveFirstChunk = resolve;
  });
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('{"model":"streamed",'));
      tailGate.then(() => {
        controller.enqueue(encoder.encode('"input":"hello"}'));
        controller.close();
      });
    },
  });
  const stub = makeEnv(async (request) => {
    assert.equal(request.redirect, "manual");
    const reader = request.body.getReader();
    const first = await reader.read();
    assert.equal(decoder.decode(first.value), '{"model":"streamed",');
    assert.equal(first.done, false);
    resolveFirstChunk();

    await tailGate;
    const second = await reader.read();
    assert.equal(decoder.decode(second.value), '"input":"hello"}');
    assert.equal(second.done, false);
    assert.equal((await reader.read()).done, true);
    return new Response("accepted", { status: 202 });
  });

  const withDeadline = async (promise, label) => {
    let timeout;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error(`${label} was buffered`)), 500);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  };

  try {
    const pendingResponse = worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/openai/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        duplex: "half",
      }),
      stub.env,
    );

    await withDeadline(firstChunkSeen, "container request body");
    assert.equal(stub.getStartCalls(), 0);
    releaseTail();
    const response = await withDeadline(pendingResponse, "container response");
    assert.equal(response.status, 202);
    assert.equal(await response.text(), "accepted");
  } finally {
    releaseTail();
  }

  assert.equal(stub.getCalls(), 1);
});

test("worker preserves caller cancellation when reconstructing container requests", async () => {
  const controller = new AbortController();
  let resolveContainerReceived;
  const containerReceived = new Promise((resolve) => {
    resolveContainerReceived = resolve;
  });
  let forwardedAbortObserved = false;
  const stub = makeEnv(async (request) => {
    resolveContainerReceived();
    await new Promise((resolve) => {
      if (request.signal.aborted) {
        forwardedAbortObserved = true;
        resolve();
        return;
      }
      const timeout = setTimeout(resolve, 150);
      request.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timeout);
          forwardedAbortObserved = true;
          resolve();
        },
        { once: true },
      );
    });
    return new Response(null, { status: 204 });
  });

  const pendingResponse = worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/dashboard", {
      signal: controller.signal,
    }),
    stub.env,
  );
  await containerReceived;
  controller.abort();

  assert.equal((await pendingResponse).status, 204);
  assert.equal(forwardedAbortObserved, true);
  assert.equal(stub.getStartCalls(), 0);
});

test("worker omits routine environment inventory logs and sanitizes startup errors", async () => {
  const workerUrl = new URL("../cloudflare-worker.mjs", import.meta.url);
  const source = await readFile(workerUrl, "utf8");
  assert.doesNotMatch(source, /Worker env check|Container starting|envKeys|hasAdminApiKey/);
  assert.doesNotMatch(source, /\bstartAndWaitForPorts\b|\bswitchPort\b/);
  assert.equal(Object.hasOwn(MultiLLMProxyContainer.prototype, "onStart"), false);

  const logCalls = [];
  const originalConsoleLog = console.log;
  console.log = (...args) => logCalls.push(args);
  try {
    const stub = makeEnv(async () => {
      throw new Error("health must remain Worker-only");
    });
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/health"),
      stub.env,
    );
    assert.equal(response.status, 200);
  } finally {
    console.log = originalConsoleLog;
  }
  assert.deepEqual(logCalls, []);

  const errorCalls = [];
  const originalConsoleError = console.error;
  console.error = (...args) => errorCalls.push(args);
  try {
    const container = new MultiLLMProxyContainer({}, {
      ADMIN_API_KEY: "must-not-be-logged",
      LINKAPI_KEY: "must-not-be-logged-either",
    });
    container.onError(new Error("startup failed"));
  } finally {
    console.error = originalConsoleError;
  }
  assert.deepEqual(errorCalls, [[{
    event: "container_start_failed",
    errorName: "Error",
  }]]);
  assert.doesNotMatch(JSON.stringify(errorCalls), /must-not-be-logged|ADMIN_API_KEY|LINKAPI_KEY/);
});

test("container entrypoint uses a query-safe format when access logs are explicitly enabled", async () => {
  const scriptUrl = new URL("../scripts/cloudflare-entrypoint.sh", import.meta.url);
  const source = await readFile(scriptUrl, "utf8");

  assert.match(source, /GUNICORN_ACCESS_LOG/);
  assert.doesNotMatch(source, /--access-logfile\s+-\s*\\?$/m);
  const enabledBlock = source.match(
    /if \[ -n "\$\{GUNICORN_ACCESS_LOG:-\}" \]; then([\s\S]*?)\nfi/,
  )?.[1] ?? "";
  assert.match(enabledBlock, /--access-logfile\s+"\$GUNICORN_ACCESS_LOG"/);
  assert.match(enabledBlock, /--access-logformat\s+'%\(m\)s %\(U\)s %\(H\)s'/);
  assert.doesNotMatch(source, /%\(r\)s|%\(q\)s|RAW_URI|request[ _-]?line|referer/i);
});

test("worker serves / from the container when it is available", async () => {
  const stub = makeEnv(async () => {
    return new Response("<html><body>container dashboard</body></html>", {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
      },
    });
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/"),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(stub.getCalls(), 1);
  assert.match(await response.text(), /container dashboard/);
});

test("worker preserves container redirects for dashboard form posts", async () => {
  const stub = makeEnv(async (request) => {
    assert.equal(request.method, "POST");
    assert.equal(request.redirect, "manual");
    assert.equal(await request.text(), "username=admin");
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie": "session=authenticated; HttpOnly; Path=/; SameSite=Lax",
      },
    });
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "username=admin",
    }),
    stub.env,
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "/");
  assert.equal(
    response.headers.get("Set-Cookie"),
    "session=authenticated; HttpOnly; Path=/; SameSite=Lax",
  );
  assert.equal(stub.getCalls(), 1);
});

test("worker reports / as unavailable when the container is unavailable", async () => {
  const stub = makeEnv(async () => {
    throw new Error("root container unavailable");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/"),
    stub.env,
  );

  assert.equal(response.status, 503);
  assert.equal(stub.getCalls(), 1);
  assert.match(await response.text(), /MultiLLM Proxy/);
});

test("worker sanitizes the container package's resolved startup 500 response", async () => {
  const packageError =
    "Failed to start container: Container did not start after 8000ms; token=must-not-leak";
  const stub = makeEnv(async () => {
    return new Response(packageError, { status: 500 });
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/"),
    stub.env,
  );
  const body = await response.text();

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("Retry-After"), "5");
  assert.match(body, /MultiLLM Proxy/);
  assert.doesNotMatch(body, /must-not-leak|Failed to start container/);
  assert.equal(stub.getCalls(), 1);
});

test("worker sanitizes the container package's resolved capacity 503 response", async () => {
  const packageError = [
    "There is no Container instance available at this time.",
    "This is likely because you have reached your max concurrent instance count (set in wrangler config) or are you currently provisioning the Container.",
    "If you are deploying your Container for the first time, check your dashboard to see provisioning status, this may take a few minutes.",
  ].join("\n");
  const origin = "https://client.example";
  const stub = makeEnv(async () => {
    return new Response(packageError, { status: 503 });
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/ready", {
      headers: { Origin: origin },
    }),
    stub.env,
  );
  const body = await response.text();

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("Retry-After"), "5");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(response.headers.get("Content-Type") ?? "", /application\/json/);
  assert.deepEqual(JSON.parse(body), {
    error: "Proxy unavailable",
    message: "The proxy container is not ready to handle requests.",
  });
  assert.doesNotMatch(body, /max concurrent instance|provisioning/);
  assert.equal(stub.getCalls(), 1);
});

test("worker preserves genuine application text and JSON 5xx responses", async () => {
  const cases = [
    {
      path: "/dashboard",
      response: new Response("Application maintenance window", {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=UTF-8" },
      }),
      expectedBody: "Application maintenance window",
      expectedContentType: "text/plain; charset=UTF-8",
    },
    {
      path: "/openai/chat/completions",
      response: new Response(JSON.stringify({ error: "upstream unavailable" }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      }),
      expectedBody: JSON.stringify({ error: "upstream unavailable" }),
      expectedContentType: "application/json",
    },
  ];

  for (const testCase of cases) {
    const stub = makeEnv(async () => testCase.response);
    const response = await worker.fetch(
      new Request(`https://multillm-proxy.cserules.workers.dev${testCase.path}`),
      stub.env,
    );

    assert.equal(response.status, testCase.response.status);
    assert.equal(response.headers.get("Content-Type"), testCase.expectedContentType);
    assert.equal(response.headers.get("Retry-After"), null);
    assert.equal(await response.text(), testCase.expectedBody);
    assert.equal(stub.getCalls(), 1);
  }
});

test("worker authenticates OpenCode callers before revealing provider configuration", async () => {
  const originalTimingSafeEqual = crypto.subtle.timingSafeEqual;
  let timingSafeCalls = 0;
  Object.defineProperty(crypto.subtle, "timingSafeEqual", {
    configurable: true,
    value(left, right) {
      timingSafeCalls += 1;
      const leftBytes = new Uint8Array(left.buffer ?? left, left.byteOffset ?? 0, left.byteLength);
      const rightBytes = new Uint8Array(right.buffer ?? right, right.byteOffset ?? 0, right.byteLength);
      return leftBytes.every((value, index) => value === rightBytes[index]);
    },
  });
  const stub = makeEnv(
    async () => {
      throw new Error("OpenCode auth checks must bypass the container");
    },
    { ADMIN_API_KEY: "admin-live-key" },
  );

  try {
    const unauthorized = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/models", {
        headers: { Authorization: "Bearer wrong-key" },
      }),
      stub.env,
    );
    assert.equal(unauthorized.status, 401);
    assert.doesNotMatch(await unauthorized.text(), /OPENCODE_API_KEY/);

    const authenticated = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/models", {
        headers: { Authorization: "Bearer admin-live-key" },
      }),
      stub.env,
    );
    assert.equal(authenticated.status, 500);
    assert.match(await authenticated.text(), /OPENCODE_API_KEY/);
  } finally {
    if (originalTimingSafeEqual === undefined) {
      delete crypto.subtle.timingSafeEqual;
    } else {
      Object.defineProperty(crypto.subtle, "timingSafeEqual", {
        configurable: true,
        value: originalTimingSafeEqual,
      });
    }
  }

  assert.equal(timingSafeCalls, 2);
  assert.equal(stub.getCalls(), 0);
});

test("worker exposes protocol-native OpenCode Go chat and model routes", async () => {
  const requestBody =
    '{"model":"kimi-k3","messages":[{"role":"user","content":"ping"}],"stream":false}';
  const rawResponse =
    '{"choices":[{"message":{"content":"pong","reasoning_content":"native"}}]}';
  const stub = makeEnv(
    async () => {
      throw new Error("OpenCode Go native routes must bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_GO_API_KEY: "go-live-key",
    },
  );
  const upstreamRequests = [];

  await withGlobalFetch(
    async (input, init) => {
      const upstreamRequest =
        input instanceof Request ? input : new Request(input, init);
      upstreamRequests.push(upstreamRequest);

      if (upstreamRequest.method === "GET") {
        assert.equal(
          upstreamRequest.url,
          "https://opencode.ai/zen/go/v1/models?region=us&region=eu",
        );
        assert.equal(upstreamRequest.headers.get("Authorization"), "Bearer go-live-key");
        assert.equal(upstreamRequest.headers.get("Content-Type"), null);
        return new Response('{"object":"list","data":[]}', {
          headers: { "Content-Type": "application/json" },
        });
      }

      assert.equal(
        upstreamRequest.url,
        "https://opencode.ai/zen/go/v1/chat/completions",
      );
      assert.equal(upstreamRequest.headers.get("Authorization"), "Bearer go-live-key");
      assert.equal(await upstreamRequest.text(), requestBody);
      return new Response(rawResponse, {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": "must-not-leak=yes",
          "X-RateLimit-Remaining": "9",
        },
      });
    },
    async () => {
      const chatResponse = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/opencode/v1/chat/completions",
          {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
            },
            body: requestBody,
          },
        ),
        stub.env,
      );
      assert.equal(chatResponse.status, 200);
      assert.equal(await chatResponse.text(), rawResponse);
      assert.equal(chatResponse.headers.get("Set-Cookie"), null);
      assert.equal(chatResponse.headers.get("X-RateLimit-Remaining"), "9");

      const modelsResponse = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/opencode/v1/models?region=us&region=eu",
          { headers: { Authorization: "Bearer admin-live-key" } },
        ),
        stub.env,
      );
      assert.equal(modelsResponse.status, 200);
      assert.deepEqual(await modelsResponse.json(), { object: "list", data: [] });
    },
  );

  assert.equal(upstreamRequests.length, 2);
  assert.equal(stub.getCalls(), 0);
});

test("worker preserves OpenCode Go Anthropic messages and caller-owned credentials", async () => {
  const events =
    'event: message_start\ndata: {"type":"message_start"}\n\n' +
    'event: message_stop\ndata: {"type":"message_stop"}\n\n';
  const stub = makeEnv(
    async () => {
      throw new Error("OpenCode Go messages must bypass the container");
    },
    { ADMIN_API_KEY: "admin-live-key" },
  );

  await withGlobalFetch(
    async (input, init) => {
      const upstreamRequest =
        input instanceof Request ? input : new Request(input, init);
      assert.equal(
        upstreamRequest.url,
        "https://opencode.ai/zen/go/v1/messages",
      );
      assert.equal(upstreamRequest.headers.get("X-Api-Key"), "caller-go-key");
      assert.equal(upstreamRequest.headers.get("Authorization"), null);
      assert.equal(
        upstreamRequest.headers.get("Anthropic-Version"),
        "2023-06-01",
      );
      assert.equal(
        upstreamRequest.headers.get("Anthropic-Dangerous-Direct-Browser-Access"),
        "true",
      );
      return new Response(events, {
        headers: {
          "Content-Type": "text/event-stream",
          "Anthropic-RateLimit-Requests-Remaining": "4",
        },
      });
    },
    async () => {
      const response = await worker.fetch(
        new Request(
          "https://multillm-proxy.cserules.workers.dev/opencode/v1/messages",
          {
            method: "POST",
            headers: {
              "X-MultiLLM-Api-Key": "admin-live-key",
              "X-Api-Key": "caller-go-key",
              "Anthropic-Dangerous-Direct-Browser-Access": "true",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              model: "minimax-m3",
              max_tokens: 128,
              messages: [{ role: "user", content: "ping" }],
              stream: true,
            }),
          },
        ),
        stub.env,
      );

      assert.equal(response.status, 200);
      assert.equal(await response.text(), events);
      assert.equal(
        response.headers.get("Anthropic-RateLimit-Requests-Remaining"),
        "4",
      );
    },
  );

  assert.equal(stub.getCalls(), 0);
});

test("worker streams OpenCode request bodies without buffering", async () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let releaseTail;
  let resolveFirstChunk;
  const tailGate = new Promise((resolve) => {
    releaseTail = resolve;
  });
  const firstChunkSeen = new Promise((resolve) => {
    resolveFirstChunk = resolve;
  });
  const requestBody = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('{"model":"kimi-k2.5",'));
      tailGate.then(() => {
        controller.enqueue(encoder.encode('"messages":[]}'));
        controller.close();
      });
    },
  });
  const stub = makeEnv(
    async () => {
      throw new Error("OpenCode fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );
  const withDeadline = async (promise, label) => {
    let timeout;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error(`${label} was buffered`)), 500);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  };

  try {
    await withGlobalFetch(
      async (input, init) => {
        const upstreamRequest = input instanceof Request ? input : new Request(input, init);
        assert.equal(upstreamRequest.url, "https://opencode.ai/zen/go/v1/chat/completions");
        assert.equal(upstreamRequest.redirect, "manual");
        const reader = upstreamRequest.body.getReader();
        const first = await reader.read();
        assert.equal(decoder.decode(first.value), '{"model":"kimi-k2.5",');
        assert.equal(first.done, false);
        resolveFirstChunk();

        await tailGate;
        const second = await reader.read();
        assert.equal(decoder.decode(second.value), '"messages":[]}');
        assert.equal(second.done, false);
        assert.equal((await reader.read()).done, true);
        return new Response(JSON.stringify({ ok: true }), {
          headers: { "Content-Type": "application/json" },
        });
      },
      async () => {
        const pendingResponse = worker.fetch(
          new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
            method: "POST",
            headers: {
              Authorization: "Bearer admin-live-key",
              "Content-Type": "application/json",
            },
            body: requestBody,
            duplex: "half",
          }),
          stub.env,
        );

        await withDeadline(firstChunkSeen, "OpenCode request body");
        releaseTail();
        const response = await withDeadline(pendingResponse, "OpenCode response");
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { ok: true });
      },
    );
  } finally {
    releaseTail();
  }

  assert.equal(stub.getCalls(), 0);
});

test("worker propagates caller aborts to the direct OpenCode fetch", async () => {
  const controller = new AbortController();
  let resolveFetchReceived;
  const fetchReceived = new Promise((resolve) => {
    resolveFetchReceived = resolve;
  });
  let upstreamSawAbort = false;
  const stub = makeEnv(
    async () => {
      throw new Error("OpenCode fast path should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  await withGlobalFetch(
    async (input, init) => {
      const upstreamRequest = input instanceof Request ? input : new Request(input, init);
      resolveFetchReceived();
      await new Promise((resolve) => {
        if (upstreamRequest.signal.aborted) {
          upstreamSawAbort = true;
          resolve();
          return;
        }
        const timeout = setTimeout(resolve, 150);
        upstreamRequest.signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timeout);
            upstreamSawAbort = true;
            resolve();
          },
          { once: true },
        );
      });
      return new Response(JSON.stringify({ data: [] }), {
        headers: { "Content-Type": "application/json" },
      });
    },
    async () => {
      const pendingResponse = worker.fetch(
        new Request("https://multillm-proxy.cserules.workers.dev/opencode/models", {
          headers: { Authorization: "Bearer admin-live-key" },
          signal: controller.signal,
        }),
        stub.env,
      );
      await fetchReceived;
      controller.abort();
      assert.equal((await pendingResponse).status, 200);
    },
  );

  assert.equal(upstreamSawAbort, true);
  assert.equal(stub.getCalls(), 0);
});

test("worker proxies opencode requests directly when the container is unavailable", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("opencode fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    assert.equal(request.url, "https://opencode.ai/zen/go/v1/chat/completions");
    assert.equal(request.headers.get("Authorization"), "Bearer opencode-live-key");
    assert.equal(request.headers.get("Content-Type"), "application/json");
    assert.equal(await request.text(), JSON.stringify({ model: "kimi-k2.5", messages: [{ role: "user", content: "ping" }] }));

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  };

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://janitorai.com");
    assert.deepEqual(await response.json(), { ok: true });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker renders non-streaming opencode reasoning as a visible think block", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("opencode fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        id: "chatcmpl-1",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: "Pong!",
              reasoning: "private",
              reasoning_details: [{ text: "private" }],
            },
          },
        ],
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
        },
      },
    );

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.equal(payload.choices[0].message.content, "<think>private</think>\n\nPong!");
    assert.equal("reasoning" in payload.choices[0].message, false);
    assert.equal("reasoning_details" in payload.choices[0].message, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker preserves non-streaming opencode reasoning_content for DeepSeek thinking mode", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("opencode fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        id: "chatcmpl-deepseek",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: "Pong!",
              reasoning_content: "state that must be sent back on the next turn",
              reasoning: "private",
              reasoning_details: [{ text: "private" }],
            },
          },
        ],
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
        },
      },
    );

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const payload = await response.json();
    const message = payload.choices[0].message;
    assert.equal(response.status, 200);
    assert.equal(message.content, "<think>state that must be sent back on the next turnprivate</think>\n\nPong!");
    assert.equal(message.reasoning_content, "state that must be sent back on the next turn");
    assert.equal("reasoning" in message, false);
    assert.equal("reasoning_details" in message, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker strips raw non-stream think blocks from opencode content", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("opencode fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        id: "chatcmpl-1",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content:
                '<think>\nThe user is saying Mysterious gets up from his position.\n</think>\n\n<think>duplicate private draft</think>\n\n*The warmth vanishes.*',
              reasoning:
                'The user wants me to reply with exactly "pong".So I should output just the word "pong "without any punctuation. No,"exactly pong "implies just the word.',
            },
          },
        ],
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
        },
      },
    );

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.equal(
      payload.choices[0].message.content,
      '<think>The user wants me to reply with exactly "pong".So I should output just the word "pong "without any punctuation. No,"exactly pong "implies just the word.</think>\n\n*The warmth vanishes.*',
    );
    assert.doesNotMatch(payload.choices[0].message.content, /Mysterious gets up|duplicate private draft/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker does not truncate long non-stream reasoning text", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("opencode fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const longReasoning = `start-${"x".repeat(1300)}-end`;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        id: "chatcmpl-long-think",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: "pong",
              reasoning: longReasoning,
            },
          },
        ],
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
        },
      },
    );

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.equal(payload.choices[0].message.content, `<think>${longReasoning}</think>\n\npong`);
    assert.doesNotMatch(payload.choices[0].message.content, /…<\/think>/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker renders streaming opencode reasoning and strips duplicate raw think blocks", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("streaming fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const leakedPayload =
    '{"id":"gen-1776744934","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":"x","reasoning_details":[{"text":"x"}]}}]}' +
    '{"id":"gen-1776744935","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":"y","reasoning_details":[{"text":"y"}]}}]}' +
    '*The ascent was a brutal ballet of desperation and calculated intent.*';

  const streamBody = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(encoder.encode("<think>\n"));
      controller.enqueue(encoder.encode("private reasoning\n"));
      controller.enqueue(encoder.encode("</think>\n"));
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-live","object":"chat.completion.chunk","choices":[{"delta":{"content":"","role":"assistant","reasoning":"The","reasoning_details":[{"text":"The"}]}}]}\n',
        ),
      );
      controller.enqueue(encoder.encode(`${leakedPayload}\n`));
      controller.enqueue(encoder.encode("data: [DONE]\n"));
      controller.close();
    },
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(streamBody, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
      },
    });

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", stream: true, messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const text = await response.text();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.match(text, /<think>/);
    assert.match(text, /private reasoning/);
    assert.match(text, /The/);
    assert.match(text, /<\/think>\\n\\n/);
    assert.match(text, /\*The ascent was a brutal ballet of desperation and calculated intent\.\*/);
    assert.doesNotMatch(text, /"reasoning":/);
    assert.doesNotMatch(text, /reasoning_details/);
    assert.doesNotMatch(text, /gen-1776744934/);
    assert.match(text, /data: \[DONE\]/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker ignores streaming reasoning deltas before and after visible content", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("streaming fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const streamBody = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think","object":"chat.completion.chunk","choices":[{"delta":{"content":"","role":"assistant","reasoning":"first pass"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-content","object":"chat.completion.chunk","choices":[{"delta":{"content":"Visible answer"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-late-think","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":"late hidden thought"}}]}\n',
        ),
      );
      controller.enqueue(encoder.encode("data: [DONE]\n"));
      controller.close();
    },
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(streamBody, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
      },
    });

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", stream: true, messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const text = await response.text();
    assert.equal(response.status, 200);
    const contentChunks = [...text.matchAll(/"content":"((?:\\.|[^"])*)"/g)].map(([, content]) => content);
    assert.deepEqual(contentChunks, [
      "<think>",
      "first pass",
      "</think>\\n\\n",
      "Visible answer",
    ]);
    assert.match(text, /Visible answer/);
    assert.match(text, /first pass/);
    assert.doesNotMatch(text, /late hidden thought/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker preserves streamed thinking fragments", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("streaming fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const streamBody = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-1","object":"chat.completion.chunk","choices":[{"delta":{"content":"","role":"assistant","reasoning":"The"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-2","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":" user"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-3","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":" wants"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-4","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":" pong."}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-content","object":"chat.completion.chunk","choices":[{"delta":{"content":"pong"}}]}\n',
        ),
      );
      controller.enqueue(encoder.encode("data: [DONE]\n"));
      controller.close();
    },
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(streamBody, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
      },
    });

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", stream: true, messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const text = await response.text();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.match(text, /The user wants pong\./);
    assert.match(text, /"content":"<\/think>\\n\\n"/);
    assert.match(text, /"content":"pong"/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker does not truncate long streamed reasoning text", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("streaming fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const longReasoning = `start-${"x".repeat(1300)}-end.`;
  const streamBody = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(
        encoder.encode(
          `data: ${JSON.stringify({
            id: "gen-long-think",
            object: "chat.completion.chunk",
            choices: [{ delta: { content: "", role: "assistant", reasoning: longReasoning } }],
          })}\n`,
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-content","object":"chat.completion.chunk","choices":[{"delta":{"content":"pong"}}]}\n',
        ),
      );
      controller.enqueue(encoder.encode("data: [DONE]\n"));
      controller.close();
    },
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(streamBody, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
      },
    });

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", stream: true, messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const text = await response.text();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.match(text, /"content":"<think>"/);
    assert.match(text, new RegExp(longReasoning));
    assert.doesNotMatch(text, /…<\/think>/);
    assert.match(text, /"content":"pong"/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker preserves quoted and colon-prefixed streamed thinking text", async () => {
  const stub = makeEnv(
    async () => {
      throw new Error("streaming fallback should bypass the container");
    },
    {
      ADMIN_API_KEY: "admin-live-key",
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  const streamBody = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-1","object":"chat.completion.chunk","choices":[{"delta":{"content":"","role":"assistant","reasoning":"The user wants \\""}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-2","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":"p"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-3","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":"ong"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-4","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":"\\". The answer is simply:"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-think-5","object":"chat.completion.chunk","choices":[{"delta":{"content":"","reasoning":" pong"}}]}\n',
        ),
      );
      controller.enqueue(
        encoder.encode(
          'data: {"id":"gen-content","object":"chat.completion.chunk","choices":[{"delta":{"content":"pong"}}]}\n',
        ),
      );
      controller.enqueue(encoder.encode("data: [DONE]\n"));
      controller.close();
    },
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(streamBody, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
      },
    });

  try {
    const response = await worker.fetch(
      new Request("https://multillm-proxy.cserules.workers.dev/opencode/chat/completions", {
        method: "POST",
        headers: {
          Authorization: "Bearer admin-live-key",
          Origin: "https://janitorai.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "kimi-k2.5", stream: true, messages: [{ role: "user", content: "ping" }] }),
      }),
      stub.env,
    );

    const text = await response.text();
    assert.equal(response.status, 200);
    assert.equal(stub.getCalls(), 0);
    assert.match(text, /\\"pong\\"\. The answer is simply: pong/);
    assert.match(text, /"content":"pong"/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
