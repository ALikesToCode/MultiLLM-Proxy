import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function loadWorkerModule() {
  const workerUrl = new URL("./cloudflare-worker.mjs", import.meta.url);
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

  return {
    getCalls() {
      return calls;
    },
    env: {
      MULTILLM_PROXY_CONTAINER: {
        getByName(name) {
          assert.equal(name, "primary");

          return {
            async startAndWaitForPorts() {
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
      OPENCODE_API_KEY: "opencode-live-key",
    },
  );

  assert.equal(container.envVars.ADMIN_API_KEY, "admin-live-key");
  assert.equal(container.envVars.FLASK_SECRET_KEY, "flask-live-secret");
  assert.equal(container.envVars.JWT_SECRET, "jwt-live-secret");
  assert.equal(container.envVars.OPENCODE_API_KEY, "opencode-live-key");
  assert.equal(container.envVars.AUTH_DB_PATH, "/tmp/auth.sqlite3");
  assert.equal(container.envVars.HOME, "/tmp");
  assert.equal(container.envVars.SERVER_PORT, "8080");
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

test("worker falls back on / when the container is unavailable", async () => {
  const stub = makeEnv(async () => {
    throw new Error("root container unavailable");
  });

  const response = await worker.fetch(
    new Request("https://multillm-proxy.cserules.workers.dev/"),
    stub.env,
  );

  assert.equal(response.status, 200);
  assert.equal(stub.getCalls(), 1);
  assert.match(await response.text(), /MultiLLM Proxy/);
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

test("worker renders a safe visible <think> block for non-streaming opencode responses", async () => {
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
    assert.match(payload.choices[0].message.content, /^<think>private<\/think>\n\nPong!$/);
    assert.equal("reasoning" in payload.choices[0].message, false);
    assert.equal("reasoning_details" in payload.choices[0].message, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker renders a safe visible <think> block for streaming opencode responses", async () => {
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
    assert.match(text, /<\/think>/);
    assert.match(text, /\*The ascent was a brutal ballet of desperation and calculated intent\.\*/);
    assert.doesNotMatch(text, /"reasoning":/);
    assert.doesNotMatch(text, /reasoning_details/);
    assert.doesNotMatch(text, /gen-1776744934/);
    assert.match(text, /data: \[DONE\]/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker ignores later reasoning deltas after visible streaming content starts", async () => {
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
    assert.deepEqual(contentChunks.slice(0, 4), [
      "<think>",
      "first pass",
      "</think>\\n\\n",
      "Visible answer",
    ]);
    assert.match(text, /Visible answer/);
    assert.doesNotMatch(text, /late hidden thought/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
