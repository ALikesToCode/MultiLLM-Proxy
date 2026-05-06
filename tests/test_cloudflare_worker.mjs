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
      OPENCODE_API_KEY: "opencode-live-key",
      MIMO_API_KEY: "mimo-live-key",
    },
  );

  assert.equal(container.envVars.ADMIN_API_KEY, "admin-live-key");
  assert.equal(container.envVars.FLASK_SECRET_KEY, "flask-live-secret");
  assert.equal(container.envVars.JWT_SECRET, "jwt-live-secret");
  assert.equal(container.envVars.OPENCODE_API_KEY, "opencode-live-key");
  assert.equal(container.envVars.MIMO_API_KEY, "mimo-live-key");
  assert.equal(container.envVars.AUTH_DB_PATH, "/tmp/auth.sqlite3");
  assert.equal(container.envVars.RATE_LIMIT_DB_PATH, "/tmp/rate_limits.sqlite3");
  assert.equal(container.envVars.MODEL_REGISTRY_DB_PATH, "/tmp/model_registry.sqlite3");
  assert.equal(container.envVars.GUNICORN_WORKERS, "1");
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
