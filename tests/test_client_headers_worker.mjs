import assert from "node:assert/strict";
import test from "node:test";
import { CLIENT_HEADER_NAMES, clientContextHeaders, withClientDefaults, withOpencodeSession } from "../worker/client-headers.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { MAX_SESSION_BODY_BYTES, withOpencodeRequestSession } from "../worker/opencode-session.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { completionResponse, makeRoleplayEnv, roleplayRequest, withGlobalFetch } from "./helpers/roleplay_fixture.mjs";

const { default: worker } = await loadWorkerModule();

const sessionAuth = { Authorization: "Bearer synthetic-provider-key" };
function sessionRequest(payload) {
  const body = JSON.stringify(payload);
  return new Request("https://proxy.example/opencode/v1/chat/completions", {
    method: "POST", body, headers: { "Content-Type": "application/json", "Content-Length": String(new TextEncoder().encode(body).byteLength) },
  });
}
async function inferredSession(payload, headers = sessionAuth) {
  return (await withOpencodeRequestSession(sessionRequest(payload), headers)).get("x-opencode-session");
}

test("headerless OpenCode requests infer stable credential-scoped conversation affinity", async () => {
  const messages = [{ role: "system", content: "Synthetic coding assistant" }, { role: "user", content: "Fix the parser" }];
  const first = await inferredSession({ messages, model: "first" });
  const later = { messages: [...messages, { role: "assistant", content: "Done" }, { role: "user", content: "Add tests" }], model: "second", stream: true };
  assert.equal(first, await inferredSession(later));
  assert.equal(first, await inferredSession(later));
  assert.notEqual(first, await inferredSession({ messages }, { Authorization: "Bearer other-key" }));
  assert.notEqual(first, await inferredSession({ messages, instructions: "Different instructions" }));
  assert.match(first, /^multillm_v1_[a-f0-9]{64}$/);
  assert.equal(await inferredSession({ input: "Fix the parser" }), await inferredSession({ input: [{ role: "user", content: "Fix the parser" }] }));
  for (const payload of [
    { session_id: "body-session" }, { conversation_id: "body-session" },
    { metadata: { session_id: "body-session" } }, { metadata: { conversation_id: "body-session" } },
    { conversation: "body-session" }, { conversation: { id: "body-session" } },
  ]) {
    assert.equal(await inferredSession(payload), await inferredSession({ ...payload, messages }));
  }
  const payloads = Array.from({ length: 20 }, (_, i) => ({ session_id: `conversation-${i}` }));
  const concurrent = await Promise.all(payloads.map((payload) => inferredSession(payload)));
  assert.equal(new Set(concurrent).size, 20);
  assert.deepEqual(concurrent, await Promise.all(payloads.map((payload) => inferredSession(payload))));
});

test("session inference preserves bytes, honors overrides, and bounds discovery", async () => {
  for (const body of ["invalid", "[]", "{}", '{"messages":[]}', "x".repeat(MAX_SESSION_BODY_BYTES + 1)]) {
    const request = new Request("https://proxy.example", {
      method: "POST", body, headers: { "Content-Type": "application/json", "Content-Length": String(body.length) },
    });
    const headers = await withOpencodeRequestSession(request, sessionAuth);
    assert.match(headers.get("x-opencode-session"), /^multillm_request_/);
    assert.equal(await request.text(), body);
    assert.equal((await withOpencodeRequestSession(new Request("https://proxy.example"), headers)).get("x-opencode-session"), headers.get("x-opencode-session"));
  }
  assert.notEqual(await inferredSession({}), await inferredSession({}));
  const override = sessionRequest({ messages: [{ role: "user", content: "test" }] });
  await override.text();
  assert.equal((await withOpencodeRequestSession(override, { ...sessionAuth, "thread-id": "explicit-thread" })).get("x-opencode-session"), "explicit-thread");
  assert.match(await inferredSession({ input: "test" }, { ...sessionAuth, "x-opencode-session": " " }), /^multillm_v1_/);
  assert.match(await inferredSession({ input: "test" }, { ...sessionAuth, "x-opencode-session": "é" }), /^multillm_v1_/);
});

test("Worker and Container use the same Unicode content fingerprint", async () => {
  assert.equal(await inferredSession({ messages: [{ role: "user", content: [{ type: "text", text: "Fix café ☀️" }] }] }), "multillm_v1_83fe68c7b57180ce4a00dad94ce61a386749ceeeab759bc938035d56734c00e2");
});

test("stalled affinity discovery times out without consuming the original upload", async () => {
  let controller;
  const request = new Request("https://proxy.example", {
    method: "POST", duplex: "half",
    headers: { "Content-Type": "application/json", "Content-Length": "26" },
    body: new ReadableStream({ start(value) { controller = value; } }),
  });
  const headers = await withOpencodeRequestSession(request, sessionAuth);
  assert.match(headers.get("x-opencode-session"), /^multillm_request_/);
  controller.enqueue(new TextEncoder().encode('{"input":"Delayed upload"}'));
  controller.close();
  assert.equal(await request.text(), '{"input":"Delayed upload"}');
});

test("every direct OpenCode protocol supplies a session without harness headers", async () => {
  for (const path of ["/opencode/v1/chat/completions", "/opencode/v1/responses", "/opencode/v1/messages", "/opencode/v1/models"]) {
    const env = { ADMIN_API_KEY: "admin-test", OPENCODE_GO_API_KEY: "opencode-test", OPENCODE_EDGE_FETCH: "true" };
    let seen;
    const response = await withGlobalFetch(async (request) => {
      seen = request.headers;
      if (!seen.get("x-opencode-session")) return new Response('{"error":{"type":"MissingSessionID"}}', { status: 400 });
      return new Response('{"data":[]}', { headers: { "Content-Type": "application/json" } });
    }, () => worker.fetch(new Request(`https://proxy.example${path}`, {
      method: path.endsWith("/models") ? "GET" : "POST",
      headers: { Authorization: "Bearer admin-test", "Content-Type": "application/json", "Content-Length": "29" },
      ...(path.endsWith("/models") ? {} : { body: '{"input":"Synthetic request"}' }),
    }), env));
    assert.equal(response.status, 200, path);
    assert.match(seen.get("x-opencode-session"), /^multillm_(v1|request)_/, path);
    assert.equal(seen.get("User-Agent"), "codex-cli", path);
  }
});

test("Codex defaults are overridable, validated, and do not mutate caller headers", () => {
  const source = new Headers({ "uSeR-aGeNt": "fleet/1", Authorization: "Bearer test" });
  const env = { UPSTREAM_DEFAULT_USER_AGENT: "central/2", UPSTREAM_DEFAULT_ORIGINATOR: "central" };
  assert.equal(withClientDefaults(source, env).get("User-Agent"), "fleet/1");
  assert.equal(withClientDefaults(source, env).get("Originator"), "central");
  assert.equal(source.has("originator"), false);
  assert.equal(withClientDefaults({}, env).get("User-Agent"), "central/2");
  const defaults = withClientDefaults({ "User-Agent": "", Originator: " " }, {
    UPSTREAM_DEFAULT_USER_AGENT: "bad\r\nvalue",
  });
  assert.equal(defaults.get("User-Agent"), "codex-cli");
  assert.equal(defaults.get("Originator"), "codex_cli_rs");
  assert.equal(clientContextHeaders(source).has("Authorization"), false);
  assert.deepEqual([...clientContextHeaders({ Cookie: "private", "ChatGPT-Account-Id": "account" })], []);
  assert.deepEqual(Object.fromEntries(Object.keys(env).map((key) => [key, collectContainerEnv(env)[key]])), env);
});

test("OpenCode session mapping preserves native headers without fabricating a shared session", () => {
  assert.equal(withOpencodeSession({}).has("x-opencode-session"), false);
  for (const name of CLIENT_HEADER_NAMES.filter((name) => !["user-agent", "originator"].includes(name))) {
    assert.equal(withOpencodeSession({ [name]: "conversation" }).get("x-opencode-session"), "conversation");
  }
  const native = { "session-id": "vm", "thread-id": "thread" };
  assert.equal(withOpencodeSession(native).get("x-opencode-session"), "thread");
  assert.equal(withOpencodeSession({ ...native, "x-opencode-session": "explicit" }).get("x-opencode-session"), "explicit");
  assert.equal(clientContextHeaders({ "x-opencode-session": "explicit" }, "nanogpt").has("x-opencode-session"), false);
});

test("all Worker provider namespaces carry defaults and caller overrides", async () => {
  const paths = [
    "/opencode/v1/models", "/opencode/v1/responses", "/opencode/v1/messages",
    "/linkapi/v1/models", "/linkapi/v1/messages", "/linkapi/v1beta/models/test:generateContent",
    "/codex-easy/v1/responses", "/kimi-code/v1/chat/completions", "/nanogpt/v1/chat/completions",
    "/openai/v1/responses", "/v1/chat/completions", "/v1/free/vision/chat/completions",
  ];
  for (const path of paths) {
    for (const custom of [false, true]) {
      const requests = [];
      const receive = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        requests.push(request);
        return new Response('{"data":[]}', { headers: { "Content-Type": "application/json" } });
      };
      const env = {
        ADMIN_API_KEY: "admin-test", OPENCODE_GO_API_KEY: "opencode-test", OPENCODE_EDGE_FETCH: "true",
        LINKAPI_KEY: "linkapi-test", CODEX_EASY_API_KEY: "easy-test", KIMI_CODE_API_KEY: "kimi-test",
        MULTILLM_PROXY_CONTAINER: { getByName: () => ({ fetch: receive }) },
      };
      const isGet = path.endsWith("/models");
      const response = await withGlobalFetch(receive, () => worker.fetch(new Request(`https://proxy.example${path}`, {
        method: isGet ? "GET" : "POST",
        headers: {
          Authorization: "Bearer admin-test", "Content-Type": "application/json", "session-id": "vm", "thread-id": "thread",
          ...(custom ? { "User-Agent": "my-agent/2", Originator: "my-agent" } : {}),
        },
        ...(isGet ? {} : { body: '{"model":"test","messages":[{"role":"user","content":"Synthetic"}]}' }),
      }), env));
      assert.equal(response.status, 200, path);
      assert.equal(requests.length, 1, path);
      const headers = requests[0].headers;
      assert.equal(headers.get("User-Agent"), custom ? "my-agent/2" : "codex-cli", path);
      assert.equal(headers.get("Originator"), custom ? "my-agent" : "codex_cli_rs", path);
      assert.equal(headers.get("session-id"), "vm", path);
      assert.equal(headers.get("thread-id"), "thread", path);
      if (path.startsWith("/opencode/")) assert.equal(headers.get("x-opencode-session"), "thread");
    }
  }
});

test("roleplay preserves per-turn overrides and stable scoped sessions on every route", async () => {
  const fixture = makeRoleplayEnv();
  const seen = [];
  await withGlobalFetch(async (_input, init) => {
    seen.push(new Headers(init.headers));
    return completionResponse(JSON.parse(init.body).model);
  }, async () => {
    for (const [index, path] of ["/v1/roleplay", "/roleplay/v1/chat/completions", "/v1/roleplay/chat/completions"].entries()) {
      const response = await worker.fetch(roleplayRequest({
        session_id: "conversation-a", input: "Continue the synthetic scene.", stream: false,
      }, index === 1 ? { "User-Agent": "fleet/2", Originator: "fleet" } : {}, path), fixture.env);
      assert.equal(response.status, 200, path);
      await response.text();
      await fixture.waitForBackgroundWork();
    }
    const response = await worker.fetch(roleplayRequest({
      session_id: "conversation-b", input: "Another synthetic scene.", stream: false,
    }), fixture.env);
    assert.equal(response.status, 200);
    await response.text();
    await fixture.waitForBackgroundWork();
  });
  assert.equal(seen.length, 4);
  assert.deepEqual(seen.map((headers) => headers.get("User-Agent")), ["codex-cli", "fleet/2", "codex-cli", "codex-cli"]);
  assert.deepEqual(seen.map((headers) => headers.get("Originator")), ["codex_cli_rs", "fleet", "codex_cli_rs", "codex_cli_rs"]);
  assert.ok(seen[0].get("x-opencode-session"));
  assert.equal(seen[0].get("x-opencode-session"), seen[2].get("x-opencode-session"));
  assert.notEqual(seen[0].get("x-opencode-session"), seen[3].get("x-opencode-session"));
});

test("roleplay fallback carries native identity without forwarding cookies or admin credentials", async () => {
  const fixture = makeRoleplayEnv({ ROLEPLAY_PROVIDER_ORDER: "opencode,navyai", NAVYAI_API_KEY: "navy-test" });
  const attempts = [];
  const response = await withGlobalFetch(async (input, init) => {
    const headers = new Headers(init.headers);
    attempts.push({ host: new URL(input).hostname, headers });
    return new URL(input).hostname === "opencode.ai"
      ? new Response('{"error":"temporarily unavailable"}', { status: 503 })
      : completionResponse(JSON.parse(init.body).model);
  }, () => worker.fetch(roleplayRequest({
    session_id: "fallback-conversation", input: "Synthetic scene.", stream: false,
  }, {
    "User-Agent": "fleet/9", Originator: "fleet", "session-id": "native-session", "thread-id": "native-thread",
    "x-opencode-session": "explicit-session", Cookie: "private-cookie", "ChatGPT-Account-Id": "private-account",
  }), fixture.env));
  assert.equal(response.status, 200);
  await response.text();
  await fixture.waitForBackgroundWork();
  assert.ok(attempts.some(({ host }) => host === "api.navy"));
  for (const { host, headers } of attempts) {
    assert.equal(headers.get("User-Agent"), "fleet/9");
    assert.equal(headers.get("Originator"), "fleet");
    assert.equal(headers.get("session-id"), "native-session");
    assert.equal(headers.get("thread-id"), "native-thread");
    assert.equal(headers.get("x-opencode-session"), host === "opencode.ai" ? "explicit-session" : null);
    assert.equal(headers.has("cookie"), false);
    assert.equal(headers.has("ChatGPT-Account-Id"), false);
    assert.notEqual(headers.get("Authorization"), "Bearer admin-roleplay-key");
  }
});

test("browser preflight permits client identity and session overrides", async () => {
  const response = await worker.fetch(new Request("https://proxy.example/opencode/v1/responses", {
    method: "OPTIONS", headers: { Origin: "https://example.test" },
  }), {});
  assert.equal(response.status, 204);
  const allowed = response.headers.get("Access-Control-Allow-Headers").toLowerCase().split(/,\s*/);
  for (const name of [...CLIENT_HEADER_NAMES, "x-opencode-session"]) assert.ok(allowed.includes(name));
});

test("stream continuation retains the original turn's client and session headers", async () => {
  const fixture = makeRoleplayEnv({ ROLEPLAY_MAX_AUTO_CONTINUATIONS: "1" });
  const seen = [];
  await withGlobalFetch(async (_input, init) => {
    seen.push(new Headers(init.headers));
    const first = seen.length === 1;
    const payload = { choices: [{ delta: { content: first ? "A synthetic start. " : "A synthetic end." }, finish_reason: first ? "length" : "stop" }] };
    return new Response(`data: ${JSON.stringify(payload)}\n\ndata: [DONE]\n\n`, {
      headers: { "Content-Type": "text/event-stream" },
    });
  }, async () => {
    const response = await worker.fetch(roleplayRequest({
      session_id: "stream-conversation", model: "roleplay:glm", messages: [{ role: "user", content: "Continue." }], stream: true, max_tokens: 0,
    }, { "User-Agent": "stream-client/1", Originator: "stream-client", "thread-id": "stream-thread", Origin: "https://janitorai.com" }, "/roleplay/v1/chat/completions"), fixture.env);
    const body = await response.text();
    assert.equal(response.status, 200, body);
    assert.match(body, /A synthetic start\./);
    assert.match(body, /A synthetic end\./);
    assert.equal(body.match(/data: \[DONE\]/g)?.length, 1);
    await fixture.waitForBackgroundWork();
  });
  assert.equal(seen.length, 2);
  for (const headers of seen) {
    assert.equal(headers.get("User-Agent"), "stream-client/1");
    assert.equal(headers.get("Originator"), "stream-client");
    assert.equal(headers.get("x-opencode-session"), "stream-thread");
  }
});
