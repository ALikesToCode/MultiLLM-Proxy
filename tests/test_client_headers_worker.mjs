import assert from "node:assert/strict";
import test from "node:test";
import { CLIENT_HEADER_NAMES, clientContextHeaders, withClientDefaults, withOpencodeSession } from "../worker/client-headers.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { completionResponse, makeRoleplayEnv, roleplayRequest, withGlobalFetch } from "./helpers/roleplay_fixture.mjs";

const { default: worker } = await loadWorkerModule();

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
