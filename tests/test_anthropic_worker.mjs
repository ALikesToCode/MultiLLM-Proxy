import assert from "node:assert/strict";
import test from "node:test";

import { collectContainerEnv } from "../worker/container-env.mjs";
import { isApiRequestPath } from "../worker/api-paths.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

test("container receives the Anthropic secrets, spare keys and provider limits", async () => {
  const { MultiLLMProxyContainer } = await loadWorkerModule();
  const source = {
    ANTHROPIC_API_KEY: "anthropic-test-key",
    ANTHROPIC_API_KEY_1: "anthropic-spare-test-key",
    ANTHROPIC_API_KEY_12: "anthropic-later-spare-test-key",
    ANTHROPIC_WORKSPACE_ID: "workspace-test",
    ANTHROPIC_RATE_LIMIT_RPM: "50",
    ANTHROPIC_MAX_PROMPT_TOKENS: "1000000",
    ANTHROPIC_MAX_OUTPUT_TOKENS: "128000",
    UNRELATED_SECRET: "unrelated-test-key",
  };
  const container = new MultiLLMProxyContainer({}, source);
  const forwarded = collectContainerEnv(source);
  for (const name of Object.keys(source).filter((name) => name.startsWith("ANTHROPIC_"))) {
    assert.equal(forwarded[name], source[name]);
    assert.equal(container.envVars[name], source[name]);
  }
  assert.equal(forwarded.UNRELATED_SECRET, undefined);
  assert.equal(collectContainerEnv({ ANTHROPIC_API_KEY_SPARE: "not-a-numbered-spare" }).ANTHROPIC_API_KEY_SPARE, undefined);
});

test("Anthropic native routes use edge API handling", () => {
  assert.equal(isApiRequestPath("/anthropic/v1/messages"), true);
  assert.equal(isApiRequestPath("/anthropic/v1/messages/count_tokens"), true);
  assert.equal(isApiRequestPath("/anthropic/v1/models"), true);
  assert.equal(isApiRequestPath("/anthropic-other/v1/messages"), false);
});

test("Anthropic preflight allows Claude headers without waking the container", async () => {
  const { default: worker } = await loadWorkerModule();
  const origin = "https://chat.example";
  const response = await worker.fetch(new Request("https://proxy.example/anthropic/v1/messages", {
    method: "OPTIONS",
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "x-api-key, anthropic-version, anthropic-beta, content-type",
    },
  }), {
    MULTILLM_PROXY_CONTAINER: {
      getByName() { throw new Error("preflight should not wake the container"); },
    },
  });
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.match(response.headers.get("Access-Control-Allow-Headers"), /anthropic-beta/i);
});
