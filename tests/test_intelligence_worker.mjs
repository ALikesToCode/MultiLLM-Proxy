import assert from "node:assert/strict";
import test from "node:test";

import { isApiRequestPath } from "../worker/api-paths.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";

test("intelligence and media paths participate in edge API handling", () => {
  for (const path of ["/intelligence/v1/chat/completions", "/v1/audio/transcriptions", "/v1/audio/speech", "/v1/embeddings"]) {
    assert.equal(isApiRequestPath(path), true);
  }
  assert.equal(isApiRequestPath("/dashboard"), false);
});

test("containers require durable intelligence storage and pass through reviewed policy", () => {
  const policy = '{"version":1,"enabled":false}';
  const env = collectContainerEnv({ INTELLIGENCE_POLICY_JSON: policy, INTELLIGENCE_REQUIRE_DURABLE_STORAGE: "false" });
  assert.equal(env.INTELLIGENCE_POLICY_JSON, policy);
  assert.equal(env.INTELLIGENCE_REQUIRE_DURABLE_STORAGE, "true");
});

test("containers receive the isolated NanoGPT subscription key under its own name only", () => {
  const key = "synthetic-subscription-key";
  const env = collectContainerEnv({ INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY: key, NANOGPT_API_KEY: "synthetic-pool-key" });
  assert.equal(env.INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY, key);
  assert.equal(env.NANOGPT_API_KEY, "synthetic-pool-key");
  assert.deepEqual(Object.keys(env).filter((name) => env[name] === key), ["INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY"]);
  assert.equal(collectContainerEnv({}).INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY, undefined);
});
