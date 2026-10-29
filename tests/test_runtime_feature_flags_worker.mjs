import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { runtimeFeatureValue, withRuntimeFeatureFlags } from "../worker/runtime-feature-flags.mjs";
import { usageBucketsEnabled } from "../worker/usage-buckets-d1.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
const { MultiLLMProxyContainer } = await loadWorkerModule();

test("deployment groups feature settings while preserving Container flags and secrets", () => {
  assert.equal(Object.keys(config.vars.RUNTIME_FEATURE_FLAGS).length, 7);
  // Vars and secrets share the Worker's limit of 128 text bindings, and the release has 127.
  // Put a new nonsecret setting in RUNTIME_FEATURE_FLAGS instead of raising this count.
  assert.equal(Object.keys(config.vars).length, 65);
  const source = { ...config.vars, ANTHROPIC_API_KEY: "synthetic-provider-secret" };
  const container = new MultiLLMProxyContainer({}, source);
  assert.equal(container.envVars.MODEL_COOLDOWN_ENABLED, "true");
  assert.equal(container.envVars.POOL_RESET_SCHEDULING_ENABLED, "true");
  assert.equal(container.envVars.PROMPT_CACHE_AFFINITY_ENABLED, "true");
  assert.equal(container.envVars.PROMPT_CACHE_USAGE_BUCKETS_ENABLED, "true");
  assert.equal(container.envVars.UPSTREAM_RETRY_AFTER_ADVICE_ENABLED, "true");
  assert.equal(container.envVars.MULTILLM_STREAM_PREFLIGHT, "strict");
  assert.equal(container.envVars.ANTHROPIC_API_KEY, "synthetic-provider-secret");
  assert.equal(container.envVars.RUNTIME_FEATURE_FLAGS, undefined);
  assert.equal(usageBucketsEnabled(source), true);
  assert.equal(runtimeFeatureValue(source, "ROLEPLAY_CANDIDATE_CONTEXT_REFIT"), "window");
});

test("individual settings retain disabled values and precedence without mutating bindings", () => {
  for (const disabled of ["false", "", false, null]) {
    const source = { ...config.vars, PROMPT_CACHE_USAGE_BUCKETS_ENABLED: disabled };
    assert.equal(usageBucketsEnabled(source), false);
    assert.equal(runtimeFeatureValue(source, "PROMPT_CACHE_USAGE_BUCKETS_ENABLED"), disabled);
  }
  const source = { ...config.vars, MODEL_COOLDOWN_ENABLED: "false", MULTILLM_STREAM_PREFLIGHT: "off" };
  const snapshot = structuredClone(source);
  const resolved = withRuntimeFeatureFlags(source);
  assert.equal(resolved.MODEL_COOLDOWN_ENABLED, "false");
  assert.equal(resolved.MULTILLM_STREAM_PREFLIGHT, "off");
  const container = collectContainerEnv(source);
  assert.equal(container.MODEL_COOLDOWN_ENABLED, "false");
  assert.equal(container.MULTILLM_STREAM_PREFLIGHT, "off");
  assert.deepEqual(source, snapshot);
});

test("malformed grouped settings cannot enable features or inject credentials", () => {
  for (const flags of [null, true, [], "{\"MODEL_COOLDOWN_ENABLED\":\"true\"}", 1]) {
    const source = { RUNTIME_FEATURE_FLAGS: flags };
    assert.equal(runtimeFeatureValue(source, "MODEL_COOLDOWN_ENABLED"), undefined);
    assert.equal(collectContainerEnv(source).MODEL_COOLDOWN_ENABLED, undefined);
    assert.equal(usageBucketsEnabled(source), false);
  }
  const flags = {
    MODEL_COOLDOWN_ENABLED: {}, PROMPT_CACHE_USAGE_BUCKETS_ENABLED: [],
    ANTHROPIC_API_KEY: "synthetic-untrusted-secret", ADMIN_API_KEY: "synthetic-untrusted-admin",
  };
  const source = { RUNTIME_FEATURE_FLAGS: flags };
  assert.equal(runtimeFeatureValue(source, "ANTHROPIC_API_KEY"), undefined);
  assert.equal(collectContainerEnv(source).ANTHROPIC_API_KEY, undefined);
  assert.equal(collectContainerEnv(source).ADMIN_API_KEY, undefined);
  assert.equal(collectContainerEnv(source).MODEL_COOLDOWN_ENABLED, undefined);
  assert.equal(usageBucketsEnabled(source), false);
});

test("boolean grouped flags and legacy individual bindings work without a group", () => {
  const grouped = { RUNTIME_FEATURE_FLAGS: { MODEL_COOLDOWN_ENABLED: true } };
  assert.equal(collectContainerEnv(grouped).MODEL_COOLDOWN_ENABLED, "true");
  const legacy = { MODEL_COOLDOWN_ENABLED: "true", MULTILLM_STREAM_PREFLIGHT: "strict" };
  assert.equal(collectContainerEnv(legacy).MODEL_COOLDOWN_ENABLED, "true");
  assert.equal(collectContainerEnv(legacy).MULTILLM_STREAM_PREFLIGHT, "strict");
});
