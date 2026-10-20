import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { bundleArguments, bundleConfig } from "../scripts/check_worker_bundle.mjs";
import { checkConfig, checkPrerequisites, checkRelease } from "../scripts/key_data_preflight.mjs";

const main = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url)));
const knowledge = JSON.parse(readFileSync(new URL("../wrangler.knowledge.jsonc", import.meta.url)));
const commit = "a".repeat(40);
function release(changes = {}) {
  const evidence = {
    migrations: [{ name: "0043_integration_data_policy.sql" }],
    columns: ["official_only", "forced_provider_preferences", "max_stream_cost_microusd"].map(name => ({ name })),
    secrets: ["ADMIN_API_KEY", "FLASK_SECRET_KEY", "JWT_SECRET"].map(name => ({ name, type: "secret_text" })),
    versions: [{ version_id: "private-version", percentage: 100 }], tag: commit, ...changes,
  };
  return { main, knowledge, commit, migrations: ["0043_integration_data_policy.sql"], run: args => {
    if (args[0] === "secret") return JSON.stringify(evidence.secrets);
    if (args[0] === "deployments") return JSON.stringify({ versions: evidence.versions });
    if (args[0] === "versions") return JSON.stringify({ annotations: { "workers/tag": evidence.tag } });
    if (args[0] === "d1") return JSON.stringify([{ success: true,
      results: args.at(-1).includes("PRAGMA") ? evidence.columns : evidence.migrations }]);
    throw new Error("Unexpected release probe");
  } };
}
test("committed release bindings are consistent", () => assert.equal(checkConfig(main, knowledge), "multillm-intelligence"));
test("absent or mismatched configuration refuses deploy admission", () => {
  for (const mutation of [config => { delete config.d1_databases; }, config => { delete config.services; },
    config => { config.vars.AUTH_STORAGE_BACKEND = "sql"; }, config => { config.containers = []; }]) {
    const config = structuredClone(main); mutation(config);
    assert.throws(() => checkConfig(config, knowledge));
  }
  assert.throws(() => checkConfig(main, { ...knowledge, d1_databases: [] }));
});
test("a complete release is admitted without reading secret values", () => assert.doesNotThrow(() => checkRelease(release())));
test("prerequisites refuse missing main bindings before updating the private Worker", () => {
  assert.throws(() => checkPrerequisites(release({ secrets: [] })));
  assert.doesNotThrow(() => checkPrerequisites(release({ tag: "b".repeat(40) })));
});
test("missing credentials, schema, migrations or current private version refuse deployment", () => {
  for (const changes of [{ secrets: [] }, { columns: [] }, { migrations: [] }, { tag: "b".repeat(40) },
    { versions: [] }, { versions: [{ version_id: "old", percentage: 50 }, { version_id: "new", percentage: 50 }] }]) {
    assert.throws(() => checkRelease(release(changes)));
  }
  assert.throws(() => checkRelease({ ...release(), run: () => { throw new Error("Unavailable evidence"); } }));
});
test("independent builds cannot upload through the default build without preflight", () => {
  assert.match(main.build.command, /^node scripts\/key_data_preflight.mjs --deploy && /);
  const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.equal(ci.split("node scripts/check_worker_bundle.mjs --config").length - 1, 2);
  for (const mainWorker of [false, true]) assert.ok(bundleArguments("temporary", "output", mainWorker).includes("--dry-run"));
  const injected = bundleArguments("temporary", "--dry-run=false", true);
  assert.equal(injected.includes("--dry-run=false"), false);
  assert.ok(injected.includes("--dry-run"));
  const copy = bundleConfig(main);
  assert.equal(Object.hasOwn(copy, "build"), false);
  assert.deepEqual(copy, Object.fromEntries(Object.entries(main).filter(([name]) => name !== "build")));
  assert.match(main.build.command, /key_data_preflight/);
  const manual = readFileSync(new URL("../scripts/deploy.sh", import.meta.url), "utf8");
  const workflow = readFileSync(new URL("../.github/workflows/deploy.yml", import.meta.url), "utf8");
  assert.ok(manual.indexOf("key_data_preflight.mjs --check") < manual.indexOf("migrations apply"));
  assert.ok(workflow.indexOf("key_data_preflight.mjs --check") < workflow.indexOf("Apply D1 migrations"));
  assert.ok(workflow.indexOf("key_data_preflight.mjs --prepare") < workflow.indexOf("Deploy Knowledge Worker"));
  assert.ok(manual.indexOf("key_data_preflight.mjs --prepare") < manual.indexOf("wrangler deploy --config wrangler.knowledge.jsonc"));
});
