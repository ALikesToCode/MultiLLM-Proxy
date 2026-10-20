import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scryptSync } from "node:crypto";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "./helpers/local_miniflare.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";

const run = promisify(execFile);
const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url)));
const digest = scryptSync("mllm_synthetic_incident_key_long_enough", "synthetic-salt", 64,
  { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex");

test("migrated account rows cross the real private RPC and registered Container routes", async t => {
  const bundle = await build({ stdin: { resolveDir: process.cwd(), contents: `
    import {handleIntelligenceOutbound} from './worker/intelligence-outbound.mjs';
    export default {fetch(request,env) {
      // The private account host is owned by the main Worker, never Knowledge.
      env.KNOWLEDGE_SERVICE = {fetch(){throw new Error('Old Knowledge must not receive account requests')}};
      return handleIntelligenceOutbound(new Request('http://intelligence.internal'+new URL(request.url).pathname, request),env);
    }};` }, bundle: true, format: "esm", platform: "neutral", external: ["node:*", "cloudflare:*"], write: false });
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text,
    compatibilityFlags: ["nodejs_compat"], d1Databases: ["INTELLIGENCE_DB"], bindings: config.vars }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  // Insert a pre-existing account directly, letting the actual migrations supply
  // NULL defaults. No helper manufactures a policy envelope or an RPC response.
  await db.prepare(`INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at,
    last_used_at,last_used_ip,created_by,secret_scan_mode,shadow_eval_rate)
    VALUES('synthetic',?,?,'chat,models',0,'2026-10-01T00:00:00Z','2026-10-02T00:00:00Z',
    '192.0.2.1','admin','observe',0)`)
    .bind(`scrypt:32768:8:1$synthetic-salt$${digest}`, "mllm_mllm_syn").run();
  const rpc = async body => {
    const response = await mf.dispatchFetch("http://local/v1/users", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) });
    return { status: response.status, body: await response.json() };
  };
  const containerEnv = collectContainerEnv({ ...config.vars, INTELLIGENCE_DB: db, KNOWLEDGE_SERVICE: {},
    ADMIN_API_KEY: "synthetic-bootstrap-admin-long-enough", FLASK_SECRET_KEY: "synthetic-session-secret-long-enough",
    JWT_SECRET: "synthetic-jwt-secret-long-enough", OPENROUTER_API_KEY: "synthetic-operator" });
  assert.equal(containerEnv.CONFIG_REVISION_SYNC_ENABLED ?? "false", "false");
  assert.equal(containerEnv.STREAM_COST_BREAKER_ENABLED ?? "false", "false");
  const routes = async () => {
    const { stdout } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
      (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(containerEnv)],
    { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
    return stdout.split("\n").filter(line => line.startsWith('{"path":')).map(line => JSON.parse(line));
  };
  await t.test("unset flags and an old Knowledge binding do not break ordinary durable keys", async () => {
    assert.deepEqual((await routes()).map(row => row.status), [200, 200]);
    const current = await rpc({ operation: "get", username: "synthetic", data_policy_version: 1 });
    assert.deepEqual(current.body.user.data_policy, { version: 1, official_only: null, forced_provider_preferences: null });
  });
  await t.test("legacy readers receive the exact earlier row shape", async () => {
    const legacy = await rpc({ operation: "get", username: "synthetic" });
    assert.equal(legacy.status, 200);
    assert.equal(Object.keys(legacy.body.user).length, 19);
    assert.equal(Object.hasOwn(legacy.body.user, "data_policy"), false);
    assert.equal(Object.hasOwn(legacy.body.user, "official_only"), false);
    const write = await rpc({ operation: "upsert", user: legacy.body.user });
    assert.equal(write.status, 200);
  });
  await t.test("unsupported envelopes are refused", async () => {
    assert.equal((await rpc({ operation: "get", username: "synthetic", data_policy_version: 2 })).status, 400);
  });
  await db.prepare("UPDATE control_users SET official_only=1, forced_provider_preferences=? WHERE username='synthetic'")
    .bind(JSON.stringify({ data_collection: "deny" })).run();
  await t.test("current controls reach the actual provider dispatch", async () => {
    const rows = await routes();
    assert.deepEqual(rows.map(row => row.status), [200, 200]);
    assert.equal(rows[1].preferences.data_collection, "deny");
  });
  await t.test("legacy readers and writers cannot erase or bypass controlled accounts", async () => {
    const expanded = await rpc({ operation: "get", username: "synthetic" });
    assert.equal(expanded.status, 200);
    assert.equal(expanded.body.user.official_only, 1);
    const current = (await rpc({ operation: "get", username: "synthetic", data_policy_version: 1 })).body.user;
    const legacy = Object.fromEntries(Object.entries(current).filter(([name]) => !["data_policy", "official_only", "forced_provider_preferences"].includes(name)));
    assert.equal((await rpc({ operation: "upsert", user: legacy })).status, 200);
    assert.equal((await rpc({ operation: "get", username: "synthetic", data_policy_version: 1 })).body.user.official_only, 1);
  });
  await db.prepare("UPDATE control_users SET revoked_at='2026-10-20T00:00:00Z' WHERE username='synthetic'").run();
  await t.test("the same registered requests reject a revoked durable key", async () => {
    assert.deepEqual((await routes()).map(row => row.status), [401, 401]);
  });
});
