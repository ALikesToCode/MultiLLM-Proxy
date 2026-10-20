import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scryptSync } from "node:crypto";
import { runtimeBundle, runtimeModule, MemoryStorage } from "./helpers/runtime_versions.mjs";
import { Miniflare, convertV4MiniflareOptions } from "./helpers/local_miniflare.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { requirePeer } from "../worker/peer-capability.mjs";

const run = promisify(execFile), A = "085399e", versions = [A, ""];
const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url)));
const policies = [
  { official_only: null, forced_provider_preferences: null },
  { official_only: 1, forced_provider_preferences: null },
  { official_only: null, forced_provider_preferences: '{"data_collection":"deny"}' },
  { official_only: 0, forced_provider_preferences: null },
  { official_only: null, forced_provider_preferences: '{}' },
];
const key = "mllm_synthetic_incident_key_long_enough";
const digest = scryptSync(key, "syntheticsalt", 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex");
const privateEntry = `export {default,KnowledgeCatalogue} from './worker/knowledge/index.mjs';
export {defaultPolicy} from './worker/knowledge/policy.mjs';`;

test("every expansion/enforcement runtime combination preserves NULL accounts and fences controlled rollback", async t => {
  const mains = new Map(), privates = new Map();
  for (const version of versions) {
    mains.set(version, (await runtimeModule("export {default} from './cloudflare-worker.mjs';", version)).default);
    privates.set(version, await runtimeModule(privateEntry, version));
  }
  const original = globalThis.fetch;
  let external = 0;
  globalThis.fetch = async () => { external++; return Response.json({ results: [] }); };
  t.after(() => { globalThis.fetch = original; });
  for (const main of versions) {
    const script = await runtimeBundle(`import {handleIntelligenceOutbound} from './worker/intelligence-outbound.mjs';
      export default {fetch(request,env){return handleIntelligenceOutbound(new Request('http://intelligence.internal'+new URL(request.url).pathname,request),env)}}`, main, "neutral");
    const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script, compatibilityFlags: ["nodejs_compat"],
      d1Databases: ["INTELLIGENCE_DB"], bindings: config.vars }));
    try {
      const db = await mf.getD1Database("INTELLIGENCE_DB");
      await applyMigrations(db);
      await db.prepare(`INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at)
        VALUES('synthetic',?,?,'chat,models,knowledge:read,knowledge:manage',0,'2026-10-01T00:00:00Z')`)
        .bind(`scrypt:32768:8:1$syntheticsalt$${digest}`, "mllm_mllm_syn").run();
      // A restricted neighbour must not interrupt a different NULL-policy account.
      await db.prepare(`INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at,official_only)
        VALUES('synthetic-neighbour',?,'synthetic-other-prefix','chat',0,'2026-10-01T00:00:00Z',1)`)
        .bind(`scrypt:32768:8:1$syntheticsalt$${digest}`).run();
      const settings = collectContainerEnv({ ...config.vars, ADMIN_API_KEY: "synthetic-bootstrap-long-key",
        FLASK_SECRET_KEY: "synthetic-session-long-enough", JWT_SECRET: "synthetic-jwt-long-enough", OPENROUTER_API_KEY: "synthetic-operator" });
      // Exercise Container authentication directly too: front-door rejection alone
      // cannot prove that a legacy account RPC preserved the rollback fence.
      for (const policy of policies) {
        await db.prepare("UPDATE control_users SET official_only=?,forced_provider_preferences=? WHERE username='synthetic'")
          .bind(policy.official_only, policy.forced_provider_preferences).run();
        const { stdout } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
          (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(settings), A],
        { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
        const rows = stdout.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse);
        assert.equal(rows.at(-1).status, policy === policies[0] ? 200 : 503);
        assert.equal(rows.at(-1).dispatches, policy === policies[0] ? 1 : 0);
      }
      for (const container of versions) for (const privateRef of versions) for (const [index, policy] of policies.entries()) {
        await t.test(`${main || "B"}/${container || "B"}/${privateRef || "B"}/policy-${index}`, async () => {
          await db.prepare("UPDATE control_users SET official_only=?,forced_provider_preferences=? WHERE username='synthetic'")
            .bind(policy.official_only, policy.forced_provider_preferences).run();
          let forwarded = 0, privatePosts = 0, containerDispatches = 0, submittedPreferences;
          external = 0;
          const env = { ...config.vars, ADMIN_API_KEY: "synthetic-bootstrap-long-key", EXA_API_KEY: "synthetic-operator", INTELLIGENCE_DB: db };
          const knowledge = privates.get(privateRef), storage = new MemoryStorage(), configuration = knowledge.defaultPolicy();
          configuration.enabled = true;
          Object.assign(configuration.providers.exa, { enabled: true, limit: 100, background_limit: 50, hard_limit_confirmed: true, retention_allowed: true });
          await storage.put("policy", configuration);
          const catalogue = new knowledge.KnowledgeCatalogue({ storage }, env);
          env.KNOWLEDGE_AUTHORITY = { idFromName: () => 1, get: () => ({ fetch: (url, init) => catalogue.fetch(new Request(url, init)) }) };
          env.KNOWLEDGE_SERVICE = { fetch: (url, init) => {
            if (init?.method === "POST") privatePosts++;
            return knowledge.default.fetch(new Request(url, init), env, { waitUntil() {} });
          } };
          env.MULTILLM_PROXY_CONTAINER = { getByName: () => ({ async fetch(input) {
            const request = input instanceof Request ? input : new Request(input);
            const path = new URL(request.url).pathname, health = path === "/healthz";
            if (!health) forwarded++;
            const { stdout } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
              (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(settings), container,
              JSON.stringify([[path, health || request.method === "GET" ? "get" : "post"]])],
            { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
            const row = stdout.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse).at(-1);
            containerDispatches += row.dispatches;
            if (row.dispatches) submittedPreferences = row.preferences;
            return Response.json(row.body, { status: row.status });
          } }) };
          // Read the complete account set with real login/session/CSRF handling.
          // Neither the current user's policy nor another user's may disable management.
          const { stdout: management, stderr: managementErrors } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
            (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(settings), container,
            JSON.stringify([["/login", "post", "synthetic"], ["/login", "post", "admin"], ["/users", "get"]])],
          { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
          const results = management.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse);
          assert.deepEqual(results.map(row => row.status), [302, 302, 200], managementErrors);
          assert.ok(results.every(row => row.dispatches === 0));
          assert.deepEqual(await db.prepare("SELECT official_only,forced_provider_preferences FROM control_users WHERE username='synthetic'").first(), policy,
            "Dashboard sign-in must preserve stored restrictions");
          const worker = mains.get(main);
          if (index === 0) {
            const models = await worker.fetch(new Request("https://gateway.example/v1/models", {
              headers: { authorization: `Bearer ${key}` },
            }), env, { waitUntil() {} });
            assert.equal(models.status, 200, "unrestricted models during rollback: " + await models.clone().text());
          }
          const chat = await worker.fetch(new Request("https://gateway.example/v1/chat/completions", {
            method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
            body: JSON.stringify({ model: "openrouter:example", messages: [{ role: "user", content: "synthetic" }] }),
          }), env, { waitUntil() {} });
          const chatAllowed = index === 0 || !main && !container;
          assert.equal(chat.status, chatAllowed ? 200 : 503, "chat status: " + await chat.clone().text());
          assert.equal(containerDispatches, chatAllowed ? 1 : 0, "provider dispatches");
          if (chatAllowed && index === 2) assert.equal(submittedPreferences.data_collection, "deny");
          if (!chatAllowed && main === "") assert.equal(forwarded, 0, "No content sent to an expansion Container");
          const response = await worker.fetch(new Request("https://gateway.example/v1/knowledge/native/exa_search", {
            method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: JSON.stringify({ query: "synthetic" }),
          }), env, { waitUntil() {} });
          if (index === 0) {
            assert.equal(response.status, 200, "unrestricted Knowledge: " + await response.clone().text());
            assert.equal(external, 1);
          } else {
            assert.ok(response.status >= 400, "controlled Knowledge must be enforced or refused");
            assert.equal(external, 0);
            if (main === "" && privateRef === A) assert.equal(privatePosts, 0, "No content sent to an expansion private Worker");
          }
        });
      }
    } finally { await mf.dispose(); }
  }
});

test("controlled peer admission refuses absent, malformed, failed and stale capabilities without a content request", async () => {
  for (const capability of [null, {}, { protocol: 1, enforcement: false }, { protocol: 2, enforcement: false }, { protocol: "2", enforcement: true }]) {
    const calls = [];
    await assert.rejects(requirePeer({ fetch(url, init) { calls.push(init.method); return Response.json({ key_controls: capability }); } }, "http://knowledge.internal/ready"), { status: 503 });
    assert.deepEqual(calls, ["GET"]);
  }
  await assert.rejects(requirePeer({ fetch() { throw Error("unavailable"); } }, "http://knowledge.internal/ready"), { status: 503 });
});

test("private Knowledge accepts headerless NULL accounts but refuses controlled legacy or mismatched senders", async () => {
  const { default: knowledge, KnowledgeCatalogue } = await runtimeModule(privateEntry);
  const { policyStore } = await import("./helpers/dispatch_fixture.mjs");
  for (const [index, policy] of policies.entries()) {
    let delegated = 0;
    const env = { INTELLIGENCE_DB: policyStore(policy) };
    const catalogue = new KnowledgeCatalogue({ storage: new MemoryStorage() }, env);
    env.KNOWLEDGE_AUTHORITY = { idFromName: () => 1, get: () => ({ fetch(url, init) {
      delegated++; return catalogue.fetch(new Request(url, init));
    } }) };
    const response = await knowledge.fetch(new Request("http://knowledge.internal/v1/dispatch", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "status",
        principal: { id: "synthetic", scopes: ["knowledge:manage"] }, payload: {} }),
    }), env, { waitUntil() {} });
    if (index) { assert.equal(response.status, 503); assert.equal(delegated, 0); }
    else assert.equal(response.status, 200);
  }
  const { handleKnowledgeOutbound } = await import("../worker/knowledge-outbound.mjs");
  let sent = 0;
  const response = await handleKnowledgeOutbound(new Request("http://knowledge.internal/v1/dispatch", { method: "POST",
    headers: { "content-type": "application/json", "X-MultiLLM-Dispatch-Principal": JSON.stringify({ version: 1, username: "different" }) },
    body: JSON.stringify({ version: 1, operation: "status", principal: { id: "synthetic", scopes: ["knowledge:manage"] }, payload: {} }),
  }), { INTELLIGENCE_DB: policyStore(), KNOWLEDGE_SERVICE: { fetch() { sent++; return Response.json({}); } } });
  assert.equal(response.status, 403); assert.equal(sent, 0);
});
