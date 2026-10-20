import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scryptSync } from "node:crypto";
import { OLD, runtimeBundle, runtimeModule, MemoryStorage } from "./helpers/runtime_versions.mjs";
import { Miniflare, convertV4MiniflareOptions } from "./helpers/local_miniflare.mjs";
import { applyMigrations } from "./d1_migrations.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";


import { controlNetwork } from "../worker/dispatch-network.mjs";
import { policyStore } from "./helpers/dispatch_fixture.mjs";

const EXPAND = "085399e";
const { handleControlUsersRequest, providerFetch, providerOperation, legacyBindingControls } = await runtimeModule(`
export {handleControlUsersRequest} from './worker/control-users-d1.mjs';
export {providerFetch,providerOperation} from './worker/provider-dispatch.mjs';
export {legacyBindingControls} from './worker/legacy-binding-policy.mjs';`, EXPAND);
const run = promisify(execFile);
const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url)));
const states = [
  { official_only: null, forced_provider_preferences: null },
  { official_only: 1, forced_provider_preferences: null },
  { official_only: 0, forced_provider_preferences: null },
  { official_only: null, forced_provider_preferences: '{}' },
  { official_only: null, forced_provider_preferences: '{"data_collection":"deny"}' },
];

test("expansion refuses future controls at every Worker provider boundary", async () => {
  for (const policy of states.slice(1)) for (const provider of ["openai", "gemini", "openrouter", "cloudflare", "linkapi", "knowledge"]) {
    const env = { INTELLIGENCE_DB: policyStore(policy) };
    const options = { env, authority: { authenticated: true, keyId: "synthetic" }, send() { assert.fail("No upstream request"); } };
    await assert.rejects(providerFetch(provider, "https://provider.example", {}, options), { status: 503 });
    await assert.rejects(providerOperation(provider, () => assert.fail("No SDK dispatch"), options), { status: 503 });
  }
});

test("old and expansion account RPC and Container pairs keep NULL-policy routes working", async t => {
  const digest = scryptSync("mllm_synthetic_incident_key_long_enough", "synthetic-salt", 64,
    { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex");
  for (const revision of [OLD, EXPAND]) {
    const admission = revision === OLD ? "" : `import {providerFetch} from './worker/provider-dispatch.mjs';`;
    const script = await runtimeBundle(`${admission} import {handleIntelligenceOutbound} from './worker/intelligence-outbound.mjs';
      export default {async fetch(request,env){
        ${revision === OLD ? "" : `if(new URL(request.url).pathname==='/probe-provider') {
          try { return await providerFetch('openrouter','https://openrouter.ai/api/v1/chat/completions',{},
            {env,authority:{legacyBinding:true},send:()=>Response.json({ok:true})}); }
          catch { return Response.json({error:'key_controls_require_upgrade'},{status:503}); }
        }`}
        return handleIntelligenceOutbound(new Request('http://intelligence.internal'+new URL(request.url).pathname,request),env)}}`, revision, "neutral");
    const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script, compatibilityFlags: ["nodejs_compat"],
      d1Databases: ["INTELLIGENCE_DB"], bindings: config.vars }));
    try {
      const db = await mf.getD1Database("INTELLIGENCE_DB");
      await applyMigrations(db);
      await db.prepare(`INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at)
        VALUES('synthetic',?,?,'chat,models',0,'2026-10-01T00:00:00Z')`)
        .bind(`scrypt:32768:8:1$synthetic-salt$${digest}`, "mllm_mllm_syn").run();
      const settings = collectContainerEnv({ ...config.vars, ADMIN_API_KEY: "synthetic-bootstrap-long-enough",
        FLASK_SECRET_KEY: "synthetic-session-long-enough", JWT_SECRET: "synthetic-jwt-long-enough", OPENROUTER_API_KEY: "synthetic-operator" });
      for (const container of [OLD, EXPAND]) await t.test(`${revision || "expand"} RPC / ${container || "expand"} Container`, async () => {
        const { stdout } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
          (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(settings), container,
          JSON.stringify([["/v1/models", "get"], ["/v1/chat/completions", "post"], ["/login", "post", "synthetic"], ["/login", "post", "admin"], ["/users", "get"]])],
        { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
        const rows = stdout.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse);
        assert.deepEqual(rows.map(row => row.status), [200, 200, 302, 302, 200]);
      });
      if (revision === EXPAND) {
        // A future controlled row must never poison login or a full management cache reload.
        await db.prepare("UPDATE control_users SET official_only=1 WHERE username='synthetic'").run();
        const { stdout: management } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
          (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(settings), EXPAND,
          JSON.stringify([["/login", "post", "synthetic"], ["/login", "post", "admin"], ["/users", "get"], ["/v1/chat/completions", "post", "admin"]])],
        { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
        const results = management.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse);
        assert.deepEqual(results.map(row => row.status), [302, 302, 200, 200]);
        assert.ok(results.slice(0, 3).every(row => row.dispatches === 0));
        assert.equal(results.at(-1).dispatches, 1);
        assert.equal((await db.prepare("SELECT official_only FROM control_users WHERE username='synthetic'").first()).official_only, 1);
        // Use the actual strict decoder and auth/cache paths from the pre-expansion Container.
        // A legacy management projection must not turn cached restricted identities into dispatch authority.
        for (const policy of states) {
          await db.prepare("UPDATE control_users SET official_only=?,forced_provider_preferences=? WHERE username='synthetic'")
            .bind(policy.official_only, policy.forced_provider_preferences).run();
          const { stdout: oldManagement } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
            (await mf.ready).href.replace(/\/$/, ""), JSON.stringify({ ...settings, ACCOUNT_DRIVER_OUTBOUND_ADMISSION: "true" }), OLD,
            JSON.stringify([["/login", "post", "synthetic"], ["/login", "post", "admin"], ["/users", "get"], ["/v1/chat/completions", "post"]])],
          { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
          const oldRows = oldManagement.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse);
          assert.deepEqual(oldRows.slice(0, 3).map(row => row.status), [302, 302, 200]);
          assert.equal(oldRows.at(-1).status, policy === states[0] ? 200 : 503);
          assert.equal(oldRows.at(-1).dispatches, policy === states[0] ? 1 : 0);
          const current = await db.prepare("SELECT official_only,forced_provider_preferences FROM control_users WHERE username='synthetic'").first();
          assert.deepEqual(current, policy);
        }
        for (const policy of states.slice(1)) {
          await db.prepare("UPDATE control_users SET official_only=?,forced_provider_preferences=? WHERE username='synthetic'")
            .bind(policy.official_only, policy.forced_provider_preferences).run();
          const { stdout } = await run(process.env.PYTHON || "python3", ["-I", "tests/support/account_envelope_driver.py",
            (await mf.ready).href.replace(/\/$/, ""), JSON.stringify(settings), EXPAND],
          { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 120000 });
          const rows = stdout.split("\n").filter(line => line.startsWith('{"path":')).map(JSON.parse);
          assert.equal(rows.at(-1).status, 503);
          assert.equal(rows.at(-1).dispatches, 0);
        }
      }
    } finally { await mf.dispose(); }
  }
});

test("legacy upsert cannot reset a policy enabled between the read and atomic write", async t => {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response()}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  await db.prepare(`INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at)
    VALUES('synthetic','synthetic-hash','synthetic-prefix','chat',0,'2026-10-01T00:00:00Z')`).run();
  const call = (body, database = db) => handleControlUsersRequest(new Request("http://intelligence.internal/v1/users", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
  }), { INTELLIGENCE_DB: database });
  const legacy = (await (await call({ operation: "get", username: "synthetic", unknown_extension: 1 })).json()).user;
  assert.equal(Object.keys(legacy).length, 19);
  let interleaved = false;
  const racing = { prepare: sql => db.prepare(sql), async batch(statements) {
    if (!interleaved) {
      interleaved = true;
      await db.prepare("UPDATE control_users SET official_only=1,forced_provider_preferences=? WHERE username='synthetic'")
        .bind('{"data_collection":"deny"}').run();
    }
    return db.batch(statements);
  } };
  assert.equal((await call({ operation: "upsert", user: legacy }, racing)).status, 200);
  assert.deepEqual(await db.prepare("SELECT official_only,forced_provider_preferences FROM control_users").first(),
    { official_only: 1, forced_provider_preferences: '{"data_collection":"deny"}' });
});

test("old and expansion Knowledge pairs keep unrestricted requests identical; rollback refuses controlled content", async () => {
  const entry = `export {default,KnowledgeCatalogue} from './worker/knowledge/index.mjs';
    export {defaultPolicy} from './worker/knowledge/policy.mjs';
    export {handleKnowledgeEdgeRequest} from './worker/knowledge-edge.mjs';`;
  const modules = new Map([[OLD, await runtimeModule(entry, OLD)], [EXPAND, await runtimeModule(entry, EXPAND)]]);
  const original = globalThis.fetch;
  let dispatches = 0;
  globalThis.fetch = async () => { dispatches++; return Response.json({ results: [] }); };
  try {
    for (const main of [OLD, EXPAND]) for (const privateRef of [OLD, EXPAND]) for (const policy of main === OLD && privateRef === OLD ? states.slice(0, 1) : states) {
      dispatches = 0;
      const edge = modules.get(main), knowledge = modules.get(privateRef);
      const storage = new MemoryStorage(), configuration = knowledge.defaultPolicy();
      configuration.enabled = true;
      Object.assign(configuration.providers.exa, { enabled: true, limit: 100, background_limit: 50, hard_limit_confirmed: true, retention_allowed: true });
      await storage.put("policy", configuration);
      const env = { ADMIN_API_KEY: "synthetic-bootstrap-long-key", ADMIN_USERNAME: "synthetic", AUTH_STORAGE_BACKEND: "d1",
        EXA_API_KEY: "synthetic-operator", INTELLIGENCE_DB: policyStore(policy) };
      const catalogue = new knowledge.KnowledgeCatalogue({ storage }, env);
      env.KNOWLEDGE_AUTHORITY = { idFromName: () => 1, get: () => ({ fetch: (url, init) => catalogue.fetch(new Request(url, init)) }) };
      env.KNOWLEDGE_SERVICE = { fetch: (url, init) => knowledge.default.fetch(new Request(url, init), env, { waitUntil() {} }) };
      const invoke = () => edge.handleKnowledgeEdgeRequest(new Request("https://gateway.example/v1/knowledge/native/exa_search", {
        method: "POST", headers: { authorization: "Bearer synthetic-bootstrap-long-key", "content-type": "application/json" },
        body: JSON.stringify({ query: "synthetic" }),
      }), env);
      // Only the pinned baseline predates the runtime test guard.
      const response = privateRef ? await controlNetwork("https://api.exa.ai/search", invoke) : await invoke();
      assert.equal(response.status, policy === states[0] ? 200 : 503, `${main || "A"}/${privateRef || "A"}`);
      assert.equal(dispatches, policy === states[0] ? 1 : 0);
    }
  } finally { globalThis.fetch = original; }
});


test("legacy background work runs only while every durable policy remains NULL", async () => {
  for (const policy of states) {
    let dispatches = 0;
    const options = { env: { INTELLIGENCE_DB: policyStore(policy) }, authority: { legacyBinding: true },
      send: () => { dispatches++; return new Response("ok"); } };
    const operation = () => providerFetch("knowledge", "https://provider.example", {}, options);
    if (policy === states[0]) assert.equal((await operation()).status, 200);
    else await assert.rejects(operation(), { status: 503 });
    assert.equal(dispatches, policy === states[0] ? 1 : 0);
  }
});


test("registered Container forwarding refuses controlled accounts before sending any body", async () => {
  const worker = (await runtimeModule("export {default} from './cloudflare-worker.mjs';", EXPAND)).default;
  for (const policy of states) for (const path of ["/v1/chat/completions", "/v1/images/generations", "/v1/videos/generations",
    "/v1/embeddings", "/v1/audio/speech", "/gemini/v1beta/models/example:generateContent", "/v1/models"]) {
    let sent = 0;
    const env = { ADMIN_API_KEY: "synthetic-bootstrap-long-key", ADMIN_USERNAME: "synthetic", INTELLIGENCE_DB: policyStore(policy),
      MULTILLM_PROXY_CONTAINER: { getByName: () => ({ fetch() { sent++; return Response.json({ ok: true }); } }) } };
    const response = await worker.fetch(new Request("https://gateway.example" + path, {
      method: path.endsWith("/models") ? "GET" : "POST", headers: { authorization: "Bearer synthetic-bootstrap-long-key", "content-type": "application/json" },
      ...(path.endsWith("/models") ? {} : { body: JSON.stringify({ model: "openrouter:example", input: "synthetic" }) }),
    }), env, { waitUntil() {} });
    assert.equal(response.status, policy === states[0] ? 200 : 503, path);
    assert.equal(sent, policy === states[0] ? 1 : 0, path);
  }
});

test("a fenced expansion Container preserves a NULL private call beside other controlled accounts", async () => {
  for (const policy of states.slice(1)) {
    const database = policyStore(policy);
    for (const capability of [{ protocol: 1, enforcement: false }, { protocol: 0 }, null]) {
      let probes = 0;
      const env = { INTELLIGENCE_DB: database, MULTILLM_PROXY_CONTAINER: { getByName: () => ({ fetch(url, init) {
        probes++; assert.equal(new URL(url).pathname, "/healthz"); assert.equal(init.method, "GET");
        return Response.json({ key_controls: capability });
      } }) } };
      if (capability?.protocol === 1) assert.deepEqual(await legacyBindingControls(env), states[0]);
      else await assert.rejects(legacyBindingControls(env));
      assert.equal(probes, 1);
    }
  }
  let probes = 0;
  await assert.rejects(legacyBindingControls({ INTELLIGENCE_DB: policyStore({}), MULTILLM_PROXY_CONTAINER: {
    getByName() { probes++; assert.fail("Unreadable policy must not negotiate a fallback"); },
  } }));
  assert.equal(probes, 0);
});
