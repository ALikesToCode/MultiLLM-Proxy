import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { TenantContext, AuthorityResult } from "../worker/enterprise-contract.mjs";
import { createCreditsLifecycle, CreditsAdmissionError } from "../worker/credits-admission.mjs";
import { appendCredit, readCredits, contextOwner } from "../worker/credits-d1.mjs";
import { handleTenantGovernanceRequest } from "../worker/tenant-governance-d1.mjs";
import { handleReservationsRequest } from "../worker/reservations-d1.mjs";
import { nativeGenerationFetch, nativeGenerationSetup } from "../worker/gateway-extensions.mjs";
import { exactCacheIdentity } from "../worker/exact-generation-cache.mjs";
import { semanticPartition } from "../worker/semantic-generation-cache.mjs";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { handleIdempotencyRequest } from "../worker/idempotency-d1.mjs";
import { handleResponsesStateRequest } from "../worker/responses-state-d1.mjs";
import { handleContextPageStateRequest } from "../worker/context-pages-d1.mjs";
import { recordNativeUsage } from "../worker/usage-ledger-d1.mjs";
import { tenantStorageKey } from "../worker/tenants-d1.mjs";
import { retentionRequestId } from "../worker/retention-policy.mjs";
import { USER_FIELDS } from "../worker/control-users-d1.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { handleManagedStateRequest } from "../worker/managed-state-dispatch.mjs";

const request = path => new Request(`http://intelligence.internal${path}`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "probe" }),
});
test("enterprise private domains retain disabled gates and reach enabled authorities", async () => {
  for (const [domain, flag] of [["saml", "SAML_ENABLED"], ["scim", "SCIM_ENABLED"], ["credits", "CREDITS_ENABLED"], ["payments", "PAYMENTS_ENABLED"]]) {
    assert.equal((await handleManagedStateRequest(request(`/v1/managed-state/${domain}`), {})).status, 404);
    assert.notEqual((await handleManagedStateRequest(request(`/v1/managed-state/${domain}`), { [flag]: "true", PAYMENT_PROCESSOR_CONFIG_JSON: JSON.stringify({ processor: "stripe", secret_key_ref: "PAYMENT_TEST_KEY", return_origins: ["https://portal.test"], product_name: "Gateway credits" }), PAYMENT_WEBHOOK_KEY_REF: "PAYMENT_TEST_WEBHOOK" })).status, 404);
  }
});

const allFlags = { ORGANISATIONS_ENABLED: "true", TENANT_GOVERNANCE_ENABLED: "true", SAML_ENABLED: "true", SCIM_ENABLED: "true",
  CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: "all", PAYMENTS_ENABLED: "true" };
const tenant = (org = null) => new TenantContext({ principal_id: "admin", org_id: org });
const route = "/test/v1/chat/completions";
const payload = { model: "test", messages: [{ role: "user", content: "fixture" }], max_tokens: 8, temperature: 0 };
const nativeRequest = (headers = {}) => new Request(`https://provider.invalid${route}`, {
  method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(payload),
});
const completion = JSON.stringify({ choices: [{ message: { content: "fixture" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 2 } });
const complete = () => new Response(completion, { headers: { "content-type": "application/json" } });
const authority = { authenticated: true, provider: "openai", route, principal: { id: "admin" } };
function fixture(t, flags = {}) {
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  for (const migration of ["0003_control_users.sql", "0007_usage_ledger.sql", "0011_secret_firewall.sql", "0013_shadow_eval.sql",
    "0017_control_revisions.sql", "0019_generation_cache.sql", "0020_usage_reservations.sql", "0023_idempotency.sql",
    "0024_context_pages.sql", "0026_semantic_cache.sql", "0028_responses_state.sql", "0033_tenant_hierarchy.sql", "0034_tenant_governance.sql",
    "0035_saml_federation.sql", "0036_scim_provisioning.sql", "0037_credits_ledger.sql", "0038_payment_billing.sql"])
    sql.exec(readFileSync(new URL(`../intelligence-migrations/${migration}`, import.meta.url), "utf8"));
  const operations = [];
  let failBatch = false;
  const db = { prepare(query) {
    let values = [];
    const execute = () => {
      operations.push(query);
      const numbered = /\?[1-9]/.test(query);
      const stmt = sql.prepare(query.replace(/\?(\d+)/g, (_, n) => `$v${n}`));
      stmt.setAllowUnknownNamedParameters(true);
      const args = numbered ? [Object.fromEntries(values.map((v,i) => [`v${i+1}`, v]))] : values;
      const rows = stmt.columns().length ? stmt.all(...args) : (stmt.run(...args), []);
      return { success: true, results: rows.map(row => ({ ...row })), meta: { changes: sql.prepare("SELECT changes() n").get().n } };
    };
    const statement = { bind(...args) { values = args; return statement; }, all: execute, run: execute,
      first: () => execute().results[0] ?? null };
    return statement;
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try {
      const results = statements.map(statement => statement.all());
      if (failBatch) { failBatch = false; throw Error("synthetic batch failure"); }
      sql.exec("COMMIT"); return results;
    } catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
  const objects = new Map();
  const bucket = { async put(key,value,options = {}) {
    const bytes = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
    objects.set(key, { bytes, customMetadata: options.customMetadata });
  }, async get(key) {
    const item = objects.get(key);
    return item ? { size: item.bytes.length, customMetadata: item.customMetadata, arrayBuffer: async () => item.bytes.slice().buffer,
      text: async () => new TextDecoder().decode(item.bytes) } : null;
  }, async head(key) { return objects.has(key) ? { size: objects.get(key).bytes.length } : null; },
  async delete(key) { objects.delete(key); } };
  const env = { ADMIN_API_KEY: "synthetic-admin-key", INTELLIGENCE_DB: db, multillm_media: bucket,
    MODEL_PRICING_USD_PER_MILLION: '{"openai:test":{"input":1,"output":2}}', MEDIA_SIGNING_SECRET: "synthetic-media-key", ...flags };
  const bind = (org, principal = "admin") => {
    sql.prepare("INSERT OR IGNORE INTO tenant_organisations VALUES (?,?,'active',1)").run(org,org);
    sql.prepare("INSERT OR IGNORE INTO tenant_memberships VALUES (?,?,NULL,'member','active',1)").run(org,principal);
    sql.prepare("INSERT INTO tenant_bindings VALUES (?,?,NULL,1) ON CONFLICT(principal) DO UPDATE SET org_id=excluded.org_id,revision=revision+1")
      .run(principal,org);
  };
  return { sql, db, env, objects, operations, bind, failNextBatch() { failBatch = true; } };
}
const privateRequest = (domain, body) => new Request(`http://intelligence.internal/v1/managed-state/${domain}`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
});
async function fund(f, context = tenant(), amount = 1_000_000) {
  const owner = contextOwner(context);
  await appendCredit(f.db, { owner, kind: "credit", amount_microusd: amount, operation_id: "fund", revision: 0 });
}
for (const mode of ["funded", "all"]) test(`native ${mode} reserves and commits measured credits with metrics off`, async t => {
  const f = fixture(t, { CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: mode }); await fund(f);
  let calls = 0;
  const result = await nativeGenerationFetch(nativeRequest(), f.env, {}, authority, () => { calls++; return complete(); });
  assert.equal(result.status, 200); assert.equal(await result.text(), completion); assert.equal(calls,1);
  const balance = await readCredits(f.db, "admin");
  assert.equal(balance.balance_microusd, 999993); assert.equal(balance.held_microusd,0);
  assert.deepEqual(balance.entries.map(entry => entry.kind), ["credit","reserve","commit"]);
  assert.equal(new Set(balance.entries.slice(1).map(entry => entry.scoped_id)).size,1);
});
for (const [mode, amount] of [["off", 0], ["funded", null]]) test(`native ${mode} uncharged owner skips ledger and pricing`, async t => {
  const f = fixture(t, { CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: mode, MODEL_PRICING_USD_PER_MILLION: undefined });
  if (amount === 0) await fund(f, tenant(),0);
  f.operations.length = 0;
  const result = await nativeGenerationFetch(nativeRequest(), f.env, {}, authority, complete);
  assert.equal(await result.text(), completion);
  assert.equal(f.sql.prepare("SELECT count(*) n FROM credits_entries WHERE kind='reserve'").get().n,0);
  if (mode === "off") assert.equal(f.operations.some(query => query.includes("credits_")), false);
});
for (const [amount, priced, code, status] of [[0,true,"credits_insufficient",402], [1_000_000,false,"credits_unpriced",503]])
  test(`native ${code} denies before upstream and admission`, async t => {
    const f = fixture(t, { CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: "all", ADMISSION_ENABLED: "true",
      ...(priced ? {} : { MODEL_PRICING_USD_PER_MILLION: undefined }),
      ADMISSION_LIMITS_JSON: '{"principal":1}', ADMISSION_COORDINATOR: { getByName() { assert.fail("denial must precede admission lease"); } } });
    await fund(f, tenant(), amount);
    const result = await nativeGenerationFetch(nativeRequest(), f.env, {}, authority, () => assert.fail("denied upstream"));
    assert.equal(result.status,status); assert.equal((await result.json()).error.code,code);
    assert.equal((await readCredits(f.db,"admin")).held_microusd,0);
  });
test("native unknown response retains only its attempt hold", async t => {
  const f = fixture(t, { CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: "all" }); await fund(f);
  const result = await nativeGenerationFetch(nativeRequest(), f.env, {}, authority, () => new Response("{}", { headers: { "content-type": "application/json" } }));
  await result.text();
  const summary = await readCredits(f.db,"admin");
  assert.ok(summary.held_microusd > 0); assert.equal(summary.balance_microusd,1_000_000);
  assert.equal(JSON.parse(f.sql.prepare("SELECT document FROM credits_entries ORDER BY revision DESC LIMIT 1").get().document).unknown,true);
});
test("credit revision retries preserve operation amount and ID and stop at three", async () => {
  const seen = [];
  const helper = createCreditsLifecycle({ CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: "all" }, { context: tenant(),
    read: async () => ({ revision: seen.length }), authority: () => ({
      async reserve(operation) {
        seen.push(operation);
        if (seen.length < 3) throw Object.assign(Error(), { status: 412 });
        const { amount: _amount, ...result } = operation;
        return new AuthorityResult({ ...result, allowed: true, revision: operation.revision+1 });
      }, commit() {}, reconcile() {},
    }) });
  await helper.admit({ amount:10, tariff_revision:7 });
  assert.equal(seen.length,3);
  assert.equal(new Set(seen.map(operation => operation.operation_id)).size,1);
  assert.equal(new Set(seen.map(operation => operation.scoped_id)).size,1);
  assert.deepEqual(seen.map(operation => operation.amount),[10,10,10]);
  assert.deepEqual(seen.map(operation => operation.revision),[0,1,2]);
});
test("pre-dispatch cancellation releases the estimate once with a separate operation ID", async t => {
  const f = fixture(t, { CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: "all" }); await fund(f);
  const hooks = createCreditsLifecycle(f.env, { context: tenant(), scoped_id: "attempt_one" });
  await hooks.admit({ amount:73, tariff_revision:7 }); await hooks.before_dispatch();
  await hooks.finalize({ handedOff:false }); await hooks.finalize({ handedOff:false });
  const summary = await readCredits(f.db,"admin");
  assert.equal(summary.held_microusd,0); assert.equal(summary.balance_microusd,1_000_000);
  assert.deepEqual(summary.entries.slice(1).map(entry => [entry.kind, entry.amount_microusd, entry.operation_id]),
    [["reserve",73,"attempt_one.reserve"],["release",73,"attempt_one.release"]]);
});
test("all flags on reject tenant before security, policies, storage or admission", async t => {
  const f = fixture(t, { ...allFlags, CONFIG_REVISION_SYNC_ENABLED:"true", ADMISSION_ENABLED:"true" });
  f.bind("org:a"); f.sql.exec("UPDATE tenant_memberships SET status='deactivated'");
  const result = await nativeGenerationFetch(nativeRequest(),f.env,{},authority,()=>assert.fail("forbidden upstream"));
  assert.equal(result.status,403); assert.equal((await result.json()).error.code,"workspace_forbidden");
  assert.equal(f.operations.some(query => /credits_|governance|control_users|usage_reservations/.test(query)),false);
});
test("organisations on keep the native generation deadline hook", () => {
  const setup = nativeGenerationSetup(nativeRequest({"X-MultiLLM-Deadline-Ms":"5000"}), { ORGANISATIONS_ENABLED:"true" });
  assert.notEqual(setup.hook, null);
  setup.hook.deadline?.stop();
});
test("all flags on governance budget denial leaves no credits, key holds, claims or admission", async t => {
  const f = fixture(t, {...allFlags, ADMISSION_ENABLED:"true", USAGE_RESERVATIONS_ENABLED:"true"}); f.bind("org:a"); await fund(f,tenant("org:a"));
  f.sql.prepare("INSERT INTO tenant_governance_policies (org_id,team_id,revision,models,tools,daily,monthly) VALUES (?,'',1,NULL,NULL,0,NULL)").run("org:a");
  const result = await nativeGenerationFetch(nativeRequest(),f.env,{},authority,()=>assert.fail("budget upstream"));
  assert.equal(result.status,429); assert.equal((await result.json()).error.code,"tenant_budget_exceeded");
  for (const table of ["credits_entries","usage_reservations","tenant_governance_reservations","managed_idempotency"])
    assert.equal(f.sql.prepare(`SELECT count(*) n FROM ${table}${table === "credits_entries" ? " WHERE kind='reserve'" : ""}`).get().n,0);
});
test("all flags on reserves workspace governance and credits once and settles actual micro USD", async t => {
  const f = fixture(t, {...allFlags, USAGE_RESERVATIONS_ENABLED:"true"}); f.bind("org:a"); await fund(f,tenant("org:a"));
  const result = await nativeGenerationFetch(nativeRequest(),f.env,{}, { ...authority,
    principal: { id:"admin",daily_budget_usd:1,monthly_budget_usd:10 } }, () => {
    assert.equal(f.sql.prepare("SELECT state FROM tenant_governance_reservations").get().state,"dispatched");
    assert.equal(f.sql.prepare("SELECT count(*) n FROM credits_entries WHERE kind='reserve'").get().n,1);
    assert.equal(f.sql.prepare("SELECT count(*) n FROM usage_reservations").get().n,0);
    return complete();
  });
  assert.equal(await result.text(),completion);
  assert.equal(f.sql.prepare("SELECT charged FROM tenant_governance_reservations").get().charged,7);
  assert.equal((await readCredits(f.db,contextOwner(tenant("org:a")))).held_microusd,0);
});
test("late hook denial releases governance and credits without dispatch", async t => {
  const f = fixture(t,allFlags); f.bind("org:a"); await fund(f,tenant("org:a"));
  const result = await nativeGenerationFetch(nativeRequest(),f.env,{},authority,()=>assert.fail("late upstream"),[{
    enabled:()=>true, before_dispatch() { throw new CreditsAdmissionError("credits_unavailable"); },
  }]);
  assert.equal(result.status,503); assert.equal((await readCredits(f.db,contextOwner(tenant("org:a")))).held_microusd,0);
  assert.equal(f.sql.prepare("SELECT charged FROM tenant_governance_reservations").get().charged,0);
});
test("governance fixed domain is reachable and grant denial precedes cache and credits", async t => {
  const f = fixture(t,{ORGANISATIONS_ENABLED:"true",TENANT_GOVERNANCE_ENABLED:"true"}); f.bind("org:a");
  const res = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/tenant-governance",{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({version:1,operation:"policies",context:tenant("org:a")}),
  }),f.env); assert.equal(res.status,200);
  f.sql.prepare("INSERT INTO tenant_governance_policies (org_id,team_id,revision,models,tools) VALUES (?,'',1,'[]',NULL)").run("org:a");
  const denied = await nativeGenerationFetch(nativeRequest(),f.env,{},authority,()=>assert.fail("grant upstream"));
  assert.equal(denied.status,403); assert.equal((await denied.json()).error.code,"model_not_allowed");
  assert.equal(f.sql.prepare("SELECT count(*) n FROM tenant_governance_reservations").get().n,0);
});

const scimId = n => String(n).padStart(32,"0");
function scimUser(n, active = true, revision = 1) {
  return { schemas:["urn:ietf:params:scim:schemas:core:2.0:User"], id:scimId(n),userName:`user-${n}`,active,
    meta:{resourceType:"User",version:`W/"${revision}"`,created:"2026-10-09T00:00:00Z",lastModified:"2026-10-09T00:00:00Z",location:`/scim/v2/Users/${scimId(n)}`} };
}
function scimAccount(n, changes = {}) {
  return {...Object.fromEntries(USER_FIELDS.map(field=>[field,null])),username:`user-${n}`,api_key_hash:"synthetic-hash",
    api_key_prefix:"mllm_synthetic",is_admin:0,scopes:"chat,models",created_at:"2026-10-09T00:00:00Z",...changes};
}
async function scimPut(f, row, account, expected = 0, kind = "Users", deactivate = false) {
  const response = await handleManagedStateRequest(privateRequest("scim", { operation:"put",org_id:"org:a",resource:row,kind,
    account,expected,token_digest:null,deactivate }),f.env);
  return {status:response.status,...await response.json()};
}
test("registered SCIM creates and deactivates accounts, identities and memberships in one batch", async t => {
  const f = fixture(t,{SCIM_ENABLED:"true",CONFIG_REVISION_SYNC_ENABLED:"true"}); f.bind("org:a");
  assert.equal((await scimPut(f,scimUser(1),scimAccount(1))).status,200);
  assert.equal(f.sql.prepare("SELECT status FROM tenant_memberships WHERE principal='user-1'").get().status,"active");
  assert.equal(f.sql.prepare("SELECT count(*) n FROM tenant_bindings WHERE principal='user-1'").get().n,0);
  const revoked = scimAccount(1,{api_key_hash:"synthetic-new-hash",api_key_prefix:"mllm_rotated",revoked_at:"2026-10-09T01:00:00Z"});
  assert.equal((await scimPut(f,scimUser(1,false,2),revoked,1)).status,200);
  assert.equal(f.sql.prepare("SELECT revoked_at FROM control_users WHERE username='user-1'").get().revoked_at,revoked.revoked_at);
  assert.equal(f.sql.prepare("SELECT status FROM tenant_memberships WHERE principal='user-1'").get().status,"deactivated");
  assert.equal(f.sql.prepare("SELECT revision FROM control_revisions WHERE domain='key_controls'").get().revision,2);
});
test("SCIM batch failure rolls back account, resource, membership, audit and security revision", async t => {
  const f = fixture(t,{SCIM_ENABLED:"true",CONFIG_REVISION_SYNC_ENABLED:"true"}); f.bind("org:a"); f.failNextBatch();
  assert.equal((await scimPut(f,scimUser(2),scimAccount(2))).status,503);
  for (const table of ["control_users","scim_resources","scim_audit","control_revisions"])
    assert.equal(f.sql.prepare(`SELECT count(*) n FROM ${table}`).get().n,0);
  assert.equal(f.sql.prepare("SELECT count(*) n FROM tenant_memberships WHERE principal='user-2'").get().n,0);
});
test("registered SCIM groups update tenant teams atomically and reject foreign memberships", async t => {
  const f = fixture(t,{SCIM_ENABLED:"true",CONFIG_REVISION_SYNC_ENABLED:"true"}); f.bind("org:a");
  await scimPut(f,scimUser(1),scimAccount(1));
  const group = { schemas:["urn:ietf:params:scim:schemas:core:2.0:Group"],id:scimId(3),displayName:"team-three",members:[{value:scimId(1)}],
    meta:{resourceType:"Group",version:'W/"1"',created:"2026-10-09T00:00:00Z",lastModified:"2026-10-09T00:00:00Z",location:`/scim/v2/Groups/${scimId(3)}`} };
  assert.equal((await scimPut(f,group,null,0,"Groups")).status,200);
  assert.equal(f.sql.prepare("SELECT team_id FROM tenant_memberships WHERE principal='user-1'").get().team_id,scimId(3));
  const foreign = {...group,id:scimId(4),meta:{...group.meta,location:`/scim/v2/Groups/${scimId(4)}`}};
  assert.equal((await scimPut(f,foreign,null,0,"Groups")).status,503);
  assert.equal(f.sql.prepare("SELECT count(*) n FROM tenant_teams WHERE id=?").get(scimId(4)).n,0);
});
test("workspace exact and semantic keys isolate two workspaces and preserve legacy bytes", async t => {
  const f = fixture(t,{ORGANISATIONS_ENABLED:"true"});
  const retentionPolicy = {enabled:false};
  const ctx = context => ({retentionPolicy,tenantContext:context,cacheRevisions:{}});
  const exact = context => exactCacheIdentity(nativeRequest(),f.env,{...authority,tenantContext:context},ctx(context));
  const legacy = await exact(tenant());
  const old = await exactCacheIdentity(nativeRequest(),{...f.env,ORGANISATIONS_ENABLED:undefined},authority,ctx(tenant("org:a")));
  assert.deepEqual(legacy,old);
  const one = await exact(tenant("org:a")),two = await exact(tenant("org:b"));
  assert.notEqual(one.cache_key,two.cache_key); assert.notEqual(one.principal_hash,two.principal_hash);
  const partition = (context, env = f.env) => semanticPartition("admin","openai",route,payload,ctx(context),{embedding_model:"openai:embed"},env);
  assert.notDeepEqual(await partition(tenant("org:a")),await partition(tenant("org:b")));
  assert.deepEqual(await partition(tenant()),await partition(tenant("org:a"),{...f.env,ORGANISATIONS_ENABLED:undefined}));
});
test("workspace idempotency claims cannot replay or hand off another workspace", async t => {
  const f = fixture(t,{ORGANISATIONS_ENABLED:"true",MANAGED_IDEMPOTENCY_ENABLED:"true"});
  const body = {operation:"claim",scope:"a".repeat(64),digest:"b".repeat(64),owner:"c".repeat(32)};
  const call = async (data,context) => {
    const response = await handleIdempotencyRequest(privateRequest("idempotency",data),f.env,{tenantContext:context});
    return {status:response.status,...await response.json()};
  };
  const one = await call(body,tenant("org:a")); assert.equal(one.result.status,"claimed");
  assert.equal((await call(body,tenant("org:b"))).result.status,"claimed");
  assert.equal((await call(body,tenant())).result.status,"claimed");
  assert.equal(f.sql.prepare("SELECT count(*) n FROM managed_idempotency").get().n,3);
  assert.ok(f.sql.prepare("SELECT scope FROM managed_idempotency").all().some(row=>row.scope===body.scope));
});
test("workspace Responses owners and context page owners refuse foreign reads", async t => {
  const f = fixture(t,{ORGANISATIONS_ENABLED:"true",HOSTED_RESPONSES_ENABLED:"true",CONTEXT_PAGING_ENABLED:"true"});
  const id = `gwresp_${"1".repeat(32)}`,owner = "a".repeat(64);
  const put = {operation:"put",owner,id,provider:"openai",model:"test",parent_id:null,policy_revision:"b".repeat(64),depth:1,
    document:{input:[{role:"user",content:"fixture"}],response:{id,object:"response",status:"completed",output:[]}}};
  const send = async (body,context) => {
    const response = await handleResponsesStateRequest(privateRequest("responses",body),f.env,{tenantContext:context});
    return {status:response.status,...await response.json()};
  };
  assert.equal((await send(put,tenant("org:a"))).status,200);
  assert.equal((await send({operation:"get",id,owner},tenant("org:a"))).result.state.document.response.id,id);
  for (const other of [tenant("org:b"),tenant()]) assert.equal((await send({operation:"get",id,owner},other)).result.state,null);
  const scope = {principal:"admin",session:"session-one",revision:"revision-one"};
  const group = [{role:"assistant",tool_calls:[{id:"call-one",type:"function",function:{name:"search",arguments:"{}"}}]},
    {role:"tool",tool_call_id:"call-one",content:"fixture"}];
  const page = async (body,context) => {
    const response = await handleContextPageStateRequest(privateRequest("context-pages",{...body,granted:true,retention_policy:{enabled:false,mode:"inherit"}}),f.env,{tenantContext:context});
    return {status:response.status,...await response.json()};
  };
  const stored = await page({operation:"put",scope,bodies:[Buffer.from(JSON.stringify(group)).toString("base64")]},tenant("org:a"));
  assert.equal(stored.status,200); const page_id = stored.pages[0].page_id;
  assert.equal((await page({operation:"get",scope,page_id},tenant("org:a"))).status,200);
  assert.equal((await page({operation:"get",scope,page_id},tenant("org:b"))).status,404);
  assert.equal((await page({operation:"get",scope,page_id},tenant())).status,404);
});
test("workspace usage attribution isolates rows and keeps legacy identity bytes", async t => {
  const f = fixture(t,{ORGANISATIONS_ENABLED:"true"});
  for (const context of [tenant("org:a"),tenant("org:b"),tenant()]) await recordNativeUsage(f.env,{
    principal:"edge:fixture",tenantContext:context,requestId:crypto.randomUUID(),provider:"openai",model:"test",endpoint:route,status:200,
    input_tokens:1,output_tokens:1,cost_usd:0.1,cost_basis:"usage",duration_ms:1,ttft_ms:1,outcome:"success",
  },{});
  const principals = f.sql.prepare("SELECT principal FROM usage_events ORDER BY principal").all().map(row=>row.principal);
  assert.deepEqual(principals.sort(),[tenantStorageKey("edge:fixture",tenant("org:a")),tenantStorageKey("edge:fixture",tenant("org:b")),"edge:fixture"].sort());
});
test("all flags off native streaming and account reads leave bytes and storage unchanged", async () => {
  const forbidden = { prepare() { assert.fail("disabled storage"); } };
  const env = {INTELLIGENCE_DB:forbidden};
  for (const body of [completion, 'data: {"choices":[{"delta":{"content":"fixture"}}]}\n\ndata: [DONE]\n\n']) {
    const response = await nativeGenerationFetch(nativeRequest(),env,{},authority,()=>new Response(body));
    assert.equal(await response.text(),body); assert.equal(response.headers.get("X-MultiLLM-Cache"),null);
  }
  const accountRequest = new Request("https://provider.invalid/v1/models");
  assert.equal(await (await nativeGenerationFetch(accountRequest,{...env,...allFlags},{},authority,()=>new Response("models"))).text(),"models");
});
test("all flags on forwarded webhook, SCIM and SAML retain raw bytes with no edge key or policies", async () => {
  const {default:worker} = await loadWorkerModule();
  for (const path of ["/v1/payments/webhook","/scim/v2/Users","/auth/saml/acs","/v1/chat/completions"]) {
    const raw = ' {"fixture":"é"}\r\n'; let calls=0;
    const env = {...allFlags,INTELLIGENCE_DB:{prepare(){assert.fail("forwarded edge storage");}},
      MULTILLM_PROXY_CONTAINER:{getByName:()=>({async fetch(request){calls++;assert.equal(await request.text(),raw);return new Response("forwarded");}})}};
    const result = await worker.fetch(new Request(`https://gateway.example${path}`,{method:"POST",body:raw}),env,{waitUntil(){}});
    assert.equal(await result.text(),"forwarded"); assert.equal(calls,1);
  }
});

test("concurrent cancellation finalizers release one immutable hold once", async t => {
  const f = fixture(t,{CREDITS_ENABLED:"true",CREDITS_ENFORCEMENT:"all"}); await fund(f);
  const hooks = createCreditsLifecycle(f.env,{context:tenant(),scoped_id:"concurrent_attempt"});
  await hooks.admit({amount:73,tariff_revision:7});
  await Promise.all([hooks.finalize({handedOff:false}),hooks.finalize({handedOff:false})]);
  assert.equal((await readCredits(f.db,"admin")).held_microusd,0);
  assert.equal(f.sql.prepare("SELECT count(*) n FROM credits_entries WHERE kind='release'").get().n,1);
});
test("all flags on credit denial cancels the earlier governance hold and never leases admission", async t => {
  const f = fixture(t,{...allFlags,USAGE_RESERVATIONS_ENABLED:"true",ADMISSION_ENABLED:"true",
    ADMISSION_LIMITS_JSON:'{"principal":1}',ADMISSION_COORDINATOR:{getByName(){assert.fail("credit denial lease");}}});
  f.bind("org:a"); await fund(f,tenant("org:a"),0);
  const response = await nativeGenerationFetch(nativeRequest(),f.env,{},authority,()=>assert.fail("credit denial upstream"));
  assert.equal(response.status,402);
  assert.equal(f.sql.prepare("SELECT state FROM tenant_governance_reservations").get().state,"settled");
  assert.equal(f.sql.prepare("SELECT charged FROM tenant_governance_reservations").get().charged,0);
  assert.equal((await readCredits(f.db,contextOwner(tenant("org:a")))).held_microusd,0);
});
test("each native attempt owns its hold and an undispatched loser releases only its estimate", async t => {
  const f = fixture(t,{CREDITS_ENABLED:"true",CREDITS_ENFORCEMENT:"all"}); await fund(f);
  const winner = createCreditsLifecycle(f.env,{context:tenant(),scoped_id:"winner"});
  const loser = createCreditsLifecycle(f.env,{context:tenant(),scoped_id:"loser"});
  await winner.admit({amount:73,tariff_revision:7}); await loser.admit({amount:73,tariff_revision:7});
  await winner.before_dispatch();
  await winner.finalize({outcome:"success",cost_basis:"usage",cost_usd:0.000007});
  await loser.finalize({handedOff:false});
  const summary = await readCredits(f.db,"admin");
  assert.equal(summary.balance_microusd,999993); assert.equal(summary.held_microusd,0);
  assert.deepEqual(summary.entries.slice(1).map(row=>row.operation_id),["winner.reserve","loser.reserve","winner.commit","loser.release"]);
});
test("uncertain credit settlement fails closed and preserves the dispatched hold", async t => {
  const f = fixture(t,{CREDITS_ENABLED:"true",CREDITS_ENFORCEMENT:"all"}); await fund(f);
  const hooks = createCreditsLifecycle(f.env,{context:tenant(),scoped_id:"uncertain_attempt"});
  await hooks.admit({amount:73,tariff_revision:7}); await hooks.before_dispatch();
  f.failNextBatch();
  await assert.rejects(hooks.finalize({outcome:"success",cost_basis:"usage",cost_usd:0.000007}),error=>error.code==="credits_unavailable");
  assert.equal((await readCredits(f.db,"admin")).held_microusd,73);
});

test("native semantic embeddings charge separate attempts and a hit releases the generation estimate", async t => {
  const f = fixture(t,{...allFlags,SEMANTIC_CACHE_ENABLED:"true",SEMANTIC_CACHE_POLICY_JSON:JSON.stringify({
    routes:[route],embedding_model:"openai:embed"}),
    MODEL_PRICING_USD_PER_MILLION:'{"openai:test":{"input":1,"output":2},"openai:embed":{"input":0.1,"output":0}}'});
  f.bind("org:a"); await fund(f,tenant("org:a")); const calls=[],waits=[];
  const fetcher = req => { calls.push(new URL(req.url).pathname); return req.url.endsWith("/embeddings")
    ? Response.json({data:[{embedding:[1,0]}],usage:{prompt_tokens:3}}) : complete(); };
  for (let i=0;i<2;i++) {
    const response = await nativeGenerationFetch(nativeRequest(),f.env,{waitUntil:p=>waits.push(p)},authority,fetcher);
    assert.equal(await response.text(),completion);
    if(i) assert.equal(response.headers.get("X-MultiLLM-Cache"),"semantic-hit");
  }
  await Promise.all(waits);
  assert.deepEqual(calls,["/test/v1/embeddings",route,"/test/v1/embeddings"]);
  const summary = await readCredits(f.db,contextOwner(tenant("org:a")));
  assert.equal(summary.balance_microusd,999991); assert.equal(summary.held_microusd,0);
  assert.equal(new Set(summary.entries.filter(row=>row.kind==="reserve").map(row=>row.scoped_id)).size,4);
  assert.equal(summary.entries.filter(row=>row.kind==="release").length,1);
});
test("Realtime disabled routes retain forwarding before every enabled enterprise policy", async () => {
  const {default:worker} = await loadWorkerModule();
  for (const path of ["/v1/realtime/client_secrets"]) {
    const env = {...allFlags,INTELLIGENCE_DB:{prepare(){assert.fail("realtime enterprise storage");}},
      MULTILLM_PROXY_CONTAINER:{getByName:()=>({fetch:async()=>new Response("realtime forwarded")})}};
    const response = await worker.fetch(new Request(`https://gateway.example${path}`,{method:"POST",body:"{}"}),env,{waitUntil(){}});
    assert.equal(response.status,200); assert.equal(await response.text(),"realtime forwarded");
  }
});

test("enabled governance leaves an unbound legacy request body and storage unchanged", async () => {
  const raw="legacy opaque body";
  const request = new Request(`https://provider.invalid${route}`,{method:"POST",body:raw});
  const env={TENANT_GOVERNANCE_ENABLED:"true",ADMIN_API_KEY:"synthetic-admin-key",INTELLIGENCE_DB:{prepare(){assert.fail("legacy governance storage");}}};
  const response=await nativeGenerationFetch(request,env,{},authority,async req=>new Response(await req.text()));
  assert.equal(await response.text(),raw);
});
test("enabled workspace key grants use the same case-insensitive wildcard intersection", async t => {
  const f=fixture(t,{ORGANISATIONS_ENABLED:"true",TENANT_GOVERNANCE_ENABLED:"true"}); f.bind("org:a");
  const response=await nativeGenerationFetch(nativeRequest(),f.env,{}, {...authority,principal:{id:"admin",allowed_models:"OPENAI:*es*"}},complete);
  assert.equal(await response.text(),completion);
});

test("organisations off preserves claim and Responses ownership despite a supplied workspace context", async t => {
  const f=fixture(t,{MANAGED_IDEMPOTENCY_ENABLED:"true",HOSTED_RESPONSES_ENABLED:"true"});
  const context=tenant("org:a"),scope="d".repeat(64),owner="e".repeat(64),id=`gwresp_${"2".repeat(32)}`;
  const claimed=await handleManagedStateRequest(privateRequest("idempotency",{operation:"claim",scope,digest:"b".repeat(64),owner:"c".repeat(32)}),f.env,{tenantContext:context});
  assert.equal(claimed.status,200); assert.equal(f.sql.prepare("SELECT scope FROM managed_idempotency").get().scope,scope);
  const saved=await handleManagedStateRequest(privateRequest("responses",{operation:"put",owner,id,provider:"openai",model:"test",parent_id:null,
    policy_revision:"b".repeat(64),depth:1,document:{input:[{role:"user",content:"fixture"}],response:{id,object:"response",status:"completed",output:[]}}}),f.env,{tenantContext:context});
  assert.equal(saved.status,200); assert.equal(f.sql.prepare("SELECT owner FROM hosted_responses").get().owner,owner);
});
test("repeated revision mismatches stop after three attempts with no dispatch", async () => {
  let attempts=0;
  const hooks=createCreditsLifecycle({CREDITS_ENABLED:"true",CREDITS_ENFORCEMENT:"all"},{context:tenant(),
    read:async()=>({revision:attempts}),authority:()=>({reserve(){attempts++;throw Object.assign(Error(),{status:412});},commit(){},reconcile(){}})});
  await assert.rejects(hooks.admit({amount:73,tariff_revision:7}),error=>error.code==="credits_unavailable");
  assert.equal(attempts,3);
});

test("organisations off preserves native budget ownership with a supplied workspace context", async t => {
  const f=fixture(t,{USAGE_RESERVATIONS_ENABLED:"true"});
  const response=await nativeGenerationFetch(nativeRequest(),f.env,{}, {...authority,tenantContext:tenant("org:a"),
    principal:{id:"admin",daily_budget_usd:1}},complete);
  assert.equal(await response.text(),completion);
  assert.equal(f.sql.prepare("SELECT principal FROM usage_reservations").get().principal,
    `edge:${await retentionRequestId("native-admin:admin")}`);
});

for (const workspace of [false, true]) test(`operator reconciliation settles linked native credits once; workspace=${workspace}`, async t => {
  const f = fixture(t, { CREDITS_ENABLED: "true", CREDITS_ENFORCEMENT: "all", USAGE_RESERVATIONS_ENABLED: "true",
    ...(workspace ? { ORGANISATIONS_ENABLED: "true", TENANT_GOVERNANCE_ENABLED: "true" } : {}) });
  if (workspace) f.bind("org:a");
  const context = tenant(workspace ? "org:a" : undefined);
  await fund(f, context);
  const checked = { ...authority, principal: { ...authority.principal, daily_budget_usd: 1 } };
  const response = await nativeGenerationFetch(nativeRequest(), f.env, {}, checked,
    () => new Response(JSON.stringify({ choices: [{ message: { content: "synthetic" } }] }), { headers: { "content-type": "application/json" } }));
  await response.text();
  const row = f.sql.prepare(`SELECT * FROM ${workspace ? "tenant_governance_reservations" : "usage_reservations"}`).get();
  assert.equal(row.state, "unknown");
  const balance = await readCredits(f.db, contextOwner(context));
  assert.equal(balance.entries.find(entry => entry.kind === "reserve" && entry.held_delta > 0).scoped_id, row.id);
  const call = async body => {
    const handler = workspace ? handleTenantGovernanceRequest : handleReservationsRequest;
    const response = await handler(new Request(`http://intelligence.internal/v1/${workspace ? "tenant-governance" : "reservations"}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), f.env);
    return { status: response.status, ...await response.json() };
  };
  const values = { id: row.id, revision: row.revision, transition_id: "b".repeat(32), admin: true, reason: "review", evidence: "receipt" };
  const body = workspace ? { operation: "reconcile", cost: 25, ...values }
    : { operation: "transition", state: "reconciled", cost_usd: 0.000025, basis: "provider", settlement_id: row.id, ...values };
  for (const applied of [true, false]) {
    const result = await call(body);
    assert.equal(result.status, 200); assert.equal(result.applied, applied);
  }
  const settled = await readCredits(f.db, contextOwner(context));
  assert.equal(settled.balance_microusd, 999975); assert.equal(settled.held_microusd, 0);
  assert.equal(settled.entries.filter(entry => entry.kind === "commit").length, 1);
});
