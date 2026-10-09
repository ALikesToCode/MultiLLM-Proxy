import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { SemanticCacheD1, handleSemanticCache, cleanupSemanticCache } from "../worker/semantic-cache-d1.mjs";
import { semanticCacheSettings, semanticPartition, guardHash, prepareSemanticCache, semanticCacheServedEvent } from "../worker/semantic-generation-cache.mjs";

const policy = {routes: ["/fixture/v1/chat/completions"], embedding_model: "openai:embed-test", revision: "one"};
const enabled = {SEMANTIC_CACHE_ENABLED: "true", SEMANTIC_CACHE_POLICY_JSON: JSON.stringify(policy),
  MODEL_PRICING_USD_PER_MILLION: JSON.stringify({"openai:embed-test": {input: 0.1, output: 0}})};
const payload = {model: "chat-test", messages: [{role: "user", content: "explain caching"}], temperature: 0};
const body = JSON.stringify({choices: [{message: {content: "actual answer"}, finish_reason: "stop"}]});
const metadata = {content_type: "application/json", headers: {}, provider: "fixture", model: "chat-test"};
const authority = {provider: "fixture", route: policy.routes[0], principal: {id: "owner", keyHash: "a".repeat(64)}};
const context = {retentionPolicy: {enabled: false, mode: "inherit"}, cacheRevisions: {policy: "one"}};
const request = (changes = {}, headers = {}) => new Request("https://provider.invalid/v1/chat/completions", {
  method: "POST", headers: {"content-type": "application/json", ...headers}, body: JSON.stringify({...payload, ...changes})});
const identity = {principal_hash: "a".repeat(64), partition_hash: "b".repeat(64), model_revision: "c".repeat(64)};

function storage() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE old_rows(id); INSERT INTO old_rows VALUES(7);");
  const sql = readFileSync(new URL("../intelligence-migrations/0026_semantic_cache.sql", import.meta.url), "utf8");
  db.exec(sql); db.exec(sql); assert.equal(db.prepare("SELECT id FROM old_rows").get().id, 7);
  const execute = (sql, args) => {
    const stmt = db.prepare(sql.replace(/\?(\d+)/g, (_, n) => `$v${n}`));
    const rows = /\?[1-9]/.test(sql) ? stmt.all(Object.fromEntries(args.map((value, i) => [`v${i+1}`, value]))) : stmt.all(...args);
    return {results: rows.map(row => ({...row})), meta: {changes: db.prepare("SELECT changes() AS n").get().n}};
  };
  const binding = {prepare(sql) {return {sql, args: [], bind(...args) {this.args=args; return this;},
    async all() {return execute(sql, this.args);}, async run() {return execute(sql, this.args);}, async first() {return execute(sql, this.args).results[0] ?? null;}};},
    async batch(items) {db.exec("BEGIN"); try {const results=items.map(item=>execute(item.sql,item.args)); db.exec("COMMIT"); return results;}
      catch(error) {db.exec("ROLLBACK"); throw error;}}};
  const rows=new Map();
  const bucket={rows, async put(key,value,options) {rows.set(key,{value:new Uint8Array(value),customMetadata:options.customMetadata});},
    async get(key) {const row=rows.get(key); return row?{size:row.value.length, async arrayBuffer() {return row.value.slice().buffer;}}:null;},
    async delete(key) {rows.delete(key);}, async list() {return {objects:[...rows].map(([key,row])=>({key,customMetadata:row.customMetadata})),truncated:false};}};
  return {db, env:{...enabled, INTELLIGENCE_DB:binding,multillm_media:bucket}};
}

test("configuration defaults and unsupported tools/streams disable the feature", () => {
  for(const env of [{},{SEMANTIC_CACHE_ENABLED:"",SEMANTIC_CACHE_POLICY_JSON:""},
    {...enabled,SEMANTIC_CACHE_POLICY_JSON:'{"allow_tools":true}'}, {...enabled,SEMANTIC_CACHE_POLICY_JSON:'{"allow_streams":true}'},
    {...enabled,SEMANTIC_CACHE_ENABLED:"bad"}]) assert.equal(semanticCacheSettings(env).enabled,false);
  assert.equal(semanticCacheSettings(enabled).enabled,true);
});

test("last-message partition preserves every conversation and parameter invariant", async () => {
  const one=await semanticPartition("owner", authority.provider,authority.route,payload,context,policy,enabled);
  assert.deepEqual(one,await semanticPartition("owner",authority.provider,authority.route,
    {...payload,messages:[{role:"user",content:"describe caching"}]},context,policy,enabled));
  for(const field of ["model","temperature","top_p","seed","response_format"]) {
    assert.notDeepEqual(one,await semanticPartition("owner",authority.provider,authority.route,{...payload,[field]:"changed"},context,policy,enabled));
  }
  assert.notDeepEqual(one,await semanticPartition("other",authority.provider,authority.route,payload,context,policy,enabled));
  for(const [a,b] of [["buy 1","buy 2"],["do it","do not do it"],['say "one"','say "two"'],["2026-10-09","2026-10-10"],
    ["October 9","November 9"],["meet Monday","meet Tuesday"],["buy twelve shares","buy thirteen shares"]]) {
    assert.notEqual(await guardHash(a),await guardHash(b));
  }
});

test("D1 exact scan is scoped with TTL, corruption checks and oldest eviction", async () => {
  const {env,db}=storage(); let now=1000;
  const store=new SemanticCacheD1(env,{clock:()=>now}); const guard="d".repeat(64);
  for(let i=0;i<257;i++) {
    await store.put(identity,[1,i/1000],guard,new TextEncoder().encode(body),metadata); now+=0.001;
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM semantic_generation_cache").get().n,256);
  const rows=await store.scan(identity); assert.equal(rows.length,256);
  assert.equal(await store.scan({...identity,principal_hash:"e".repeat(64)}).then(x=>x.length),0);
  assert.equal(new TextDecoder().decode((await store.body(identity,rows[0])).body),body);
  const blob=env.multillm_media.rows.get(rows[0].body_pointer); blob.value[0]^=1;
  assert.equal(await store.body(identity,rows[0]),null);
  assert.equal(await store.put(identity,[1,0],guard,new Uint8Array(1024*1024+1),metadata),false);
  now+=300; assert.equal((await store.scan(identity)).length,0);
  await cleanupSemanticCache(env,{now,limit:1000}); assert.equal(env.multillm_media.rows.size,0);
});

test("native collaborator stores and replays complete responses with paid embedding accounting", async () => {
  const {env}=storage(); const costs=[];
  const collaborators={embeddingAllowed:()=>true,reserveEmbedding:()=>null,embed:async()=>({data:[{embedding:[1,0]}],usage:{prompt_tokens:4}}),accountEmbedding:event=>costs.push(event)};
  const first=await prepareSemanticCache(request(),env,authority,context,collaborators);
  assert.equal(await first.lookup(),null);
  await first.store(new Response(body,{headers:{"content-type":"application/json"}}),{canStore:()=>true});
  const next=await prepareSemanticCache(request({messages:[{role:"user",content:"describe caching"}]}),env,authority,context,collaborators);
  const hit=await next.lookup(); assert.equal(await hit.text(),body);
  assert.equal(hit.headers.get("X-MultiLLM-Cache"),"semantic-hit");
  assert.equal(hit.headers.get("X-MultiLLM-Provider-Calls"),"0");
  assert.equal(costs.length,2); assert.ok(costs[0].cost_usd>0);
  assert.equal(semanticCacheServedEvent(hit,{startedAt:performance.now()}).cost_usd,0);
});

test("schema failure returns JSON 503 before any provider; other storage errors miss", async () => {
  const {env,db}=storage(); db.exec("DROP TABLE semantic_generation_cache"); let embeddings=0;
  const cache=await prepareSemanticCache(request(),env,authority,context,{embed:async()=>{embeddings++;return [1,0];},accountEmbedding:()=>{}});
  const rejection=await cache.lookup(); assert.equal(rejection.status,503); assert.equal(embeddings,0);
  assert.equal((await rejection.json()).error,"semantic_cache_schema_missing");
});

test("tools streams n>1 retention no-store unknown price and non-opted scope bypass before storage", async () => {
  let touched=0;
  const env={...enabled,INTELLIGENCE_DB:{prepare(){touched++;throw Error();}}};
  const collaborator={embed:async()=>assert.fail("embedding called"),accountEmbedding:()=>{}};
  for(const changes of [{stream:true},{n:2},{tools:[{}],tool_choice:"none"},{messages:[{role:"tool",content:"result"},{role:"user",content:"hello"}]},
    {messages:[{role:"user",content:"latest weather today"}]},{messages:[{role:"user",content:"x".repeat(4097)}]}]) {
    assert.equal(await prepareSemanticCache(request(changes),env,authority,context,collaborator),null);
  }
  for(const change of [{SEMANTIC_CACHE_POLICY_JSON:"{}"},{MODEL_PRICING_USD_PER_MILLION:"{}"},
    {MODEL_PRICING_USD_PER_MILLION:JSON.stringify({"openai:embed-test":{input:100,output:0}})}]) {
    assert.equal(await prepareSemanticCache(request(),{...env,...change},authority,context,collaborator),null);
  }
  assert.equal(await prepareSemanticCache(request({}, {"Cache-Control":"no-store"}),env,authority,context,collaborator),null);
  assert.equal(await prepareSemanticCache(request(),env,authority,{retentionPolicy:{mode:"zero",enabled:true}},collaborator),null);
  assert.equal(touched,0);
});

test("protected mismatch and low similarity cannot hit; policy mutation and abort cannot store", async () => {
  const {env}=storage(); let vector=[1,0]; let revision=1;
  const ctx={...context,cacheRevisions:()=>({revision})};
  const collab={embeddingAllowed:()=>true,reserveEmbedding:()=>null,embed:async()=>({data:[{embedding:vector}]}),accountEmbedding:()=>{}};
  const first=await prepareSemanticCache(request({messages:[{role:"user",content:"explain 12 caches"}]}),env,authority,ctx,collab);
  await first.lookup(); await first.store(new Response(body,{headers:{"content-type":"application/json"}}),{canStore:()=>true});
  for(const text of ["describe 13 caches","do not explain 12 caches"]) {
    const next=await prepareSemanticCache(request({messages:[{role:"user",content:text}]}),env,authority,ctx,collab); assert.equal(await next.lookup(),null);
  }
  vector=[0.9,0.44]; const low=await prepareSemanticCache(request({messages:[{role:"user",content:"describe 12 caches"}]}),env,authority,ctx,collab);
  assert.equal(await low.lookup(),null); revision++; await low.store(new Response(body,{headers:{"content-type":"application/json"}}),{canStore:()=>true});
  assert.equal((await env.INTELLIGENCE_DB.prepare("SELECT COUNT(*) AS n FROM semantic_generation_cache").first()).n,1);
});

test("private handler validates operations, forbids cross-scope bodies and sanitizes schema errors", async () => {
  const {env}=storage();
  assert.equal((await handleSemanticCache(env.INTELLIGENCE_DB,{version:1,operation:"ready"},env)).status,200);
  assert.equal(await handleSemanticCache(env.INTELLIGENCE_DB,{version:1,operation:"scan",...identity,principal_hash:"bad"},env),null);
  const broken={prepare(){throw Error("no such table: semantic_generation_cache");}};
  const failed=await handleSemanticCache(broken,{version:1,operation:"ready"},env);
  assert.equal(failed.status,503); assert.doesNotMatch(await failed.text(),/no such table/);
});

test("embedding grants and budget admission precede dispatch and failures retain accounting", async () => {
  const {env}=storage(); let calls=0; const costs=[];
  const collaborators={embeddingAllowed:()=>true,reserveEmbedding:()=>null,
    embed:async()=>{calls++;throw Error("upstream failed");},accountEmbedding:event=>costs.push(event)};
  for(const change of [{embeddingAllowed:()=>false},{reserveEmbedding:()=>false},{embeddingAllowed:undefined}]) {
    assert.equal(await prepareSemanticCache(request(),env,authority,context,{...collaborators,...change}),null);
  }
  assert.equal(calls,0); assert.equal(costs.length,0);
  assert.equal(await prepareSemanticCache(request(),env,authority,context,collaborators),null);
  assert.equal(calls,1); assert.equal(costs[0].status,502); assert.equal(costs[0].provider_calls,1);
  assert.ok(costs[0].cost_usd>0); assert.equal(costs[0].submission_outcome,"unknown");
});

test("cancellation, unclassified success, incomplete output and outages never replay or store", async () => {
  const {env,db}=storage(); const controller=new AbortController();
  const req=new Request(request(),{signal:controller.signal});
  const collaborators={embeddingAllowed:()=>true,reserveEmbedding:()=>null,embed:async()=>[1,0],accountEmbedding:()=>{}};
  const prepared=await prepareSemanticCache(req,env,authority,context,collaborators);
  await prepared.store(new Response(body,{headers:{"content-type":"application/json"}}));
  for(const invalid of [JSON.stringify({choices:[{message:{content:"cut"},finish_reason:"length"}]}),
    JSON.stringify({choices:[{message:{tool_calls:[{}]},finish_reason:"stop"}]})]) {
    await prepared.store(new Response(invalid,{headers:{"content-type":"application/json"}}),{canStore:()=>true});
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM semantic_generation_cache").get().n,0);
  const reply=new Response(body,{headers:{"content-type":"application/json"}});
  controller.abort(); assert.equal(await prepared.store(reply,{canStore:()=>true}),reply);
  assert.equal(await prepared.lookup(),null);
  assert.equal(await prepareSemanticCache(req,env,authority,context,collaborators),null);
  const failed={async ready(){},async scan(){throw Error("unavailable");},async put(){throw Error("unavailable");}};
  const unavailable=await prepareSemanticCache(request(),env,authority,context,{...collaborators,store:failed});
  assert.equal(await unavailable.lookup(),null);
  const original=new Response(body,{headers:{"content-type":"application/json"}});
  assert.equal(await unavailable.store(original,{canStore:()=>true}),original); assert.equal(await original.text(),body);
  const missing=await prepareSemanticCache(request(),env,authority,context,
    {...collaborators,store:{...failed,async scan(){throw Error("no such table: semantic_generation_cache");}}});
  assert.equal((await missing.lookup()).status,503);
});

test("embedding timeout aborts its transport and records uncertain submission once", async () => {
  const {env}=storage(); const costs=[]; let signal;
  assert.equal(await prepareSemanticCache(request(),env,authority,context,{embeddingAllowed:()=>true,reserveEmbedding:()=>null,
    embed:async(_model,_text,options)=>{signal=options.signal;return new Promise(()=>{});},accountEmbedding:event=>costs.push(event)}),null);
  assert.equal(signal.aborted,true); assert.equal(costs.length,1); assert.equal(costs[0].submission_outcome,"unknown");
});

test("parallel writes stay scoped and strictly within principal capacity", async () => {
  const {env,db}=storage(); const store=new SemanticCacheD1(env);
  await Promise.all(Array.from({length:270},()=>store.put(identity,[1,0],"d".repeat(64),new TextEncoder().encode(body),metadata)));
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM semantic_generation_cache").get().n,256);
  const row=(await store.scan(identity))[0];
  assert.equal(await store.body({...identity,principal_hash:"e".repeat(64)},row),null);
  const scan=await handleSemanticCache(env.INTELLIGENCE_DB,{version:1,operation:"scan",...identity,vector:[1,0],guard_hash:"d".repeat(64)},env);
  const matches=(await scan.json()).rows; assert.equal(matches.length,4);
  const foreign=await handleSemanticCache(env.INTELLIGENCE_DB,{version:1,operation:"scan",...identity,vector:[1,0],guard_hash:"e".repeat(64)},env);
  assert.equal((await foreign.json()).rows.length,0);
});
