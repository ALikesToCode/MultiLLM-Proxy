import {test} from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {Miniflare} from "miniflare";
import {handleIntelligenceAuthRequest} from "../worker/intelligence-auth-d1.mjs";

const hash = "scrypt:32768:8:1$salt123456789012$" + "a".repeat(128);
const prefix = "mllm_intelligence_" + "a".repeat(16);
test("D1 credentials survive new callers, rotate atomically and retain revocation tombstones", async () => {
  const mf = new Miniflare({modules:true, script:"export default {fetch(){return new Response('ok')}}", d1Databases:["INTELLIGENCE_DB"]});
  try {
    const db = await mf.getD1Database("INTELLIGENCE_DB");
    const migration = await readFile(new URL("../intelligence-migrations/0002_integration_principals.sql", import.meta.url),"utf8");
    for (const statement of migration.split(";").filter(x=>x.trim())) await db.prepare(statement).run();
    const call = body => handleIntelligenceAuthRequest(new Request("http://intelligence.internal/v1/auth", {
      method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({version:1,...body})}), {INTELLIGENCE_DB:db});
    const provision = {operation:"provision",principalId:"integration:omni",keyPrefix:prefix,keyHash:hash,scopes:["chat","models"]};
    assert.equal((await call({...provision,scopes:["admin"]})).status,400);
    assert.equal((await call({...provision,is_admin:true})).status,400);
    assert.equal((await call(provision)).status,201);
    assert.equal((await call({...provision,scopes:["audio"],keyPrefix:"mllm_intelligence_"+"d".repeat(16)})).status,409);
    assert.equal((await call({operation:"rotate",principalId:"integration:omni",expectedVersion:1,keyPrefix:"mllm_intelligence_"+"e".repeat(16),keyHash:hash,scopes:["admin"]})).status,400);
    assert.equal((await call(provision)).status,409);
    const lookup = async keyPrefix => (await (await call({operation:"lookup",keyPrefix})).json()).principal;
    assert.equal((await lookup(prefix)).id,"integration:omni");
    const next = "mllm_intelligence_" + "b".repeat(16);
    const rotate = {operation:"rotate",principalId:"integration:omni",expectedVersion:1,keyPrefix:next,keyHash:hash};
    const races = await Promise.all([call(rotate),call(rotate)]);
    assert.deepEqual(races.map(x=>x.status).sort(),[200,409]);
    assert.equal(await lookup(prefix),null);
    assert.equal((await lookup(next)).credentialVersion,2);
    assert.equal((await call({...rotate,expectedVersion:2,keyPrefix:prefix})).status,409);
    assert.equal((await call({operation:"revoke",principalId:"integration:omni",expectedVersion:2})).status,200);
    assert.ok((await lookup(next)).revokedAt);
    assert.equal((await call({...rotate,expectedVersion:2,keyPrefix:"mllm_intelligence_"+"c".repeat(16)})).status,409);
    assert.equal((await call(provision)).status,409);
  } finally { await mf.dispose(); }
});

test("auth RPC rejects invalid envelopes and unavailable storage", async () => {
  const request = body => new Request("http://intelligence.internal/v1/auth", {method:"POST",headers:{"content-type":"application/json"},body});
  assert.equal((await handleIntelligenceAuthRequest(request("{}"),{})).status,503);
  const env = {INTELLIGENCE_DB:{prepare(){throw new Error("private database detail")}}};
  for (const body of [JSON.stringify({version:1,operation:"lookup",keyPrefix:[prefix]}), JSON.stringify({version:1,operation:"revoke",principalId:["integration:omni"],expectedVersion:1}), "x".repeat(4097), "not-json", JSON.stringify({version:1,operation:"sql",sql:"SELECT * FROM users"})])
    assert.equal((await handleIntelligenceAuthRequest(request(body),env)).status,400);
  const response = await handleIntelligenceAuthRequest(request(JSON.stringify({version:1,operation:"lookup",keyPrefix:prefix})),env);
  assert.equal(response.status,503);
  assert.equal((await response.text()).includes("private database detail"),false);
});

test("auth RPC confines its origin, content type and body size", async () => {
  const env = {INTELLIGENCE_DB:{prepare(){throw new Error("must not read")}}};
  for (const url of ["https://intelligence.internal/v1/auth", "http://other.internal/v1/auth", "http://intelligence.internal/v1/auth?sql=1"]) {
    const result = await handleIntelligenceAuthRequest(new Request(url,{method:"POST",headers:{"content-type":"application/json"},body:"{}"}),env);
    assert.equal(result.status,404);
    assert.equal(result.headers.get("cache-control"),"no-store");
    assert.equal((await result.json()).version,1);
  }
  for (const headers of [{}, {"content-type":"text/plain"}, {"content-type":"application/json","content-length":"9999"}]) {
    const result = await handleIntelligenceAuthRequest(new Request("http://intelligence.internal/v1/auth",{method:"POST",headers,body:"{}"}),env);
    assert.equal(result.status,400);
    assert.equal((await result.json()).error.code,"invalid_request");
  }
});
