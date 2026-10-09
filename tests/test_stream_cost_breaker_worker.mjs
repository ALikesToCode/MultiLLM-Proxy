import assert from "node:assert/strict";
import test from "node:test";
import { prepareStreamCostBreaker, wrapStreamCost, streamCostEnabled, validStreamCap } from "../worker/stream-cost-breaker.mjs";
const env={STREAM_COST_BREAKER_ENABLED:"true",MODEL_PRICING_USD_PER_MILLION:JSON.stringify({"openai:m":{input:1,cache_read:0.25,cache_write:2,output:1}})};
const enc=new TextEncoder();
const frame=v=>enc.encode("data: "+JSON.stringify(v)+"\n\n");
const delta=text=>frame({choices:[{delta:{content:text}}]});
function source(chunks) {
  let closes=0;
  return {stream:new ReadableStream({pull(c){chunks.length?c.enqueue(chunks.shift()):c.close();},cancel(){closes++;}},{highWaterMark:0}),closes:()=>closes};
}
const read=stream=>new Response(stream).text();
test("off and null preserve identity",()=>{
  for(const flag of ["","false","garbage"]) assert.equal(streamCostEnabled({STREAM_COST_BREAKER_ENABLED:flag}),false);
  const original=source([delta("x")]).stream;
  assert.equal(wrapStreamCost(original,null),original);
  assert.equal(prepareStreamCostBreaker(env,{},["missing"],0,"chat"),null);
  for(const cap of [-1,0.5,true,NaN,1e16]) assert.equal(validStreamCap(cap),false);
});
for(const [protocol,marker] of [["chat",'data: {"error"'],["anthropic","event: error"],["responses","event: response.failed"]]) {
  test(protocol+" crossing closes once",async()=>{
    const state=prepareStreamCostBreaker(env,{max_stream_cost_microusd:4},["openai:m"],0,protocol);
    const upstream=source([delta("four"),delta("secret-response"),enc.encode("data: [DONE]\n\n")]);
    const text=await read(wrapStreamCost(upstream.stream,state));
    assert.ok(text.startsWith(new TextDecoder().decode(delta("four"))) && text.includes(marker));
    assert.ok(text.includes("stream_cost_cap_exceeded") && !text.includes("secret-response") && !text.includes("[DONE]"));
    assert.equal(upstream.closes(),1); assert.equal(state.basis,"conservative_estimate");
  });
}
test("split unicode SSE",async()=>{
  const bytes=delta("ह"),state=prepareStreamCostBreaker(env,{max_stream_cost_microusd:3},["openai:m"],0,"chat");
  assert.equal(await read(wrapStreamCost(source([...bytes].map(v=>Uint8Array.of(v))).stream,state)),new TextDecoder().decode(bytes));
  assert.equal(state.runningMicrousd,3);
});
test("measured buckets and unknown final",async()=>{
  const state=prepareStreamCostBreaker(env,{max_stream_cost_microusd:100},["openai:m"],0,"anthropic");
  await read(wrapStreamCost(source([frame({type:"message",usage:{input_tokens:4,cache_read_input_tokens:8,cache_creation_input_tokens:2,output_tokens:1}}),frame({type:"message_stop"})]).stream,state));
  assert.equal(state.runningMicrousd,11); assert.equal(state.basis,"measured"); assert.ok(state.finalUsage);
  const unknown=prepareStreamCostBreaker(env,{max_stream_cost_microusd:100},["openai:m"],0,"chat");
  await read(wrapStreamCost(source([delta("x")]).stream,unknown)); assert.equal(unknown.finalUsage,null);
});
test("unpriced candidate rejects",()=>{
  assert.throws(()=>prepareStreamCostBreaker(env,{max_stream_cost_microusd:20},["openai:m","missing"],0,"chat"),e=>e.code==="stream_cost_unpriced"&&e.status===503);
});

import { USER_FIELDS, validUser, handleControlUsersRequest } from "../worker/control-users-d1.mjs";
const account = cap => ({...Object.fromEntries(USER_FIELDS.map(name=>[name,null])),
  username:"reader",api_key_hash:"synthetic-hash",api_key_prefix:"synthetic-prefix",scopes:"chat",is_admin:0,
  created_at:"2026-10-09T00:00:00Z",...cap});
function fakeDb({missing=false,stored={}}={}) {
  const statements=[],rows=new Map(Object.entries(stored));
  const db={prepare(sql){
    if(missing && sql.includes("max_stream_cost_microusd")) throw new Error("no such column: max_stream_cost_microusd");
    const query={sql,args:[],bind(...args){this.args=args;return this;},
      async first(){return sql.includes("LIMIT 1")?null:rows.get(this.args[0])??null;},
      async all(){return {results:[...rows.values()]};}};
    statements.push(query); return query;
  },async batch(items){
    for(const item of items) if(item.sql.startsWith("INSERT INTO control_users")) {
      const names=item.sql.match(/\(([^)]+)\)/)[1].split(",").map(v=>v.trim());
      const row=Object.fromEntries(names.map((name,i)=>[name,item.args[i]]));
      rows.set(row.username,{...rows.get(row.username),...row});
    }
    return [];
  }};
  return {db,rows,statements};
}
async function call(db,body,flags=env) {
  return handleControlUsersRequest(new Request("http://intelligence.internal/v1/users",{method:"POST",
    headers:{"content-type":"application/json"},body:JSON.stringify({version:1,...body})}),{...flags,INTELLIGENCE_DB:db});
}
test("strict caps and omitted updates preserve existing column",async()=>{
  for(const value of [-1,0.5,true,NaN,1e16]) assert.equal(validUser(account({max_stream_cost_microusd:value})),false);
  const {db,rows,statements}=fakeDb({stored:{reader:account({max_stream_cost_microusd:4})}});
  assert.equal((await call(db,{operation:"upsert",user:account({})})).status,200);
  assert.equal(rows.get("reader").max_stream_cost_microusd,4);
  assert.equal((await call(db,{operation:"upsert",user:account({max_stream_cost_microusd:null})})).status,200);
  assert.equal(rows.get("reader").max_stream_cost_microusd,null);
  const legacy=fakeDb();
  assert.equal((await call(legacy.db,{operation:"upsert",user:account({})},{})).status,200);
  assert.ok(legacy.statements.every(s=>!s.sql.includes("max_stream_cost_microusd")));
  assert.equal(Object.keys(legacy.rows.get("reader")).length,USER_FIELDS.length);
});
test("enabled missing column fails closed before writes",async()=>{
  const {db,statements}=fakeDb({missing:true});
  for(const body of [{operation:"get",username:"reader"},{operation:"list",after:null,limit:5},
    {operation:"by_prefix",prefix:"synthetic-prefix"},{operation:"upsert",user:account({max_stream_cost_microusd:4})}]) {
    const response=await call(db,body); assert.equal(response.status,503);
    assert.equal((await response.json()).error.code,"stream_cost_storage_unavailable");
  }
  assert.ok(statements.every(s=>!s.sql.startsWith("INSERT")));
});
test("late provider usage overrun withholds successful completion",async()=>{
  const state=prepareStreamCostBreaker(env,{max_stream_cost_microusd:4},["openai:m"],0,"chat");
  const text=await read(wrapStreamCost(source([delta("four"),
    frame({choices:[{delta:{},finish_reason:"stop"}]}),
    frame({usage:{prompt_tokens:0,prompt_tokens_details:{cached_tokens:0},completion_tokens:5}}),
    enc.encode("data: [DONE]\n\n")]).stream,state));
  assert.ok(text.includes("stream_cost_cap_exceeded")&&!text.includes("finish_reason")&&!text.includes("[DONE]"));
  assert.equal(state.finalUsage?.output,5);
});
test("cancel before reading invokes cleanup and finalization once",async()=>{
  const state=prepareStreamCostBreaker(env,{max_stream_cost_microusd:4},["openai:m"],0,"chat"),upstream=source([delta("x")]);
  let aborts=0,finals=0;
  const wrapped=wrapStreamCost(upstream.stream,state,{abort(){aborts++;},onFinal(){finals++;}});
  await wrapped.cancel(); assert.equal(upstream.closes(),1);assert.equal(aborts,1);assert.equal(finals,1);
});
