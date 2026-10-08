import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { convertV4MiniflareOptions, Miniflare } from 'miniflare';
import { BUCKET_FIELDS, serializeUsageBuckets, recordUsageWithBuckets, bucketInsertStatement } from '../worker/usage-buckets-d1.mjs';
import { validRow } from '../worker/usage-ledger-d1.mjs';
import { applyMigrations } from './d1_migrations.mjs';

const base = {at:'2026-10-01T00:00:00.000Z', principal:'reader', key_prefix:null, kind:'chat',
 endpoint:'/v1/chat/completions', requested_model:'openai:m', selected_model:'openai:m', status:200,
 latency_ms:1, input_tokens:100, output_tokens:10, cost_usd:0.00019, cost_basis:'usage', request_id:null};
const buckets = Object.fromEntries(BUCKET_FIELDS.map(name => [name, null]));
Object.assign(buckets, {ordinary_input_tokens:40, cache_read_input_tokens:60, cache_write_input_tokens:0,
 ordinary_input_cost_microusd:80, cache_read_input_cost_microusd:30, cache_write_input_cost_microusd:0,
 output_cost_microusd:80, bucket_basis:'measured', bucket_source:'openai'});
const row = {...base, ...buckets};

test('disabled serializer returns legacy row and does not execute new statements', async () => {
 assert.deepEqual(serializeUsageBuckets(row, {}), base);
 assert.ok(validRow(serializeUsageBuckets(row, {})));
 let extended = 0;
 const result = await recordUsageWithBuckets({}, {rows:[row]}, {
  recordBase: async body => {assert.deepEqual(body.rows,[base]); return {version:1,recorded:1,duplicate:false};},
  recordExtended: async () => {extended++;},
 });
 assert.equal(result.status,200); assert.equal(extended,0);
 for (const flag of ['', 'false', 'malformed']) assert.deepEqual(serializeUsageBuckets(row,{PROMPT_CACHE_USAGE_BUCKETS_ENABLED:flag}),base);
});

test('strict nullable counts, bounded microUSD and provenance', () => {
 const env={PROMPT_CACHE_USAGE_BUCKETS_ENABLED:'true'};
 assert.deepEqual(serializeUsageBuckets(row,env),row);
 for (const value of [-1, true, '3', Number.MAX_SAFE_INTEGER+1])
  assert.throws(()=>serializeUsageBuckets({...row,cache_read_input_tokens:value},env));
 assert.throws(()=>serializeUsageBuckets({...row,output_cost_microusd:1e12+1},env));
 assert.throws(()=>serializeUsageBuckets({...row,bucket_source:'secret text'},env));
 assert.equal(serializeUsageBuckets({...row,cache_read_input_tokens:null},env).cache_read_input_tokens,null);
 assert.throws(()=>serializeUsageBuckets({...row,unexpected:1},env));
});

test('migration accepts old rows; missing columns fail closed after preserving base ledger', async t => {
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:"export default {fetch(){return new Response('ok')}}",d1Databases:['DB']}));
 t.after(()=>mf.dispose()); const db=await mf.getD1Database('DB');
 await applyMigrations(db,{skip:['0016_usage_buckets.sql']});
 const legacySql='INSERT INTO usage_events (day,'+Object.keys(base).join(',')+') VALUES ('+Array(Object.keys(base).length+1).fill('?').join(',')+')';
 const callbacks={recordBase:async body=>{await db.prepare(legacySql).bind('2026-10-01',...Object.values(body.rows[0])).run();return {version:1,recorded:1,duplicate:false};},
  recordExtended:async body=>{await db.prepare(bucketInsertStatement(Object.keys(base))).bind(JSON.stringify(body.rows),'a'.repeat(32),'token').run(); return {version:1,recorded:1,duplicate:false};}};
 await db.prepare('INSERT INTO usage_batches(id,token,at) VALUES (?,?,?)').bind('a'.repeat(32),'token',base.at).run();
 const response=await recordUsageWithBuckets({PROMPT_CACHE_USAGE_BUCKETS_ENABLED:'true'},{rows:[row]},callbacks);
 assert.equal(response.status,503); assert.equal((await response.json()).error.code,'usage_buckets_unavailable');
 assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM usage_events').first()).n,1);
 const sql=await readFile(new URL('../intelligence-migrations/0016_usage_buckets.sql',import.meta.url),'utf8');
 for(const statement of sql.replace(/^--.*$/gm,'').split(';').filter(s=>s.trim())) await db.prepare(statement).run();
 const success=await recordUsageWithBuckets({PROMPT_CACHE_USAGE_BUCKETS_ENABLED:'true'},{rows:[row]},callbacks);
 assert.equal(success.status,200);
 const rows=(await db.prepare('SELECT * FROM usage_events ORDER BY id').all()).results;
 assert.equal(rows[0].cache_read_input_tokens,null); assert.equal(rows[1].cache_read_input_tokens,60);
});


test('bad metadata and missing base storage stay closed without leaking details', async () => {
 for(const metadata of ['[]', 'bad json', '{"m":{"cache_read":-1}}', '{"m":{"cache_read":"0x10"}}']) {
  assert.deepEqual(serializeUsageBuckets(row,{PROMPT_CACHE_USAGE_BUCKETS_ENABLED:'true',PROMPT_CACHE_PRICE_METADATA_JSON:metadata}),base);
 }
 const response=await recordUsageWithBuckets({PROMPT_CACHE_USAGE_BUCKETS_ENABLED:'true'},{rows:[row]}, {
  recordBase: async ()=>{throw new Error('private detail');}, recordExtended: async ()=>{throw new Error('private detail');},
 });
 assert.equal(response.status,503); assert.equal((await response.json()).error.code,'storage_unavailable');
});
