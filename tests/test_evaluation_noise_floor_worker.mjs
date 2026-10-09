import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { convertV4MiniflareOptions, Miniflare } from 'miniflare';
import { applyMigrations } from './d1_migrations.mjs';
import { handleShadowEvalRequest, validResult } from '../worker/shadow-eval-d1.mjs';

const id = number => number.toString(16).padStart(32, '0');
const paired = () => ({ sample_id: id(1), task_type: 'chat', candidate_model: 'openai:candidate',
  candidate_route: 'openai:candidate', production_model: 'openai:production', outcome: 'win', judge_model: 'free:json',
  latencies: { production: 100, candidate: 50, judges: [30, 30] },
  usage: { production: {}, candidate: {}, judges: [{}, {}] },
  costs: { production: null, candidate: null, judges: [null, null] }, tool_validity: null });
const three = () => {
  const value = paired();
  for (const name of ['latencies', 'usage', 'costs']) value[name].judges = Array(6).fill(value[name].judges[0]);
  value.noise_floor = { version: 1, run_id: id(100), seed: 17, bootstrap_draws: 1000, completed_arms: 3,
    candidate_first: [true, false, true], pairs: { ab: 'tie', ac: 'win', bc: 'win' },
    repeat: { model: 'openai:production', latency_ms: 90, usage: {}, cost: null, tool_validity: null } };
  return value;
};
const config = () => ({ enabled: true, candidate_models: { coding: [], extraction: [], writing: [], reasoning: [], chat: ['openai:candidate'] },
  judge_model: 'free:json', max_replays_per_run: 18, daily_cap: 18 });
const sample = number => ({ id: id(number), created_at: Date.now() / 1000, key_id: 'synthetic-user', route: 'auto:test', task_type: 'chat',
  request: { messages: [{ role: 'user', content: 'Synthetic greeting' }] }, production_model: 'openai:production',
  production_answer: { content: 'Synthetic answer' }, latency_ms: 100, usage: { prompt_tokens: 4, completion_tokens: 2 } });

async function database(t, enabled = false) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ['INTELLIGENCE_DB'] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database('INTELLIGENCE_DB');
  await applyMigrations(db);
  const env = { INTELLIGENCE_DB: db, SHADOW_EVAL_NOISE_FLOOR_ENABLED: enabled ? 'true' : 'false' };
  const call = async (operation, values = {}) => {
    const response = await handleShadowEvalRequest(new Request('http://intelligence.internal/v1/shadow-eval', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ version: 1, operation, ...values }),
    }), env);
    return { status: response.status, ...(await response.json()) };
  };
  const settings = JSON.stringify(config());
  await call('config_seed', { document: settings });
  for (let number = 1; number <= 4; number++) {
    const value = sample(number);
    await call('put', { id: value.id, created_at: value.created_at, document: JSON.stringify(value) });
  }
  await call('lease', { run_id: id(100), until: Date.now() / 1000 + 300 });
  const claim = (number, operation = 'claim_three_arm') => call(operation,
    { sample_id: id(number), candidate: 'openai:candidate', config: settings, run_id: id(100), id: id(200 + number) });
  return { db, call, claim, settings, env };
}

test('default-off validation accepts exactly the legacy shapes and rejects extended judges', () => {
  assert.equal(validResult(paired()), true);
  assert.equal(validResult(three()), false);
  assert.equal(validResult({ ...paired(), noise_floor: {} }), false);
  const value = paired();
  value.usage.judges.push({});
  assert.equal(validResult(value), false);
  assert.equal(validResult({ ...paired(), extra: true }, true), false);
});

test('enabled validation has a fixed bounded content-free contract', () => {
  assert.equal(validResult(three(), true), true);
  assert.equal(validResult(paired(), true), true);
  const mutations = [
    value => { value.noise_floor.extra = true; },
    value => { value.noise_floor.repeat.answer = 'private'; },
    value => { value.noise_floor.pairs.extra = 'win'; },
    value => { value.noise_floor.seed = true; },
    value => { value.noise_floor.seed = 2 ** 32; },
    value => { value.noise_floor.bootstrap_draws = 5001; },
    value => { value.noise_floor.candidate_first.push(true); },
    value => { value.noise_floor.pairs.ab = 'other'; },
    value => { value.noise_floor.run_id = 'invalid'; },
    value => { value.noise_floor.version = 2; },
    value => { value.noise_floor.completed_arms = 4; },
    value => { value.noise_floor.repeat.model = 'openai:other'; },
    value => { value.outcome = 'loss'; },
    value => { value.candidate_truncated = true; },
    value => { value.usage.judges.push({}); },
    value => { value.costs.judges.pop(); },
    value => { value.noise_floor.repeat.cost = -1; },
    value => { value.noise_floor.repeat.usage = { arbitrary: 1 }; },
  ];
  for (const mutate of mutations) {
    const value = three(); mutate(value);
    assert.equal(validResult(value, true), false, String(mutate));
  }
  const failed = three();
  failed.outcome = 'failed'; failed.noise_floor.completed_arms = 1;
  failed.noise_floor.pairs = { ab: null, ac: null, bc: null };
  for (const name of ['latencies', 'usage', 'costs']) failed[name].judges = [];
  assert.equal(validResult(failed, true), true);
});

test('disabled claims and stored document bytes retain one-unit legacy accounting', async t => {
  const { db, call, claim } = await database(t);
  assert.equal((await claim(1)).status, 400);
  assert.equal((await claim(1, 'claim')).result, true);
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 1);
  const document = JSON.stringify(paired());
  assert.equal((await call('finish', { id: id(201), document })).result, true);
  assert.equal((await db.prepare('SELECT document FROM shadow_eval_results WHERE id = ?').bind(id(201)).first()).document, document);
  assert.equal((await call('finish', { id: id(201), document: JSON.stringify(three()) })).status, 400);
});

test('three-arm D1 claims reserve nine calls atomically across concurrent attempts', async t => {
  const { db, call, claim } = await database(t, true);
  const results = await Promise.all([claim(1), claim(1), claim(2), claim(3)]);
  assert.equal(results.filter(value => value.result === true).length, 2);
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 18);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_results').first()).n, 2);
  const document = JSON.stringify(three());
  assert.equal((await call('finish', { id: id(201), document })).result, true);
  assert.equal((await db.prepare('SELECT document FROM shadow_eval_results WHERE id = ?').bind(id(201)).first()).document, document);
  await call('purge');
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 18);
});

test('insufficient remaining D1 cap changes nothing and next day resets by nine', async t => {
  const { db, claim } = await database(t, true);
  await db.prepare('UPDATE shadow_eval_config SET day = ?, replay_count = 10').bind(Math.floor(Date.now() / 86400000)).run();
  assert.equal((await claim(1)).result, false);
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 10);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_results').first()).n, 0);
  await db.prepare('UPDATE shadow_eval_config SET day = day - 1').run();
  assert.equal((await claim(1)).result, true);
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 9);
});

test('disabled SQL claim remains the legacy one-unit operation', () => {
  const sql = JSON.parse(readFileSync(new URL('../worker/shadow-eval-sql.json', import.meta.url)));
  assert.match(sql.claim[0], /replay_count \+ 1 ELSE 1 END/);
  assert.doesNotMatch(sql.claim[0], /noise_floor|units|\+ 9/);
});
