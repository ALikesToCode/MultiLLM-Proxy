import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { convertV4MiniflareOptions, Miniflare } from 'miniflare';
import { applyMigrations } from './d1_migrations.mjs';
import { handleShadowEvalRequest, validConfig, validSample, validResult } from '../worker/shadow-eval-d1.mjs';
import { runScheduledShadowEval } from '../worker/shadow-eval-schedule.mjs';

const config = () => ({ enabled: true, candidate_models: { coding: [], extraction: [], writing: [], reasoning: [], chat: ['openai:candidate'] },
  judge_model: 'free:json', max_replays_per_run: 3, daily_cap: 2 });
const id = number => number.toString(16).padStart(32, '0');
const sample = (number = 1) => ({ id: id(number), created_at: Date.now() / 1000, key_id: 'synthetic-user', route: 'auto:test', task_type: 'chat',
  request: { messages: [{ role: 'user', content: 'Synthetic greeting' }] }, production_model: 'openai:production',
  production_answer: { content: 'Synthetic answer' }, latency_ms: 100, usage: { prompt_tokens: 4, completion_tokens: 2 } });
const result = (number = 1) => ({ sample_id: id(number), task_type: 'chat', candidate_model: 'openai:candidate', candidate_route: 'openai:candidate',
  production_model: 'openai:production', outcome: 'win', judge_model: 'free:json', latencies: { production: 100, candidate: 50, judges: [30, 30] },
  usage: { production: {}, candidate: {}, judges: [{}, {}] }, costs: { production: null, candidate: null, judges: [null, null] }, tool_validity: null });
async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ['INTELLIGENCE_DB'] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database('INTELLIGENCE_DB');
  await applyMigrations(db);
  const call = async (operation, values = {}) => {
    const response = await handleShadowEvalRequest(new Request('http://intelligence.internal/v1/shadow-eval', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ version: 1, operation, ...values }),
    }), { INTELLIGENCE_DB: db });
    return { status: response.status, ...(await response.json()) };
  };
  return { db, call };
}

test('Flask and edge share strict config validation vectors', () => {
  for (const vector of JSON.parse(readFileSync(new URL('./fixtures/shadow_eval_vectors.json', import.meta.url)))) {
    assert.equal(validConfig({ ...config(), ...vector.changes }), vector.valid, JSON.stringify(vector.changes));
  }
  assert.equal(validSample(sample(), Date.now() / 1000), true);
  assert.equal(validResult(result()), true);
  assert.equal(validResult({ ...result(), answer: 'must not persist' }), false);
  assert.equal(validSample({ ...sample(), request: { messages: [{ content: 'sk-' + 'proj-' + 'Abc0123456789'.repeat(6) }] } }, Date.now() / 1000), false);
  assert.equal(validSample({ ...sample(), production_answer: { content: 'x'.repeat(32768) } }, Date.now() / 1000), false);
});

test('private D1 endpoint rejects public URLs and malformed operations', async t => {
  const { call } = await database(t);
  for (const values of [{ document: '{}' }, { document: JSON.stringify(config()), extra: true }]) {
    assert.equal((await call('config_seed', values)).status, 400);
  }
  assert.equal((await call('unknown')).status, 400);
  const response = await handleShadowEvalRequest(new Request('https://gateway.test/v1/shadow-eval', { method: 'POST' }), {});
  assert.equal(response.status, 404);
  assert.equal((await call('put', { id: id(1), created_at: sample().created_at, document: JSON.stringify({ ...sample(), key_id: '' }) })).status, 400);
});

test('D1 stores bounded samples, hides expired text and purges samples/results', async t => {
  const { db, call } = await database(t);
  const first = sample();
  assert.equal((await call('put', { id: first.id, created_at: first.created_at, document: JSON.stringify(first) })).result, true);
  assert.equal((await call('sample', { id: first.id })).result.production_answer.content, 'Synthetic answer');
  const metadata = await call('samples');
  assert.equal(metadata.result.length, 1);
  assert.doesNotMatch(JSON.stringify(metadata), /Synthetic answer|Synthetic greeting|messages/);
  const expired = { ...sample(2), created_at: Date.now() / 1000 - 604801 };
  await db.prepare('INSERT INTO shadow_eval_samples VALUES (?, ?, ?)').bind(expired.id, expired.created_at, JSON.stringify(expired)).run();
  assert.equal((await call('sample', { id: expired.id })).result, null);
  await call('cleanup');
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_samples').first()).n, 1);
  for (let offset = 0; offset < 2005; offset += 100) {
    await db.batch(Array.from({ length: Math.min(100, 2005 - offset) }, (_, index) => {
      const value = sample(offset + index + 10);
      return db.prepare('INSERT INTO shadow_eval_samples VALUES (?, ?, ?)').bind(value.id, value.created_at, JSON.stringify(value));
    }));
  }
  const last = sample(5000);
  await call('put', { id: last.id, created_at: last.created_at, document: JSON.stringify(last) });
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_samples').first()).n, 2000);
  assert.equal((await call('samples')).result.length, 20);
  assert.equal((await call('sample', { id: first.id })).result, null, 'oldest evicted first');
  await call('purge');
  assert.equal((await call('samples')).result.length, 0);
});

test('leases and atomic claims enforce daily limits across runners and purge', async t => {
  const { db, call } = await database(t);
  const settings = JSON.stringify(config());
  assert.equal((await call('config_seed', { document: settings })).result, true);
  assert.equal((await call('config_save', { document: settings, expected: '{}' })).status, 400);
  const changed = JSON.stringify({ ...config(), daily_cap: 3 });
  assert.equal((await call('config_save', { document: settings, expected: changed })).result, false);
  for (let number = 1; number <= 4; number++) {
    const value = sample(number);
    await call('put', { id: value.id, created_at: value.created_at, document: JSON.stringify(value) });
  }
  assert.equal((await call('lease', { run_id: id(100), until: Date.now() / 1000 + 300 })).result, true);
  assert.equal((await call('lease', { run_id: id(101), until: Date.now() / 1000 + 300 })).result, false);
  const claim = number => call('claim', { sample_id: id(number), candidate: 'openai:candidate', config: settings, run_id: id(100), id: id(200 + number) });
  const claims = await Promise.all([claim(1), claim(1), claim(2), claim(3)]);
  assert.equal(claims.filter(item => item.result === true).length, 2);
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 2);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_results').first()).n, 2);
  assert.equal((await call('finish', { id: id(201), document: JSON.stringify(result()) })).result, true);
  assert.equal((await call('finish', { id: id(201), document: JSON.stringify(result()) })).result, false);
  const rows = await call('results', { after: '' });
  assert.equal(rows.result.length, 1);
  assert.doesNotMatch(JSON.stringify(rows), /Synthetic answer|Synthetic greeting|messages/);
  await call('purge');
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 2);
  await db.prepare('UPDATE shadow_eval_config SET day = day - 1').run();
  const value = sample(4);
  await call('put', { id: value.id, created_at: value.created_at, document: JSON.stringify(value) });
  assert.equal((await claim(4)).result, true);
  assert.equal((await db.prepare('SELECT replay_count AS n FROM shadow_eval_config').first()).n, 1);
  const unconfigured = await call('claim', { sample_id: id(4), candidate: 'openai:other', config: settings, run_id: id(100), id: id(300) });
  assert.equal(unconfigured.result, false);
  await call('release', { run_id: id(101) });
  assert.equal((await call('lease', { run_id: id(101), until: Date.now() / 1000 + 300 })).result, false);
  await call('release', { run_id: id(100) });
  assert.equal((await call('lease', { run_id: id(101), until: Date.now() / 1000 + 300 })).result, true);
});

test('guarded D1 policy update stores a backup and rejects stale revisions', async t => {
  const { db, call } = await database(t);
  const before = { version: 1, enabled: true, candidates: [], max_total_tokens: 1000, principal_daily_tokens: 1000, global_daily_tokens: 2000, max_inflight: 100, media: {} };
  const after = { ...before, enabled: false };
  await db.prepare('INSERT INTO intelligence_policy (id, document) VALUES (1, ?)').bind(JSON.stringify(before)).run();
  assert.equal((await call('apply', { expected: JSON.stringify(before), document: JSON.stringify(after), id: id(1) })).result, true);
  assert.equal((await db.prepare('SELECT document FROM shadow_eval_policy_backups').first()).document, JSON.stringify(before));
  assert.equal((await call('apply', { expected: JSON.stringify(before), document: JSON.stringify(after), id: id(2) })).result, false);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_policy_backups').first()).n, 1);
});

test('cron never wakes an idle Container and expires D1 samples while asleep', async t => {
  const { db } = await database(t);
  const value = { ...sample(), created_at: Date.now() / 1000 - 604801 };
  await db.prepare('INSERT INTO shadow_eval_samples VALUES (?, ?, ?)').bind(value.id, value.created_at, JSON.stringify(value)).run();
  let calls = 0;
  const container = { fetch() { throw new Error('must not wake'); }, async fetchIfRunning(path, options) {
    calls++;
    assert.equal(path, '/admin/shadow-eval/run');
    assert.equal(options.method, 'POST');
    assert.equal(options.headers.Authorization, 'Bearer synthetic-admin');
    return null;
  } };
  assert.deepEqual(await runScheduledShadowEval({ ADMIN_API_KEY: 'synthetic-admin', INTELLIGENCE_DB: db }, container), { skipped: 'container_asleep' });
  assert.equal(calls, 1);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM shadow_eval_samples').first()).n, 0);
  container.fetchIfRunning = async () => new Response('{}', { status: 202 });
  assert.deepEqual(await runScheduledShadowEval({ ADMIN_API_KEY: 'synthetic-admin' }, container), { status: 202 });
  assert.deepEqual(await runScheduledShadowEval({}, container), { skipped: 'admin_key_missing' });
  container.fetchIfRunning = async () => { throw new Error('synthetic unavailable'); };
  assert.deepEqual(await runScheduledShadowEval({ ADMIN_API_KEY: 'synthetic-admin' }, container), { skipped: 'unavailable' });
});


test('private sample/result contracts retain replay bounds and classify exclusions', async t => {
  const { call } = await database(t);
  const value = { ...sample(), production_finish_reason: 'length',
    request: { ...sample().request, max_tokens: 500, max_completion_tokens: 600 } };
  assert.equal(validSample(value, Date.now() / 1000), true);
  assert.equal(validSample({ ...value, production_finish_reason: 'bad' }, Date.now() / 1000), false);
  assert.equal(validSample({ ...value, request: { ...value.request, max_tokens: true } }, Date.now() / 1000), false);
  assert.equal((await call('put', { id: value.id, created_at: value.created_at, document: JSON.stringify(value) })).result, true);
  assert.deepEqual((await call('sample', { id: value.id })).result, value);
  assert.equal(validResult({ ...result(), outcome: 'same_model' }), true);
  assert.equal(validResult({ ...result(), outcome: 'candidate_truncated', candidate_truncated: true }), true);
  assert.equal(validResult({ ...result(), candidate_truncated: 'true' }), false);
  const settings = JSON.stringify(config());
  await call('config_seed', { document: settings });
  await call('lease', { run_id: id(100), until: Date.now() / 1000 + 300 });
  await call('claim', { sample_id: value.id, candidate: 'openai:candidate', config: settings, run_id: id(100), id: id(200) });
  const excluded = { ...result(), outcome: 'candidate_truncated', candidate_truncated: true };
  assert.equal((await call('finish', { id: id(200), document: JSON.stringify(excluded) })).result, true);
  assert.deepEqual(JSON.parse((await call('results', { after: '' })).result[0].document), excluded);
});


test('dashboard coverage renders numeric counters only', async t => {
  const { renderCounts } = await import('../static/js/workbench/shadow.mjs');
  class Element {
    children = [];
    textContent = '';
    append(...children) { this.children.push(...children); }
    replaceChildren() { this.children = []; }
  }
  const previous = globalThis.document;
  t.after(() => { if (previous === undefined) delete globalThis.document; else globalThis.document = previous; });
  globalThis.document = { createElement() { return new Element(); } };
  const container = new Element();
  renderCounts(container, { eligible: 10, sampled: 2, skipped_secret: '<synthetic prompt>', extra: 'private' },
    [['eligible', 'Eligible'], ['sampled', 'Sampled'], ['skipped_secret', 'Skipped: secret']]);
  const list = container.children[0];
  assert.deepEqual(list.children.map(child => child.textContent), ['Eligible', '10', 'Sampled', '2', 'Skipped: secret', '0']);
  assert.doesNotMatch(JSON.stringify(container), /synthetic prompt|private/);
});
