import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { handleCreditsRequest, appendCredit, readCredits, registerCreditAuthority, creditsEnabled, contextOwner } from '../worker/credits-d1.mjs';
import { AuthorityOperation, TenantContext, callAuthority, registerEnterpriseAdapters } from '../worker/enterprise-contract.mjs';

const migration = readFileSync(new URL('../intelligence-migrations/0037_credits_ledger.sql', import.meta.url), 'utf8');
const vectors = JSON.parse(readFileSync(new URL('../docs/credits-ledger.md', import.meta.url), 'utf8').split('```json\n')[1].split('```')[0]);

function database(t, schema = true) {
  const sql = new DatabaseSync(':memory:');
  t.after(() => sql.close());
  if (schema) sql.exec(migration);
  const db = { prepare(query) {
    let values = [];
    const statement = {
      bind(...args) { values = args; return statement; },
      first() { return sql.prepare(query).get(...values) ?? null; },
      all() {
        const prepared = sql.prepare(query);
        if (prepared.columns().length) return { results: prepared.all(...values), success: true };
        return { results: [], success: true, meta: { changes: Number(prepared.run(...values).changes) } };
      },
    };
    return statement;
  }, async batch(statements) {
    sql.exec('BEGIN IMMEDIATE');
    try {
      const rows = statements.map(statement => statement.all());
      sql.exec('COMMIT');
      return rows;
    } catch (error) { sql.exec('ROLLBACK'); throw error; }
  } };
  const env = { CREDITS_ENABLED: 'true', CREDITS_CURRENCY: 'USD', INTELLIGENCE_DB: db };
  const call = async body => {
    const response = await handleCreditsRequest(new Request('http://intelligence.internal/v1/credits', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ version: 1, ...body }),
    }), env);
    return { status: response.status, ...await response.json() };
  };
  return { sql, db, env, call };
}

const entry = (kind, amount, operation_id, revision, extra = {}) => ({ owner: 'alice', kind,
  amount_microusd: amount, operation_id, revision, ...extra });

test('shared integer, insufficient and duplicate operation vectors', async t => {
  const { call } = database(t);
  for (const vector of vectors) {
    const request = vector.request ?? entry('credit', vector.invalid_amount, 'bad', 0);
    const result = await call({ operation: 'append', ...request });
    if ('invalid_amount' in vector) assert.equal(result.status, 400);
    else if (vector.error) assert.equal(result.error.code, vector.error);
    else assert.equal(result.entry.revision, vector.revision);
    if (vector.summary) {
      const { summary } = await call({ operation: 'read', owner: request.owner });
      for (const [key, value] of Object.entries(vector.summary)) assert.equal(summary[key], value);
    }
  }
  const summary = (await call({ operation: 'read', owner: 'alice' })).summary;
  assert.equal(summary.balance_microusd, 75);
  assert.equal(summary.held_microusd, 0);
  assert.equal(summary.available_microusd, 75);
});

test('concurrent CAS reserves and duplicate requests spend once', async t => {
  const { db } = database(t);
  await appendCredit(db, entry('credit', 100, 'fund', 0));
  const reserve = name => appendCredit(db, entry('reserve', 80, name, 1, { scoped_id: name, tariff_revision: 1 }));
  const results = await Promise.allSettled([reserve('hedge'), reserve('shadow')]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal((await readCredits(db, 'alice')).available_microusd, 20);
  const { db: other } = database(t);
  const fund = entry('credit', 100, 'fund', 0);
  const duplicates = await Promise.all([appendCredit(other, fund), appendCredit(other, fund)]);
  assert.deepEqual(duplicates[0], duplicates[1]);
  assert.equal((await readCredits(other, 'alice')).balance_microusd, 100);
});

test('unknown reconciliation retains hold and all attempts settle independently', async t => {
  const { db, env } = database(t);
  await appendCredit(db, entry('credit', 100, 'fund', 0));
  const authority = registerCreditAuthority(db, { env, tariff: (_op, phase) => phase === 'reconcile' ? null : 7 });
  const adapters = registerEnterpriseAdapters({ credit: authority });
  const op = (revision, operation_id, amount, scoped_id = 'hedge') => new AuthorityOperation({
    context: new TenantContext({ principal_id: 'alice' }), revision, operation_id, amount, scoped_id });
  await callAuthority(adapters, 'credit', 'reserve', op(1, 'hold1', 50));
  await callAuthority(adapters, 'credit', 'reconcile', op(2, 'unknown1', 0));
  assert.equal((await readCredits(db, 'alice')).held_microusd, 50);
  await callAuthority(adapters, 'credit', 'commit', op(3, 'charge1', 20));
  await callAuthority(adapters, 'credit', 'reserve', op(4, 'hold2', 40, 'batch'));
  await callAuthority(adapters, 'credit', 'commit', op(5, 'charge2', 30, 'batch'));
  assert.equal((await readCredits(db, 'alice')).balance_microusd, 50);
  await assert.rejects(registerCreditAuthority(db, { env, tariff: () => null }).reserve(op(6, 'unpriced', 0, 'new')), /credits_unpriced/);
  const disabled = registerCreditAuthority({ prepare() { assert.fail('disabled storage'); } }, { tariff: () => assert.fail('disabled tariff') });
  await assert.rejects(disabled.reserve(op(6, 'disabled', 0, 'new')), /credits_disabled/);
});

test('compensation, releases, overflow and cursor owner isolation', async t => {
  const { db } = database(t);
  const original = await appendCredit(db, entry('credit', 100, 'fund', 0));
  await appendCredit(db, entry('adjust', -20, 'debit', 1, { actor: 'admin', reason: 'reviewed' }));
  await appendCredit(db, entry('compensate', 20, 'correction', 2, { actor: 'admin', reason: 'reviewed', reference: 'debit' }));
  await assert.rejects(appendCredit(db, entry('compensate', 20, 'twice', 3, { actor: 'admin', reason: 'reviewed', reference: 'debit' })), /credits_conflict/);
  await assert.rejects(appendCredit(db, entry('credit', 1000000000000000, 'overflow', 3)), /invalid_credits_request/);
  assert.deepEqual((await readCredits(db, 'alice')).entries[0], original);
  assert.deepEqual((await readCredits(db, 'bob')).entries, []);
  assert.equal((await readCredits(db, 'alice', { limit: 1 })).next_cursor, '1');
  assert.equal((await readCredits(db, 'alice', { limit: 1, cursor: '1' })).entries[0].operation_id, 'debit');
  await appendCredit(db, entry('reserve', 40, 'hold', 3, { scoped_id: 'new', tariff_revision: 1 }));
  await appendCredit(db, entry('release', 40, 'release', 4, { scoped_id: 'new' }));
  assert.equal((await readCredits(db, 'alice')).held_microusd, 0);
});

test('private boundary, disabled traffic and missing schema fail closed', async t => {
  const { call, env, db } = database(t, false);
  assert.equal((await call({ operation: 'append', ...entry('credit', 1, 'fund', 0) })).error.code, 'credits_unavailable');
  assert.equal((await call({ operation: 'read', owner: 'alice' })).status, 503);
  for (const flag of [undefined, '', 'false', 'bad']) {
    const response = await handleCreditsRequest(new Request('http://intelligence.internal/v1/credits', { method: 'POST' }), {
      CREDITS_ENABLED: flag, INTELLIGENCE_DB: { prepare() { assert.fail('disabled storage'); } },
    });
    assert.equal(response.status, 404);
  }
  const foreign = await handleCreditsRequest(new Request('https://example.test/v1/credits', { method: 'POST' }), env);
  assert.equal(foreign.status, 404);
  const { call: healthy } = database(t);
  assert.equal((await healthy({ operation: 'append', ...entry('credit', 1, 'fund', 0), prompt: 'content' })).status, 400);
  assert.equal((await healthy({ operation: 'append', ...entry('reserve', 1, 'hold', 0, { scoped_id: 'attempt' }) })).error.code, 'credits_unpriced');
  for (const currency of ['EUR', false, null]) assert.equal(creditsEnabled({ CREDITS_ENABLED: 'true', CREDITS_CURRENCY: currency }), false);
  assert.equal(creditsEnabled({ CREDITS_ENABLED: 'true', CREDITS_CURRENCY: '' }), true);
  let dispatched = false;
  const operation = new AuthorityOperation({ context: new TenantContext({ principal_id: 'alice' }),
    scoped_id: 'attempt', operation_id: 'hold', revision: 0, amount: 1 });
  try {
    await registerCreditAuthority(db, { env, tariff: () => 1 }).reserve(operation);
    dispatched = true;
  } catch (error) {
    assert.equal(error.status, 503);
    assert.equal((await error.response().json()).error.code, 'credits_unavailable');
  }
  assert.equal(dispatched, false);
});

test('actual spend above estimate closes only its hold', async t => {
  const { db } = database(t);
  await appendCredit(db, entry('credit', 100, 'fund', 0));
  await appendCredit(db, entry('reserve', 30, 'hedge', 1, { scoped_id: 'hedge', tariff_revision: 1 }));
  await appendCredit(db, entry('reserve', 60, 'shadow', 2, { scoped_id: 'shadow', tariff_revision: 1 }));
  await appendCredit(db, entry('commit', 41, 'charge', 3, { scoped_id: 'hedge', tariff_revision: 1 }));
  const summary = await readCredits(db, 'alice');
  assert.deepEqual([summary.balance_microusd, summary.held_microusd, summary.available_microusd], [59, 60, -1]);
  await appendCredit(db, entry('reserve', 0, 'unknown', 4, { scoped_id: 'shadow', unknown: true }));
  assert.equal((await readCredits(db, 'alice')).held_microusd, 60);
  await appendCredit(db, entry('release', 60, 'release', 5, { scoped_id: 'shadow' }));
  await assert.rejects(appendCredit(db, entry('commit', 1, 'late', 6, { scoped_id: 'shadow', tariff_revision: 1 })), /credits_conflict/);
  assert.equal((await readCredits(db, 'alice')).balance_microusd, 59);
});

for (const recovery of ['credit', 'adjust']) test(`commit overrun blocks new spend until ${recovery} funding`, async t => {
  const { db, env, call } = database(t);
  await appendCredit(db, entry('credit', 100, 'fund', 0));
  const authority = registerCreditAuthority(db, { env, tariff: () => 1 });
  const op = (revision, operation_id, amount, scoped_id = 'attempt') => new AuthorityOperation({
    context: new TenantContext({ principal_id: 'alice' }), revision, operation_id, amount, scoped_id });
  await authority.reserve(op(1, 'hold', 60));
  await assert.rejects(authority.commit(op(1, 'charge', 150)), error => error.code === 'credits_revision_mismatch' && error.status === 412);
  const charged = await authority.commit(op(2, 'charge', 150));
  assert.deepEqual(await authority.commit(op(2, 'charge', 150)), charged);
  const { status, summary } = await call({ operation: 'read', owner: 'alice' });
  assert.equal(status, 200);
  assert.deepEqual([summary.balance_microusd, summary.held_microusd, summary.available_microusd], [-50, 0, -50]);
  assert.equal(summary.revision, 3);
  for (const amount of [0, 1]) await assert.rejects(authority.reserve(op(3, `denied${amount}`, amount, `new${amount}`)), /credits_insufficient/);
  await assert.rejects(appendCredit(db, entry('adjust', -1, 'debit', 3, { actor: 'admin', reason: 'reviewed' })), /credits_insufficient/);
  await assert.rejects(authority.commit(op(3, 'late', 1)), /credits_conflict/);
  await assert.rejects(authority.commit(op(2, 'charge', 151)), /credits_conflict/);
  const extra = recovery === 'adjust' ? { actor: 'admin', reason: 'reviewed' } : {};
  await appendCredit(db, entry(recovery, 25, 'partial', 3, extra));
  assert.equal((await readCredits(db, 'alice')).available_microusd, -25);
  await appendCredit(db, entry(recovery, 25, 'zero', 4, extra));
  await assert.rejects(authority.reserve(op(5, 'zero-denied', 0, 'zero-attempt')), /credits_insufficient/);
  await appendCredit(db, entry(recovery, 50, 'recovered', 5, extra));
  assert.equal((await readCredits(db, 'alice')).available_microusd, 50);
  await authority.reserve(op(6, 'next', 1, 'next'));
  assert.equal((await readCredits(db, 'alice')).available_microusd, 49);
});

test('migration rehearsal, incomplete columns, audit and bounded pagination', async t => {
  const { db, sql } = database(t);
  sql.exec('CREATE TABLE old_usage (cost INTEGER); INSERT INTO old_usage VALUES (NULL)');
  sql.exec(migration);
  assert.equal(sql.prepare('SELECT cost FROM old_usage').get().cost, null);
  for (let revision = 0; revision < 102; revision++) {
    await appendCredit(db, entry('adjust', 1, `grant${revision}`, revision, { actor: 'admin', reason: 'Reviewed allocation' }));
  }
  const first = await readCredits(db, 'alice');
  assert.equal(first.entries.length, 100);
  assert.equal(first.next_cursor, '100');
  assert.equal((await readCredits(db, 'alice', { cursor: '100' })).entries.length, 2);
  assert.equal(sql.prepare('SELECT count(*) AS n FROM credits_audit').get().n, 102);
  assert.deepEqual(sql.prepare('PRAGMA table_info(credits_audit)').all().map(row => row.name), ['owner', 'operation_id', 'revision', 'actor', 'kind']);
  for (const options of [{ limit: 101 }, { limit: true }, { cursor: '-1' }, { cursor: '1.5' }]) await assert.rejects(readCredits(db, 'alice', options), /invalid_credits_request/);
  const { db: broken, sql: partial } = database(t, false);
  partial.exec(`CREATE TABLE credits_balances (owner TEXT PRIMARY KEY,balance_microusd INTEGER,held_microusd INTEGER,revision INTEGER);
    CREATE TABLE credits_entries (owner TEXT); CREATE TABLE credits_audit (owner TEXT)`);
  await assert.rejects(readCredits(broken, 'alice'), /credits_unavailable/);
  await assert.rejects(appendCredit(broken, entry('credit', 1, 'fund', 0)), /credits_unavailable/);
  assert.equal(partial.prepare('SELECT count(*) AS n FROM credits_balances').get().n, 0);
  const org = new TenantContext({ principal_id: 'alice', org_id: 'org', team_id: 'team' });
  assert.equal(contextOwner(org), 'tenant:["org","team","alice"]');
  assert.notEqual(contextOwner(org), contextOwner(new TenantContext({ principal_id: 'alice', org_id: 'other', team_id: 'team' })));
});

test('Python and D1 return identical ledger vectors', async t => {
  const { db } = database(t);
  for (const vector of vectors.filter(vector => vector.request && !vector.error)) await appendCredit(db, vector.request);
  const code = `import os,sys,json,tempfile\nfrom pathlib import Path\nsys.path.insert(0,os.getcwd())\nfrom services.credits_ledger import SqlCreditsLedger\ntext=Path('docs/credits-ledger.md').read_text()\nvectors=json.loads(text.split('\x60\x60\x60json\\n',1)[1].split('\x60\x60\x60',1)[0])\nwith tempfile.TemporaryDirectory() as d:\n store=SqlCreditsLedger(Path(d)/'credits.sqlite3',initialize=True)\n for v in vectors:\n  if 'request' in v and not v.get('error'): store.append(**v['request'])\n print(json.dumps(store.read('alice')))\n`;
  const python = spawnSync('/home/mysterious/storage/github/MultiLLM-Proxy/.venv/bin/python', ['-I', '-c', code], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8', timeout: 10000,
  });
  assert.equal(python.status, 0, python.stderr);
  assert.deepEqual(await readCredits(db, 'alice'), JSON.parse(python.stdout));
});
