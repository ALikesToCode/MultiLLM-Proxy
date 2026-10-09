/** Private append-only integer credits with atomic D1 balance revisions. */
import { AuthorityDenied, AuthorityOperation, AuthorityResult, TenantContext } from './enterprise-contract.mjs';

export const MAX_AMOUNT = 1_000_000_000_000_000;
const warned = new Set();
const entryKeys = ['operation_id', 'revision', 'kind', 'amount_microusd', 'balance_delta',
  'held_delta', 'scoped_id', 'reference', 'tariff_revision'];

export class CreditsError extends Error {
  constructor(code = 'credits_unavailable', status = 503) {
    super(code); this.code = code; this.status = status;
  }
}

export class CreditDenied extends AuthorityDenied {
  constructor(code, status = 503) { super(code); this.code = code; this.status = status; }
  response() {
    return Response.json({ error: { code: this.code, message: 'Credits operation unavailable.' } }, {
      status: this.status, headers: { 'Cache-Control': 'no-store' },
    });
  }
}

export function creditsEnabled(env = {}, warn = message => console.warn(message)) {
  const raw = env.CREDITS_ENABLED;
  const flag = raw === undefined ? '' : typeof raw === 'string' ? raw.trim().toLowerCase() : 'invalid';
  const invalid = name => {
    if (!warned.has(name)) { warned.add(name); warn(`Invalid ${name}; credits disabled`); }
    return false;
  };
  if (['', '0', 'false', 'no', 'off'].includes(flag)) return false;
  if (!['1', 'true', 'yes', 'on'].includes(flag)) return invalid('CREDITS_ENABLED');
  if ((env.CREDITS_CURRENCY === undefined || env.CREDITS_CURRENCY === '' ? 'USD' : env.CREDITS_CURRENCY) !== 'USD') {
    return invalid('CREDITS_CURRENCY');
  }
  return true;
}

function integer(value, nonnegative = false) {
  if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_AMOUNT || nonnegative && value < 0) {
    throw new CreditsError('invalid_credits_request', 400);
  }
  return value;
}
function label(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_:.\-]{1,128}$/.test(value) || /\n|\r/.test(value)) {
    throw new CreditsError('invalid_credits_request', 400);
  }
  return value;
}
function ownerId(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 512 || /[\x00-\x1f\x7f]/.test(value)) {
    throw new CreditsError('invalid_credits_request', 400);
  }
  return value;
}
function reasonText(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 512 || /[^\x20-\x7e]/.test(value)) {
    throw new CreditsError('invalid_credits_request', 400);
  }
  return value;
}
export function contextOwner(context) {
  if (!(context instanceof TenantContext)) throw new CreditsError('invalid_credits_request', 400);
  return context.org_id === null ? ownerId(context.principal_id)
    : `tenant:${JSON.stringify([context.org_id, context.team_id, context.principal_id])}`;
}
function requestFields(data) {
  const { owner, kind, amount_microusd, operation_id, revision, scoped_id = null, reference = null,
    tariff_revision = null, actor = null, reason = null, unknown = false } = data;
  ownerId(owner); label(operation_id); integer(amount_microusd); integer(revision, true);
  if (!['credit', 'reserve', 'commit', 'release', 'adjust', 'compensate'].includes(kind) || typeof unknown !== 'boolean') {
    throw new CreditsError('invalid_credits_request', 400);
  }
  for (const value of [scoped_id, reference, actor]) if (value !== null) label(value);
  if (['reserve', 'commit', 'release'].includes(kind)) { label(scoped_id); integer(amount_microusd, true); }
  if (['reserve', 'commit'].includes(kind) && !unknown) {
    if (tariff_revision === null) throw new CreditsError('credits_unpriced');
    integer(tariff_revision, true);
  } else if (tariff_revision !== null) integer(tariff_revision, true);
  if (kind === 'credit') integer(amount_microusd, true);
  if (['adjust', 'compensate'].includes(kind)) { label(actor); reasonText(reason); }
  else if (reason !== null) reasonText(reason);
  if (kind === 'compensate') label(reference);
  else if (reference !== null) throw new CreditsError('invalid_credits_request', 400);
  if (unknown && (kind !== 'reserve' || amount_microusd !== 0)) throw new CreditsError('invalid_credits_request', 400);
  return { owner, kind, amount_microusd, operation_id, revision, scoped_id, reference, tariff_revision, actor, reason, unknown };
}
const documentFor = fields => JSON.stringify(Object.fromEntries(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b))));
const publicEntry = row => Object.fromEntries(entryKeys.map(key => [key, row[key]]));

function deltas(fields, entries) {
  const { kind, amount_microusd: amount } = fields;
  let bd = 0, hd = 0;
  if (['credit', 'adjust'].includes(kind)) bd = amount;
  else if (kind === 'compensate') {
    const original = entries.find(row => row.operation_id === fields.reference);
    if (!original || !['credit', 'adjust', 'commit'].includes(original.kind) || amount !== -original.balance_delta ||
        entries.some(row => row.kind === 'compensate' && row.reference === fields.reference)) throw new CreditsError('credits_conflict', 409);
    bd = amount;
  } else {
    const attempt = entries.filter(row => row.scoped_id === fields.scoped_id);
    const hold = attempt.find(row => row.kind === 'reserve' && row.reference === null);
    if (kind === 'reserve' && !fields.unknown) {
      if (hold) throw new CreditsError('credits_conflict', 409);
      hd = amount;
    } else {
      if (!hold || attempt.some(row => ['commit', 'release'].includes(row.kind))) throw new CreditsError('credits_conflict', 409);
      fields.reference = hold.operation_id;
      if (kind === 'commit') { bd = -amount; hd = -hold.amount_microusd; }
      else if (kind === 'release') {
        if (amount !== hold.amount_microusd) throw new CreditsError('invalid_credits_request', 400);
        hd = -amount;
      }
    }
  }
  return [bd, hd];
}

async function schema(db) {
  if (!db || typeof db.prepare !== 'function' || typeof db.batch !== 'function') throw new CreditsError();
  // Probe all required columns before any owner initialization or write.
  await db.batch([
    db.prepare('SELECT owner,balance_microusd,held_microusd,revision FROM credits_balances LIMIT 0'),
    db.prepare('SELECT owner,operation_id,revision,kind,amount_microusd,balance_delta,held_delta,scoped_id,reference,tariff_revision,actor,reason,document FROM credits_entries LIMIT 0'),
    db.prepare('SELECT owner,operation_id,revision,actor,kind FROM credits_audit LIMIT 0'),
  ]);
}

export async function appendCredit(db, data) {
  const fields = requestFields(data);
  const document = documentFor(fields);
  try {
    await schema(db);
    const find = () => db.prepare('SELECT * FROM credits_entries WHERE owner=? AND operation_id=?')
      .bind(fields.owner, fields.operation_id).first();
    const replay = row => {
      if (row.document !== document) throw new CreditsError('credits_conflict', 409);
      return publicEntry(row);
    };
    const existing = await find();
    if (existing) return replay(existing);
    const row = await db.prepare('SELECT * FROM credits_balances WHERE owner=?').bind(fields.owner).first();
    const balance = row?.balance_microusd ?? 0, held = row?.held_microusd ?? 0, revision = row?.revision ?? 0;
    if (revision !== fields.revision) {
      const duplicate = await find();
      if (duplicate) return replay(duplicate);
      throw new CreditsError('credits_revision_mismatch', 412);
    }
    const entries = (await db.prepare('SELECT * FROM credits_entries WHERE owner=? AND (scoped_id=? OR operation_id=? OR reference=?)')
      .bind(fields.owner, fields.scoped_id, fields.reference, fields.reference).all()).results;
    const [bd, hd] = deltas(fields, entries);
    integer(balance + bd); integer(held + hd, true); integer(revision + 1, true);
    const available = balance + bd - held - hd;
    const reservation = fields.kind === 'reserve' && !fields.unknown;
    const enforcedSpend = reservation || (fields.kind === 'adjust' && fields.amount_microusd < 0);
    if (enforcedSpend && (available < 0 || (reservation && balance - held <= 0))) {
      throw new CreditsError('credits_insufficient', 409);
    }
    const { owner, operation_id, kind, amount_microusd, scoped_id, reference, tariff_revision, actor, reason } = fields;
    try {
      await db.batch([
        db.prepare('INSERT OR IGNORE INTO credits_balances(owner) VALUES (?)').bind(owner),
        db.prepare(`INSERT INTO credits_entries
          (owner,operation_id,revision,kind,amount_microusd,balance_delta,held_delta,scoped_id,reference,tariff_revision,actor,reason,document)
          SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? FROM credits_balances WHERE owner=? AND revision=?`)
          .bind(owner, operation_id, revision + 1, kind, amount_microusd, bd, hd, scoped_id, reference,
            tariff_revision, actor, reason, document, owner, revision),
        db.prepare(`UPDATE credits_balances SET balance_microusd=?,held_microusd=?,revision=revision+1
          WHERE owner=? AND revision=? AND EXISTS
          (SELECT 1 FROM credits_entries WHERE owner=? AND operation_id=? AND revision=? AND document=?)`)
          .bind(balance + bd, held + hd, owner, revision, owner, operation_id, revision + 1, document),
        db.prepare(`INSERT OR IGNORE INTO credits_audit SELECT owner,operation_id,revision,actor,kind
          FROM credits_entries WHERE owner=? AND operation_id=? AND actor IS NOT NULL`)
          .bind(owner, operation_id),
      ]);
    } catch (error) {
      const duplicate = await find();
      if (duplicate) return replay(duplicate);
      throw error;
    }
    const saved = await find();
    if (!saved) throw new CreditsError('credits_revision_mismatch', 412);
    return replay(saved);
  } catch (error) { throw error instanceof CreditsError ? error : new CreditsError(); }
}

export async function readCredits(db, owner, { cursor = '0', limit = 100 } = {}) {
  ownerId(owner);
  if (typeof cursor !== 'string' || !/^[0-9]{1,16}$/.test(cursor) || /\n|\r/.test(cursor) ||
      Number(cursor) > MAX_AMOUNT || !Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new CreditsError('invalid_credits_request', 400);
  }
  try {
    await schema(db);
    const results = await db.batch([
      db.prepare('SELECT * FROM credits_balances WHERE owner=?').bind(owner),
      db.prepare('SELECT * FROM credits_entries WHERE owner=? AND revision>? ORDER BY revision LIMIT ?').bind(owner, Number(cursor), limit + 1),
    ]);
    const row = results[0].results[0], rows = results[1].results, page = rows.slice(0, limit);
    const balance = row?.balance_microusd ?? 0, held = row?.held_microusd ?? 0;
    return { currency: 'USD', balance_microusd: balance, held_microusd: held, available_microusd: balance - held,
      revision: row?.revision ?? 0, entries: page.map(publicEntry), next_cursor: rows.length > limit ? String(page.at(-1).revision) : null };
  } catch (error) { throw error instanceof CreditsError ? error : new CreditsError(); }
}

const reply = (body, status = 200) => Response.json({ version: 1, ...body }, {
  status, headers: { 'Cache-Control': 'no-store' },
});

async function boundedBody(request) {
  const reader = request.body?.getReader();
  if (!reader) throw new CreditsError('invalid_credits_request', 400);
  const parts = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16384) throw new CreditsError('invalid_credits_request', 400);
      parts.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) { throw error instanceof CreditsError ? error : new CreditsError('invalid_credits_request', 400); }
  finally { void reader.cancel().catch(() => {}); }
}

export async function handleCreditsRequest(request, env) {
  const url = new URL(request.url);
  if (url.origin !== 'http://intelligence.internal' || url.username || url.password || url.search || url.hash ||
      !['/v1/credits', '/v1/managed-state/credits'].includes(url.pathname) || !creditsEnabled(env)) {
    return reply({ error: { code: 'not_found', message: 'Credits operation unavailable.' } }, 404);
  }
  try {
    if (request.method !== 'POST') return reply({ error: { code: 'method_not_allowed' } }, 405);
    const body = await boundedBody(request);
    if (!body || typeof body !== 'object' || Array.isArray(body) || body.version !== 1 || !['append', 'read'].includes(body.operation)) {
      throw new CreditsError('invalid_credits_request', 400);
    }
    const required = body.operation === 'append' ? ['owner', 'kind', 'amount_microusd', 'operation_id', 'revision'] : ['owner'];
    const optional = body.operation === 'append' ? ['scoped_id', 'reference', 'tariff_revision', 'actor', 'reason', 'unknown'] : ['cursor', 'limit'];
    if (required.some(key => !(key in body)) || Object.keys(body).some(key => !['version', 'operation', ...required, ...optional].includes(key))) {
      throw new CreditsError('invalid_credits_request', 400);
    }
    const db = env.INTELLIGENCE_DB;
    return body.operation === 'append' ? reply({ entry: await appendCredit(db, body) })
      : reply({ summary: await readCredits(db, body.owner, body) });
  } catch (error) {
    const failure = error instanceof CreditsError ? error : new CreditsError();
    return reply({ error: { code: failure.code, message: 'Credits operation unavailable.' } }, failure.status);
  }
}

export function registerCreditAuthority(db, { tariff, env = {} }) {
  if (typeof tariff !== 'function') throw new TypeError('Explicit operator tariff required');
  const apply = async (operation, phase) => {
    if (!(operation instanceof AuthorityOperation)) throw new TypeError('AuthorityOperation required');
    if (!creditsEnabled(env)) throw new CreditDenied('credits_disabled', 404);
    try {
      const tariff_revision = await tariff(operation, phase);
      const unknown = phase === 'reconcile' && tariff_revision === null;
      if (tariff_revision === null && !unknown) throw new CreditDenied('credits_unpriced');
      const row = await appendCredit(db, { owner: contextOwner(operation.context), kind: phase === 'reserve' || unknown ? 'reserve' : 'commit',
        amount_microusd: unknown ? 0 : operation.amount, operation_id: operation.operation_id, revision: operation.revision,
        scoped_id: operation.scoped_id, tariff_revision, unknown });
      return new AuthorityResult({ context: operation.context, scoped_id: operation.scoped_id,
        operation_id: operation.operation_id, revision: row.revision, allowed: true });
    } catch (error) { throw error instanceof CreditsError ? new CreditDenied(error.code, error.status) : error; }
  };
  return Object.freeze({ reserve: op => apply(op, 'reserve'), commit: op => apply(op, 'commit'), reconcile: op => apply(op, 'reconcile') });
}
