/**
 * Dashboard audit trail on the private users handler. The Worker already appends every
 * account write to control_user_audit; control_audit_events adds sign-ins, sign-outs,
 * refused single sign-on and administrator setting changes. audit_list reads both, newest
 * first, one bounded page at a time. Fixed statements only: no operation updates or
 * deletes an audit row, and no SQL crosses the private boundary.
 */
import { logFailure } from "./log.mjs";

export const AUDIT_OPERATIONS = new Set(["audit_list", "audit_record"]);
export const EVENT_ACTIONS = new Set(["sign_in", "sign_out", "setting_change"]);
export const ACCOUNT_ACTIONS = new Set(["upsert", "delete"]);
const OUTCOMES = new Set(["succeeded", "refused"]);
const MAX_AUDIT_PAGE = 100;
const CONTROL = /[\x00-\x1f\x7f]/;
const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !CONTROL.test(value);
const optionalText = (value, maximum) => value === null || text(value, maximum);
const cursor = value => value === null || (Number.isSafeInteger(value) && value >= 0);
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));

async function read(query) {
  try { return await query(); }
  catch (error) {
    logFailure("audit_storage_retry", error);
    return query();
  }
}

async function recordEvent(db, body) {
  if (!fields(body, ["version", "operation", "action", "outcome", "actor", "target", "detail"])
    || !EVENT_ACTIONS.has(body.action) || !OUTCOMES.has(body.outcome) || !optionalText(body.actor, 256)
    || !optionalText(body.target, 256) || !optionalText(body.detail, 512)) return null;
  // The Worker's clock stamps the row, as it does for account writes.
  await db.prepare("INSERT INTO control_audit_events (at, actor, action, outcome, target, detail) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(new Date().toISOString(), body.actor, body.action, body.outcome, body.target, body.detail).run();
  return { version: 1, recorded: true };
}

// One statement per table from fixed fragments; only bound values vary.
function accountStatement(db, { before, target, action }, limit) {
  const clauses = [], values = [];
  if (before !== null) { clauses.push("id < ?"); values.push(before); }
  if (target !== null) { clauses.push("username = ?"); values.push(target); }
  if (action !== null) { clauses.push("operation = ?"); values.push(action); }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  return db.prepare(`SELECT id, at, operation AS action, outcome, username AS target, is_admin, scopes, api_key_prefix,
    revoked_at FROM control_user_audit ${where} ORDER BY id DESC LIMIT ?`).bind(...values, limit);
}

function eventStatement(db, { before, actor, target, action }, limit) {
  const clauses = [], values = [];
  if (before !== null) { clauses.push("id < ?"); values.push(before); }
  if (actor !== null) { clauses.push("actor = ?"); values.push(actor); }
  if (target !== null) { clauses.push("target = ?"); values.push(target); }
  if (action !== null) { clauses.push("action = ?"); values.push(action); }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  return db.prepare(`SELECT id, at, actor, action, outcome, target, detail FROM control_audit_events ${where}
    ORDER BY id DESC LIMIT ?`).bind(...values, limit);
}

const newestFirst = (left, right) => (left.at < right.at ? 1 : left.at > right.at ? -1
  : left.source < right.source ? 1 : left.source > right.source ? -1 : right.id - left.id);

/**
 * One page of both audit tables merged by time. Each table has its own id cursor: null
 * means "from the newest row", 0 means "nothing further". Account rows have no actor, so
 * an actor filter reads only events.
 */
async function listEntries(db, body) {
  if (!fields(body, ["version", "operation", "actor", "target", "action", "before_account", "before_event", "limit"])
    || !optionalText(body.actor, 256) || !optionalText(body.target, 256)
    || !(body.action === null || ACCOUNT_ACTIONS.has(body.action) || EVENT_ACTIONS.has(body.action))
    || !cursor(body.before_account) || !cursor(body.before_event)
    || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > MAX_AUDIT_PAGE) return null;
  const { actor, target, action, limit } = body;
  const readAccounts = actor === null && (action === null || ACCOUNT_ACTIONS.has(action)) && body.before_account !== 0;
  const readEvents = (action === null || EVENT_ACTIONS.has(action)) && body.before_event !== 0;
  const [accounts, events] = await Promise.all([
    readAccounts ? read(() => accountStatement(db, { before: body.before_account, target, action }, limit + 1).all()) : { results: [] },
    readEvents ? read(() => eventStatement(db, { before: body.before_event, actor, target, action }, limit + 1).all()) : { results: [] },
  ]);
  const rows = [
    ...accounts.results.map(row => ({ source: "account", id: row.id, at: row.at, actor: null, action: row.action,
      outcome: row.outcome, target: row.target, detail: null, is_admin: row.is_admin ?? null, scopes: row.scopes ?? null,
      api_key_prefix: row.api_key_prefix ?? null, revoked_at: row.revoked_at ?? null })),
    ...events.results.map(row => ({ source: "event", id: row.id, at: row.at, actor: row.actor ?? null, action: row.action,
      outcome: row.outcome, target: row.target ?? null, detail: row.detail ?? null, is_admin: null, scopes: null,
      api_key_prefix: null, revoked_at: null })),
  ].sort(newestFirst);
  const entries = rows.slice(0, limit);
  const nextCursor = (source, wanted, fetched, current) => {
    const shown = entries.filter(row => row.source === source).map(row => row.id);
    if (shown.length) return Math.min(...shown);
    return wanted && fetched ? current : 0;
  };
  const next = rows.length > limit ? {
    account: nextCursor("account", readAccounts, accounts.results.length, body.before_account),
    event: nextCursor("event", readEvents, events.results.length, body.before_event),
  } : null;
  return { version: 1, entries, next };
}

/** Handle an audit operation; null means the request was invalid. */
export function handleAuditOperation(db, body) {
  return body.operation === "audit_record" ? recordEvent(db, body) : listEntries(db, body);
}
