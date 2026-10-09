import { recordSettledUsage } from "./usage-receipts.mjs";
import { retentionRequestId } from "./retention-policy.mjs";
/** Private, atomic monetary holds and injected request lifecycle. */
const SCALE = 10_000_000_000;
const MAX_UNITS = Number.MAX_SAFE_INTEGER;
const DEFAULT_REVIEW = 259200;
const ACTIVE = new Set(["reserved", "dispatched", "unknown"]);
const ID = /^[a-f0-9]{32}$/;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const warned = new Set();
const FIELDS = {
  reserve: ["id", "principal", "estimate_usd", "daily_budget_usd", "monthly_budget_usd", "day_spent_usd", "month_spent_usd"],
  transition: ["id", "revision", "state", "transition_id", "settlement_id", "cost_usd", "basis", "input_tokens", "output_tokens",
    "admin", "evidence", "authorized_adjustment", "reason", "handoff_not_started"],
  get: ["id"], audit: ["id"], summary: ["principal"],
};
export class ReservationError extends Error {
  constructor(code = "usage_reservations_unavailable", status = 503) { super(code); this.code = code; this.status = status; }
  response() { return reply({ error: { code: this.code, message: "The usage reservation operation could not be completed." } }, this.status); }
}
function fail(code = "invalid_reservation_request", status = 400) { throw new ReservationError(code, status); }
function warn(name) {
  if (!warned.has(name)) { warned.add(name); console.warn(`Invalid ${name}; usage reservations disabled`); }
}
export function reservationSettings(env) {
  const flag = String(env.USAGE_RESERVATIONS_ENABLED ?? "").trim().toLowerCase();
  if (["", "false", "0", "off", "no"].includes(flag)) return { enabled: false, review: DEFAULT_REVIEW };
  if (!["true", "1", "on", "yes"].includes(flag)) { warn("USAGE_RESERVATIONS_ENABLED"); return { enabled: false }; }
  const raw = String(env.USAGE_HOLD_REVIEW_AFTER_SECONDS ?? "").trim();
  const review = raw ? Number(raw) : DEFAULT_REVIEW;
  if ((raw && !/^\d+$/.test(raw)) || !Number.isSafeInteger(review) || review < 1 || review > 2 ** 31 - 1) {
    warn("USAGE_HOLD_REVIEW_AFTER_SECONDS"); return { enabled: false };
  }
  return { enabled: true, review };
}
function identifier(value) { if (typeof value !== "string" || value.length !== 32 || !ID.test(value)) fail(); return value; }
function principal(value) {
  if (typeof value !== "string" || ![...value].length || [...value].length > 256 || /[\x00-\x1f\x7f]/.test(value)) fail();
  return value;
}
function integer(value) { return Number.isSafeInteger(value) && value >= 0; }
export function reservationUnits(value, { limit = false } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > MAX_UNITS / SCALE) fail();
  // Parse the decimal representation, including exponents, without binary rounding.
  const [mantissa, exponent = "0"] = String(value).toLowerCase().split("e");
  const [whole, fraction = ""] = mantissa.split(".");
  const digits = BigInt(whole + fraction);
  const power = 10 + Number(exponent) - fraction.length;
  let result;
  if (power >= 0) result = digits * 10n ** BigInt(power);
  else {
    const divisor = 10n ** BigInt(-power);
    result = limit ? digits / divisor : (digits + divisor - 1n) / divisor;
  }
  if (result > BigInt(MAX_UNITS)) fail();
  return Number(result);
}
function document(value) { return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)))); }
function periods(at) {
  const day = new Date(at).toISOString().slice(0, 10);
  return { at, day, month: day.slice(0, 7) };
}
function publicRow(row) {
  if (!row) fail("reservation_not_found", 404);
  const { amount_units, charged_units, ...value } = row;
  return { ...value, estimate_usd: amount_units / SCALE, cost_usd: charged_units === null ? null : charged_units / SCALE };
}
async function batch(db, statements) {
  const results = await db.batch(statements);
  if (results.some(r => !r.success)) throw new ReservationError();
  return results;
}
const TOTALS = `SELECT
 COALESCE(SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN amount_units ELSE 0 END),0) AS held_units,
 COALESCE(SUM(CASE WHEN state IN ('settled','reconciled') AND day = ? THEN charged_units ELSE 0 END),0) AS day_units,
 COALESCE(SUM(CASE WHEN state IN ('settled','reconciled') AND month = ? THEN charged_units ELSE 0 END),0) AS month_units,
 COUNT(CASE WHEN state = 'reserved' THEN 1 END) AS reserved,
 COUNT(CASE WHEN state = 'dispatched' THEN 1 END) AS dispatched,
 COUNT(CASE WHEN state = 'unknown' THEN 1 END) AS unknown,
 COUNT(CASE WHEN state IN ('reserved','dispatched','unknown') AND created_at <= ? THEN 1 END) AS needs_review
 FROM usage_reservations WHERE principal = ?`;
export async function reservationSummary(db, identity, now, review = DEFAULT_REVIEW) {
  principal(identity);
  const { at, day, month } = periods(now);
  const results = await batch(db, [db.prepare(TOTALS).bind(day, month, at - review * 1000, identity),
    db.prepare("SELECT period, baseline_units FROM usage_reservation_budgets WHERE principal = ? AND period IN (?, ?)").bind(identity, day, month)]);
  const totals = results[0].results[0];
  const bases = new Map(results[1].results.map(row => [row.period, row.baseline_units]));
  const { held_units, day_units, month_units, ...counts } = totals;
  return { ...counts, day_seeded: bases.has(day), month_seeded: bases.has(month), held_usd: held_units / SCALE,
    spent_today_usd: (day_units + (bases.get(day) ?? 0)) / SCALE,
    spent_this_month_usd: (month_units + (bases.get(month) ?? 0)) / SCALE };
}
const RESERVE = `INSERT INTO usage_reservations
 (id,principal,day,month,amount_units,state,created_at,updated_at,transition_id)
 SELECT ?1,?2,?3,?4,?5,'reserved',?6,?6,?1
 WHERE NOT EXISTS (SELECT 1 FROM usage_reservation_transitions WHERE transition_id=?1)
 AND (?7 IS NULL OR
   (COALESCE((SELECT baseline_units FROM usage_reservation_budgets WHERE principal=?2 AND period=?3),0)
   + COALESCE((SELECT SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN amount_units
       WHEN day=?3 THEN charged_units ELSE 0 END) FROM usage_reservations WHERE principal=?2),0)) < ?7
   AND (COALESCE((SELECT baseline_units FROM usage_reservation_budgets WHERE principal=?2 AND period=?3),0)
   + COALESCE((SELECT SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN amount_units
       WHEN day=?3 THEN charged_units ELSE 0 END) FROM usage_reservations WHERE principal=?2),0)) <= ?7-?5)
 AND (?8 IS NULL OR
   (COALESCE((SELECT baseline_units FROM usage_reservation_budgets WHERE principal=?2 AND period=?4),0)
   + COALESCE((SELECT SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN amount_units
       WHEN month=?4 THEN charged_units ELSE 0 END) FROM usage_reservations WHERE principal=?2),0)) < ?8
   AND (COALESCE((SELECT baseline_units FROM usage_reservation_budgets WHERE principal=?2 AND period=?4),0)
   + COALESCE((SELECT SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN amount_units
       WHEN month=?4 THEN charged_units ELSE 0 END) FROM usage_reservations WHERE principal=?2),0)) <= ?8-?5)
 ON CONFLICT(id) DO NOTHING`;
export async function reserveUsage(db, body, now) {
  identifier(body.id); principal(body.principal);
  if (body.daily_budget_usd == null && body.monthly_budget_usd == null) fail();
  if (body.estimate_usd == null) fail("unpriced_reservation", 503);
  const amount = reservationUnits(body.estimate_usd);
  const daily = body.daily_budget_usd == null ? null : reservationUnits(body.daily_budget_usd, { limit: true });
  const monthly = body.monthly_budget_usd == null ? null : reservationUnits(body.monthly_budget_usd, { limit: true });
  const dayBase = reservationUnits(body.day_spent_usd), monthBase = reservationUnits(body.month_spent_usd);
  const { at, day, month } = periods(now);
  const doc = document({ id: body.id, principal: body.principal, amount_units: amount, day, month });
  const results = await batch(db, [
    db.prepare("INSERT OR IGNORE INTO usage_reservation_budgets VALUES (?, ?, ?)").bind(body.principal, day, dayBase),
    db.prepare("INSERT OR IGNORE INTO usage_reservation_budgets VALUES (?, ?, ?)").bind(body.principal, month, monthBase),
    db.prepare(RESERVE).bind(body.id, body.principal, day, month, amount, at, daily, monthly),
    db.prepare(`INSERT OR IGNORE INTO usage_reservation_transitions
      (transition_id,reservation_id,state,at,document) SELECT id,id,'reserved',created_at,?
      FROM usage_reservations WHERE id=? AND revision=0`).bind(doc, body.id),
    db.prepare("SELECT * FROM usage_reservations WHERE id=?").bind(body.id),
    db.prepare("SELECT document FROM usage_reservation_transitions WHERE transition_id=?").bind(body.id),
  ]);
  const row = results[4].results[0];
  if (!row) fail(results[5].results.length ? "reservation_conflict" : "budget_exceeded", results[5].results.length ? 409 : 429);
  if (row.state !== "reserved" || results[5].results[0]?.document !== doc) fail("reservation_conflict", 409);
  return publicRow(row);
}
function transitionFields(body) {
  const state = body.state;
  if (!["dispatched", "unknown", "settled", "reconciled"].includes(state) || !integer(body.revision)) fail();
  identifier(body.id); identifier(body.transition_id);
  const { cost_usd = null, basis = null, input_tokens = null, output_tokens = null, settlement_id = null,
    evidence = null, reason = null } = body;
  for (const count of [input_tokens, output_tokens]) if (count !== null && !integer(count)) fail();
  const charged_units = cost_usd === null ? null : reservationUnits(cost_usd);
  if (["settled", "reconciled"].includes(state)) {
    identifier(settlement_id);
    if (charged_units === null || !["provider", "released", "adjustment"].includes(basis)) fail();
  } else if ([cost_usd, basis, settlement_id, evidence, reason].some(value => value !== null)) fail();
  if (state === "settled" && (basis === "adjustment" || (basis === "released" && charged_units !== 0))) fail();
  if (state === "reconciled") {
    if (body.admin !== true) fail("admin_required", 403);
    if (typeof reason !== "string" || /[\r\n]/.test(reason) || !LABEL.test(reason)) fail("reconciliation_evidence_required");
    if (basis === "provider") {
      if (typeof evidence !== "string" || /[\r\n]/.test(evidence) || !LABEL.test(evidence)) fail("reconciliation_evidence_required");
    } else if (basis !== "adjustment" || body.authorized_adjustment !== true || evidence !== null) fail("reconciliation_evidence_required");
  } else if (evidence !== null || reason !== null || body.admin || body.authorized_adjustment) fail();
  return { charged_units, basis, input_tokens, output_tokens, settlement_id, evidence, reason };
}
export async function transitionUsage(db, body, now) {
  const fields = transitionFields(body);
  if (body.handoff_not_started !== undefined && (body.handoff_not_started !== true || body.state !== "settled" || fields.basis !== "released")) fail();
  const doc = document({ id: body.id, revision: body.revision, state: body.state, ...fields, ...(body.handoff_not_started ? { handoff_not_started: true } : {}) });
  const row = await db.prepare("SELECT * FROM usage_reservations WHERE id=?").bind(body.id).first();
  if (!row) fail("reservation_not_found", 404);
  const previous = await db.prepare("SELECT document FROM usage_reservation_transitions WHERE transition_id=?").bind(body.transition_id).first();
  if (previous) {
    if (previous.document !== doc) fail("reservation_conflict", 409);
    return { applied: false, reservation: publicRow(row) };
  }
  const legal = (row.state === "reserved" && body.state === "dispatched")
    || (row.state === "reserved" && body.state === "settled" && fields.basis === "released")
    || (row.state === "dispatched" && ["unknown", "settled"].includes(body.state) && (fields.basis !== "released" || body.handoff_not_started === true))
    || (row.state === "unknown" && body.state === "reconciled");
  if (row.revision !== body.revision || !legal) fail("reservation_conflict", 409);
  const { charged_units, basis, input_tokens, output_tokens, settlement_id, evidence, reason } = fields;
  const results = await batch(db, [db.prepare(`UPDATE usage_reservations SET state=?1, revision=revision+1,
    charged_units=?2,basis=?3,input_tokens=COALESCE(?4,input_tokens),output_tokens=COALESCE(?5,output_tokens),
    updated_at=?6,handoff_at=CASE WHEN ?1='dispatched' THEN ?6 ELSE handoff_at END,transition_id=?7,settlement_id=?8
    WHERE id=?9 AND revision=?10 AND state=?11
      AND NOT EXISTS (SELECT 1 FROM usage_reservation_transitions WHERE transition_id=?7) AND NOT EXISTS
      (SELECT 1 FROM usage_reservations WHERE settlement_id=?8 AND id!=?9)`)
    .bind(body.state, charged_units, basis, input_tokens, output_tokens, now, body.transition_id, settlement_id, body.id, body.revision, row.state),
    db.prepare(`INSERT OR IGNORE INTO usage_reservation_transitions
      (transition_id,reservation_id,previous_state,state,at,basis,evidence,reason,document)
      SELECT ?1,id,?2,state,updated_at,basis,?3,?4,?5 FROM usage_reservations WHERE id=?6 AND transition_id=?1`)
      .bind(body.transition_id, row.state, evidence, reason, doc, body.id),
    db.prepare("SELECT * FROM usage_reservations WHERE id=?").bind(body.id),
    db.prepare("SELECT document FROM usage_reservation_transitions WHERE transition_id=?").bind(body.transition_id)]);
  if (results[3].results[0]?.document !== doc) fail("reservation_conflict", 409);
  return { applied: results[0].meta.changes === 1, reservation: publicRow(results[2].results[0]) };
}
function validate(body) {
  if (!body || typeof body !== "object" || Array.isArray(body) || body.version !== 1 || !Object.hasOwn(FIELDS, body.operation)) fail();
  const allowed = new Set(["version", "operation", ...FIELDS[body.operation]]);
  if (Object.keys(body).some(key => !allowed.has(key))) fail();
  if (["get", "audit"].includes(body.operation)) identifier(body.id);
  if (body.operation === "summary") principal(body.principal);
  return body;
}
async function readBody(request) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") fail();
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > 32768)) fail();
  if (!request.body) fail();
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0, finished = false;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) { finished = true; break; }
      size += item.value.byteLength;
      if (size > 32768) fail();
      chunks.push(item.value);
    }
  } finally { if (!finished) void reader.cancel().catch(() => {}); reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return validate(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))); }
  catch (error) { if (error instanceof ReservationError) throw error; fail(); }
}
function reply(value, status = 200) {
  return Response.json({ version: 1, ...value }, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}
/** Must be mounted only by the trusted private outbound dispatcher. */
export async function handleReservationsRequest(request, env, { now = Date.now } = {}) {
  const settings = reservationSettings(env);
  if (!settings.enabled) return reply({ error: { code: "not_found" } }, 404);
  try {
    const url = new URL(request.url);
    if (url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/reservations" || url.search || url.hash
      || url.username || url.password) fail("store_route_not_found", 404);
    if (request.method !== "POST") fail("store_method_not_allowed", 405);
    const body = await readBody(request);
    const db = env.INTELLIGENCE_DB;
    if (!db || typeof db.prepare !== "function" || typeof db.batch !== "function") throw new ReservationError();
    let result;
    if (body.operation === "reserve") result = { reservation: await reserveUsage(db, body, now()) };
    else if (body.operation === "transition") result = await transitionUsage(db, body, now());
    else if (body.operation === "summary") result = { summary: await reservationSummary(db, body.principal, now(), settings.review) };
    else if (body.operation === "audit") {
      const rows = await db.prepare("SELECT * FROM usage_reservation_transitions WHERE reservation_id=? ORDER BY rowid LIMIT 100")
        .bind(body.id).all();
      result = { transitions: rows.results };
    } else result = { reservation: publicRow(await db.prepare("SELECT * FROM usage_reservations WHERE id=?").bind(body.id).first()) };
    if (body.operation === "transition" && body.state === "reconciled" && result.applied) {
      const row = result.reservation;
      await recordSettledUsage(env, row.principal, body.transition_id, { reservation_id: row.id,
        settlement_id: row.settlement_id, state: row.state, cost_usd: row.cost_usd, cost_basis: row.basis,
        input_tokens: row.input_tokens, output_tokens: row.output_tokens });
    }
    return reply(result);
  } catch (error) {
    const failure = error instanceof ReservationError ? error : new ReservationError();
    return reply({ error: { code: failure.code, message: "The usage reservation operation could not be completed." } }, failure.status);
  }
}
/** One instance per native request. Identity and pricing come from verified admission. */
export function createReservationLifecycle(env, { call, identity }) {
  let reservation, finalEvent;
  let dispatching;
  const transition = async (state, fields = {}) => {
    const result = await call({ version: 1, operation: "transition", id: reservation.id, revision: reservation.revision,
      state, transition_id: crypto.randomUUID().replaceAll("-", ""), ...fields });
    if (result.error) throw new ReservationError(result.error.code, result.error.code === "reservation_conflict" ? 409 : 503);
    reservation = result.reservation;
  };
  const hooks = {
    enabled: env => reservationSettings(env).enabled,
    async admit(context) {
      if (!reservationSettings(env).enabled) return;
      const values = await identity(context);
      if (values.daily_budget_usd == null && values.monthly_budget_usd == null) return;
      const result = await call({ version: 1, operation: "reserve", id: crypto.randomUUID().replaceAll("-", ""), ...values });
      if (result.error) throw new ReservationError(result.error.code, result.error.code === "budget_exceeded" ? 429 : 503);
      reservation = result.reservation;
      if (finalEvent) await hooks.finalize(finalEvent);
    },
    async before_dispatch() {
      if (reservation?.state === "reserved") await (dispatching = transition("dispatched"));
    },
    async finalize(context) {
      finalEvent = context;
      await dispatching;
      if (!reservation || !ACTIVE.has(reservation.state) || reservation.state === "unknown") return;
      if (reservation.state === "reserved" || context.handedOff === false) {
        await transition("settled", { cost_usd: 0, basis: "released", settlement_id: reservation.id,
          ...(reservation.state === "dispatched" ? { handoff_not_started: true } : {}) });
        return;
      }
      const row = context.usage ?? context;
      const measured = (!context.outcome || context.outcome === "success") && !context.cancellationOutcome?.ambiguous && row.cost_usd != null && row.cost_basis === "usage";
      await transition(measured ? "settled" : "unknown", measured
        ? { cost_usd: row.cost_usd, basis: "provider", settlement_id: reservation.id,
          input_tokens: row.input_tokens ?? null, output_tokens: row.output_tokens ?? null }
        : { input_tokens: context.cancellationOutcome?.ambiguous ? null : row.input_tokens ?? null,
          output_tokens: context.cancellationOutcome?.ambiguous ? null : row.output_tokens ?? null });
    },
  };
  return hooks;
}

function nativePrice(table, provider, model, input, output, units) {
  if (typeof model !== "string") return null;
  const qualified = (model.includes(":") ? model : `${provider}:${model}`).toLowerCase();
  const rate = table?.[qualified] ?? table?.[`${qualified.split(":")[0]}:*`] ?? table?.["*"];
  if (!rate || typeof rate !== "object") return null;
  const flat = Object.hasOwn(rate, "request") && !["input", "output", "input_cost_per_million", "output_cost_per_million"].some(k => Object.hasOwn(rate, k));
  const amount = value => (typeof value === "number" || typeof value === "string" && value.trim()) ? Number(value) : NaN;
  const rates = [flat ? 0 : amount(rate.input ?? rate.input_cost_per_million),
    flat ? 0 : amount(rate.output ?? rate.output_cost_per_million), Object.hasOwn(rate, "request") ? amount(rate.request) : 0];
  if (!rates.every(n => Number.isFinite(n) && n >= 0)) return null;
  const cost = (input * rates[0] + output * rates[1]) * units / 1_000_000 + units * rates[2];
  return Number.isFinite(cost) && cost <= MAX_UNITS / SCALE ? cost : null;
}

async function boundedReservationBody(request) {
  const reader = request.clone().body?.getReader();
  if (!reader) throw new ReservationError("unpriced_reservation");
  let size = 0;
  const parts = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 65536) throw new ReservationError("unpriced_reservation");
      parts.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
    return { body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), size };
  } finally { void reader.cancel().catch(() => {}); }
}

async function nativeReservationIdentity(request, env, authority, context) {
  let principal = authority.principal;
  if (!principal?.id) throw new ReservationError();
  // Native bootstrap authentication uses the environment; stored controls are optional metadata.
  if (principal.daily_budget_usd === undefined && principal.monthly_budget_usd === undefined
      && env.INTELLIGENCE_DB && env.ADMIN_API_KEY) {
    const stored = await env.INTELLIGENCE_DB.prepare(`SELECT daily_budget_usd, monthly_budget_usd FROM control_users
      WHERE username = ? AND is_admin = 1 AND revoked_at IS NULL`).bind(principal.id).first();
    principal = { ...principal, ...stored };
  }
  const limits = { daily_budget_usd: principal.daily_budget_usd ?? null, monthly_budget_usd: principal.monthly_budget_usd ?? null };
  if (limits.daily_budget_usd === null && limits.monthly_budget_usd === null) return limits;
  const identity = `edge:${await retentionRequestId(`native-admin:${principal.id}`)}`;
  let estimate = 0;
  if (!context.cacheServed) {
    const { body, size } = await boundedReservationBody(request);
    const models = authority.eligibleModels ?? [context.model];
    const raw = env.MODEL_PRICING_USD_PER_MILLION;
    if (typeof raw !== "string" || raw.length > 65536) throw new ReservationError("unpriced_reservation");
    const table = JSON.parse(raw);
    const outputs = [body.max_tokens, body.max_completion_tokens, body.max_output_tokens, body.generationConfig?.maxOutputTokens].filter(n => n != null);
    if (outputs.some(n => !Number.isSafeInteger(n) || n < 0)) throw new ReservationError("unpriced_reservation");
    const units = body.n ?? 1;
    if (!Number.isSafeInteger(units) || units < 1 || units > 100) throw new ReservationError("unpriced_reservation");
    const costs = models.map(model => nativePrice(table, authority.provider, model, size, outputs.length ? Math.max(...outputs) : 1024, units));
    if (!costs.length || costs.some(cost => cost === null)) throw new ReservationError("unpriced_reservation");
    estimate = Math.max(...costs);
  }
  const day = new Date().toISOString().slice(0, 10);
  const baseline = await env.INTELLIGENCE_DB.prepare(`SELECT COALESCE(SUM(CASE WHEN day = ? THEN cost_usd ELSE 0 END), 0) AS day_spent_usd,
    COALESCE(SUM(cost_usd), 0) AS month_spent_usd FROM usage_daily WHERE principal = ? AND day >= ? AND day <= ?`)
    .bind(day, identity, `${day.slice(0, 7)}-01`, day).first();
  if (!baseline) throw new ReservationError();
  return { principal: identity, estimate_usd: estimate, ...limits,
    day_spent_usd: baseline.day_spent_usd, month_spent_usd: baseline.month_spent_usd };
}

async function boundedReservationOperation(action) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(action), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new ReservationError()), 3000);
    })]);
  } catch (error) { throw error instanceof ReservationError ? error : new ReservationError(); }
  finally { clearTimeout(timer); }
}

/** Only server-verified principal metadata can impose native monetary limits. */
export function nativeReservationLifecycle(request, env, authority) {
  return createReservationLifecycle(env, { call: body => boundedReservationOperation(async () => {
    const response = await handleReservationsRequest(new Request("http://intelligence.internal/v1/reservations", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    }), env);
    return response.json();
  }), identity: context => boundedReservationOperation(() => nativeReservationIdentity(request, env, authority, context)) });
}
