/** Per-attempt native charging, using the immutable enterprise credit authority. */
import { createHash } from "node:crypto";
import { creditsEnabled, creditsEnforcement, contextOwner, readCredits, appendCredit, registerCreditAuthority } from "./credits-d1.mjs";
import { TenantContext, AuthorityOperation, callAuthority, registerEnterpriseAdapters } from "./enterprise-contract.mjs";

export class CreditsAdmissionError extends Error {
  constructor(code = "credits_unavailable", status = 503) { super(code); this.code = code; this.status = status; }
  response() { return Response.json({ error: { code: this.code, message: "Credit admission could not be completed." } }, { status: this.status }); }
}
export function integerMicroUsd(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new CreditsAdmissionError("credits_unpriced");
  const [mantissa, exponent = "0"] = String(value).toLowerCase().split("e");
  const [whole, fraction = ""] = mantissa.split(".");
  const digits = BigInt(whole + fraction), power = 6 + Number(exponent) - fraction.length;
  const divisor = power < 0 ? 10n ** BigInt(-power) : 1n;
  const result = power < 0 ? (digits + divisor - 1n) / divisor : digits * 10n ** BigInt(power);
  if (result > BigInt(Number.MAX_SAFE_INTEGER - 1)) throw new CreditsAdmissionError("credits_unpriced");
  return Number(result);
}
export function nativeTariffRevision(env) {
  const raw = env.MODEL_PRICING_USD_PER_MILLION;
  if (typeof raw !== "string" || !raw || raw.length > 65536) return null;
  try { const table = JSON.parse(raw); if (!table || Array.isArray(table) || typeof table !== "object") return null; }
  catch { return null; }
  return Number.parseInt(createHash("sha256").update(raw).digest("hex").slice(0, 12), 16);
}
/** Only failed compare-and-swap operations retry; IDs and amounts never change. */
export async function withCreditRevision(db, owner, apply, read = readCredits) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const revision = (await read(db, owner)).revision;
    try { return await apply(revision); }
    catch (error) { if (error.status !== 412 || attempt === 2) throw error; }
  }
}
function admissionFailure(error, phase) {
  if (error instanceof CreditsAdmissionError) return error;
  if (phase === "reserve" && error.code === "credits_insufficient") return new CreditsAdmissionError("credits_insufficient", 402);
  return new CreditsAdmissionError(error.code === "credits_unpriced" ? "credits_unpriced" : "credits_unavailable");
}
export function createCreditsLifecycle(env, { context, db = env.INTELLIGENCE_DB, scoped_id,
  read = readCredits, append = appendCredit, authority = registerCreditAuthority } = {}) {
  const mode = creditsEnforcement(env);
  scoped_id ??= mode === "off" ? "disabled" : `native_${crypto.randomUUID().replaceAll("-", "")}`;
  let owner, charging, held = false, dispatched = false, finished = false, estimate, revision, finalEvent;

  const decide = async () => {
    if (mode === "off") return false;
    if (charging !== undefined) return charging;
    try {
      owner = contextOwner(context);
      charging = mode === "all" || (await read(db, owner)).revision > 0;
      return charging;
    } catch (error) { throw admissionFailure(error, "reserve"); }
  };
  const apply = async (phase, amount) => {
    const adapters = registerEnterpriseAdapters({ credit: authority(db, { env,
      tariff: (operation, action) => action === "reconcile" || operation.amount !== amount
        || operation.scoped_id !== scoped_id ? null : revision }) });
    return withCreditRevision(db, owner, current => callAuthority(adapters, "credit", phase,
      new AuthorityOperation({ context, scoped_id, revision: current, operation_id: `${scoped_id}.${phase}`, amount })), read);
  };
  const hooks = {
    requiresPricing: decide,
    async admit(event) {
      if (held || finished || !await decide()) return;
      if (event.scoped_id !== undefined) scoped_id = event.scoped_id;
      estimate = event.amount; revision = event.tariff_revision;
      if (!Number.isSafeInteger(estimate) || estimate < 0 || !Number.isSafeInteger(revision) || revision < 0)
        throw new CreditsAdmissionError("credits_unpriced");
      try { await apply("reserve", estimate); held = true; }
      catch (error) { throw admissionFailure(error, "reserve"); }
      if (finalEvent) await hooks.finalize(finalEvent);
    },
    async before_dispatch() { if (held && !finished) dispatched = true; },
    async finalize(event) {
      finalEvent = event;
      if (!held || finished) return;
      const row = event.usage ?? event;
      try {
        if (!dispatched || event.handedOff === false || row.cost_basis === "cache") {
          await withCreditRevision(db, owner, current => append(db, { owner, kind: "release", amount_microusd: estimate,
            scoped_id, revision: current, operation_id: `${scoped_id}.release` }), read);
        } else if ((!event.outcome || event.outcome === "success") && !event.cancellationOutcome?.ambiguous && row.cost_basis === "usage"
            && (Number.isSafeInteger(row.cost_micro_usd) || row.cost_usd != null)) {
          await apply("commit", row.cost_micro_usd ?? integerMicroUsd(row.cost_usd));
        } else await apply("reconcile", 0);
        finished = true;
      } catch (error) { throw admissionFailure(error, "settle"); }
    },
  };
  return hooks;
}

/** Recover a linked attempt from immutable ledger evidence, without current membership. */
export async function reconcileCreditsReservation(env, row, transition_id) {
  if (!creditsEnabled(env) || row.cost_usd == null) return;
  const db = env.INTELLIGENCE_DB;
  try {
    const found = await db.prepare("SELECT owner,kind,amount_microusd,held_delta,tariff_revision FROM credits_entries WHERE scoped_id=?")
      .bind(row.id).all();
    const entries = found.results;
    const reserve = entries.find(entry => entry.kind === "reserve" && entry.held_delta > 0);
    if (!reserve) return;
    if (entries.some(entry => entry.owner !== reserve.owner)) throw new CreditsAdmissionError();
    if (entries.some(entry => ["commit", "release"].includes(entry.kind))) return;
    let principal_id = reserve.owner, org_id = null, team_id = null;
    if (principal_id.startsWith("tenant:")) [org_id, team_id, principal_id] = JSON.parse(principal_id.slice(7));
    const context = new TenantContext({ principal_id, org_id, team_id });
    const amount = integerMicroUsd(row.cost_usd);
    const operation_id = createHash("sha256").update(JSON.stringify([row.id, "reconcile", transition_id])).digest("hex");
    const adapters = registerEnterpriseAdapters({ credit: registerCreditAuthority(db, { env,
      tariff: (operation, phase) => phase === "reconcile" && operation.amount === amount
        && operation.scoped_id === row.id ? reserve.tariff_revision : null }) });
    await withCreditRevision(db, reserve.owner, revision => callAuthority(adapters, "credit", "reconcile",
      new AuthorityOperation({ context, scoped_id: row.id, revision, operation_id, amount })));
  } catch (error) { throw admissionFailure(error, "settle"); }
}
