/** Content-free Realtime price evidence and durable monetary holds. */
import { reserveUsage, transitionUsage } from "./reservations-d1.mjs";
import { recordNativeUsage } from "./usage-ledger-d1.mjs";

const integer = value => Number.isSafeInteger(value) && value >= 0;
const money = value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1_000_000;
const id = () => crypto.randomUUID().replaceAll("-", "");
export class RealtimeError extends Error {
  constructor(code, status = 503) { super(code); this.code = code; this.status = status; }
  response() { return Response.json({ error: { code: this.code, message: "The Realtime request could not be admitted or completed." } },
    { status: this.status, headers: { "cache-control": "no-store", ...(this.status === 426 ? { Upgrade: "websocket" } : {}) } }); }
}
export function realtimeCostPolicy(env, model) {
  const cap = Number(String(env.REALTIME_SESSION_CAP_USD ?? "").trim());
  let price;
  try { const raw = String(env.REALTIME_PRICING_JSON ?? ""); if (raw.length > 65536) throw Error(); price = JSON.parse(raw || "{}")[model]; }
  catch { throw new RealtimeError("realtime_unpriced"); }
  // This ceiling must be enforced by the approved provider's account/session contract.
  // Post-response usage alone cannot cap money already spent upstream.
  if (!money(cap) || cap <= 0 || !price || Array.isArray(price)
    || !["input_text", "output_text", "input_audio", "output_audio"].every(name => money(price[name]))
    || !money(price.provider_session_limit_usd) || price.provider_session_limit_usd <= 0
    || price.provider_session_limit_usd > cap) throw new RealtimeError("realtime_unpriced_or_unbounded");
  return Object.freeze({ ...price, cap });
}
function usageDetails(usage, policy) {
  const input = usage?.input_token_details, output = usage?.output_token_details;
  const counts = [input?.text_tokens, input?.audio_tokens, output?.text_tokens, output?.audio_tokens];
  if (!counts.every(integer) || !integer(usage.input_tokens) || !integer(usage.output_tokens)
    || counts[0] + counts[1] !== usage.input_tokens || counts[2] + counts[3] !== usage.output_tokens) return null;
  let cost = (counts[0] * policy.input_text + counts[1] * policy.input_audio
    + counts[2] * policy.output_text + counts[3] * policy.output_audio) / 1_000_000;
  const cached = input.cached_tokens ?? 0;
  if (!integer(cached) || cached > usage.input_tokens) return null;
  if (cached) {
    const details = input.cached_tokens_details;
    if (!integer(details?.text_tokens) || !integer(details?.audio_tokens) || details.text_tokens + details.audio_tokens !== cached
      || details.text_tokens > counts[0] || details.audio_tokens > counts[1]
      || !money(policy.cached_text) || !money(policy.cached_audio)) return null;
    cost += (details.text_tokens * (policy.cached_text - policy.input_text)
      + details.audio_tokens * (policy.cached_audio - policy.input_audio)) / 1_000_000;
  }
  return money(cost) ? { counts, cost } : null;
}
export function createRealtimeMeter(policy) {
  let cost = 0, unknown = false, seenUsage = false, inputDirty = false;
  const totals = [0, 0, 0, 0], completed = new Set(), pending = new Set();
  return {
    noteInput(data) {
      if (typeof data !== "string") { inputDirty = true; return; }
      let event; try { event = JSON.parse(data); } catch { inputDirty = true; return; }
      if (["conversation.item.create", "input_audio_buffer.append", "input_audio_buffer.commit", "response.create"].includes(event?.type)) inputDirty = true;
    },
    observe(data) {
      if (typeof data !== "string") return;
      let event; try { event = JSON.parse(data); } catch { unknown = true; return; }
      if (event?.type === "error" || event?.error) { unknown = true; return "upstream_error"; }
      if (event?.type === "conversation.item.input_audio_transcription.completed") unknown = true;
      if (typeof event?.type === "string" && event.type.startsWith("response.") && event.type !== "response.done") {
        const responseId = event.response?.id ?? event.response_id;
        if (responseId !== undefined || event.type === "response.created" || event.type.endsWith(".delta")) {
          if (typeof responseId !== "string" || !responseId || responseId.length > 128 || pending.size >= 256) { unknown = true; return "policy"; }
          if (completed.has(responseId)) unknown = true;
          else pending.add(responseId);
        }
      }
      if (event?.type !== "response.done") return;
      const responseId = event.response?.id;
      if (typeof responseId !== "string" || responseId.length > 128) { unknown = true; return; }
      if (completed.has(responseId)) return;
      if (completed.size >= 256) { unknown = true; return "policy"; }
      completed.add(responseId); pending.delete(responseId);
      const usage = usageDetails(event.response?.usage, policy);
      if (!usage || event.response.status !== "completed") { unknown = true; return; }
      seenUsage = true; inputDirty = false; cost += usage.cost;
      totals.forEach((value, index) => { totals[index] = value + usage.counts[index]; });
      if (!money(cost) || !totals.every(integer) || cost > policy.cap || cost > policy.provider_session_limit_usd) {
        unknown = true; return "policy";
      }
    },
    finish({ uncertain = false } = {}) {
      const known = seenUsage && !unknown && !pending.size && !inputDirty && !uncertain;
      return { input_text_tokens: seenUsage ? totals[0] : null, input_audio_tokens: seenUsage ? totals[1] : null,
        output_text_tokens: seenUsage ? totals[2] : null, output_audio_tokens: seenUsage ? totals[3] : null,
        input_tokens: seenUsage ? totals[0] + totals[1] : null, output_tokens: seenUsage ? totals[2] + totals[3] : null,
        cost_usd: known ? cost : null, cost_basis: known ? "usage" : null };
    },
  };
}
export async function reserveRealtime(env, principal, policy, sessionId, now) {
  const defaultBudget = Number(String(env.REALTIME_DAILY_BUDGET_USD ?? "").trim());
  const daily = principal.daily_budget_usd ?? (money(defaultBudget) && defaultBudget > 0 ? defaultBudget : null);
  const monthly = principal.monthly_budget_usd ?? null;
  if (daily === null && monthly === null) throw new RealtimeError("realtime_budget_required");
  const day = new Date(now).toISOString().slice(0, 10);
  const spent = await env.INTELLIGENCE_DB.prepare(`SELECT
    COALESCE(SUM(CASE WHEN day=?2 THEN cost_usd ELSE 0 END),0) AS day_usd,
    COALESCE(SUM(cost_usd),0) AS month_usd FROM usage_daily WHERE principal=?1 AND day>=?3 AND day<=?2`)
    .bind(principal.owner, day, day.slice(0, 7) + "-01").first();
  await reserveUsage(env.INTELLIGENCE_DB, { id: sessionId, principal: principal.owner,
    estimate_usd: policy.provider_session_limit_usd, daily_budget_usd: daily, monthly_budget_usd: monthly,
    day_spent_usd: spent.day_usd, month_spent_usd: spent.month_usd }, now);
  let revision = 0, handedOff = false, finished;
  return {
    async dispatch() { await transitionUsage(env.INTELLIGENCE_DB, { id: sessionId, revision, state: "dispatched", transition_id: id() }, now);
      revision++; handedOff = true; },
    finalize(usage, context, status, ctx) {
      if (finished) return finished;
      finished = (async () => {
        const known = usage.cost_usd !== null;
        const state = !handedOff || known ? "settled" : "unknown";
        // The ledger is idempotent, but its writer absorbs storage faults. Persist the
        // uncertainty state first, then leave durable session metadata for reconciliation.
        await transitionUsage(env.INTELLIGENCE_DB, { id: sessionId, revision, state, transition_id: id(),
          input_tokens: usage.input_tokens, output_tokens: usage.output_tokens,
          ...(!handedOff || known ? { cost_usd: handedOff ? usage.cost_usd : 0,
            basis: handedOff ? "provider" : "released", settlement_id: id() } : {}) }, Date.now());
        if (handedOff) await recordNativeUsage(env, { ...context, ...usage, status,
          duration_ms: Math.min(86_400_000, Math.max(0, Date.now() - now)) }, ctx);
        return state;
      })();
      return finished;
    },
  };
}
