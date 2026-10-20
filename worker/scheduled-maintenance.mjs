/** Bounded shared-cache maintenance and content-free alert delivery. */
import { cleanupGenerationCache } from "./generation-cache-d1.mjs";
import { generationCacheSettings } from "./exact-generation-cache.mjs";
import { semanticCacheSettings } from "./semantic-generation-cache.mjs";
import { cleanupSemanticCache } from "./semantic-cache-d1.mjs";
import { alertSettings, runAlertDelivery } from "./alert-delivery.mjs";

const CACHE_BATCHES = 3;
const validTotal = value => typeof value === "number" && Number.isFinite(value) && value >= 0;

/** Pool and circuit observations are supplied by Flask's passive health observer. */
export async function collectAlertAggregates(env, rules, now = new Date()) {
  const day = now.toISOString().slice(0, 10);
  const summaries = new Map(), observations = [];
  for (const rule of rules) {
    if (!["spend", "unknown_price"].includes(rule.kind)) continue;
    if (!summaries.has(rule.period)) {
      const since = rule.period === "day" ? day : `${day.slice(0, 7)}-01`;
      const totals = await env.INTELLIGENCE_DB.prepare(`SELECT COALESCE(SUM(cost_usd), 0) AS cost_usd,
        COALESCE(SUM(requests), 0) AS requests, COALESCE(SUM(priced_requests), 0) AS priced_requests
        FROM usage_daily WHERE day >= ? AND day <= ?`).bind(since, day).first();
      if (!totals || ![totals.cost_usd, totals.requests, totals.priced_requests].every(validTotal)
          || totals.priced_requests > totals.requests) throw Error("alert_aggregate_unavailable");
      summaries.set(rule.period, totals);
    }
    const totals = summaries.get(rule.period);
    observations.push({ rule_id: rule.id, value: rule.kind === "spend" ? totals.cost_usd
      : totals.requests ? 100 * (totals.requests - totals.priced_requests) / totals.requests : 0,
    basis: rule.kind === "spend" ? "gateway_cost_estimate" : "unknown_price_coverage",
    window: rule.period === "day" ? day : day.slice(0, 7) });
  }
  return observations;
}

export function alertTransport(destination, options) {
  // The delivery owner provides its three-second abort signal and bounds the payload.
  return fetch(destination, { method: "POST", headers: options.headers, body: options.body,
    redirect: "error", signal: options.signal });
}

/** Scheduled work is registered only when a feature that needs it is enabled. */
export function scheduledMaintenanceEnabled(env) {
  return generationCacheSettings(env).enabled || alertSettings(env).enabled || semanticCacheSettings(env).enabled;
}

export async function runScheduledMaintenance(env, { cleanup = cleanupGenerationCache, cleanupSemantic = cleanupSemanticCache, deliver = runAlertDelivery,
  collect = rules => collectAlertAggregates(env, rules), transport = alertTransport } = {}) {
  const result = { cache_batches: 0, alerts: null };
  const tasks = [];
  if (semanticCacheSettings(env).enabled) tasks.push((async () => {
    result.semantic_cache_batches = 0;
    try {
      let cursor;
      for (let batch = 0; batch < CACHE_BATCHES; batch++) {
        const page = await cleanupSemantic(env, { limit: 100, cursor });
        result.semantic_cache_batches++;
        cursor = page.cursor;
        if (!cursor) break;
      }
    } catch { console.warn(JSON.stringify({ event: "semantic_cache_cleanup_failed" })); }
  })());
  if (generationCacheSettings(env).enabled) tasks.push((async () => {
    try {
      let cursor;
      for (let batch = 0; batch < CACHE_BATCHES; batch++) {
        const page = await cleanup(env, { limit: 100, cursor });
        result.cache_batches++;
        cursor = page.cursor;
        if (!cursor) break;
      }
    } catch { console.warn(JSON.stringify({ event: "generation_cache_cleanup_failed" })); }
  })());
  if (alertSettings(env).enabled) tasks.push((async () => {
    try { result.alerts = await deliver(env, { collect, transport }); }
    catch { console.warn(JSON.stringify({ event: "gateway_alert_delivery_failed" })); }
  })());
  await Promise.all(tasks);
  return result;
}
