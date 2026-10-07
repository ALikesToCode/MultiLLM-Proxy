/** Shadow runs must never start the Container or renew its sleep timer. */
import { handleShadowEvalRequest } from "./shadow-eval-d1.mjs";
import { logFailure } from "./log.mjs";
export const SHADOW_RUN_PATH = "/admin/shadow-eval/run";
export async function runScheduledShadowEval(env, container) {
  // D1 retention maintenance never needs a running Container.
  if (env.INTELLIGENCE_DB) await handleShadowEvalRequest(new Request("http://intelligence.internal/v1/shadow-eval", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ version: 1, operation: "cleanup" }),
  }), env);
  if (!env.ADMIN_API_KEY) return { skipped: "admin_key_missing" };
  try {
    const result = await container.fetchIfRunning(SHADOW_RUN_PATH, {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_API_KEY}`,
        "Content-Type": "application/json", Accept: "application/json" }, body: "{}",
    });
    return result ? { status: result.status } : { skipped: "container_asleep" };
  } catch (error) {
    logFailure("shadow_eval_schedule_failed", error);
    return { skipped: "unavailable" };
  }
}
