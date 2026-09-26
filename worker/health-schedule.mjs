/**
 * The Worker's cron: free provider health checks and optional keep-warm.
 *
 * Every tick (wrangler.jsonc triggers.crons, every five minutes) may:
 * - with KEEP_WARM=true, request /healthz so the Container never reaches its 15-minute
 *   sleepAfter. That keeps a basic instance running around the clock (see
 *   docs/status-and-health.md for the cost); it is off by default.
 * - every HEALTH_CHECK_INTERVAL_MINUTES (30), ask the Container to run the free model-list
 *   checks at POST /v1/health/checks with the admin key. A sleeping Container is not woken
 *   for this unless HEALTH_CHECKS_WAKE=true or KEEP_WARM=true, and a running one is reached
 *   without renewing its sleep timer, so checks alone never keep it awake.
 */
import { logFailure } from "./log.mjs";

export const CHECK_PATH = "/v1/health/checks";
const RUNNING = new Set(["running", "healthy"]);
const INTERNAL_ORIGIN = "https://container.internal";

const flag = value => ["1", "true", "yes", "on"].includes(String(value ?? "").trim().toLowerCase());

export function scheduleSettings(env = {}) {
  const interval = Number.parseInt(env.HEALTH_CHECK_INTERVAL_MINUTES ?? "30", 10);
  return {
    keepWarm: flag(env.KEEP_WARM),
    checksWake: flag(env.HEALTH_CHECKS_WAKE),
    checkEveryMinutes: Number.isInteger(interval) ? Math.min(1440, Math.max(5, interval)) : 30,
  };
}

/** Whether this tick is a check tick: whole multiples of the interval since the epoch. */
export function isCheckTick(scheduledTime, checkEveryMinutes) {
  return Math.floor(scheduledTime / 60000) % checkEveryMinutes === 0;
}

/**
 * Container Durable Object method body: fetch a running Container directly on its port, so
 * the request neither starts it nor renews sleepAfter. Returns null while it is not running.
 */
export async function fetchIfRunning(container, path, init = {}) {
  const state = await container.getState();
  const runtime = container.ctx?.container;
  if (!RUNNING.has(state?.status) || !runtime?.running) return null;
  const response = await runtime.getTcpPort(container.defaultPort).fetch(`http://container${path}`, init);
  return { status: response.status, body: await response.text() };
}

function checkRequestInit(env) {
  return {
    method: "POST",
    headers: { Authorization: `Bearer ${env.ADMIN_API_KEY}`, Accept: "application/json", "Content-Type": "application/json" },
    body: "{}",
  };
}

async function runChecks(env, container, wake) {
  if (!env.ADMIN_API_KEY) return { checks: "skipped", reason: "admin_key_missing" };
  const init = checkRequestInit(env);
  if (wake) {
    const response = await container.fetch(new Request(`${INTERNAL_ORIGIN}${CHECK_PATH}`, init));
    await response.body?.cancel();
    return { checks: response.ok ? "ran" : "failed", status: response.status };
  }
  const result = await container.fetchIfRunning(CHECK_PATH, init);
  if (!result) return { checks: "skipped", reason: "container_asleep" };
  return { checks: result.status === 200 ? "ran" : "failed", status: result.status };
}

/** The scheduled() handler body; returns what it did for logs and tests. */
export async function runScheduledHealth(controller, env, container) {
  const settings = scheduleSettings(env);
  const outcome = { cron: controller.cron };
  if (settings.keepWarm) {
    try {
      const response = await container.fetch(new Request(`${INTERNAL_ORIGIN}/healthz`));
      await response.body?.cancel();
      outcome.keepWarm = response.status;
    } catch (error) {
      logFailure("keep_warm_failed", error);
      outcome.keepWarm = "failed";
    }
  }
  if (isCheckTick(controller.scheduledTime, settings.checkEveryMinutes)) {
    try {
      Object.assign(outcome, await runChecks(env, container, settings.keepWarm || settings.checksWake));
    } catch (error) {
      logFailure("health_checks_failed", error);
      outcome.checks = "failed";
    }
  }
  console.log(JSON.stringify({ event: "scheduled_health", ...outcome }));
  return outcome;
}
