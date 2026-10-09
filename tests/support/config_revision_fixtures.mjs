// Shared D1 fixtures for the config revision Worker and integration suites.
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { handleIntelligenceOutbound } from "../../worker/intelligence-outbound.mjs";
import { handleRevisionedAutoRoutes } from "../../worker/config-revision.mjs";
import { handleAutoRoutesRequest } from "../../worker/auto-routes-d1.mjs";
import { boundedBody } from "../../worker/control-users-d1.mjs";
import { applyMigrations } from "../d1_migrations.mjs";

export async function database(t, missing = false) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true,
    script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, { skip: missing ? ["0017_control_revisions.sql"] : [] });
  const env = { INTELLIGENCE_DB: db, CONFIG_REVISION_SYNC_ENABLED: "true" };
  const call = async (domain, body, targetEnv = env) => {
    const request = new Request(`http://intelligence.internal${domain === "routes" ? "/v1/auto-routes" : `/v1/state/${domain}`}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) });
    const response = domain === "routes" ? await handleRevisionedAutoRoutes(request, targetEnv, { handleAutoRoutesRequest, boundedBody })
      : await handleIntelligenceOutbound(request, targetEnv);
    return { status: response.status, body: await response.json() };
  };
  const revisions = async domains => call("models", { operation: "revisions", domains });
  return { db, env, call, revisions };
}

export const account = (changes = {}) => ({ username: "alice", api_key_hash: "synthetic-hash", api_key_prefix: "mllm_syntheti",
  scopes: "chat,models", is_admin: 0, created_at: "2026-10-09T00:00:00+00:00", last_login: null,
  last_used_at: null, last_used_ip: null, created_by: null, rotated_at: null, revoked_at: null,
  daily_budget_usd: null, monthly_budget_usd: null, allowed_models: null, allowed_ips: null,
  expires_at: null, secret_scan_mode: null, shadow_eval_rate: null, ...changes });

const usersRequest = body => new Request("http://intelligence.internal/v1/users", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
});

export async function usersCall(env, body) {
  const response = await handleIntelligenceOutbound(usersRequest(body), env);
  return { status: response.status, body: await response.json() };
}
