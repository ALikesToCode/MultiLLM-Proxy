import { logFailure } from "./log.mjs";

// Every table the intelligence-migrations directory creates; a test keeps the two in step.
export const REQUIRED_D1_TABLES = Object.freeze(["intelligence_policy", "intelligence_reservations",
  "intelligence_principals", "intelligence_credentials", "control_users", "control_user_audit", "auto_routes", "cascades",
  "control_audit_events",
  "control_rate_usage", "control_rate_flushes", "control_login_attempts", "control_model_overrides",
  "control_free_cooldowns", "control_connection_profiles", "control_comparison_results", "control_provider_catalog",
  "route_health", "route_health_snapshot",
  "usage_events", "usage_daily", "usage_batches",
  "media_jobs", "media_job_items", "shadow_eval_samples", "shadow_eval_results",
  "shadow_eval_config", "shadow_eval_policy_backups", "prompt_templates",
  "config_snapshot_revisions", "config_snapshots", "config_snapshot_applications", "control_revisions", "tool_grants", "generation_cache", "usage_reservation_budgets", "usage_reservations", "usage_reservation_transitions", "session_tiers", "gateway_alert_rules", "gateway_alert_events", "managed_idempotency", "context_pages", "canary_traffic", "semantic_generation_cache", "gateway_batch_files", "gateway_batches", "gateway_batch_items", "hosted_responses", "realtime_tickets", "realtime_sessions", "learned_cooldown", "usage_receipt_keys", "usage_receipt_heads", "usage_receipts", "tenant_organisations", "tenant_teams", "tenant_memberships", "tenant_bindings", "tenant_audit", "tenant_governance_policies", "tenant_governance_reservations", "tenant_governance_components", "tenant_governance_baselines", "tenant_governance_audit", "saml_requests", "saml_subject_links", "saml_audit", "scim_resources", "scim_group_members", "scim_token_digests", "scim_audit"]);

/**
 * Readiness for the D1 schema. A deploy that skipped `wrangler d1 migrations apply` reports
 * the missing tables here instead of failing authentication at request time.
 */
export async function d1Readiness(db) {
  if (!db) return { ready: true, checked: false };
  try {
    const placeholders = REQUIRED_D1_TABLES.map(() => "?").join(", ");
    const { results } = await db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`)
      .bind(...REQUIRED_D1_TABLES).all();
    const present = new Set(results.map(row => row.name));
    const missing = REQUIRED_D1_TABLES.filter(name => !present.has(name));
    if (missing.length) logFailure("d1_schema_missing", new Error(`Missing tables: ${missing.join(", ")}`));
    return { ready: missing.length === 0, checked: true, missing };
  } catch (error) {
    logFailure("d1_schema_check_failed", error);
    return { ready: false, checked: true, missing: null };
  }
}
