import { logFailure } from "./log.mjs";

// Every table the intelligence-migrations directory creates; a test keeps the two in step.
export const REQUIRED_D1_TABLES = Object.freeze(["intelligence_policy", "intelligence_reservations",
  "intelligence_principals", "intelligence_credentials", "control_users", "control_user_audit", "auto_routes"]);

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
