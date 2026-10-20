/** Explicit durable controls for transport tests; never a runtime fallback. */
export function policyStore(controls = { official_only: null, forced_provider_preferences: null }) {
  return { prepare(query) {
    if (!query.startsWith("SELECT official_only, forced_provider_preferences FROM control_users")) throw Error(`Unexpected policy query: ${query}`);
    return { bind() { return this; }, async first() { return structuredClone(controls); }, async all() { return { results: [structuredClone(controls)] }; } };
  } };
}
export const dispatchEnv = () => ({ INTELLIGENCE_DB: policyStore() });

const policyEnvironments = new WeakSet();

/** Independent middleware tests supply a durable policy without emulating unrelated SQL. */
export function policyFixtureEnv(env = {}) {
  if (policyEnvironments.has(env)) return env;
  const db = env.INTELLIGENCE_DB;
  const policy = policyStore();
  const bound = { ...env, INTELLIGENCE_DB: { ...db, prepare(query) {
    if (query.startsWith("SELECT official_only, forced_provider_preferences FROM control_users")
      || query.startsWith("SELECT official_only, forced_provider_preferences FROM intelligence_principals")) {
      return policy.prepare(query.replace("intelligence_principals", "control_users"));
    }
    if (!db) throw Error(`Unexpected fixture SQL: ${query}`);
    return db.prepare(query);
  } } };
  policyEnvironments.add(bound);
  return bound;
}


/** Real binding fixtures use the same NULL controls in a migrated disposable D1. */
export async function initializePolicyAccount(mf, username) {
  const { applyMigrations } = await import("../d1_migrations.mjs");
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  await db.prepare("INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,is_admin,created_at) VALUES(?,?,?,'knowledge:read,knowledge:manage',0,'2026-10-01T00:00:00Z')")
    .bind(username, "synthetic-hash", "synthetic-prefix").run();
}
