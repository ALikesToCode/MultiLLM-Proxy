/** Explicit durable controls for transport tests; never a runtime fallback. */
export function policyStore(controls = { official_only: null, forced_provider_preferences: null }) {
  return { prepare(query) {
    if (!query.startsWith("SELECT official_only, forced_provider_preferences FROM control_users")) throw Error(`Unexpected policy query: ${query}`);
    return { bind() { return this; }, async first() { return structuredClone(controls); } };
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
