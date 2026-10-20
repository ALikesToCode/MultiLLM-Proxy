/** Shared provider classes and administrator-owned preferences at native dispatch. */
import classes from "../providers/data-classes.json" with { type: "json" };

const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
export function parsePreferences(value) {
  if (value == null) return null;
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!object(parsed) || new TextEncoder().encode(JSON.stringify(parsed)).length > 4096
    || (Object.hasOwn(parsed, "data_collection") && !["allow", "deny"].includes(parsed.data_collection))) {
    throw new TypeError("Invalid provider preferences");
  }
  return parsed;
}

export function validDataControls(user) {
  try {
    if (!user || !Object.hasOwn(user, "official_only") || !Object.hasOwn(user, "forced_provider_preferences")
      || user.official_only === undefined || user.forced_provider_preferences === undefined) return false;
    parsePreferences(user.forced_provider_preferences);
    return user.official_only === null || [0, 1].includes(user.official_only);
  } catch { return false; }
}

export function providerDataClass(provider, env = {}) {
  provider = String(provider).trim().toLowerCase();
  if (provider === "free" || String(env.FREE_ROUTE_FREE_TIER_PROVIDERS ?? "").split(/[\s,]+/).includes(provider)) return "free";
  if (provider === "gemini") return env.GEMINI_DATA_TIER === "paid" ? "official" : "free";
  return Object.hasOwn(classes, provider) ? classes[provider] : provider.startsWith("ce-") ? "subscription" : "reseller";
}

export function providerClassPermitted(user, provider, env = {}) {
  return !user?.official_only || providerDataClass(provider, env) === "official";
}

export function mergePreferences(caller, forced) {
  const entries = new Map(Object.entries(object(caller) ? caller : {}));
  for (const [name, value] of Object.entries(forced)) {
    if (name === "data_collection" && entries.get(name) === "deny") continue;
    entries.set(name, object(value) ? mergePreferences(entries.get(name), value) : structuredClone(value));
  }
  return Object.fromEntries(entries);
}

/** Read current administrator controls without accepting policy from client headers. */
export async function currentDataControls(env, authority) {
  const id = authority.keyId ?? authority.principal?.owner ?? authority.principal?.id;
  if (!env.INTELLIGENCE_DB || !id) throw new TypeError("Unverifiable authority");
  const user = id.startsWith("integration:")
    ? await env.INTELLIGENCE_DB.prepare("SELECT official_only, forced_provider_preferences FROM intelligence_principals WHERE id = ? AND revoked_at IS NULL").bind(id).first()
    : await env.INTELLIGENCE_DB.prepare(
    "SELECT official_only, forced_provider_preferences FROM control_users WHERE username = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)")
    .bind(id, new Date().toISOString()).first();
  if (!validDataControls(user)) throw new TypeError("Unverifiable controls");
  return user;
}

/** Resolve controls from trusted authority or durable accounts, never client headers. */
export async function guardNativeRequest(request, env, authority) {
  if (authority.authenticated !== true) return { response: Response.json({ error: { code: "key_data_controls_unavailable" } }, { status: 503 }) };
  try {
    const user = await currentDataControls(env, authority);
    if (!providerClassPermitted(user, authority.provider, env)) {
      return { response: Response.json({ error: { code: "provider_class_not_allowed" } }, { status: 403 }) };
    }
    const forced = parsePreferences(user.forced_provider_preferences);
    if (authority.provider !== "openrouter" || !forced || !request.body) return { request };
    const payload = await request.clone().json();
    if (!object(payload)) return { response: Response.json({ error: { code: "invalid_request" } }, { status: 400 }) };
    payload.provider = mergePreferences(payload.provider, forced);
    const headers = new Headers(request.headers); headers.delete("content-length");
    return { request: new Request(request, { headers, body: JSON.stringify(payload) }) };
  } catch {
    return { response: Response.json({ error: { code: "key_data_controls_unavailable" } }, { status: 503 }) };
  }
}
