/** A supported version and both explicit fields are mandatory, including nulls. */
import { parsePreferences, validDataControls } from "./key-data-guards.mjs";

export function dataPolicy(user) {
  if (!validDataControls(user)) throw new TypeError("Unverifiable data policy");
  return { version: 1, official_only: user.official_only,
    forced_provider_preferences: parsePreferences(user.forced_provider_preferences) };
}
export function verifyDataPolicy(policy) {
  if (!policy || policy.version !== 1 || Object.keys(policy).sort().join() !== "forced_provider_preferences,official_only,version") {
    throw new TypeError("Unverifiable data policy");
  }
  return dataPolicy(policy);
}
