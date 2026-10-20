/** Headerless private calls are compatible only with the expansion Container fence. */
import { legacyDataControls } from "./key-data-guards.mjs";
export async function legacyBindingControls(env) {
  try { return await legacyDataControls(env); }
  catch (error) {
    // Store outages and malformed rows never acquire an alternate authority.
    if (error.code !== "legacy_controlled_accounts") throw error;
    const container = env.MULTILLM_PROXY_CONTAINER?.getByName("primary");
    const response = await container.fetch("https://container.internal/healthz", {
      method: "GET", redirect: "manual", signal: AbortSignal.timeout(5000),
    });
    const capability = (await response.json()).key_controls;
    if (!response.ok || capability?.protocol !== 1 || capability.enforcement !== false) throw Error("Unverifiable legacy sender");
    // A's Container rereads and refuses controlled accounts before this private
    // hop. It sends no new headers, so a verified A sender proves this call is NULL.
    return { official_only: null, forced_provider_preferences: null };
  }
}
