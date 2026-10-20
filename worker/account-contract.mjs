/** Negotiate additive account metadata before crossing a strict Container decoder. */
import { controlled } from "./key-controls-capability.mjs";
import { verifyDataPolicy } from "./dispatch-policy.mjs";

export const ACCOUNT_POLICY_VERSION = 1;
const POLICY_FIELDS = new Set(["official_only", "forced_provider_preferences", "data_policy"]);

export function accountPolicyVersion(body) {
  if (!Object.hasOwn(body, "data_policy_version")) return null;
  if (body.data_policy_version !== ACCOUNT_POLICY_VERSION) throw new Error("Unsupported account policy version");
  delete body.data_policy_version;
  return ACCOUNT_POLICY_VERSION;
}

export const hasAccountPolicy = controlled;

export function accountReply(row, version) {
  if (!row || version === ACCOUNT_POLICY_VERSION) return row;
  // Expansion decoders understand controlled rows and refuse their dispatch.
  // Older strict decoders also refuse this shape; never project controls away.
  verifyDataPolicy(row.data_policy);
  if (hasAccountPolicy(row)) return row;
  return Object.fromEntries(Object.entries(row).filter(([name]) => !POLICY_FIELDS.has(name)));
}

export function accountWrite(user, version) {
  if (version === ACCOUNT_POLICY_VERSION || !user || typeof user !== "object" || Array.isArray(user)) return user;
  if ([...POLICY_FIELDS].some(name => Object.hasOwn(user, name))) throw new Error("Account policy requires negotiation");
  return { ...user, official_only: null, forced_provider_preferences: null };
}
