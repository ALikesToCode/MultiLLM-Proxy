import { fail, fields, integer } from "./contracts.mjs";

const VALID_PROVIDERS = new Set(["context7", "exa", "firecrawl"]);
const isFingerprint = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const validFingerprints = value => Array.isArray(value) && value.length <= 32
  && value.every(isFingerprint) && new Set(value).size === value.length;

export async function credentialOperation(tx, operation, input, now) {
  if (!VALID_PROVIDERS.has(input.provider)) fail("invalid_credentials", "Invalid credential provider.");
  const key = `credentials:${input.provider}`;
  const state = await tx.get(key) ?? { active: null, blocked: {} };
  if (operation === "credentials.select") {
    fields(input, ["provider", "fingerprints", "excluded"], ["provider", "fingerprints", "excluded"]);
    if (!validFingerprints(input.fingerprints) || !input.fingerprints.length || !validFingerprints(input.excluded)
      || input.excluded.some(id => !input.fingerprints.includes(id))) fail("invalid_credentials", "Invalid credential selection.");
    // Overlapping deployments may have different key lists; neither can clear the other's cooldowns.
    state.blocked = Object.fromEntries(Object.entries(state.blocked).filter(([, record]) => record.until > now));
    const available = id => !state.blocked[id] && !input.excluded.includes(id);
    const active = input.fingerprints.includes(state.active) && available(state.active) ? state.active
      : input.fingerprints.find(available) ?? null;
    state.active = active;
    await tx.put(key, state);
    return { fingerprint: active };
  }
  if (operation === "credentials.reject") {
    fields(input, ["provider", "fingerprint", "reason", "cooldown_seconds"], ["provider", "fingerprint", "reason", "cooldown_seconds"]);
    if (!isFingerprint(input.fingerprint) || !["quota", "rate_limit"].includes(input.reason)) fail("invalid_credentials", "Invalid credential rejection.");
    integer(input.cooldown_seconds, 1, 31 * 86400, "credential cooldown");
    state.blocked[input.fingerprint] = { reason: input.reason,
      until: Math.max(state.blocked[input.fingerprint]?.until ?? 0, now + input.cooldown_seconds * 1000) };
    if (state.active === input.fingerprint) state.active = null;
    await tx.put(key, state);
    return { recorded: true };
  }
  fail("unknown_operation", "Unknown credential operation.", 404);
}
