import { ANY_PUBLIC_HOST, fields, integer, fail, isRecord, publicHost, PROVIDER_IDS } from "./contracts.mjs";

// Discoveries from hosts that only "*" admits are kept for a shorter time than reviewed sources.
export const UNREVIEWED_RETENTION_HOURS = 24;

export function defaultPolicy() {
  return {
    revision: 1, enabled: false, cache_ttl_seconds: 300, retention_hours: 168,
    unreviewed_retention_hours: UNREVIEWED_RETENTION_HOURS,
    allowed_hosts: ["developers.cloudflare.com", "flask.palletsprojects.com", "werkzeug.palletsprojects.com",
      "docs.python.org", "github.com", "raw.githubusercontent.com", "nextjs.org", "react.dev"],
    providers: Object.fromEntries(PROVIDER_IDS.map(id => [id, {
      enabled: false, limit: 0, background_limit: 0, interactive_reserve: 0, units_per_call: 1,
      hard_limit_confirmed: false, retention_allowed: false,
    }])),
  };
}

export function withProviderDefaults(policy) {
  return { ...policy, unreviewed_retention_hours: policy.unreviewed_retention_hours ?? UNREVIEWED_RETENTION_HOURS,
    providers: { ...defaultPolicy().providers, ...policy.providers } };
}

/**
 * An operator reviewed a source by registering it or by listing its host. A source that
 * only the "*" policy admits is unreviewed, whatever its content claims about itself.
 */
export function sourceReviewed(source, policy) {
  if (source?.identity_confirmed === true) return true;
  try { return policy.allowed_hosts.includes(new URL(source.url).hostname); }
  catch { return false; }
}

export function retentionHours(source, policy) {
  return sourceReviewed(source, policy) ? policy.retention_hours
    : Math.min(policy.retention_hours, policy.unreviewed_retention_hours ?? UNREVIEWED_RETENTION_HOURS);
}

export function validatePolicy(body) {
  fields(body, ["expected_revision", "enabled", "cache_ttl_seconds", "retention_hours", "unreviewed_retention_hours", "allowed_hosts", "providers"],
    ["expected_revision", "enabled", "cache_ttl_seconds", "retention_hours", "allowed_hosts", "providers"]);
  integer(body.expected_revision, 1, Number.MAX_SAFE_INTEGER - 1, "expected_revision");
  if (typeof body.enabled !== "boolean" || !Array.isArray(body.allowed_hosts)
    || !body.allowed_hosts.length || body.allowed_hosts.length > 100
    || body.allowed_hosts.some(host => host !== ANY_PUBLIC_HOST && !publicHost(host))
    || new Set(body.allowed_hosts).size !== body.allowed_hosts.length) {
    fail("invalid_policy", "Policy requires an enabled flag and unique approved public hostnames, or * for any public host.");
  }
  integer(body.cache_ttl_seconds, 0, 3600, "cache_ttl_seconds");
  integer(body.retention_hours, 1, 720, "retention_hours");
  if (body.unreviewed_retention_hours !== undefined) integer(body.unreviewed_retention_hours, 1, 720, "unreviewed_retention_hours");
  if (!isRecord(body.providers) || Object.keys(body.providers).some(id => !PROVIDER_IDS.includes(id))
    || PROVIDER_IDS.filter(id => id !== "alexandria").some(id => !Object.hasOwn(body.providers, id))) fail("invalid_policy", "Configure every provider allocation.");
  for (const allocation of Object.values(body.providers)) {
    fields(allocation, ["enabled", "limit", "background_limit", "interactive_reserve", "units_per_call", "hard_limit_confirmed", "retention_allowed"],
      ["enabled", "limit", "background_limit", "interactive_reserve", "units_per_call", "hard_limit_confirmed", "retention_allowed"]);
    for (const name of ["enabled", "hard_limit_confirmed", "retention_allowed"]) {
      if (typeof allocation[name] !== "boolean") fail("invalid_policy", `${name} must be a boolean.`);
    }
    for (const name of ["limit", "background_limit", "interactive_reserve"]) integer(allocation[name], 0, 100000, name);
    integer(allocation.units_per_call, 1, 100000, "units_per_call");
    if (allocation.background_limit > allocation.limit || allocation.interactive_reserve > allocation.limit) {
      fail("invalid_policy", "Background and interactive allocations must fit within the provider limit.");
    }
    if (allocation.enabled && (!allocation.hard_limit_confirmed || !allocation.retention_allowed || !allocation.limit)) {
      fail("invalid_policy", "Enabling a provider requires a finite allowance, confirmed upstream billing controls and permitted retention.");
    }
  }
  const { expected_revision, ...policy } = structuredClone(body);
  return { ...withProviderDefaults(policy), revision: expected_revision + 1 };
}
