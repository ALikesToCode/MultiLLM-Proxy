import { publicHost } from "../contracts.mjs";
import { ProviderError } from "./transport.mjs";

const SENSITIVE_QUERY = /^(?:api[-_]?key|key|token|access[-_]?token|auth|authorization|password|secret|signature|sig)$/i;

export function sourceURL(value, allowedHosts = []) {
  if (!Array.isArray(allowedHosts) || typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f\\]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.port) return null;
    if (!publicHost(url.hostname)) return null;
    if (!allowedHosts.some((host) => typeof host === "string" && host.toLowerCase() === url.hostname)) return null;
    if ([...url.searchParams.keys()].some((name) => SENSITIVE_QUERY.test(name))) return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

export function requireSourceURL(value, allowedHosts, provider) {
  const url = sourceURL(value, allowedHosts);
  if (!url) throw new ProviderError(provider, "source_not_allowed", "The source must use an approved public HTTPS host.", 400);
  return url;
}

export async function sourceOperation(operation, url) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url)));
  const suffix = [...hash.slice(0, 12)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${operation}:${suffix}`;
}

export function sourceLinks(text, allowedHosts) {
  const candidates = text.match(/https:\/\/[^\s<>"'`\[\]]+/g) || [];
  return [...new Set(candidates.map((candidate) => sourceURL(candidate.replace(/[),.;:!?]+$/, ""), allowedHosts)).filter(Boolean))].slice(0, 10);
}

export function queryText(intent, provider, maximum = 2000) {
  if (typeof intent.query !== "string" || !intent.query.trim() || intent.query.length > maximum) {
    throw new ProviderError(provider, "invalid_provider_query", "The query does not fit this knowledge provider's input limits.", 400);
  }
  return intent.query.trim();
}

export function liveAcquisition(intent) {
  return intent.freshness === "fresh" || intent.freshness === "force";
}

export function observation(provider, result, allowedHosts, maximum = 100000) {
  const url = sourceURL(result?.url, allowedHosts);
  if (!url) return null;
  const text = typeof result.text === "string" ? result.text.slice(0, maximum) : "";
  return {
    kind: text.trim() ? "source_excerpt" : "discovery", url,
    title: typeof result.title === "string" ? result.title.slice(0, 500) : url,
    text, provider, ...(text.trim() ? { freshness: "cached_or_unknown" } : {}),
  };
}
