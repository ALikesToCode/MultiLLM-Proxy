export class ProviderError extends Error {
  constructor(provider, code, message, status = 502) {
    super(message);
    this.name = "ProviderError";
    this.provider = provider;
    this.code = code;
    this.status = status;
  }
}

export function invalidResponse(provider) {
  return new ProviderError(provider, "provider_invalid_response", "The knowledge provider returned an invalid response.");
}

function retryDelay(headers, quota, now) {
  const retry = headers.get("retry-after");
  const after = retry && /^\d+$/.test(retry) ? Number(retry) : (Date.parse(retry) - now) / 1000;
  const reset = Number(headers.get("ratelimit-reset"));
  const seconds = Math.max(Number.isFinite(after) ? after : 0, Number.isFinite(reset) ? reset - now / 1000 : 0);
  return Math.min(31 * 86400, Math.max(1, Math.ceil(seconds || (quota ? 86400 : 60))));
}

export function upstreamError(provider, status, headers = new Headers(), body = null, now = Date.now()) {
  const code = status === 429 ? "provider_rate_limited" : status === 402 ? "provider_allowance_exhausted"
    : [401, 403].includes(status) ? "provider_access_denied" : "provider_request_failed";
  const error = new ProviderError(provider, code, "The knowledge provider could not complete the request.", status);
  if (provider === "alexandria" && status === 403 && body?.code === "THIRD_PARTY_DATA_TERMS_REQUIRED") {
    error.code = "provider_terms_required";
    error.message = "An organization admin must review and accept this provider's terms in Firecrawl before execution.";
    error.requires_action = { type: "accept_terms", url: "https://www.firecrawl.dev/app/settings?tab=data-sources" };
  }
  // A top-level quota refusal is eligible only without evidence of accepted work.
  // Successful HTTP responses with per-capability failures never reach this path.
  if (![402, 429].includes(status) || !body || typeof body !== "object" || Array.isArray(body)
    || body.success === true || body.chargeId || body.scrape_id || body.scrapeId || body.data || body.results || body.executed
    || body.creditsCost || body.creditsUsed || body.code === "request_unresolved") return error;
  const declared = [body.code, body.error, body.message].filter(value => typeof value === "string").join(" ").slice(0, 2000);
  if (provider === "alexandria" && !(status === 402 && body.code === "insufficient_credits")
    && !(status === 429 && /rate.?limit/i.test(declared))) return error;
  if (!["context7", "exa", "firecrawl", "alexandria"].includes(provider)) return error;
  if (status === 402 || /quota|credit|rate.?limit|too many requests|request limit/i.test(declared)) {
    const quota = status === 402 || /quota|credit|monthly/i.test(declared);
    error.key_rejection = { reason: quota ? "quota" : "rate_limit", cooldown_seconds: retryDelay(headers, quota, now) };
    error.no_charge = true;
  }
  return error;
}
