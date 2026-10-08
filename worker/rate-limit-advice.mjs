/** Gateway counters supplied by authenticated shared admission, never provider headers. */
const PREFIX = "X-MultiLLM-RateLimit-";
let warnedInvalid = false;
const capturedAdvice = new WeakSet();
const integer = (value, minimum = 0) => Number.isSafeInteger(value) && value >= minimum;

export function rateLimitHeadersEnabled(env = {}, logger = console) {
  const value = String(env.RATE_LIMIT_HEADERS_ENABLED ?? "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(value)) return true;
  if (!["", "0", "false", "no", "off"].includes(value) && !warnedInvalid) {
    warnedInvalid = true;
    logger.warn("Invalid RATE_LIMIT_HEADERS_ENABLED; advisory headers disabled");
  }
  return false;
}

function boundedSnapshot(snapshot) {
  if (!snapshot || !integer(snapshot.limit, 1)) return {};
  const result = { limit: snapshot.limit };
  if (integer(snapshot.remaining) && snapshot.remaining <= snapshot.limit) result.remaining = snapshot.remaining;
  if (integer(snapshot.reset, 1) && snapshot.reset <= 86400) result.reset = snapshot.reset;
  return result;
}

export function snapshotHeaders(snapshot) {
  return Object.fromEntries(Object.entries(boundedSnapshot(snapshot)).map(([name, value]) =>
    [PREFIX + name[0].toUpperCase() + name.slice(1), String(value)]));
}

export function captureRateLimitAdvice({ authenticated, shared, snapshot, denied = false, retryAfter } = {}) {
  if (authenticated !== true || shared !== true) return null;
  const result = Object.freeze({ snapshot: Object.freeze(boundedSnapshot(snapshot)), denied: denied === true,
    retryAfter: integer(retryAfter, 1) && retryAfter <= 86400 ? retryAfter : null });
  capturedAdvice.add(result);
  return result;
}

export function applyRateLimitAdvice(response, env, admission, { managed = true } = {}) {
  if (!rateLimitHeadersEnabled(env) || !managed || !capturedAdvice.has(admission)) return response;
  const fields = snapshotHeaders(admission.snapshot);
  const retry = response.status === 429 && admission.denied && admission.retryAfter
    && !response.headers.has("Retry-After");
  if (!Object.keys(fields).length && !retry) return response;
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(fields)) headers.set(name, value);
  if (retry) headers.set("Retry-After", String(admission.retryAfter));
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
