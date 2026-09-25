const CONTROL = /[\x00-\x1f\x7f]/g;
// Long opaque tokens (keys, hashes, bound values in a driver message) never reach the logs.
const OPAQUE = /[A-Za-z0-9_$+/=-]{24,}/g;

/**
 * One structured line for a failure the caller handles itself. The message is a bounded
 * runtime or D1 diagnostic (for example "no such table: control_users"); request bodies
 * and credentials are never passed here.
 */
export function logFailure(event, error, details = {}) {
  const candidate = error instanceof Error ? error.name : "Error";
  const errorName = /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(candidate) ? candidate : "Error";
  const message = String(error?.message ?? error ?? "").replace(CONTROL, " ").replace(OPAQUE, "[redacted]").slice(0, 300);
  console.error(JSON.stringify({ event, errorName, message, ...details }));
}
