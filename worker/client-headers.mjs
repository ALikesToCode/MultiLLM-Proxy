// Shared client identity policy. Credentials and account headers are never inferred.
export const CLIENT_HEADER_NAMES = [
  "user-agent", "originator", "session-id", "thread-id", "session_id",
  "x-session-id", "x-codex-session-id", "x-session-affinity",
];
export const OPENCODE_CLIENT_HEADER_NAMES = [
  "x-opencode-session", "x-opencode-client", "x-opencode-project", "x-opencode-request",
];
const SESSION_HEADER_NAMES = [
  "thread-id", "session-id", "session_id", "x-session-id",
  "x-codex-session-id", "x-session-affinity",
];

function validValue(value) {
  return typeof value === "string" && !/[^\x20-\x7e]/.test(value) ? value.trim() : "";
}

export function clientContextHeaders(source, provider = "") {
  const input = new Headers(source);
  const names = provider === "opencode"
    ? [...CLIENT_HEADER_NAMES, ...OPENCODE_CLIENT_HEADER_NAMES]
    : CLIENT_HEADER_NAMES;
  const headers = new Headers();
  for (const name of names) {
    if (validValue(input.get(name))) headers.set(name, input.get(name));
  }
  return headers;
}

export function withClientDefaults(source, env = {}) {
  const headers = new Headers(source);
  for (const [name, setting, fallback] of [
    ["User-Agent", "UPSTREAM_DEFAULT_USER_AGENT", "codex-cli"],
    ["Originator", "UPSTREAM_DEFAULT_ORIGINATOR", "codex_cli_rs"],
  ]) {
    if (!validValue(headers.get(name))) {
      headers.set(name, validValue(env[setting]) || fallback);
    }
  }
  return headers;
}

export function withOpencodeSession(source, fallback = "") {
  const headers = new Headers(source);
  if (!validValue(headers.get("x-opencode-session"))) {
    headers.delete("x-opencode-session");
    const session = SESSION_HEADER_NAMES.map((name) => headers.get(name)).find(validValue);
    if (session || validValue(fallback)) headers.set("x-opencode-session", session || fallback);
  }
  return headers;
}
