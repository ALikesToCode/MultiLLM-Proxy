// Immutable policy snapshots belong to requests, including their deferred callbacks.
export const RETENTION_HEADER = "X-MultiLLM-Retention";
const OFF = Object.freeze({ mode: "inherit", enabled: false });
const MODES = new Set(["inherit", "zero"]);
const warned = new Set();

function warnOnce(setting) {
  if (warned.has(setting)) return;
  warned.add(setting);
  console.warn(`Invalid ${setting}; content retention controls disabled`);
}

function rules(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.entries(value).every(([key, mode]) => key.length && MODES.has(mode));
}

export function resolveRetentionPolicy(env = {}, { keyId = "", keyHash = "", route = "", header = "" } = {}) {
  const flag = String(env.CONTENT_RETENTION_ENABLED ?? "").trim().toLowerCase();
  if (["", "0", "false", "no", "off"].includes(flag)) return OFF;
  if (!["1", "true", "yes", "on"].includes(flag)) { warnOnce("CONTENT_RETENTION_ENABLED"); return OFF; }
  let config;
  try {
    config = JSON.parse(String(env.CONTENT_RETENTION_POLICY_JSON ?? "").trim() || "{}");
    if (!config || typeof config !== "object" || Array.isArray(config)
      || Object.keys(config).some(key => !["default", "keys", "routes"].includes(key))
      || !MODES.has(Object.hasOwn(config, "default") ? config.default : "inherit")
      || !rules(Object.hasOwn(config, "keys") ? config.keys : {})
      || !rules(Object.hasOwn(config, "routes") ? config.routes : {})) throw new Error("invalid_policy");
  } catch { warnOnce("CONTENT_RETENTION_POLICY_JSON"); return OFF; }
  const modes = [config.default, config.keys?.[keyId], config.keys?.[keyHash], config.routes?.[route], String(header).trim().toLowerCase()];
  return Object.freeze({ mode: modes.includes("zero") ? "zero" : "inherit", enabled: true });
}

export function retentionAllowsContent(policy) {
  return !policy?.enabled || policy.mode !== "zero";
}

// Private service bindings transport snapshots, never caller-selected identities.
export function retentionPolicySnapshot(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== 2 || !MODES.has(value.mode) || typeof value.enabled !== "boolean") {
    throw new TypeError("invalid_retention_policy");
  }
  return Object.freeze({ mode: value.mode, enabled: value.enabled });
}

export async function retentionRequestId(value) {
  if (!value) return "";
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
}

// Only the authenticated edge may set identity headers on an internal DO request.
export function resolveRoleplayRetention(env, request) {
  return resolveRetentionPolicy(env, {
    keyId: request.headers.get("X-MultiLLM-Retention-Key-ID") ?? "",
    keyHash: request.headers.get("X-MultiLLM-Retention-Key-Hash") ?? "",
    route: request.headers.get("X-MultiLLM-Retention-Route") ?? new URL(request.url).pathname,
    header: request.headers.get(RETENTION_HEADER) ?? "",
  });
}

export function retentionResponse(response, policy) {
  if (!retentionAllowsContent(policy)) {
    response.headers.set(RETENTION_HEADER, "zero");
    response.headers.set("X-MultiLLM-Roleplay-Recovery", "unavailable");
  }
  return response;
}

const NO_CONTENT_CACHE = Object.freeze({ async match() { return undefined; }, async put() {} });
export function retentionKnowledgeOptions(policy, options = {}) {
  if (!policy?.enabled) return options;
  return { ...options, retentionPolicy: policy,
    ...(!retentionAllowsContent(policy) ? { cache: NO_CONTENT_CACHE } : {}) };
}
