import { extractBearerToken, isAuthorizedRoleplayToken, isValidRoleplaySessionId,
  isDerivedRoleplaySessionId, scopePublicRoleplaySessionId } from "./compatibility.mjs";
import { errorResponse, jsonResponse } from "./transport.mjs";
import { readBoundedBytes } from "./transport.mjs";
import { previewProfile } from "./profile-receipt.mjs";
import { BUILD_ID } from "../build-id.mjs";

async function operatorBody(request) {
  const { bytes } = await readBoundedBytes(request.body, 32_768, request.signal);
  const body = JSON.parse(new TextDecoder().decode(bytes));
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid body");
  return body;
}

export async function handleRoleplayOperatorRequest(request, env) {
  const token = extractBearerToken(request);
  if (!env.ADMIN_API_KEY || !(await isAuthorizedRoleplayToken(token, { ADMIN_API_KEY: env.ADMIN_API_KEY }))) {
    return errorResponse("Administrator authentication required", 401, "unauthorized");
  }
  const url = new URL(request.url);
  const operation = url.pathname.slice("/v1/roleplay/control/".length);
  if (operation === "status" && request.method === "GET") return jsonResponse({
    build_id: BUILD_ID === "development-unbuilt" ? null : BUILD_ID,
    version_id: env.CF_VERSION_METADATA?.id || null,
    version_tag: env.CF_VERSION_METADATA?.tag || null,
    compatibility: 1, session_storage: Boolean(env.ROLEPLAY_SESSION),
  });
  if (operation === "receipt" && request.method === "POST") {
    try { return jsonResponse(previewProfile(await operatorBody(request), env)); }
    catch (error) { return errorResponse("Invalid or unavailable connection profile", error.status || 400, "invalid_profile"); }
  }
  if (!((operation === "timeline" && request.method === "GET") ||
        (["memory", "branch", "recovery"].includes(operation) && request.method === "POST"))) {
    return errorResponse("Method not allowed", 405, "method_not_allowed");
  }
  const publicId = url.searchParams.get("session_id") || "";
  if (!isValidRoleplaySessionId(publicId)) return errorResponse("A valid session_id is required", 400, "invalid_session_id");
  const scope = url.searchParams.get("scope") || "roleplay";
  if (!["roleplay", "admin"].includes(scope)) return errorResponse("Invalid session scope", 400, "invalid_scope");
  const scopeKey = scope === "admin" ? env.ADMIN_API_KEY : env.ROLEPLAY_API_KEY || env.ADMIN_API_KEY;
  const id = isDerivedRoleplaySessionId(publicId) ? publicId : await scopePublicRoleplaySessionId(publicId, scopeKey);
  if (!env.ROLEPLAY_SESSION) return errorResponse("Session storage unavailable", 503, "not_configured");
  let body = null;
  try { if (request.method === "POST") body = await operatorBody(request); }
  catch { return errorResponse("Use a JSON object within the 32 KiB limit", 400, "invalid_request"); }
  try {
    const stub = env.ROLEPLAY_SESSION.getByName(id);
    if (operation === "branch") return await createBranch(stub, body, { env, request, scopeKey, publicId });
    if (operation === "recovery" && body.action !== "inspect") return await dispatchRecovery(stub, body, { env, request, scopeKey });
    const response = await stub.fetch(new Request(`https://roleplay.internal/operator/${operation}`, {
      method: request.method, signal: request.signal,
      ...(body ? { body: JSON.stringify(body), headers: { "Content-Type": "application/json" } } : {}),
    }));
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "no-store");
    return new Response(response.body, { status: response.status, headers });
  } catch {
    return jsonResponse({ error: { code: "session_unavailable", message: "Session diagnostics unavailable" } }, 503);
  }
}

async function dispatchRecovery(source, body, { env, request, scopeKey }) {
  const prepared = await source.fetch(new Request("https://roleplay.internal/operator/recovery", {
    method: "POST", signal: request.signal, body: JSON.stringify(body),
  }));
  if (!prepared.ok) return prepared;
  const { payload } = await prepared.json();
  const publicId = "recovery-" + crypto.randomUUID();
  const id = await scopePublicRoleplaySessionId(publicId, scopeKey);
  const response = await env.ROLEPLAY_SESSION.getByName(id).fetch(new Request("https://roleplay.internal/turn", {
    method: "POST", signal: request.signal, body: JSON.stringify({ ...payload, session_id: publicId }),
    headers: { "Content-Type": "application/json", "Idempotency-Key": body.token },
  }));
  const headers = new Headers(response.headers);
  headers.set("X-Roleplay-Session-ID", publicId);
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, headers });
}

async function createBranch(source, body, { env, request, scopeKey, publicId }) {
  if (body.confirm !== true || typeof body.label !== "string" || !/^[\w .()-]{1,64}$/.test(body.label)) {
    return errorResponse("Confirm copying retained context to a new named branch", 400, "confirmation_required");
  }
  const snapshot = await source.fetch(new Request("https://roleplay.internal/operator/memory", {
    method: "POST", signal: request.signal,
    body: JSON.stringify({ action: "export-branch", revision: body.revision, confirm: true }),
  }));
  if (!snapshot.ok) return snapshot;
  const { state } = await snapshot.json();
  const branchId = "branch-" + crypto.randomUUID();
  const storageId = await scopePublicRoleplaySessionId(branchId, scopeKey);
  const imported = await env.ROLEPLAY_SESSION.getByName(storageId).fetch(new Request("https://roleplay.internal/operator/import-branch", {
    method: "POST", signal: request.signal,
    body: JSON.stringify({ state: { ...state, branch: { parent: publicId, label: body.label, createdAt: Date.now() } } }),
  }));
  if (!imported.ok) return imported;
  return jsonResponse({ session_id: branchId, parent: publicId, label: body.label, created: true });
}
