import { handleIntelligenceStoreRequest } from "./intelligence-d1.mjs";
import { handleIntelligenceAuthRequest } from "./intelligence-auth-d1.mjs";
import { handleControlUsersRequest } from "./control-users-d1.mjs";
import { handleAutoRoutesRequest } from "./auto-routes-d1.mjs";
import { handleControlStateRequest } from "./control-state-d1.mjs";

/** Domain operations reachable only through the container's private outbound handler. */
export function handleIntelligenceOutbound(request, env) {
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.search || url.hash || url.username || url.password) {
    return Response.json({ error: { code: "invalid_store_target", message: "Invalid storage target." } }, { status: 400 });
  }
  if (request.method !== "POST") {
    return Response.json({ error: { code: "method_not_allowed", message: "Use POST for storage operations." } },
      { status: 405, headers: { Allow: "POST" } });
  }
  if (url.pathname === "/v1/store") return handleIntelligenceStoreRequest(request, env);
  if (url.pathname === "/v1/auth") return handleIntelligenceAuthRequest(request, env);
  if (url.pathname === "/v1/users") return handleControlUsersRequest(request, env);
  if (url.pathname === "/v1/auto-routes") return handleAutoRoutesRequest(request, env);
  if (url.pathname.startsWith("/v1/state/")) return handleControlStateRequest(request, env);
  return Response.json({ error: { code: "not_found", message: "Storage operation not found." } }, { status: 404 });
}
