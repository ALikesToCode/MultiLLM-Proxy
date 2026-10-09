import { handleTenantGovernanceRequest } from "./tenant-governance-d1.mjs";
import { handleAdmissionRequest } from "./admission-do.mjs";
import { handleIntelligenceStoreRequest } from "./intelligence-d1.mjs";
import { handleIntelligenceAuthRequest } from "./intelligence-auth-d1.mjs";
import { handleControlUsersRequest } from "./control-users-d1.mjs";
import { handleAutoRoutesRequest } from "./auto-routes-d1.mjs";
import { handleRevisionedAutoRoutes } from "./config-revision.mjs";
import { boundedBody } from "./control-users-d1.mjs";
import { handleCascadesRequest } from "./cascades-d1.mjs";
import { handleControlStateRequest } from "./control-state-d1.mjs";
import { handleRouteHealthRequest } from "./route-health-d1.mjs";
import { handleUsageLedgerRequest } from "./usage-ledger-d1.mjs";
import { handleShadowEvalRequest } from "./shadow-eval-d1.mjs";
import { handleMediaJobsRequest } from "./media-jobs.mjs";
import { handleReservationsRequest } from "./reservations-d1.mjs";
import { handleBatchRequest } from "./batch-jobs.mjs";
import { handleManagedStateRequest } from "./managed-state-dispatch.mjs";

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
  if (url.pathname === "/v1/tenant-governance") return handleTenantGovernanceRequest(request, env);
  if (url.pathname === "/v1/reservations") return handleReservationsRequest(request, env);
  if (url.pathname === "/v1/gateway-batches") return handleBatchRequest(request, env);
  if (url.pathname === "/v1/admission") return handleAdmissionRequest(request, env);
  if (url.pathname === "/v1/store") return handleIntelligenceStoreRequest(request, env);
  if (url.pathname === "/v1/auth") return handleIntelligenceAuthRequest(request, env);
  if (url.pathname === "/v1/users") return handleControlUsersRequest(request, env);
  if (url.pathname === "/v1/auto-routes") return handleRevisionedAutoRoutes(request, env, { handleAutoRoutesRequest, boundedBody });
  if (url.pathname === "/v1/cascades") return handleCascadesRequest(request, env);
  if (url.pathname.startsWith("/v1/state/")) return handleControlStateRequest(request, env);
  if (url.pathname === "/v1/route-health") return handleRouteHealthRequest(request, env);
  if (url.pathname === "/v1/usage") return handleUsageLedgerRequest(request, env);
  if (url.pathname === "/v1/shadow-eval") return handleShadowEvalRequest(request, env);
  if (url.pathname === "/v1/media-jobs") return handleMediaJobsRequest(request, env);
  if (url.pathname.startsWith("/v1/managed-state/")) return handleManagedStateRequest(request, env);
  return Response.json({ error: { code: "not_found", message: "Storage operation not found." } }, { status: 404 });
}
