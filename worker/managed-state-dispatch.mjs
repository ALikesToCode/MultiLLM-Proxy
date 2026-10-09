/** Fixed private managed-state domains; sibling authorities are injected explicitly. */
import { handleTenantRequest, TENANT_STORE_PATH, scimPrincipalStatements, scimTeamStatements } from "./tenants-d1.mjs";
import { handleSamlIdentityRequest } from "./saml-identity.mjs";
import { handleScimStateRequest } from "./scim-d1.mjs";
import { handleCreditsRequest } from "./credits-d1.mjs";
import { handlePaymentStoreRequest } from "./payment-webhooks.mjs";
import { handleIdempotencyRequest } from "./idempotency-d1.mjs";
import { handleResponsesStateRequest } from "./responses-state-d1.mjs";
import { handleContextPageStateRequest } from "./context-pages-d1.mjs";
import { handleUsageReceiptStoreRequest } from "./usage-receipts.mjs";

export function handleManagedStateRequest(request, env, { reservations, toolGrants, tenantContext } = {}) {
  const url = new URL(request.url);
  if (url.pathname === TENANT_STORE_PATH) return handleTenantRequest(request, env);
  if (!url.pathname.startsWith("/v1/managed-state/")) return null;
  if (url.origin !== "http://intelligence.internal" || url.search || url.hash || url.username || url.password || request.method !== "POST") {
    return Response.json({ version: 1, error: { code: "invalid_store_target", message: "Invalid managed storage target." } }, { status: 400 });
  }
  if (url.pathname === "/v1/managed-state/saml") return handleSamlIdentityRequest(request, env);
  if (url.pathname === "/v1/managed-state/scim") return handleScimStateRequest(request, env, {
    adminUsername: env.ADMIN_USERNAME || "admin",
    principalStatements: data => scimPrincipalStatements(env.INTELLIGENCE_DB, data),
    membershipStatements: data => scimPrincipalStatements(env.INTELLIGENCE_DB, data),
    teamStatements: data => scimTeamStatements(env.INTELLIGENCE_DB, data),
  });
  if (url.pathname === "/v1/managed-state/credits") return handleCreditsRequest(request, env);
  if (url.pathname === "/v1/managed-state/payments") return handlePaymentStoreRequest(request, env);
  if (url.pathname === "/v1/managed-state/idempotency") return handleIdempotencyRequest(request, env, { tenantContext });
  if (url.pathname === "/v1/managed-state/responses") return handleResponsesStateRequest(request, env, { tenantContext });
  if (url.pathname === "/v1/managed-state/context-pages") return handleContextPageStateRequest(request, env, { tenantContext });
  if (url.pathname === "/v1/managed-state/usage-receipts") return handleUsageReceiptStoreRequest(request, env);
  if (url.pathname === "/v1/managed-state/reservations" && reservations) return reservations(request, env);
  if (url.pathname === "/v1/managed-state/tool-grants" && toolGrants) return toolGrants(request, env);
  return Response.json({ version: 1, error: { code: "not_found", message: "Managed storage operation not found." } }, { status: 404 });
}
