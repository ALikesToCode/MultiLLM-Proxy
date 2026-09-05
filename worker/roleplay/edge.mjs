import { ROLEPLAY_METRICS_PATH, ROLEPLAY_MODELS_PATH, extractBearerToken, hasRoleplayAuthentication, isDerivedRoleplaySessionId, isAuthorizedRoleplayToken, isRoleplayTurnPath, isValidRoleplaySessionId, resolveRoleplaySession, responseWithRoleplaySession, scopePublicRoleplaySessionId } from "./compatibility.mjs";
import { getRoleplaySettings, roleplayCatalog, ROLEPLAY_SAFE_FALLBACK_STATUSES } from "./config.mjs";
import { ROLEPLAY_PUBLIC_MODEL_ALIASES } from "./model-selection.mjs";
import { RoleplayRequestError } from "./memory.mjs";
import { errorResponse, jsonResponse, logRoleplayError, readBoundedBytes } from "./transport.mjs";
import { handleRoleplayOperatorRequest } from "./operator-edge.mjs";

const JANITOR_ORIGINS = new Set([
  "https://janitorai.com",
  "https://www.janitorai.com",
]);
const INTERNAL_OUTPUT_MODE_HEADER = "X-MultiLLM-Roleplay-Output-Mode";

async function readBoundedJsonRequest(request, maximumBytes) {
  const declaredLength = Number.parseInt(
    request.headers.get("Content-Length") ?? "",
    10,
  );
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new RoleplayRequestError(
      `Request body exceeds ${maximumBytes} bytes`,
      413,
    );
  }

  const { bytes } = await readBoundedBytes(
    request.body,
    maximumBytes,
    request.signal,
  );
  if (!bytes.byteLength) {
    throw new RoleplayRequestError("Request body must not be empty");
  }
  const bodyText = new TextDecoder().decode(bytes);
  try {
    return {
      bodyText,
      payload: JSON.parse(bodyText),
    };
  } catch {
    throw new RoleplayRequestError("Request body must be valid JSON");
  }
}

function getIdempotencyKey(payload, request) {
  const value =
    request.headers.get("Idempotency-Key") ?? payload?.idempotency_key ?? "";
  if (value === "") {
    return "";
  }
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 200 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new RoleplayRequestError(
      "Idempotency-Key must be 1-200 visible characters",
    );
  }
  return value.trim();
}

function locationHint(request) {
  const continent = request.cf?.continent;
  if (continent === "NA") {
    return "wnam";
  }
  if (continent === "SA") {
    return "sam";
  }
  if (continent === "EU") {
    return "weur";
  }
  if (continent === "AF") {
    return "afr";
  }
  if (continent === "OC") {
    return "oc";
  }
  if (continent === "AS") {
    return "apac";
  }
  return undefined;
}

function roleplayStub(env, sessionId, request) {
  const hint = locationHint(request);
  return hint
    ? env.ROLEPLAY_SESSION.getByName(sessionId, { locationHint: hint })
    : env.ROLEPLAY_SESSION.getByName(sessionId);
}

function janitorUnlimitedOutput(request) {
  return JANITOR_ORIGINS.has(request.headers.get("Origin") ?? "");
}

export async function handleRoleplayEdgeRequest(request, env) {
  if (new URL(request.url).pathname.startsWith("/v1/roleplay/control/")) {
    return handleRoleplayOperatorRequest(request, env);
  }
  if (
    !env.ROLEPLAY_SESSION ||
    typeof env.ROLEPLAY_SESSION.getByName !== "function"
  ) {
    return errorResponse(
      "Roleplay session storage is not configured",
      503,
      "roleplay_not_configured",
    );
  }

  if (!hasRoleplayAuthentication(env)) {
    return errorResponse(
      "Roleplay authentication is not configured",
      503,
      "roleplay_not_configured",
    );
  }
  const providedToken = extractBearerToken(request);
  if (!(await isAuthorizedRoleplayToken(providedToken, env))) {
    return errorResponse("Authentication required", 401, "unauthorized");
  }

  const requestUrl = new URL(request.url);
  const settings = getRoleplaySettings(env);

  if (requestUrl.pathname === ROLEPLAY_MODELS_PATH) {
    if (request.method !== "GET") {
      return errorResponse("Method not allowed", 405, "method_not_allowed");
    }
    return jsonResponse({
      object: "list",
      data: roleplayCatalog(env, settings),
      selection: {
        provider_order: settings.providerOrder,
        policy: "strict_provider_subscription_safe_with_optional_tps_ranking",
        quality_latency_premium_percent:
          settings.qualityLatencyPremiumPercent,
        quality_minimum_samples: settings.qualityMinimumSamples,
        speed_reference_output_tokens:
          settings.speedReferenceOutputTokens,
        safe_fallback_statuses: ROLEPLAY_SAFE_FALLBACK_STATUSES,
        model_aliases: ROLEPLAY_PUBLIC_MODEL_ALIASES,
      },
    });
  }

  if (requestUrl.pathname === ROLEPLAY_METRICS_PATH) {
    if (request.method !== "GET") {
      return errorResponse("Method not allowed", 405, "method_not_allowed");
    }
    const sessionId = requestUrl.searchParams.get("session_id") ?? "";
    if (!isValidRoleplaySessionId(sessionId)) {
      return errorResponse(
        "session_id query parameter is required",
        400,
        "invalid_session_id",
      );
    }
    const storageSessionId = isDerivedRoleplaySessionId(sessionId)
      ? sessionId
      : await scopePublicRoleplaySessionId(sessionId, providedToken);
    const stub = roleplayStub(env, storageSessionId, request);
    const response = await stub.fetch(
      new Request("https://roleplay.internal/metrics", {
        method: "GET",
        signal: request.signal,
      }),
    );
    return responseWithRoleplaySession(response, sessionId, "explicit");
  }

  if (
    !isRoleplayTurnPath(requestUrl.pathname) ||
    request.method !== "POST"
  ) {
    return errorResponse("Method not allowed", 405, "method_not_allowed");
  }

  try {
    const { bodyText, payload } = await readBoundedJsonRequest(
      request,
      settings.maxRequestBytes,
    );
    const session = await resolveRoleplaySession(
      payload,
      request,
      providedToken,
    );
    if (session.error) {
      throw new RoleplayRequestError(session.error);
    }
    const idempotencyKey = getIdempotencyKey(payload, request);
    const stub = roleplayStub(env, session.id, request);
    const headers = new Headers({ "Content-Type": "application/json" });
    if (idempotencyKey) {
      headers.set("Idempotency-Key", idempotencyKey);
    }
    if (janitorUnlimitedOutput(request)) {
      headers.set(INTERNAL_OUTPUT_MODE_HEADER, "unlimited");
    }
    const response = await stub.fetch(
      new Request("https://roleplay.internal/turn", {
        method: "POST",
        headers,
        body: bodyText,
        signal: request.signal,
      }),
    );
    return responseWithRoleplaySession(
      response,
      session.publicId,
      session.source,
    );
  } catch (error) {
    if (error instanceof RoleplayRequestError) {
      return errorResponse(
        error.message,
        error.status,
        error.status === 413 ? "request_too_large" : "invalid_request",
      );
    }
    if (request.signal.aborted || error?.name === "AbortError") {
      return errorResponse(
        "Roleplay request was aborted by the client",
        499,
        "request_aborted",
      );
    }
    logRoleplayError("roleplay_edge_request_failed", error);
    return errorResponse(
      "Roleplay request could not be handled",
      502,
      "roleplay_unavailable",
    );
  }
}
