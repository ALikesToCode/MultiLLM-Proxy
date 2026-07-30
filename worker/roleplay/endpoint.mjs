import { DurableObject } from "cloudflare:workers";

import {
  buildConfiguredCandidates,
  getRoleplaySettings,
  rankRoleplayCandidates,
  roleplayCatalog,
} from "./config.mjs";
import {
  RoleplayRequestError,
  appendAssistantMessage,
  applyCompaction,
  buildRoleplayMessages,
  buildUpstreamPayload,
  compactionPlan,
  estimateTokens,
  extractAssistantContent,
  mergeSessionMessages,
  parseRoleplayPayload,
} from "./memory.mjs";
import {
  MAX_RESPONSE_BYTES,
  attemptRoleplayCandidates,
  copyUpstreamResponseHeaders,
  createObservedStream,
  decorateRoleplayHeaders,
  errorResponse,
  jsonResponse,
  logRoleplayError,
  readBoundedBytes,
  recordModelResult,
  requestCompaction,
} from "./transport.mjs";

export const ROLEPLAY_PATH = "/v1/roleplay";
export const ROLEPLAY_MODELS_PATH = "/v1/roleplay/models";
export const ROLEPLAY_METRICS_PATH = "/v1/roleplay/metrics";

const STATE_KEY = "roleplay-session";
const MESSAGES_KEY = "roleplay-messages";

function initialState() {
  return {
    version: 1,
    memory: null,
    messages: [],
    profile: {},
    stats: {},
    turns: 0,
    compactions: 0,
    storageOverflow: false,
    recentRequests: [],
    updatedAt: 0,
  };
}

function normalizeState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return initialState();
  }
  return {
    ...initialState(),
    ...value,
    messages: Array.isArray(value.messages) ? value.messages : [],
    profile:
      value.profile && typeof value.profile === "object" ? value.profile : {},
    stats: value.stats && typeof value.stats === "object" ? value.stats : {},
    recentRequests: Array.isArray(value.recentRequests)
      ? value.recentRequests
      : [],
  };
}

async function loadState(storage) {
  const [core, messages] = await Promise.all([
    storage.get(STATE_KEY),
    storage.get(MESSAGES_KEY),
  ]);
  return normalizeState({
    ...(core && typeof core === "object" ? core : {}),
    messages: Array.isArray(messages) ? messages : [],
  });
}

async function saveState(storage, state) {
  const { messages, ...core } = state;
  await storage.put({
    [STATE_KEY]: core,
    [MESSAGES_KEY]: messages,
  });
}

async function timingSafeTokenMatch(providedToken, expectedToken) {
  const encoder = new TextEncoder();
  const [providedDigest, expectedDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(providedToken ?? ""))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(expectedToken ?? ""))),
  ]);
  const providedBytes = new Uint8Array(providedDigest);
  const expectedBytes = new Uint8Array(expectedDigest);

  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return (
      Boolean(providedToken) &&
      Boolean(expectedToken) &&
      crypto.subtle.timingSafeEqual(providedBytes, expectedBytes)
    );
  }

  let mismatch = providedBytes.byteLength ^ expectedBytes.byteLength;
  for (let index = 0; index < providedBytes.byteLength; index += 1) {
    mismatch |= providedBytes[index] ^ expectedBytes[index];
  }
  return Boolean(providedToken) && Boolean(expectedToken) && mismatch === 0;
}

function extractBearerToken(request) {
  const authorization = request.headers.get("Authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() ?? "";
}

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
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new RoleplayRequestError("Request body must be valid JSON");
  }
}

function validSessionId(value) {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9_-]{8,128}$/.test(value)
  );
}

function getSessionId(payload, request) {
  const headerValue = request.headers.get("X-Roleplay-Session-ID");
  const candidate =
    typeof headerValue === "string" && headerValue.trim()
      ? headerValue.trim()
      : payload?.session_id;
  if (candidate === undefined || candidate === null || candidate === "") {
    return crypto.randomUUID();
  }
  if (!validSessionId(candidate)) {
    throw new RoleplayRequestError(
      "session_id must contain 8-128 letters, digits, underscores, or hyphens",
    );
  }
  return candidate;
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

function responseWithSession(response, sessionId) {
  const decorated = new Response(response.body, response);
  decorated.headers.set("X-Roleplay-Session-ID", sessionId);
  return decorated;
}

export function isRoleplayPath(pathname) {
  return (
    pathname === ROLEPLAY_PATH ||
    pathname === ROLEPLAY_MODELS_PATH ||
    pathname === ROLEPLAY_METRICS_PATH
  );
}

export async function handleRoleplayEdgeRequest(request, env) {
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

  if (!env.ADMIN_API_KEY) {
    return errorResponse(
      "Roleplay authentication is not configured",
      503,
      "roleplay_not_configured",
    );
  }
  const providedToken = extractBearerToken(request);
  if (!(await timingSafeTokenMatch(providedToken, env.ADMIN_API_KEY))) {
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
        policy: "latency_reliability_ewma",
        safe_fallback_statuses: [401, 403, 404, 429],
      },
    });
  }

  if (requestUrl.pathname === ROLEPLAY_METRICS_PATH) {
    if (request.method !== "GET") {
      return errorResponse("Method not allowed", 405, "method_not_allowed");
    }
    const sessionId = requestUrl.searchParams.get("session_id") ?? "";
    if (!validSessionId(sessionId)) {
      return errorResponse(
        "session_id query parameter is required",
        400,
        "invalid_session_id",
      );
    }
    const stub = roleplayStub(env, sessionId, request);
    const response = await stub.fetch(
      new Request("https://roleplay.internal/metrics", {
        method: "GET",
        signal: request.signal,
      }),
    );
    return responseWithSession(response, sessionId);
  }

  if (requestUrl.pathname !== ROLEPLAY_PATH || request.method !== "POST") {
    return errorResponse("Method not allowed", 405, "method_not_allowed");
  }

  try {
    const payload = await readBoundedJsonRequest(
      request,
      settings.maxRequestBytes,
    );
    const sessionId = getSessionId(payload, request);
    const idempotencyKey = getIdempotencyKey(payload, request);
    const stub = roleplayStub(env, sessionId, request);
    const headers = new Headers({ "Content-Type": "application/json" });
    if (idempotencyKey) {
      headers.set("Idempotency-Key", idempotencyKey);
    }
    const response = await stub.fetch(
      new Request("https://roleplay.internal/turn", {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: request.signal,
      }),
    );
    return responseWithSession(response, sessionId);
  } catch (error) {
    if (error instanceof RoleplayRequestError) {
      return errorResponse(
        error.message,
        error.status,
        error.status === 413 ? "request_too_large" : "invalid_request",
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

function markRequest(state, key, status) {
  if (!key) {
    return state;
  }
  const now = Date.now();
  const remaining = state.recentRequests
    .filter((entry) => entry?.key !== key)
    .filter((entry) => now - (entry?.at ?? 0) < 86_400_000)
    .slice(-31);
  return {
    ...state,
    recentRequests: [...remaining, { key, status, at: now }],
  };
}

function existingRequest(state, key) {
  return key
    ? state.recentRequests.find((entry) => entry?.key === key)
    : undefined;
}

function effectiveCharacter(state, parsed) {
  const supplied = Object.fromEntries(
    Object.entries(parsed.character).filter(([, value]) => Boolean(value)),
  );
  const profile = { ...state.profile, ...supplied };
  return {
    profile,
    parsed: { ...parsed, character: profile },
  };
}

export class RoleplaySession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.turnTail = Promise.resolve();
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
  }

  async fetch(request) {
    const settings = getRoleplaySettings(this.env);
    await this.ctx.storage.setAlarm(
      Date.now() + settings.sessionTtlSeconds * 1_000,
    );
    const pathname = new URL(request.url).pathname;
    if (pathname === "/metrics" && request.method === "GET") {
      await this.turnTail.catch(() => {});
      const state = await loadState(this.ctx.storage);
      const metrics = Object.fromEntries(
        Object.entries(state.stats).map(([key, value]) => [
          key,
          {
            provider: value.provider,
            model: value.model,
            family: value.family,
            attempts: value.attempts,
            successes: value.successes,
            failures: value.failures,
            consecutive_failures: value.consecutiveFailures,
            ewma_ttfb_ms: value.ewmaTtfbMs,
            ewma_total_ms: value.ewmaTotalMs,
            cooldown_until: value.cooldownUntil,
            last_status: value.lastStatus,
            last_used_at: value.lastUsedAt,
          },
        ]),
      );
      return jsonResponse({
        turns: state.turns,
        compactions: state.compactions,
        storage_overflow: state.storageOverflow,
        stored_messages: state.messages.length,
        estimated_stored_tokens: estimateTokens({
          memory: state.memory,
          messages: state.messages,
        }),
        models: metrics,
        updated_at: state.updatedAt || null,
      });
    }
    if (pathname !== "/turn" || request.method !== "POST") {
      return errorResponse("Method not allowed", 405, "method_not_allowed");
    }
    return this.enqueueTurn(request, settings);
  }

  async enqueueTurn(request, settings) {
    const previous = this.turnTail.catch(() => {});
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    this.turnTail = previous.then(() => current);
    await previous;

    try {
      const result = await this.handleTurn(request, settings);
      const completion = Promise.resolve(result.completion).finally(release);
      this.ctx.waitUntil(completion);
      return result.response;
    } catch (error) {
      release();
      if (error instanceof RoleplayRequestError) {
        return errorResponse(
          error.message,
          error.status,
          error.status === 413 ? "request_too_large" : "invalid_request",
        );
      }
      logRoleplayError("roleplay_session_turn_failed", error);
      return errorResponse(
        "Roleplay turn could not be completed",
        502,
        "roleplay_unavailable",
      );
    }
  }

  async handleTurn(request, settings) {
    const payload = await request.json();
    let state = await loadState(this.ctx.storage);
    const parsedInitial = parseRoleplayPayload(payload, settings);
    const { profile, parsed } = effectiveCharacter(state, parsedInitial);
    const idempotencyKey = request.headers.get("Idempotency-Key") ?? "";
    const duplicate = existingRequest(state, idempotencyKey);
    if (duplicate) {
      return {
        response: errorResponse(
          `Duplicate roleplay turn (${duplicate.status})`,
          409,
          "duplicate_roleplay_turn",
        ),
        completion: Promise.resolve(),
      };
    }

    const memoryEnabled = parsed.memory.mode !== "off";
    state = {
      ...state,
      ...(memoryEnabled ? { profile } : {}),
    };
    state = markRequest(state, idempotencyKey, "started");
    await saveState(this.ctx.storage, state);

    const candidates = rankRoleplayCandidates(
      buildConfiguredCandidates(this.env, settings),
      state.stats,
      parsed.modelPreference,
    );
    if (!candidates.length) {
      state = markRequest(state, idempotencyKey, "no_provider");
      await saveState(this.ctx.storage, state);
      return {
        response: errorResponse(
          "No roleplay provider is configured for this model preference",
          503,
          "no_roleplay_provider",
        ),
        completion: Promise.resolve(),
      };
    }

    const memoryState = memoryEnabled
      ? state
      : { ...state, memory: null, messages: [], profile: {} };
    let conversation = mergeSessionMessages(memoryState, parsed);
    let memoryStatus = memoryEnabled ? "retained" : "off";
    const plan = compactionPlan(
      memoryState,
      parsed,
      conversation,
      settings,
    );

    if (plan.requested) {
      try {
        const compacted = await requestCompaction(
          memoryState,
          plan,
          candidates,
          this.env,
          settings,
          request.signal,
        );
        const applied = applyCompaction(
          state,
          plan,
          compacted.digest,
        );
        if (plan.forced && !applied.compacted) {
          throw new Error("Model declined required memory compaction");
        }
        state = applied.state;
        conversation = applied.conversation;
        memoryStatus = applied.compacted ? "model_compacted" : "model_retained";
        if (applied.compacted) {
          await saveState(this.ctx.storage, state);
        }
      } catch (error) {
        logRoleplayError("roleplay_compaction_failed", error);
        if (plan.forced) {
          state = markRequest(state, idempotencyKey, "compaction_failed");
          await saveState(this.ctx.storage, state);
          return {
            response: errorResponse(
              "Memory exceeded the safe context limit and model compaction failed",
              503,
              "memory_compaction_failed",
            ),
            completion: Promise.resolve(),
          };
        }
        memoryStatus = "compaction_failed_retained";
      }
    }

    const projectedStoredBytes =
      new TextEncoder().encode(JSON.stringify(conversation)).byteLength +
      parsed.maxTokens * 12;
    if (
      memoryEnabled &&
      projectedStoredBytes > settings.maxStoredBytes
    ) {
      state = markRequest(state, idempotencyKey, "memory_storage_too_large");
      await saveState(this.ctx.storage, state);
      return {
        response: errorResponse(
          "Recent roleplay history is too large to retain safely; reduce one oversized recent message or raise the configured storage budget",
          413,
          "roleplay_memory_too_large",
        ),
        completion: Promise.resolve(),
      };
    }

    const roleplayMessages = buildRoleplayMessages(
      state,
      parsed,
      conversation,
    );
    const estimatedInputTokens = estimateTokens(roleplayMessages);
    if (estimatedInputTokens > settings.hardInputTokens) {
      state = markRequest(state, idempotencyKey, "context_too_large");
      await saveState(this.ctx.storage, state);
      return {
        response: errorResponse(
          "Roleplay context exceeds the safe input limit",
          413,
          "roleplay_context_too_large",
        ),
        completion: Promise.resolve(),
      };
    }

    const attempted = await attemptRoleplayCandidates(
      state,
      candidates,
      (candidate) =>
        buildUpstreamPayload(parsed, candidate, roleplayMessages),
      this.env,
      settings,
      request.signal,
      idempotencyKey,
    );
    state = attempted.state;
    if (attempted.terminalResponse) {
      state = markRequest(state, idempotencyKey, "provider_failed");
      await saveState(this.ctx.storage, state);
      return {
        response: attempted.terminalResponse,
        completion: Promise.resolve(),
      };
    }

    const {
      candidate,
      response,
      startedAt,
      headerMs,
      fallbackCount,
      controller,
      cleanup,
    } = attempted;
    cleanup();
    const selectionReason =
      (state.stats[candidate.key]?.successes ?? 0) < 2
        ? "exploration"
        : "adaptive_speed";
    const contentType = response.headers.get("Content-Type") ?? "";
    const responseHeaders = decorateRoleplayHeaders(
      copyUpstreamResponseHeaders(response.headers),
      candidate,
      selectionReason,
      memoryStatus,
      estimatedInputTokens,
      parsed.maxTokens,
      headerMs,
      fallbackCount,
    );

    if (
      parsed.stream &&
      response.body &&
      contentType.toLowerCase().includes("text/event-stream")
    ) {
      const observed = createObservedStream(
        response.body,
        request.signal,
        controller,
        async ({ success, assistant, ttfbMs, streamMs }) => {
          let nextState = recordModelResult(state, candidate, {
            success,
            ttfbMs: headerMs + ttfbMs,
            totalMs: performance.now() - startedAt,
            status: success ? response.status : 0,
          });
          if (success && memoryEnabled) {
            nextState = appendAssistantMessage(
              nextState,
              conversation,
              assistant,
              settings,
            );
          } else {
            nextState = { ...nextState, updatedAt: Date.now() };
          }
          nextState = markRequest(
            nextState,
            idempotencyKey,
            success ? "completed" : "stream_failed",
          );
          await saveState(this.ctx.storage, nextState);
          void streamMs;
        },
      );
      return {
        response: new Response(observed.stream, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        }),
        completion: observed.completion,
      };
    }

    const { bytes, firstByteMs } = await readBoundedBytes(
      response.body,
      MAX_RESPONSE_BYTES,
      request.signal,
    );
    let assistant = "";
    if (contentType.toLowerCase().includes("application/json")) {
      try {
        assistant = extractAssistantContent(
          JSON.parse(new TextDecoder().decode(bytes)),
        );
      } catch {
        assistant = "";
      }
    }
    state = recordModelResult(state, candidate, {
      success: true,
      ttfbMs: headerMs + firstByteMs,
      totalMs: performance.now() - startedAt,
      status: response.status,
    });
    if (memoryEnabled) {
      state = appendAssistantMessage(
        state,
        conversation,
        assistant,
        settings,
      );
    } else {
      state = { ...state, updatedAt: Date.now() };
    }
    state = markRequest(state, idempotencyKey, "completed");
    await saveState(this.ctx.storage, state);
    return {
      response: new Response(bytes, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      }),
      completion: Promise.resolve(),
    };
  }
}
