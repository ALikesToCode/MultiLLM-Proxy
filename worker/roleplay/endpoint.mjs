import { DurableObject } from "cloudflare:workers";

import {
  ROLEPLAY_METRICS_PATH,
  ROLEPLAY_MODELS_PATH,
  extractBearerToken,
  hasRoleplayAuthentication,
  isAuthorizedRoleplayToken,
  isRoleplayPath,
  isRoleplayTurnPath,
  isValidRoleplaySessionId,
  resolveRoleplaySession,
  responseWithRoleplaySession,
} from "./compatibility.mjs";
import {
  createCompactionCheckpoint,
  reuseCompactionCheckpoint,
} from "./checkpoint.mjs";
import { prepareProtectedContext } from "./directives.mjs";
import { createExtractiveCompactionDigest } from "./fallback-memory.mjs";
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

export { isRoleplayPath };

const STATE_KEY = "roleplay-session";
const MESSAGES_KEY = "roleplay-messages";
const DIRECTIVES_KEY = "roleplay-directives";

function initialState() {
  return {
    version: 2,
    memory: null,
    compactionCheckpoint: null,
    messages: [],
    directives: [],
    profile: {},
    stats: {},
    turns: 0,
    compactions: 0,
    localCompactions: 0,
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
    version: 2,
    messages: Array.isArray(value.messages) ? value.messages : [],
    directives: Array.isArray(value.directives)
      ? value.directives
      : [],
    compactionCheckpoint:
      value.compactionCheckpoint &&
      typeof value.compactionCheckpoint === "object" &&
      !Array.isArray(value.compactionCheckpoint)
        ? value.compactionCheckpoint
        : null,
    profile:
      value.profile && typeof value.profile === "object" ? value.profile : {},
    stats: value.stats && typeof value.stats === "object" ? value.stats : {},
    recentRequests: Array.isArray(value.recentRequests)
      ? value.recentRequests
      : [],
  };
}

async function loadState(storage) {
  const [core, messages, directives] = await Promise.all([
    storage.get(STATE_KEY),
    storage.get(MESSAGES_KEY),
    storage.get(DIRECTIVES_KEY),
  ]);
  return normalizeState({
    ...(core && typeof core === "object" ? core : {}),
    messages: Array.isArray(messages) ? messages : [],
    directives: Array.isArray(directives)
      ? directives
      : Array.isArray(core?.directives)
        ? core.directives
        : [],
  });
}

async function saveState(storage, state) {
  const { directives, messages, ...core } = state;
  await storage.put({
    [STATE_KEY]: core,
    [MESSAGES_KEY]: messages,
    [DIRECTIVES_KEY]: directives,
  });
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
    if (!isValidRoleplaySessionId(sessionId)) {
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
    return responseWithRoleplaySession(response, sessionId, "explicit");
  }

  if (
    !isRoleplayTurnPath(requestUrl.pathname) ||
    request.method !== "POST"
  ) {
    return errorResponse("Method not allowed", 405, "method_not_allowed");
  }

  try {
    const payload = await readBoundedJsonRequest(
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
    const response = await stub.fetch(
      new Request("https://roleplay.internal/turn", {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: request.signal,
      }),
    );
    return responseWithRoleplaySession(
      response,
      session.id,
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
        local_compactions: state.localCompactions,
        storage_overflow: state.storageOverflow,
        stored_messages: state.messages.length,
        protected_directives: state.directives.length,
        estimated_protected_directive_tokens: estimateTokens(
          state.directives,
        ),
        compacted_prefix_messages:
          state.compactionCheckpoint?.messageCount ?? 0,
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
    const { profile, parsed: parsedWithProfile } = effectiveCharacter(
      state,
      parsedInitial,
    );
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

    const memoryEnabled = parsedWithProfile.memory.mode !== "off";
    const protectedContext = prepareProtectedContext(
      state,
      parsedWithProfile,
      memoryEnabled,
    );
    state = protectedContext.state;
    if (
      estimateTokens(protectedContext.activeDirectives) >
      settings.hardInputTokens
    ) {
      throw new RoleplayRequestError(
        "Protected system and developer instructions exceed the safe input limit and will not be compacted",
        413,
      );
    }
    const checkpoint = memoryEnabled
      ? await reuseCompactionCheckpoint(
          state,
          protectedContext.parsed,
        )
      : {
          parsed: protectedContext.parsed,
          sourceMessages: protectedContext.parsed.messages,
          matched: false,
        };
    const parsed = checkpoint.parsed;
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
      : {
          ...state,
          memory: null,
          messages: [],
          directives: protectedContext.activeDirectives,
          profile: {},
        };
    let conversation = mergeSessionMessages(memoryState, parsed);
    // Generation may include one raw overflow turn that the compacted state
    // intentionally retains only through its semantic digest.
    let persistedConversation = conversation;
    let memoryStatus = memoryEnabled
      ? checkpoint.matched
        ? "checkpoint_reused"
        : "retained"
      : "off";
    const plan = compactionPlan(
      memoryState,
      parsed,
      conversation,
      settings,
    );

    if (plan.requested) {
      let compactionDigest;
      let compactionSource = "model";
      try {
        const compacted = await requestCompaction(
          memoryState,
          plan,
          candidates,
          this.env,
          settings,
          request.signal,
        );
        compactionDigest = compacted.digest;
        if (plan.forced && !compactionDigest.compact) {
          throw new Error("Model declined required memory compaction");
        }
      } catch (error) {
        logRoleplayError("roleplay_compaction_failed", error, {
          forced: plan.forced,
          olderMessages: plan.olderMessages.length,
        });
        if (plan.forced) {
          compactionDigest = createExtractiveCompactionDigest(
            memoryState,
            plan,
            settings,
          );
          compactionSource = "local";
          state = {
            ...state,
            localCompactions: (state.localCompactions ?? 0) + 1,
          };
        } else {
          memoryStatus = "compaction_failed_retained";
        }
      }

      if (compactionDigest) {
        const nextCheckpoint = compactionDigest.compact
          ? await createCompactionCheckpoint(
              state,
              parsed,
              checkpoint.sourceMessages,
              plan,
              checkpoint.matched,
            )
          : state.compactionCheckpoint;
        const applied = applyCompaction(
          state,
          plan,
          compactionDigest,
          nextCheckpoint,
        );
        state = applied.state;
        persistedConversation = applied.conversation;
        conversation = applied.compacted
          ? [...applied.conversation, ...plan.transientMessages]
          : applied.conversation;
        memoryStatus = applied.compacted
          ? `${compactionSource}_compacted`
          : "model_retained";
        if (applied.compacted) {
          await saveState(this.ctx.storage, state);
        }
      }
    }

    const projectedStoredBytes =
      new TextEncoder().encode(
        JSON.stringify(persistedConversation),
      ).byteLength +
      parsed.maxTokens * 12;
    if (
      memoryEnabled &&
      projectedStoredBytes > settings.maxStoredBytes
    ) {
      state = markRequest(state, idempotencyKey, "compaction_failed");
      await saveState(this.ctx.storage, state);
      return {
        response: errorResponse(
          "Automatic memory compaction could not produce a safe retained window",
          503,
          "memory_compaction_failed",
        ),
        completion: Promise.resolve(),
      };
    }

    const roleplayMessages = buildRoleplayMessages(
      memoryEnabled ? state : memoryState,
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
              persistedConversation,
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
        persistedConversation,
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
