import { DurableObject } from "cloudflare:workers";

import {
  ROLEPLAY_METRICS_PATH,
  ROLEPLAY_MODELS_PATH,
  extractBearerToken,
  hasRoleplayAuthentication,
  isDerivedRoleplaySessionId,
  isAuthorizedRoleplayToken,
  isRoleplayPath,
  isRoleplayTurnPath,
  isValidRoleplaySessionId,
  resolveRoleplaySession,
  responseWithRoleplaySession,
  scopePublicRoleplaySessionId,
} from "./compatibility.mjs";
import {
  createCompactionCheckpoint,
  reuseCompactionCheckpoint,
} from "./checkpoint.mjs";
import {
  prepareRoleplayCandidates,
  resolveRoleplayContextPolicy,
  shouldPreserveFullGeneration,
} from "./capacity.mjs";
import {
  compactionBackoffActive,
  recordCompactionFailure,
  recordCompactionSuccess,
} from "./compaction-policy.mjs";
import { prepareProtectedContext } from "./directives.mjs";
import { revalidateNanoCredential } from "./credential-health.mjs";
import { createExtractiveCompactionDigest } from "./fallback-memory.mjs";
import {
  buildConfiguredCandidates,
  getRoleplaySettings,
  rankRoleplayCandidates,
  ROLEPLAY_SAFE_FALLBACK_STATUSES,
  roleplayCatalog,
} from "./config.mjs";
import {
  RoleplayRequestError,
  assistantStorageReserveBytes,
  appendAssistantMessage,
  applyCompaction,
  buildRoleplayMessages,
  buildUpstreamPayload,
  compactionPlan,
  estimateTokens,
  extractAssistantContent,
  extractFinishReason,
  mergeSessionMessages,
  parseRoleplayPayload,
} from "./memory.mjs";
import { applyRoleplayOutputContract } from "./output-contract.mjs";
import { applyRoleplayPromptCache } from "./prompt-cache.mjs";
import {
  loadRoleplayState,
  saveRoleplayState,
} from "./session-storage.mjs";
import {
  MAX_RESPONSE_BYTES,
  attemptRoleplayCandidates,
  copyUpstreamResponseHeaders,
  decorateRoleplayHeaders,
  errorResponse,
  jsonResponse,
  logRoleplayError,
  readBoundedBytes,
  recordModelResult,
  requestCompaction,
} from "./transport.mjs";
import { createObservedStream } from "./streaming.mjs";
export { isRoleplayPath, scopePublicRoleplaySessionId };

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
        safe_fallback_statuses: ROLEPLAY_SAFE_FALLBACK_STATUSES,
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
      const state = await loadRoleplayState(this.ctx.storage);
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
        compaction_failures: state.compactionFailures,
        compaction_backoff_until:
          state.compactionBackoffUntil || null,
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
        estimated_input_tokens_saved: state.inputTokensSaved ?? 0,
        nanogpt_credential_checks: state.nanogptCredentialChecks ?? 0,
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
    const queuedAt = performance.now();
    const previous = this.turnTail.catch(() => {});
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    this.turnTail = previous.then(() => current);
    await previous;
    const queueMs = performance.now() - queuedAt;

    try {
      const result = await this.handleTurn(request, settings, queueMs);
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

  async handleTurn(request, settings, queueMs = 0) {
    const turnStartedAt = performance.now();
    let compactionMs = 0;
    const payload = await request.json();
    let state = await loadRoleplayState(this.ctx.storage);
    const parsedInitial = parseRoleplayPayload(
      payload,
      settings.maxRequestBytes,
    );
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
    const parsedWithOutputContract = applyRoleplayOutputContract(
      protectedContext.parsed,
      protectedContext.activeDirectives,
      settings,
    );
    state = protectedContext.state;
    const checkpoint = memoryEnabled
      ? await reuseCompactionCheckpoint(
          state,
          parsedWithOutputContract,
        )
      : {
          parsed: parsedWithOutputContract,
          sourceMessages: parsedWithOutputContract.messages,
          matched: false,
        };
    const parsed = checkpoint.parsed;
    state = {
      ...state,
      ...(memoryEnabled ? { profile } : {}),
    };
    state = markRequest(state, idempotencyKey, "started");
    await saveRoleplayState(this.ctx.storage, state);

    const configuredCandidates = buildConfiguredCandidates(
      this.env,
      settings,
    );
    const checkedState = await revalidateNanoCredential(
      state,
      configuredCandidates,
      this.env,
      settings,
      request.signal,
    );
    if (checkedState !== state) {
      state = checkedState;
      await saveRoleplayState(this.ctx.storage, state);
    }
    const candidates = rankRoleplayCandidates(
      configuredCandidates,
      state.stats,
      parsed.modelPreference,
      Date.now(),
      state.activeCredentials,
    );
    if (!candidates.length) {
      state = markRequest(state, idempotencyKey, "no_provider");
      await saveRoleplayState(this.ctx.storage, state);
      return {
        response: errorResponse(
          "No roleplay provider is configured for this model preference",
          503,
          "no_roleplay_provider",
        ),
        completion: Promise.resolve(),
      };
    }
    const contextPolicy = resolveRoleplayContextPolicy(
      candidates,
      parsed.maxTokens,
      settings,
    );
    if (
      protectedContext.activeDirectives.length > 0 &&
      contextPolicy.hardInputTokens > 0 &&
      estimateTokens(protectedContext.activeDirectives) >
      contextPolicy.hardInputTokens
    ) {
      throw new RoleplayRequestError(
        "Protected system and developer instructions exceed every eligible provider context window and will not be compacted",
        413,
      );
    }
    const capacitySettings = { ...settings, ...contextPolicy };
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
    const fullConversation = conversation;
    let generationState = memoryState;
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
      capacitySettings,
    );
    const checkpointMessageCount = checkpoint.matched
      ? state.compactionCheckpoint?.messageCount ?? 0
      : 0;
    const checkpointSavedTokens = checkpoint.matched
      ? estimateTokens(
          checkpoint.sourceMessages.slice(0, checkpointMessageCount),
        )
      : 0;
    let messagesOptimized = checkpointMessageCount;

    if (plan.requested) {
      const compactionStartedAt = performance.now();
      let compactionDigest;
      let compactionSource = "model";
      if (compactionBackoffActive(state)) {
        if (plan.forced) {
          compactionDigest = createExtractiveCompactionDigest(
            memoryState,
            plan,
            capacitySettings,
          );
          compactionSource = "local";
          state = {
            ...state,
            localCompactions: (state.localCompactions ?? 0) + 1,
          };
        } else {
          memoryStatus = "compaction_backoff_retained";
        }
      } else {
        try {
          const compacted = await requestCompaction(
            memoryState,
            plan,
            candidates,
            this.env,
            capacitySettings,
            request.signal,
          );
          compactionDigest = compacted.digest;
          if (plan.forced && !compactionDigest.compact) {
            throw new Error("Model declined required memory compaction");
          }
          state = recordCompactionSuccess(state);
        } catch (error) {
          if (request.signal.aborted) {
            throw error;
          }
          state = recordCompactionFailure(state);
          logRoleplayError("roleplay_compaction_failed", error, {
            forced: plan.forced,
            olderMessages: plan.olderMessages.length,
            failures: state.compactionFailures,
            backoffUntil: state.compactionBackoffUntil,
          });
          if (plan.forced) {
            compactionDigest = createExtractiveCompactionDigest(
              memoryState,
              plan,
              capacitySettings,
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
        const preserveFullGeneration =
          applied.compacted &&
          shouldPreserveFullGeneration(plan, parsed, contextPolicy);
        generationState = preserveFullGeneration ? memoryState : state;
        conversation = preserveFullGeneration
          ? fullConversation
          : applied.compacted
            ? [...applied.conversation, ...plan.transientMessages]
            : applied.conversation;
        memoryStatus = applied.compacted
          ? `${compactionSource}_compacted`
          : "model_retained";
        if (applied.compacted) {
          if (!preserveFullGeneration) {
            messagesOptimized += plan.olderMessages.length;
          }
          await saveRoleplayState(this.ctx.storage, state);
        }
      }
      compactionMs = performance.now() - compactionStartedAt;
    }

    const projectedStoredBytes =
      new TextEncoder().encode(
        JSON.stringify(persistedConversation),
      ).byteLength +
      assistantStorageReserveBytes(parsed, settings);
    if (
      memoryEnabled &&
      projectedStoredBytes > settings.maxStoredBytes
    ) {
      state = markRequest(state, idempotencyKey, "compaction_failed");
      await saveRoleplayState(this.ctx.storage, state);
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
      memoryEnabled ? generationState : memoryState,
      parsed,
      conversation,
    );
    const estimatedInputTokens = estimateTokens(roleplayMessages);
    const estimatedInputBefore = Math.max(
      estimatedInputTokens,
      plan.estimatedTokens + checkpointSavedTokens,
    );
    const inputTokensSaved = Math.max(
      0,
      estimatedInputBefore - estimatedInputTokens,
    );
    const generationCandidates = prepareRoleplayCandidates(
      candidates,
      estimatedInputTokens,
      parsed.maxTokens,
      settings,
    );
    if (!generationCandidates.length) {
      state = markRequest(state, idempotencyKey, "context_too_large");
      await saveRoleplayState(this.ctx.storage, state);
      return {
        response: errorResponse(
          "Roleplay context and requested output exceed every eligible provider limit",
          413,
          "roleplay_context_too_large",
        ),
        completion: Promise.resolve(),
      };
    }

    const attempted = await attemptRoleplayCandidates(
      state,
      generationCandidates,
      (candidate) =>
        applyRoleplayPromptCache(
          buildUpstreamPayload(parsed, candidate, roleplayMessages),
          candidate,
          roleplayMessages,
          settings,
          parsed.promptCache,
        ),
      this.env,
      settings,
      request.signal,
      idempotencyKey,
    );
    state = attempted.state;
    if (attempted.terminalResponse) {
      state = markRequest(state, idempotencyKey, "provider_failed");
      await saveRoleplayState(this.ctx.storage, state);
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
      promptCache,
    } = attempted;
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
      candidate.resolvedMaxOutputTokens,
      headerMs,
      fallbackCount,
      queueMs,
      compactionMs,
      queueMs + performance.now() - turnStartedAt,
      {
        estimatedInputBefore,
        inputTokensSaved,
        messagesOptimized,
        promptCache,
      },
    );

    if (
      parsed.stream &&
      response.body &&
      contentType.toLowerCase().includes("text/event-stream")
    ) {
      const observed = createObservedStream({
        upstreamBody: response.body,
        requestSignal: request.signal,
        upstreamController: controller,
        heartbeatMs: settings.streamHeartbeatMs,
        onComplete: async ({
          success,
          assistant,
          finishReason,
          reason,
          ttfbMs,
          streamMs,
          heartbeatCount,
        }) => {
          cleanup();
          console.log(
            JSON.stringify({
              event: "roleplay_stream_completed",
              provider: candidate.provider,
              model: candidate.model,
              success,
              reason,
              finishReason: finishReason || undefined,
              headerMs: Math.round(headerMs),
              ttfbMs: Math.round(ttfbMs),
              streamMs: Math.round(streamMs),
              heartbeatCount,
              assistantCharacters: assistant.length,
              maxOutputTokens: candidate.resolvedMaxOutputTokens,
              inputTokensSaved,
            }),
          );
          if (reason === "incomplete_eof") {
            logRoleplayError(
              "roleplay_stream_incomplete",
              new Error("Provider stream ended without a terminal event"),
              {
                provider: candidate.provider,
                model: candidate.model,
                assistantCharacters: assistant.length,
              },
            );
          }
          const modelSucceeded = success || reason === "output_limit";
          let nextState = recordModelResult(state, candidate, {
            success: modelSucceeded,
            ttfbMs: headerMs + ttfbMs,
            totalMs: performance.now() - startedAt,
            status: modelSucceeded ? response.status : 0,
          });
          nextState = {
            ...nextState,
            inputTokensSaved:
              (nextState.inputTokensSaved ?? 0) + inputTokensSaved,
          };
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
            success
              ? "completed"
              : reason === "output_limit"
                ? "output_limited"
                : "stream_failed",
          );
          await saveRoleplayState(this.ctx.storage, nextState);
        },
      });
      return {
        response: new Response(observed.stream, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        }),
        completion: observed.completion,
      };
    }

    let bounded;
    try {
      bounded = await readBoundedBytes(
        response.body,
        MAX_RESPONSE_BYTES,
        controller.signal,
      );
    } finally {
      cleanup();
    }
    const { bytes, firstByteMs } = bounded;
    let assistant = "";
    let finishReason = "";
    if (contentType.toLowerCase().includes("application/json")) {
      try {
        const responsePayload = JSON.parse(
          new TextDecoder().decode(bytes),
        );
        assistant = extractAssistantContent(responsePayload);
        finishReason = extractFinishReason(responsePayload);
      } catch {
        assistant = "";
      }
    }
    const outputLimited = finishReason === "length";
    state = recordModelResult(state, candidate, {
      success: true,
      ttfbMs: headerMs + firstByteMs,
      totalMs: performance.now() - startedAt,
      status: response.status,
    });
    state = {
      ...state,
      inputTokensSaved:
        (state.inputTokensSaved ?? 0) + inputTokensSaved,
    };
    if (memoryEnabled && !outputLimited) {
      state = appendAssistantMessage(
        state,
        persistedConversation,
        assistant,
        settings,
      );
    } else {
      state = { ...state, updatedAt: Date.now() };
    }
    state = markRequest(
      state,
      idempotencyKey,
      outputLimited ? "output_limited" : "completed",
    );
    await saveRoleplayState(this.ctx.storage, state);
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
