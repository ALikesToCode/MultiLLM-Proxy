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
import {
  logRoleplayNonStreamCompletion,
  logRoleplayStreamCompletion,
  roleplayCompletionDisposition,
} from "./completion-result.mjs";
import { createExtractiveCompactionDigest } from "./fallback-memory.mjs";
import { createRoleplayContinuation } from "./continuation.mjs";
import { ROLEPLAY_PUBLIC_MODEL_ALIASES } from "./model-selection.mjs";
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
  mergeSessionMessages,
  parseRoleplayPayload,
} from "./memory.mjs";
import { repairNonStreamingCompletion } from "./nonstream-repair.mjs";
import { applyRoleplayOutputContract } from "./output-contract.mjs";
import { applyRoleplayPromptCache } from "./prompt-cache.mjs";
import { buildRoleplaySessionMetrics } from "./session-metrics.mjs";
import {
  createRoleplayStateRepository,
  createSessionAlarmRefresher,
  effectiveRoleplayCharacter,
  existingRoleplayRequest,
  markRoleplayRequest,
  recordRoleplayStateCache,
} from "./state-runtime.mjs";
import {
  MAX_RESPONSE_BYTES,
  attemptRoleplayCandidates,
  copyUpstreamResponseHeaders,
  createRoleplayTimingSummary,
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

export class RoleplaySession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.settings = getRoleplaySettings(env);
    this.configuredCandidates = buildConfiguredCandidates(
      env,
      this.settings,
    );
    this.stateRepository = createRoleplayStateRepository(ctx.storage);
    this.refreshSessionAlarm = createSessionAlarmRefresher(
      ctx,
      this.settings.sessionTtlSeconds,
    );
    this.pendingTurns = 0;
    this.turnTail = Promise.resolve();
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
    this.stateRepository.clear();
  }

  async fetch(request) {
    const pathname = new URL(request.url).pathname;
    if (pathname === "/metrics" && request.method === "GET") {
      const state = await this.stateRepository.load();
      return jsonResponse(
        buildRoleplaySessionMetrics(state, {
          pendingTurns: this.pendingTurns,
        }),
      );
    }
    if (pathname !== "/turn" || request.method !== "POST") {
      return errorResponse("Method not allowed", 405, "method_not_allowed");
    }
    this.refreshSessionAlarm();
    return this.enqueueTurn(request, this.settings);
  }

  async enqueueTurn(request, settings) {
    const queuedAt = performance.now();
    this.pendingTurns += 1;
    const previous = this.turnTail.catch(() => {});
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    this.turnTail = previous.then(() => current);
    await previous;
    const queueMs = performance.now() - queuedAt;
    const finish = () => {
      this.pendingTurns = Math.max(0, this.pendingTurns - 1);
      release();
    };

    try {
      const result = await this.handleTurn(request, settings, queueMs);
      const completion = Promise.resolve(result.completion).finally(finish);
      this.ctx.waitUntil(completion);
      return result.response;
    } catch (error) {
      finish();
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
    const stateCacheHit = this.stateRepository.loaded;
    const stateLoadStartedAt = performance.now();
    let state = await this.stateRepository.load();
    const stateLoadMs = performance.now() - stateLoadStartedAt;
    state = recordRoleplayStateCache(state, stateCacheHit);
    const parsedInitial = parseRoleplayPayload(
      payload,
      settings.maxRequestBytes,
      {
        forceUnlimited:
          request.headers.get(INTERNAL_OUTPUT_MODE_HEADER) === "unlimited",
      },
    );
    const { profile, parsed: parsedWithProfile } = effectiveRoleplayCharacter(
      state,
      parsedInitial,
    );
    const idempotencyKey = request.headers.get("Idempotency-Key") ?? "";
    const duplicate = existingRoleplayRequest(state, idempotencyKey);
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
    state = checkpoint.state ?? state;
    state = {
      ...state,
      ...(memoryEnabled ? { profile } : {}),
    };
    state = markRoleplayRequest(state, idempotencyKey, "started");
    if (idempotencyKey) {
      await this.stateRepository.save(state);
    }

    const configuredCandidates = this.configuredCandidates;
    const credentialCheckStartedAt = performance.now();
    const checkedState = await revalidateNanoCredential(
      state,
      configuredCandidates,
      this.env,
      settings,
      request.signal,
    );
    const credentialCheckMs = performance.now() - credentialCheckStartedAt;
    const credentialCheckPerformed = checkedState !== state;
    if (checkedState !== state) {
      state = checkedState;
      await this.stateRepository.save(state);
    }
    const candidates = rankRoleplayCandidates(
      configuredCandidates,
      state.stats,
      parsed.modelPreference,
      Date.now(),
      state.activeCredentials,
    );
    if (!candidates.length) {
      state = markRoleplayRequest(state, idempotencyKey, "no_provider");
      await this.stateRepository.save(state);
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
          await this.stateRepository.save(state);
        }
      }
      compactionMs = performance.now() - compactionStartedAt;
    }

    const projectedStoredBytes =
      persistedConversation === fullConversation
        ? plan.projectedStoredBytes
        : new TextEncoder().encode(
            JSON.stringify(persistedConversation),
          ).byteLength +
          assistantStorageReserveBytes(parsed, settings);
    if (
      memoryEnabled &&
      projectedStoredBytes > settings.maxStoredBytes
    ) {
      state = markRoleplayRequest(state, idempotencyKey, "compaction_failed");
      await this.stateRepository.save(state);
      return {
        response: errorResponse(
          "Automatic memory compaction could not produce a safe retained window",
          503,
          "memory_compaction_failed",
        ),
        completion: Promise.resolve(),
      };
    }

    const canReuseInitialAnalysis =
      generationState === memoryState &&
      conversation === fullConversation;
    const roleplayMessages = canReuseInitialAnalysis
      ? plan.roleplayMessages
      : buildRoleplayMessages(
          memoryEnabled ? generationState : memoryState,
          parsed,
          conversation,
        );
    const estimatedInputTokens = canReuseInitialAnalysis
      ? plan.estimatedTokens
      : estimateTokens(roleplayMessages);
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
      state = markRoleplayRequest(state, idempotencyKey, "context_too_large");
      await this.stateRepository.save(state);
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
          estimatedInputTokens,
        ),
      this.env,
      settings,
      request.signal,
      idempotencyKey,
    );
    state = attempted.state;
    if (attempted.terminalResponse) {
      state = markRoleplayRequest(state, idempotencyKey, "provider_failed");
      await this.stateRepository.save(state);
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
    const continuation = createRoleplayContinuation({
      state,
      candidate,
      messages: roleplayMessages,
      parsed,
      env: this.env,
      settings,
      signal: request.signal,
      idempotencyKey,
    });
    const selectionReason =
      (state.stats[candidate.key]?.successes ?? 0) < 2
        ? "exploration"
        : "adaptive_speed";
    const contentType = response.headers.get("Content-Type") ?? "";
    const timings = createRoleplayTimingSummary({
      queueMs,
      stateLoadMs,
      credentialCheckMs,
      compactionMs,
      headerMs,
      turnStartedAt,
      stateCacheHit,
      credentialCheckPerformed,
    });
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
      timings.totalToHeadersMs,
      {
        estimatedInputBefore,
        inputTokensSaved,
        messagesOptimized,
        promptCache,
      },
      timings,
    );

    if (
      parsed.stream &&
      response.body &&
      contentType.toLowerCase().includes("text/event-stream")
    ) {
      responseHeaders.set("Cache-Control", "no-cache, no-transform");
      const observed = createObservedStream({
        upstreamBody: response.body,
        requestSignal: request.signal,
        upstreamController: controller,
        heartbeatMs: settings.streamHeartbeatMs,
        cleanup,
        openContinuation: continuation.enabled
          ? continuation.open.bind(continuation)
          : null,
        getIncompleteReason: continuation.enabled
          ? continuation.incompleteReason.bind(continuation)
          : null,
        assessCompletion: continuation.assess.bind(continuation),
        cleanOutput: continuation.cleanOutput.bind(continuation),
        getUpstreamCallCount: () => continuation.upstreamCallCount,
        bufferUntilValidated:
          parsed.outputContract?.imagePromptRequired === true,
        maxContinuations: settings.maxAutoContinuations,
        reasoningMetadata: {
          provider: candidate.provider,
          model: candidate.model,
        },
        onComplete: async (completion) => {
          const {
            success,
            assistant,
            reason,
            ttfbMs,
          } = completion;
          state = continuation.state;
          logRoleplayStreamCompletion({
            candidate,
            parsed,
            completion,
            headerMs,
            inputTokensSaved,
            timings,
          });
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
          const disposition = roleplayCompletionDisposition({
            success,
            reason,
            outputMode: parsed.outputMode,
            memoryEnabled,
            failureStatus: "stream_failed",
          });
          let nextState = recordModelResult(state, candidate, {
            success: disposition.modelSucceeded,
            ttfbMs: headerMs + ttfbMs,
            totalMs: performance.now() - startedAt,
            status: disposition.modelSucceeded ? response.status : 0,
          });
          nextState = {
            ...nextState,
            inputTokensSaved:
              (nextState.inputTokensSaved ?? 0) + inputTokensSaved,
          };
          if (disposition.persistAssistant) {
            nextState = appendAssistantMessage(
              nextState,
              persistedConversation,
              assistant,
              settings,
            );
          } else {
            nextState = { ...nextState, updatedAt: Date.now() };
          }
          nextState = markRoleplayRequest(
            nextState,
            idempotencyKey,
            disposition.requestStatus,
          );
          await this.stateRepository.save(nextState);
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
    let responseBytes = bytes;
    let completionResult = {
      assistant: "",
      finishReason: "",
      success: true,
      reason: "complete",
      continuationCount: 0,
      upstreamCallCount: 1,
      continuationDiagnostics: [],
      contractAnalysis: null,
    };
    if (contentType.toLowerCase().includes("application/json")) {
      try {
        const responsePayload = JSON.parse(
          new TextDecoder().decode(bytes),
        );
        completionResult = await repairNonStreamingCompletion({
          initialPayload: responsePayload,
          continuation,
          candidate,
          settings,
          signal: request.signal,
        });
        state = continuation.state;
        responseBytes = new TextEncoder().encode(
          JSON.stringify(completionResult.payload),
        );
      } catch (error) {
        logRoleplayError("roleplay_nonstream_normalization_failed", error, {
          provider: candidate.provider,
          model: candidate.model,
        });
        completionResult = {
          ...completionResult,
          success: false,
          reason: "invalid_completion",
        };
      }
    }
    const disposition = roleplayCompletionDisposition({
      success: completionResult.success,
      reason: completionResult.reason,
      outputMode: parsed.outputMode,
      memoryEnabled,
      failureStatus: "completion_failed",
    });
    state = recordModelResult(state, candidate, {
      success: disposition.modelSucceeded,
      ttfbMs: headerMs + firstByteMs,
      totalMs: performance.now() - startedAt,
      status: disposition.modelSucceeded ? response.status : 0,
    });
    state = {
      ...state,
      inputTokensSaved:
        (state.inputTokensSaved ?? 0) + inputTokensSaved,
    };
    logRoleplayNonStreamCompletion({
      candidate,
      parsed,
      completion: completionResult,
      timings,
    });
    if (disposition.persistAssistant) {
      state = appendAssistantMessage(
        state,
        persistedConversation,
        completionResult.assistant,
        settings,
      );
    } else {
      state = { ...state, updatedAt: Date.now() };
    }
    state = markRoleplayRequest(
      state,
      idempotencyKey,
      disposition.requestStatus,
    );
    await this.stateRepository.save(state);
    return {
      response: new Response(responseBytes, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      }),
      completion: Promise.resolve(),
    };
  }
}
