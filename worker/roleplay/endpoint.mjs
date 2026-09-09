import { DurableObject } from "cloudflare:workers";
import { clientContextHeaders } from "../client-headers.mjs";
import { TurnTraceJournal } from "./turn-trace.mjs";
import { handleOperatorMemory } from "./operator-memory.mjs";
import { recoveryTemplate, preserveRecovery, handleRecoverySnapshot } from "./recovery.mjs";
import { parseRoutingPolicy, filterRoutingCandidates, parameterReceipt } from "./routing-policy.mjs";

import {
  isRoleplayPath,
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
  applyRoleplayCompletionState,
  logRoleplayNonStreamCompletion,
  logRoleplayStreamCompletion,
  roleplayCompletionDisposition,
} from "./completion-result.mjs";
import { createExtractiveCompactionDigest } from "./fallback-memory.mjs";
import { createRoleplayContinuation } from "./continuation.mjs";
import {
  buildConfiguredCandidates,
  getRoleplaySettings,
  rankRoleplayCandidates,
  ROLEPLAY_SAFE_FALLBACK_STATUSES,
} from "./config.mjs";
import {
  RoleplayRequestError,
  assistantStorageReserveBytes,
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
  applyRoleplayRouteHeaders,
  attemptRoleplayCandidates,
  copyUpstreamResponseHeaders,
  createRoleplayTimingSummary,
  decorateRoleplayHeaders,
  errorResponse,
  jsonResponse,
  logRoleplayError,
  readBoundedBytes,
  requestCompaction,
} from "./transport.mjs";
import { createObservedStream } from "./streaming.mjs";
import {
  RoleplayTurnError, RoleplayTurnQueue,
} from "./turn-runtime.mjs";
export { isRoleplayPath, scopePublicRoleplaySessionId };

export { handleRoleplayEdgeRequest } from "./edge.mjs";
const INTERNAL_OUTPUT_MODE_HEADER = "X-MultiLLM-Roleplay-Output-Mode";

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
    this.turnQueue = new RoleplayTurnQueue();
    this.traces = new TurnTraceJournal(ctx.storage);
  }

  get pendingTurns() { return this.turnQueue.pending; }

  async alarm() {
    await this.ctx.storage.deleteAll();
    this.stateRepository.clear();
    this.traces.clear();
  }

  async fetch(request) {
    await this.traces.ready;
    const pathname = new URL(request.url).pathname;
    if (pathname === "/operator/timeline" && request.method === "GET") {
      return jsonResponse(this.traces.snapshot());
    }
    if (["/operator/memory", "/operator/import-branch"].includes(pathname)) {
      return handleOperatorMemory(this, request, pathname.split("/").pop());
    }
    if (pathname === "/operator/recovery" && request.method === "POST") return handleRecoverySnapshot(this, request);
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
    const trace = this.traces.begin();
    try {
      return await this.turnQueue.run(
        request, settings,
        async (turnRequest, queueMs) => {
          trace.phase("preparing");
          trace.metrics({ queueMs });
          const result = await this.handleTurn(turnRequest, settings, queueMs, trace);
          result.response.headers.set("X-Roleplay-Trace-ID", trace.id);
          result.completion = Promise.resolve(result.completion).then(async (completion) => {
            if (completion?.persistenceFailed) await trace.finish(false, "persistence_failed");
            return completion;
          });
          if (!result.response.ok) await trace.finish(false, "request_failed");
          return result;
        },
        (completion) => this.ctx.waitUntil(completion),
      );
    } catch (error) {
      await trace.finish(false, error.code || "turn_failed");
      if (error instanceof RoleplayTurnError) {
        return errorResponse(error.message, error.status, error.code);
      }
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

  async handleTurn(request, settings, queueMs = 0, trace = null) {
    settings = { ...settings, clientHeaders: clientContextHeaders(request.headers, "opencode") };
    const turnStartedAt = performance.now();
    let compactionMs = 0;
    const payload = await request.json();
    if (payload.recovery_enabled !== undefined && typeof payload.recovery_enabled !== "boolean") throw new RoleplayRequestError("recovery_enabled must be a boolean");
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
    parsedInitial.routing = parseRoutingPolicy(payload.routing);
    if (parsedInitial.routing.fallback === "none") {
      settings = { ...settings, refusalFallbackEnabled: false, maxAutoContinuations: 0, maxOutputContractRepairs: 0 };
    }
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

    const configuredCandidates = filterRoutingCandidates(this.configuredCandidates, parsed.routing);
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
      {
        mode: parsed.routing.mode,
        exactModel: Boolean(parsed.routing.model),
        premiumPercent: settings.qualityLatencyPremiumPercent,
        minimumSamples: settings.qualityMinimumSamples,
        referenceOutputTokens: settings.speedReferenceOutputTokens,
      },
    );
    if (parsed.routing.fallback === "none") candidates.splice(1);
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

    const recovery = recoveryTemplate(payload, roleplayMessages);
    trace?.phase("connecting");
    const attempted = await attemptRoleplayCandidates(
      state,
      generationCandidates,
      (candidate) =>
        applyRoleplayPromptCache(
          buildUpstreamPayload(
            parsed,
            candidate,
            roleplayMessages,
            settings,
          ),
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
      await preserveRecovery(this.ctx.storage, recovery, { success: false, reason: "provider_failed" }, trace?.id);
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
      refusalFallbackCandidates,
    } = attempted;
    trace?.phase("headers");
    trace?.metrics({ headerMs });
    trace?.selected(candidate, parameterReceipt(parsed, candidate, settings));
    const continuation = createRoleplayContinuation({
      state,
      candidate,
      messages: roleplayMessages,
      parsed,
      env: this.env,
      settings,
      signal: request.signal,
      idempotencyKey,
      refusalFallbackCandidates,
    });
    const selectionReason = candidate.selectionReason || (parsed.routing.mode !== "provider-priority" ? parsed.routing.mode :
      (state.stats[candidate.key]?.successes ?? 0) < 2
        ? "exploration"
        : "adaptive_speed");
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
        onProgress: (progress) => trace?.progress(progress),
        upstreamBody: response.body,
        requestSignal: request.signal,
        upstreamController: controller,
        heartbeatMs: settings.streamHeartbeatMs,
        idleTimeoutMs: settings.streamIdleTimeoutMs,
        cleanup,
        openContinuation: continuation.canOpen
          ? continuation.open.bind(continuation)
          : null,
        getIncompleteReason: continuation.enabled
          ? continuation.incompleteReason.bind(continuation)
          : null,
        assessCompletion: continuation.assess.bind(continuation),
        cleanOutput: continuation.cleanOutput.bind(continuation),
        getUpstreamCallCount: () => continuation.upstreamCallCount,
        getRefusalFallbackCount: () =>
          continuation.refusalFallbackCount,
        bufferUntilValidated:
          parsed.outputContract?.imagePromptRequired === true,
        maxContinuations: settings.maxAutoContinuations,
        reasoningMetadata: {
          provider: candidate.provider,
          model: candidate.model,
        },
        detectRefusal: continuation.classifyRefusal,
        refusalFallbackEnabled: continuation.refusalFallbackEnabled,
        onComplete: async (completion) => {
          await preserveRecovery(this.ctx.storage, recovery, completion, trace?.id);
          const {
            success,
            assistant,
            reason,
            ttfbMs,
          } = completion;
          state = continuation.state;
          const finalCandidate = continuation.candidate;
          trace?.selected(finalCandidate, parameterReceipt(parsed, finalCandidate, settings));
          logRoleplayStreamCompletion({
            candidate: finalCandidate,
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
                provider: finalCandidate.provider,
                model: finalCandidate.model,
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
          state = applyRoleplayCompletionState({
            state,
            candidate: finalCandidate,
            completion,
            disposition,
            modelResult: {
              success: disposition.modelSucceeded,
              ttfbMs: headerMs + ttfbMs,
              totalMs: performance.now() - startedAt,
              status: disposition.modelSucceeded ? response.status : 0,
              performance: { ...completion, headerMs },
            },
            inputTokensSaved,
            persistedConversation,
            settings,
            idempotencyKey,
          });
          trace?.metrics(completion);
          if (trace) await trace.finish(success, reason, (metadata) => this.stateRepository.save(state, metadata));
          else await this.stateRepository.save(state);
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
        applyRoleplayRouteHeaders(
          responseHeaders,
          continuation.candidate,
          fallbackCount + continuation.refusalFallbackCount,
        );
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
    const finalCandidate = continuation.candidate;
    state = applyRoleplayCompletionState({
      state,
      candidate: finalCandidate,
      completion: completionResult,
      disposition,
      modelResult: {
        success: disposition.modelSucceeded,
        ttfbMs: headerMs + firstByteMs,
        totalMs: performance.now() - startedAt,
        status: disposition.modelSucceeded ? response.status : 0,
      },
      inputTokensSaved,
      persistedConversation,
      settings,
      idempotencyKey,
    });
    logRoleplayNonStreamCompletion({
      candidate: finalCandidate,
      parsed,
      completion: completionResult,
      timings,
    });
    trace?.selected(finalCandidate, parameterReceipt(parsed, finalCandidate, settings));
    if (trace) await trace.finish(completionResult.success, completionResult.reason, (metadata) => this.stateRepository.save(state, metadata));
    else await this.stateRepository.save(state);
    await preserveRecovery(this.ctx.storage, recovery, completionResult, trace?.id);
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
