import { DurableObject } from "cloudflare:workers";
import { SECRET_SCAN_HEADER } from "../secret-firewall.mjs";
import { clientContextHeaders } from "../client-headers.mjs";
import { roleplayPIIRetention, resolvePIIPolicy, PIIRedactionError } from "../pii-redaction.mjs";
import { contextPagingEligible, pageContextMessages, ROLEPLAY_KEY_SCOPE_HEADER, ROLEPLAY_PAGE_SCOPE_HEADER,
  withRoleplayGatewayAuthority } from "../context-pages-d1.mjs";
import { TurnTraceJournal } from "./turn-trace.mjs";
import { prepareRoleplayCanary, injectRoleplayCanary, protectRoleplayAttempt, protectRoleplayContinuation,
  canaryCompletion, finalizeRoleplayStream, finalizeRoleplayResponse, prepareCanaryCandidates } from "../context-canary.mjs";
import { handleOperatorMemory } from "./operator-memory.mjs";
import {
  recoveryTemplate, preserveRecovery, handleRecoverySnapshot, resolveRoleplayRetention,
  retentionResponse, retentionRequestId, retentionAllowsContent, createRetentionStateRepository,
} from "./recovery.mjs";
import { parseRoutingPolicy, filterRoutingCandidates, parameterReceipt,
  SessionTierError, SessionTierPolicy, sessionTierSettings, beginRoleplaySessionTier } from "./routing-policy.mjs";

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
  prepareRoleplayPagingCandidates,
  resolveRoleplayContextPolicy,
  shouldPreserveFullGeneration,
} from "./capacity.mjs";
import {
  compactionBackoffActive,
  recordCompactionFailure,
  recordCompactionSuccess,
} from "./compaction-policy.mjs";
import { prepareProtectedContext } from "./directives.mjs";
import { parseCandidateContextMode } from "./candidate-context.mjs";
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
  autoRoutePreference,
  buildIntelligenceCandidates,
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

import { handleRoleplayEdgeRequest as roleplayEdgeRequest } from "./edge.mjs";
export const handleRoleplayEdgeRequest = (request, env) => withRoleplayGatewayAuthority(request, env, roleplayEdgeRequest);
const INTERNAL_OUTPUT_MODE_HEADER = "X-MultiLLM-Roleplay-Output-Mode";

async function preparePromptInjection(payload, env, record = true) {
  const mode = env.PROMPT_INJECTION_MODE;
  if (mode === undefined || mode === null || typeof mode === "string" && ["", "off"].includes(mode.trim().toLowerCase())) return null;
  // Load the fixed opt-in collaborator only when the operator enables inspection.
  const { evaluatePromptInjection, recordPromptInjection } = await import("../prompt-injection-detection.mjs");
  const decision = evaluatePromptInjection(payload, env);
  if (record) await recordPromptInjection(decision);
  return decision;
}

function applyPromptInjectionHeader(headers, decision) {
  if (decision?.action) headers.set("X-MultiLLM-Injection-Action", decision.action);
}

function injectionResponse(response, decision, noStore = false) {
  applyPromptInjectionHeader(response.headers, decision);
  if (noStore) response.headers.set("Cache-Control", "no-store");
  return response;
}

export class RoleplaySession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.settings = getRoleplaySettings(env);
    this.configuredCandidates = [
      ...buildConfiguredCandidates(env, this.settings),
      ...buildIntelligenceCandidates(env, this.settings),
    ];
    this.stateRepository = createRoleplayStateRepository(ctx.storage);
    this.sessionTiers = new SessionTierPolicy(ctx.storage, sessionTierSettings(env));
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
    let retention = resolveRoleplayRetention(this.env, request);
    let piiZero = false;
    await this.traces.ready;
    const pathname = new URL(request.url).pathname;
    if (pathname === "/operator/timeline" && request.method === "GET") {
      return jsonResponse(this.traces.snapshot());
    }
    if (["/operator/memory", "/operator/import-branch"].includes(pathname)) {
      if (!retentionAllowsContent(retention)) return retentionResponse(
        errorResponse("Durable conversation memory is unavailable under zero retention", 409, "retention_forbidden"), retention);
      return handleOperatorMemory(this, request, pathname.split("/").pop());
    }
    if (pathname === "/operator/recovery" && request.method === "POST") return handleRecoverySnapshot(this, request, retention);
    if (pathname === "/metrics" && request.method === "GET") {
      const state = await createRetentionStateRepository(this.ctx.storage, this.stateRepository, retention, this.configuredCandidates).load();
      return jsonResponse(
        buildRoleplaySessionMetrics(state, {
          pendingTurns: this.pendingTurns,
        }),
      );
    }
    if (pathname !== "/turn" || request.method !== "POST") {
      return errorResponse("Method not allowed", 405, "method_not_allowed");
    }
    if (this.env.PROMPT_INJECTION_MODE || this.env.PII_REDACTION_ENABLED) {
      const payload = await request.clone().json().catch(() => null);
      if (payload === null) return retentionResponse(await this.enqueueTurn(request, this.settings, retention), retention);
      const injection = await preparePromptInjection(payload, this.env, false);
      if (injection?.action === "blocked") {
        await preparePromptInjection(payload, this.env);
        return injectionResponse(errorResponse("Prompt injection heuristics exceeded the configured threshold", 422, "prompt_injection_suspected"), injection);
      }
      const prior = retention;
      try { retention = await roleplayPIIRetention(payload, this.env, request.headers.get(ROLEPLAY_KEY_SCOPE_HEADER) ?? "", retention); }
      catch (error) {
        if (!(error instanceof PIIRedactionError)) throw error;
        return injectionResponse(errorResponse("Required PII transformation failed before provider dispatch", 502,
          "pii_redaction_failed"), injection, true);
      }
      piiZero = retention !== prior;
    }
    if (retentionAllowsContent(retention)) this.refreshSessionAlarm();
    const completed = await this.enqueueTurn(request, this.settings, retention);
    const piiNoStore = piiZero || Boolean(this.env.PII_REDACTION_ENABLED && completed.headers.get("Cache-Control") === "no-store");
    const response = retentionResponse(completed, retention);
    if (piiNoStore) response.headers.set("Cache-Control", "no-store");
    return response;
  }

  async enqueueTurn(request, settings, retention = resolveRoleplayRetention(this.env, request)) {
    const trace = this.traces.begin(retention);
    const tierScope = { turn: null };
    try {
      return await this.turnQueue.run(
        request, settings,
        async (turnRequest, queueMs) => {
          trace.phase("preparing");
          trace.metrics({ queueMs });
          const result = await this.handleTurn(turnRequest, settings, queueMs, trace, retention, tierScope);
          applyPromptInjectionHeader(result.response.headers, tierScope.injection);
          if (tierScope.pii) result.response.headers.set("Cache-Control", "no-store");
          result.response.headers.set("X-Roleplay-Trace-ID", trace.id);
          result.completion = Promise.resolve(result.completion).then(async (completion) => {
            if (completion?.persistenceFailed) await trace.finish(false, "persistence_failed");
            return completion;
          });
          if (!result.response.ok) {
            await tierScope.turn?.finish(null, { success: false });
            await trace.finish(false, "request_failed");
          }
          return result;
        },
        (completion) => this.ctx.waitUntil(completion),
      );
    } catch (error) {
      try { await tierScope.turn?.finish(null, { success: false }); }
      catch (storageError) { error = storageError; }
      await trace.finish(false, error.code || "turn_failed");
      if (error instanceof RoleplayTurnError || error instanceof SessionTierError) {
        return injectionResponse(errorResponse(error.message, error.status, error.code), tierScope.injection, tierScope.pii);
      }
      if (error instanceof RoleplayRequestError) {
        return injectionResponse(errorResponse(
          error.message,
          error.status,
          error.status === 413 ? "request_too_large" : "invalid_request",
        ), tierScope.injection, tierScope.pii);
      }
      logRoleplayError("roleplay_session_turn_failed", error);
      return injectionResponse(errorResponse(
        "Roleplay turn could not be completed",
        502,
        "roleplay_unavailable",
      ), tierScope.injection, tierScope.pii);
    }
  }

  async handleTurn(request, settings, queueMs = 0, trace = null, retention = resolveRoleplayRetention(this.env, request), tierScope = { turn: null }) {
    const contentRepository = createRetentionStateRepository(this.ctx.storage, this.stateRepository, retention, this.configuredCandidates);
    const piiKeyScope = request.headers.get(ROLEPLAY_KEY_SCOPE_HEADER) ?? "";
    const piiPolicy = resolvePIIPolicy(this.env, { route: "/v1/roleplay/chat/completions", keyScope: piiKeyScope });
    let transportChecked = !piiPolicy;
    const onPIIDecision = decision => {
      transportChecked = true;
      if (decision.cacheable === false || decision.replayable === false) {
        retention = Object.freeze({ enabled: true, mode: "zero" });
        tierScope.pii = true;
      }
    };
    const stateRepository = !piiPolicy ? contentRepository : {
      get loaded() { return contentRepository.loaded; }, load: () => contentRepository.load(),
      save: async (state, metadata) => {
        if (!transportChecked) return state;
        return createRetentionStateRepository(this.ctx.storage, this.stateRepository, retention, this.configuredCandidates).save(state, metadata);
      },
    };
    const scanCounts = [0, 0];
    const applyScanHeader = headers => {
      if (scanCounts.some(Boolean)) headers.set(SECRET_SCAN_HEADER, `redacted=${scanCounts[0]}; observed=${scanCounts[1]}`);
    };
    settings = { ...settings, piiKeyScope, onPIIDecision, clientHeaders: clientContextHeaders(request.headers, "opencode"), onSecretScan: decision => {
      if (!decision.report || decision.blocked) return;
      scanCounts[0] += decision.action === "redacted" ? decision.report.high : 0;
      scanCounts[1] += decision.report.heuristic + (decision.action === "observed" ? decision.report.high : 0);
    } };
    const canary = await prepareRoleplayCanary(this.env, { keyScope: piiKeyScope, trace });
    const turnStartedAt = performance.now();
    let compactionMs = 0;
    const payload = await request.json();
    if (payload.recovery_enabled !== undefined && typeof payload.recovery_enabled !== "boolean") throw new RoleplayRequestError("recovery_enabled must be a boolean");
    const stateCacheHit = stateRepository.loaded;
    const stateLoadStartedAt = performance.now();
    let state = await stateRepository.load();
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
    const injection = await preparePromptInjection(payload, this.env);
    tierScope.injection = injection;
    if (injection?.action === "blocked") {
      const response = errorResponse("Prompt injection heuristics exceeded the configured threshold", 422, "prompt_injection_suspected");
      applyPromptInjectionHeader(response.headers, injection);
      return { response, completion: Promise.resolve() };
    }
    parsedInitial.routing = parseRoutingPolicy(payload.routing, { sessionTierEnabled: this.sessionTiers.settings.enabled });
    if (parsedInitial.routing.fallback === "none") {
      settings = { ...settings, refusalFallbackEnabled: false, maxAutoContinuations: 0, maxOutputContractRepairs: 0 };
    }
    const { profile, parsed: parsedWithProfile } = effectiveRoleplayCharacter(
      state,
      parsedInitial,
    );
    const suppliedIdempotencyKey = request.headers.get("Idempotency-Key") ?? "";
    const idempotencyKey = retentionAllowsContent(retention) ? suppliedIdempotencyKey : await retentionRequestId(suppliedIdempotencyKey);
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
    const candidateContextMode = parseCandidateContextMode(
      this.env.ROLEPLAY_CANDIDATE_CONTEXT_REFIT,
    );
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
      await stateRepository.save(state);
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
      await stateRepository.save(state);
    }
    const rankFor = (preference) => rankRoleplayCandidates(
      configuredCandidates,
      state.stats,
      preference,
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
    // ROLEPLAY_AUTO_ROUTE=intelligence sends plain roleplay:auto turns through the
    // roleplay:intelligence chain, and back to the adaptive pool if it has no key.
    const autoPreference = autoRoutePreference(parsed, settings);
    let candidates = rankFor(autoPreference);
    if (!candidates.length && autoPreference !== parsed.modelPreference) {
      candidates = rankFor(parsed.modelPreference);
    }
    const tierTurn = await beginRoleplaySessionTier(this.sessionTiers, parsed, payload,
      candidates, state.stats, this.configuredCandidates);
    tierScope.turn = tierTurn;
    if (tierTurn) {
      candidates = tierTurn.candidates;
      settings = { ...settings, refusalFallbackEnabled: false, maxAutoContinuations: 0, maxOutputContractRepairs: 0 };
    }
    if (parsed.routing.fallback === "none") candidates.splice(1);
    if (!candidates.length) {
      state = markRoleplayRequest(state, idempotencyKey, "no_provider");
      await stateRepository.save(state);
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
      candidateContextMode === "off" &&
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
    await roleplayPIIRetention({ messages: buildRoleplayMessages(memoryState, parsed, conversation, true) },
      this.env, piiKeyScope, retention, decision => { if (decision.redacted) onPIIDecision(decision); });
    const paging = { env: this.env, managed: true, capabilities: parsed.contextCapabilities ?? [], retentionPolicy: retention };
    const pagingEnabled = contextPagingEligible(paging);
    const pagingCandidates = pagingEnabled ? await prepareRoleplayPagingCandidates(candidates, parsed.maxTokens,
      { ...settings, hardInputTokens: contextPolicy.hardInputTokens || Infinity }, {
      ...paging, scope: JSON.parse(request.headers.get(ROLEPLAY_PAGE_SCOPE_HEADER) ?? "null"),
      messages: buildRoleplayMessages(memoryState, parsed, conversation, true), estimateTokens, pageMessages: pageContextMessages,
    }) : null;
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
      pagingCandidates?.[0]?.contextPlan,
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
          if (compacted.blockedResponse) {
            state = markRoleplayRequest(state, idempotencyKey, "provider_failed");
            await stateRepository.save(state);
            return {
              response: compacted.blockedResponse,
              completion: Promise.resolve(),
            };
          }
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
          await stateRepository.save(state);
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
      await stateRepository.save(state);
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
    const estimatedInputTokens = (canReuseInitialAnalysis
      ? plan.estimatedTokens
      : estimateTokens(roleplayMessages)) + (canary?.inputTokens ?? 0);
    const estimatedInputBefore = Math.max(
      estimatedInputTokens,
      plan.estimatedTokens + checkpointSavedTokens,
    );
    let generationCandidates = pagingCandidates ?? prepareRoleplayCandidates(
      candidates,
      estimatedInputTokens,
      parsed.maxTokens,
      settings,
      candidateContextMode === "window"
        ? { messages: roleplayMessages, estimateTokens }
        : null,
    );
    generationCandidates = prepareCanaryCandidates(generationCandidates, canary, roleplayMessages, estimateTokens, settings);
    if (tierTurn) generationCandidates = tierTurn.select(generationCandidates);
    if (!generationCandidates.length) {
      state = markRoleplayRequest(state, idempotencyKey, "context_too_large");
      await stateRepository.save(state);
      return {
        response: errorResponse(
          "Roleplay context and requested output exceed every eligible provider limit",
          413,
          "roleplay_context_too_large",
        ),
        completion: Promise.resolve(),
      };
    }

    const recovery = recoveryTemplate(payload, roleplayMessages, retention);
    trace?.phase("connecting");
    const attempted = await protectRoleplayAttempt(await attemptRoleplayCandidates(
      state,
      generationCandidates,
      (candidate) =>
        injectRoleplayCanary(applyRoleplayPromptCache(
          buildUpstreamPayload(
            parsed,
            candidate,
            candidate.contextPlan?.messages ?? roleplayMessages,
            settings,
          ),
          candidate,
          candidate.contextPlan?.messages ?? roleplayMessages,
          settings,
          parsed.promptCache,
          candidate.contextPlan?.estimatedInputTokens ?? estimatedInputTokens,
        ), canary),
      this.env,
      settings,
      request.signal,
      idempotencyKey,
    ), canary, request.signal);
    state = attempted.state;
    if (attempted.terminalResponse) {
      await tierTurn?.finish(null, { success: false,
        credentialFailed: [401, 403].includes(attempted.terminalResponse.status) });
      await preserveRecovery(this.ctx.storage, recovery, { success: false, reason: "provider_failed" }, trace?.id, retention);
      state = markRoleplayRequest(state, idempotencyKey, "provider_failed");
      await stateRepository.save(state);
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
    // Dispatch and continuation share the selected view. Persistence and
    // recovery above retain the original conversation independently.
    const selectedMessages =
      candidate.contextPlan?.messages ?? roleplayMessages;
    const selectedInputTokens =
      candidate.contextPlan?.estimatedInputTokens ?? estimatedInputTokens;
    const inputTokensSaved = Math.max(
      0, estimatedInputBefore - selectedInputTokens,
    );
    trace?.phase("headers");
    trace?.metrics({ headerMs });
    trace?.selected(candidate, parameterReceipt(parsed, candidate, settings));
    const continuation = createRoleplayContinuation({
      state,
      candidate,
      messages: canary ? canary.messages(selectedMessages) : selectedMessages,
      parsed,
      env: this.env,
      settings,
      signal: request.signal,
      idempotencyKey,
      refusalFallbackCandidates,
    });
    protectRoleplayContinuation(continuation, canary, request.signal);
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
      selectedInputTokens,
      candidate.resolvedMaxOutputTokens,
      headerMs,
      fallbackCount,
      queueMs,
      compactionMs,
      timings.totalToHeadersMs,
      {
        estimatedInputBefore,
        inputTokensSaved,
        messagesOptimized: messagesOptimized +
          (roleplayMessages.length - selectedMessages.length),
        promptCache,
      },
      timings,
    );
    if (candidate.contextPlan?.omittedGroups > 0) {
      responseHeaders.set("X-MultiLLM-Context-Refit", "window");
      responseHeaders.set(
        "X-MultiLLM-Context-Refit-Omitted-Groups",
        String(candidate.contextPlan.omittedGroups),
      );
      responseHeaders.set("X-MultiLLM-Optimization-Mode", "window");
    }

    applyScanHeader(responseHeaders);
    applyPromptInjectionHeader(responseHeaders, injection);

    if (
      parsed.stream &&
      response.body &&
      contentType.toLowerCase().includes("text/event-stream")
    ) {
      responseHeaders.set("Cache-Control", tierScope.pii ? "no-store" : "no-cache, no-transform");
      const observed = createObservedStream({
        onProgress: (progress) => trace?.progress(progress),
        upstreamBody: tierTurn ? tierTurn.observe(response).body : response.body,
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
          completion = canaryCompletion(completion, canary);
          await preserveRecovery(this.ctx.storage, recovery, completion, trace?.id, retention);
          const {
            success,
            assistant,
            reason,
            ttfbMs,
          } = completion;
          state = continuation.state;
          const finalCandidate = continuation.candidate;
          await tierTurn?.finish(finalCandidate, { success: success && !request.signal.aborted &&
            ["stop", "tool_calls"].includes(completion.finishReason), finishReason: completion.finishReason });
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
          if (trace && retentionAllowsContent(retention)) await trace.finish(success, reason, (metadata) => stateRepository.save(state, metadata));
          else {
            await trace?.finish(success, reason);
            await stateRepository.save(state);
          }
        },
      });
      return {
        response: new Response(finalizeRoleplayStream(observed.stream, canary), {
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
    completionResult = canaryCompletion(completionResult, canary);
    const disposition = roleplayCompletionDisposition({
      success: completionResult.success,
      reason: completionResult.reason,
      outputMode: parsed.outputMode,
      memoryEnabled,
      failureStatus: "completion_failed",
    });
    const finalCandidate = continuation.candidate;
    await tierTurn?.finish(finalCandidate, { success: completionResult.success && !request.signal.aborted &&
      contentType.toLowerCase().includes("application/json"),
      finishReason: completionResult.finishReason,
      toolCalls: completionResult.payload?.choices?.[0]?.message?.tool_calls ?? [] });
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
    if (trace && retentionAllowsContent(retention)) await trace.finish(completionResult.success, completionResult.reason, (metadata) => stateRepository.save(state, metadata));
    else {
      await trace?.finish(completionResult.success, completionResult.reason);
      await stateRepository.save(state);
    }
    await preserveRecovery(this.ctx.storage, recovery, completionResult, trace?.id, retention);
    applyScanHeader(responseHeaders);
    return {
      response: finalizeRoleplayResponse(new Response(responseBytes, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      }), canary),
      completion: Promise.resolve(),
    };
  }
}
