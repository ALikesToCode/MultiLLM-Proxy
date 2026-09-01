import { appendAssistantMessage } from "./memory.mjs";
import { markRoleplayRequest } from "./state-runtime.mjs";
import { recordRoleplayCompletionResult } from "./transport.mjs";

export function applyRoleplayCompletionState({
  state,
  candidate,
  completion,
  disposition,
  modelResult,
  inputTokensSaved,
  persistedConversation,
  settings,
  idempotencyKey,
}) {
  let nextState = recordRoleplayCompletionResult(
    state,
    candidate,
    { reason: completion.reason, ...modelResult },
  );
  nextState = {
    ...nextState,
    inputTokensSaved:
      (nextState.inputTokensSaved ?? 0) + inputTokensSaved,
  };
  nextState = disposition.persistAssistant
    ? appendAssistantMessage(
        nextState,
        persistedConversation,
        completion.assistant,
        settings,
      )
    : { ...nextState, updatedAt: Date.now() };
  return markRoleplayRequest(
    nextState,
    idempotencyKey,
    disposition.requestStatus,
  );
}

function contractTelemetry(outputContract, analysis) {
  return {
    outputContractDeclaredSchema: outputContract?.schema ?? "unknown",
    outputContractDetectedSchema: analysis?.schema ?? "unknown",
    outputContractMissingFields: analysis?.missingFields ?? [],
    outputContractMarkerCount: analysis?.markerCount ?? 0,
    outputContractBlockFinal: analysis?.blockFinal ?? false,
    outputContractStoryPresent: analysis?.storyPresent ?? false,
  };
}

export function roleplayCompletionDisposition({
  success,
  reason,
  outputMode,
  memoryEnabled,
  failureStatus,
}) {
  const outputLimited = reason === "output_limit";
  return {
    modelSucceeded: success || outputLimited,
    persistAssistant:
      memoryEnabled &&
      (success || (outputMode === "unlimited" && outputLimited)),
    requestStatus: success
      ? "completed"
      : outputLimited
        ? "output_limited"
        : reason === "output_contract"
          ? "output_contract_incomplete"
          : reason === "empty_story"
            ? "output_contract_story_missing"
          : reason === "output_contract_no_progress"
            ? "output_contract_no_progress"
            : failureStatus,
  };
}

export function logRoleplayStreamCompletion({
  candidate,
  parsed,
  completion,
  headerMs,
  inputTokensSaved,
  timings = {},
}) {
  console.log(
    JSON.stringify({
      event: "roleplay_stream_completed",
      provider: candidate.provider,
      model: candidate.model,
      success: completion.success,
      reason: completion.reason,
      finishReason: completion.finishReason || undefined,
      headerMs: Math.round(headerMs),
      queueMs: Math.round(timings.queueMs ?? 0),
      stateLoadMs: Math.round(timings.stateLoadMs ?? 0),
      credentialCheckMs: Math.round(timings.credentialCheckMs ?? 0),
      preparationMs: Math.round(timings.preparationMs ?? 0),
      totalToHeadersMs: Math.round(timings.totalToHeadersMs ?? headerMs),
      stateCacheHit: Boolean(timings.stateCacheHit),
      credentialCheckPerformed: Boolean(
        timings.credentialCheckPerformed,
      ),
      ttfbMs: Math.round(completion.ttfbMs),
      streamMs: Math.round(completion.streamMs),
      completionTokens: completion.completionTokens || undefined,
      generationMs: Math.round(completion.generationMs || 0) || undefined,
      tokensPerSecond: Number.isFinite(completion.tokensPerSecond)
        ? Math.round(completion.tokensPerSecond * 100) / 100
        : undefined,
      heartbeatCount: completion.heartbeatCount,
      continuationCount: completion.continuationCount,
      refusalFallbackCount: completion.refusalFallbackCount,
      upstreamCallCount: completion.upstreamCallCount,
      ...contractTelemetry(
        parsed.outputContract,
        completion.contractAnalysis,
      ),
      continuationDiagnostics: completion.continuationDiagnostics,
      assistantCharacters: completion.assistant.length,
      maxOutputTokens: candidate.resolvedMaxOutputTokens,
      outputMode: parsed.outputMode,
      requestedMaxTokens: parsed.requestedMaxTokens ?? undefined,
      inputTokensSaved,
    }),
  );
}

export function logRoleplayNonStreamCompletion({
  candidate,
  parsed,
  completion,
  timings = {},
}) {
  console.log(
    JSON.stringify({
      event: "roleplay_nonstream_completed",
      provider: candidate.provider,
      model: candidate.model,
      success: completion.success,
      reason: completion.reason,
      finishReason: completion.finishReason || undefined,
      continuationCount: completion.continuationCount,
      refusalFallbackCount: completion.refusalFallbackCount,
      upstreamCallCount: completion.upstreamCallCount,
      queueMs: Math.round(timings.queueMs ?? 0),
      stateLoadMs: Math.round(timings.stateLoadMs ?? 0),
      credentialCheckMs: Math.round(timings.credentialCheckMs ?? 0),
      preparationMs: Math.round(timings.preparationMs ?? 0),
      totalToHeadersMs: Math.round(timings.totalToHeadersMs ?? 0),
      stateCacheHit: Boolean(timings.stateCacheHit),
      credentialCheckPerformed: Boolean(
        timings.credentialCheckPerformed,
      ),
      ...contractTelemetry(
        parsed.outputContract,
        completion.contractAnalysis,
      ),
      continuationDiagnostics: completion.continuationDiagnostics,
    }),
  );
}
