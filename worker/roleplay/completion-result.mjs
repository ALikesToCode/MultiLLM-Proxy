function contractTelemetry(outputContract, analysis) {
  return {
    outputContractDeclaredSchema: outputContract?.schema ?? "unknown",
    outputContractDetectedSchema: analysis?.schema ?? "unknown",
    outputContractMissingFields: analysis?.missingFields ?? [],
    outputContractMarkerCount: analysis?.markerCount ?? 0,
    outputContractBlockFinal: analysis?.blockFinal ?? false,
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
      ttfbMs: Math.round(completion.ttfbMs),
      streamMs: Math.round(completion.streamMs),
      heartbeatCount: completion.heartbeatCount,
      continuationCount: completion.continuationCount,
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
      upstreamCallCount: completion.upstreamCallCount,
      ...contractTelemetry(
        parsed.outputContract,
        completion.contractAnalysis,
      ),
      continuationDiagnostics: completion.continuationDiagnostics,
    }),
  );
}
