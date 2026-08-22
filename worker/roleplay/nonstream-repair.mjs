import {
  extractAssistantContent,
  extractFinishReason,
} from "./memory.mjs";
import { normalizeRoleplayCompletionPayload } from "./reasoning-output.mjs";
import {
  MAX_RESPONSE_BYTES,
  logRoleplayError,
  readBoundedBytes,
} from "./transport.mjs";

function joinContinuationText(existing, addition, reason) {
  if (!existing || !addition) {
    return existing + addition;
  }
  if (reason !== "output_contract") {
    return existing + addition;
  }
  return /\s$/.test(existing) || /^\s|^[.,;:!?)]/.test(addition)
    ? existing + addition
    : `${existing}\n${addition}`;
}

function missingFieldsStrictlyDecreased(before, after) {
  const previous = new Set(before?.missingFields ?? []);
  const current = after?.missingFields ?? [];
  return (
    current.length < previous.size &&
    current.every((field) => previous.has(field))
  );
}

function normalizedLeg(payload, metadata) {
  const normalized = normalizeRoleplayCompletionPayload(payload, metadata);
  const clientContent = normalized.changed
    ? normalized.payload?.choices?.[0]?.message?.content ?? ""
    : extractAssistantContent(payload);
  return {
    payload: normalized.payload,
    assistant: normalized.changed
      ? normalized.visibleContent
      : clientContent,
    clientContent,
    finishReason: extractFinishReason(normalized.payload),
  };
}

function completionPayload(payload, content, finishReason) {
  const choices = Array.isArray(payload?.choices)
    ? [...payload.choices]
    : [];
  const first = choices[0] && typeof choices[0] === "object"
    ? { ...choices[0] }
    : { index: 0 };
  const message = first.message && typeof first.message === "object"
    ? { ...first.message }
    : { role: "assistant" };
  message.content = content;
  first.message = message;
  first.finish_reason = finishReason || "stop";
  choices[0] = first;
  return { ...payload, choices };
}

async function readContinuationPayload(attempted, signal) {
  const contentType = attempted.response.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    attempted.cleanup();
    await attempted.response.body?.cancel();
    return null;
  }
  try {
    const { bytes } = await readBoundedBytes(
      attempted.response.body,
      MAX_RESPONSE_BYTES,
      attempted.controller?.signal ?? signal,
    );
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (error) {
    logRoleplayError("roleplay_nonstream_continuation_invalid", error, {
      status: attempted.response.status,
    });
    return null;
  } finally {
    attempted.cleanup();
  }
}

export async function repairNonStreamingCompletion({
  initialPayload,
  continuation,
  candidate,
  settings,
  signal,
}) {
  const metadata = {
    provider: candidate.provider,
    model: candidate.model,
  };
  const initial = normalizedLeg(initialPayload, metadata);
  const basePayload = initial.payload;
  let assistant = initial.assistant;
  let clientContent = initial.clientContent;
  let finishReason = initial.finishReason;
  let continuationCount = 0;
  const continuationsByReason = {};
  const continuationDiagnostics = [];
  let terminalReason = "";
  let contractAnalysis = null;

  while (true) {
    let decision = continuation.assess({ assistant, finishReason });
    assistant = decision.cleaned?.content ?? assistant;
    clientContent = continuation.cleanOutput(clientContent).content;
    contractAnalysis = decision.contractAnalysis;
    terminalReason = decision.reason;
    if (!terminalReason) {
      break;
    }

    const reasonCount = continuationsByReason[terminalReason] ?? 0;
    const limit = Number.isFinite(decision.limit)
      ? decision.limit
      : settings.maxAutoContinuations;
    if (reasonCount >= limit) {
      break;
    }

    const attempted = await continuation.openResponse({
      assistant,
      continuationCount: continuationCount + 1,
      reason: terminalReason,
      contractAnalysis,
    });
    if (!attempted) {
      break;
    }
    const nextPayload = await readContinuationPayload(attempted, signal);
    if (!nextPayload) {
      terminalReason = "continuation_invalid";
      break;
    }

    const leg = normalizedLeg(nextPayload, metadata);
    let candidateAssistant = joinContinuationText(
      assistant,
      leg.assistant,
      terminalReason,
    );
    let candidateClientContent = joinContinuationText(
      clientContent,
      leg.clientContent,
      terminalReason,
    );
    const nextDecision = continuation.assess({
      assistant: candidateAssistant,
      finishReason: leg.finishReason,
    });
    candidateAssistant =
      nextDecision.cleaned?.content ?? candidateAssistant;
    candidateClientContent =
      continuation.cleanOutput(candidateClientContent).content;

    let accepted = true;
    if (terminalReason === "output_contract") {
      accepted = missingFieldsStrictlyDecreased(
        contractAnalysis,
        nextDecision.contractAnalysis,
      );
      continuationDiagnostics.push({
        reason: terminalReason,
        schema: nextDecision.contractAnalysis?.schema ?? "unknown",
        missingBefore: contractAnalysis?.missingFields ?? [],
        missingAfter:
          nextDecision.contractAnalysis?.missingFields ?? [],
        markerCount:
          nextDecision.contractAnalysis?.markerCount ?? 0,
        charactersAdded: Math.max(
          0,
          candidateAssistant.length - assistant.length,
        ),
        accepted,
      });
    }
    continuationCount += 1;
    continuationsByReason[terminalReason] = reasonCount + 1;
    if (!accepted) {
      terminalReason = "output_contract_no_progress";
      break;
    }

    assistant = candidateAssistant;
    clientContent = candidateClientContent;
    finishReason = leg.finishReason;
    decision = nextDecision;
    contractAnalysis = decision.contractAnalysis;
  }

  const finalDecision = continuation.assess({ assistant, finishReason });
  if (!terminalReason || finalDecision.reason === "") {
    terminalReason = finalDecision.reason;
    contractAnalysis = finalDecision.contractAnalysis;
  }
  const success = !terminalReason;
  const finalFinishReason =
    terminalReason === "output_limit" ? "length" : finishReason || "stop";

  return {
    payload: completionPayload(
      basePayload,
      continuation.cleanOutput(clientContent).content,
      finalFinishReason,
    ),
    assistant: continuation.cleanOutput(assistant).content,
    finishReason: finalFinishReason,
    success,
    reason: terminalReason || "complete",
    continuationCount,
    upstreamCallCount: continuation.upstreamCallCount,
    continuationDiagnostics,
    contractAnalysis,
  };
}
