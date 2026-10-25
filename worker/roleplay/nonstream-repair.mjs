import {
  extractAssistantContent,
  extractFinishReason,
} from "./memory.mjs";
import { normalizeRoleplayCompletionPayload } from "./reasoning-output.mjs";
import { ROLEPLAY_REFUSAL_FALLBACK_FAILURE_MESSAGE } from "./refusal-fallback.mjs";
import { withoutRoleplayHandoffToolCalls } from "./handoff.mjs";
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
    ? withoutRoleplayHandoffToolCalls({ ...first.message })
    : { role: "assistant" };
  delete message.refusal;
  message.content = content;
  first.message = message;
  first.finish_reason = finishReason || "stop";
  choices[0] = first;
  return { ...payload, choices };
}

function completionToolCalls(payload) {
  const calls = payload?.choices?.[0]?.message?.tool_calls;
  return Array.isArray(calls) ? calls : [];
}

function completionRefusal(payload) {
  const refusal = payload?.choices?.[0]?.message?.refusal;
  return typeof refusal === "string" ? refusal : "";
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
  let metadata = {
    provider: candidate.provider,
    model: candidate.model,
  };
  let initial = normalizedLeg(initialPayload, metadata);
  let basePayload = initial.payload;
  let assistant = initial.assistant;
  let clientContent = initial.clientContent;
  let finishReason = initial.finishReason;
  let continuationCount = 0;
  const continuationsByReason = {};
  const continuationDiagnostics = [];
  let terminalReason = "";
  let contractAnalysis = null;
  let refusalFallbackFailed = false;
  let handoffDraftUsed = false;

  // Starts the turn over on other candidates; null when none returned a readable completion.
  const openFreshLeg = async (reason, handoff = null) => {
    const attempted = await continuation.openResponse({
      assistant,
      continuationCount: continuationCount + 1,
      reason,
      contractAnalysis: null,
      handoff,
    });
    const payload = attempted
      ? await readContinuationPayload(attempted, signal)
      : null;
    if (!payload) return null;
    metadata = {
      provider: continuation.candidate.provider,
      model: continuation.candidate.model,
    };
    return { payload, leg: normalizedLeg(payload, metadata) };
  };
  const acceptFreshLeg = (next, reason) => {
    basePayload = next.leg.payload;
    assistant = next.leg.assistant;
    clientContent = next.leg.clientContent;
    finishReason = next.leg.finishReason;
    continuationCount += 1;
    continuationsByReason[reason] = (continuationsByReason[reason] ?? 0) + 1;
  };
  const failTurn = (reason) => {
    assistant = "";
    clientContent = ROLEPLAY_REFUSAL_FALLBACK_FAILURE_MESSAGE;
    finishReason = "stop";
    terminalReason = reason;
    refusalFallbackFailed = true;
  };
  const usableLeg = (next) =>
    next &&
    next.leg.assistant.trim() &&
    !continuation.classifyRefusal({
      assistant: next.leg.assistant,
      refusal: completionRefusal(next.payload),
      finishReason: next.leg.finishReason,
    }).refused;

  const refusal = continuation.classifyRefusal({
    assistant,
    refusal: completionRefusal(initialPayload),
    finishReason,
  });
  if (refusal.refused) {
    continuationDiagnostics.push({
      reason: "semantic_refusal",
      refusalKind: refusal.reason,
      charactersDiscarded: clientContent.length,
      accepted: false,
    });
    const attempted = await continuation.openResponse({
      assistant,
      continuationCount: 1,
      reason: "semantic_refusal",
      contractAnalysis: null,
    });
    const fallbackPayload = attempted
      ? await readContinuationPayload(attempted, signal)
      : null;
    if (fallbackPayload) {
      metadata = {
        provider: continuation.candidate.provider,
        model: continuation.candidate.model,
      };
      initial = normalizedLeg(fallbackPayload, metadata);
      const fallbackRefusal = continuation.classifyRefusal({
        assistant: initial.assistant,
        refusal: completionRefusal(fallbackPayload),
        finishReason: initial.finishReason,
      });
      if (!fallbackRefusal.refused) {
        basePayload = initial.payload;
        assistant = initial.assistant;
        clientContent = initial.clientContent;
        finishReason = initial.finishReason;
        continuationCount = 1;
        continuationsByReason.semantic_refusal = 1;
      } else {
        refusalFallbackFailed = true;
      }
    } else {
      refusalFallbackFailed = true;
    }
    if (refusalFallbackFailed) {
      assistant = "";
      clientContent = ROLEPLAY_REFUSAL_FALLBACK_FAILURE_MESSAGE;
      finishReason = "stop";
      terminalReason = "refusal_fallback_failed";
    }
  } else {
    const handoff = assistant.trim()
      ? null
      : continuation.detectHandoff(completionToolCalls(initialPayload));
    if (handoff) {
      continuationDiagnostics.push({
        reason: "handoff",
        handoffReason: handoff.reason,
        draftCharacters: handoff.draft.length,
        charactersDiscarded: clientContent.length,
        accepted: false,
      });
      const next = await openFreshLeg("handoff", handoff);
      if (usableLeg(next)) {
        acceptFreshLeg(next, "handoff");
      } else if (handoff.draft) {
        // No target wrote the turn, so the source's own draft is the reply.
        assistant = handoff.draft;
        clientContent = handoff.draft;
        finishReason = "stop";
        handoffDraftUsed = true;
      } else {
        failTurn("handoff_failed");
      }
    } else {
      let toolCalls = completionToolCalls(initialPayload);
      let retried = false;
      while (
        (continuationsByReason.empty_reply ?? 0) < 2 &&
        continuation.detectEmptyReply({
          assistant,
          finishReason,
          toolCalls,
          terminated: true,
          reason: continuation.assess({ assistant, finishReason }).reason,
        })
      ) {
        retried = true;
        continuationDiagnostics.push({
          reason: "empty_reply",
          charactersDiscarded: clientContent.length,
          accepted: false,
        });
        const next = await openFreshLeg("empty_reply");
        if (!next) break;
        acceptFreshLeg(next, "empty_reply");
        toolCalls = completionToolCalls(next.payload);
      }
      if (retried && !assistant.trim() && !toolCalls.length) failTurn("empty_reply_failed");
    }
  }

  while (!refusalFallbackFailed) {
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
    const replaceResponse = terminalReason === "empty_story";
    if (replaceResponse) {
      continuationDiagnostics.push({
        reason: terminalReason,
        charactersDiscarded: clientContent.length,
        accepted: false,
      });
    }
    const assistantAddition =
      terminalReason === "output_contract"
        ? leg.assistant.trimStart()
        : leg.assistant;
    let candidateAssistant = joinContinuationText(
      replaceResponse ? "" : assistant,
      assistantAddition,
      terminalReason,
    );
    const clientAddition =
      terminalReason === "output_contract"
        ? assistantAddition
        : leg.clientContent;
    let candidateClientContent = joinContinuationText(
      replaceResponse ? "" : clientContent,
      clientAddition,
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
  if (
    !refusalFallbackFailed &&
    (!terminalReason || finalDecision.reason === "")
  ) {
    terminalReason = finalDecision.reason;
    contractAnalysis = finalDecision.contractAnalysis;
  }
  const success = !terminalReason;
  const finalFinishReason =
    terminalReason === "output_limit" ? "length" : finishReason || "stop";
  const completionReason =
    terminalReason || (handoffDraftUsed ? "handoff_draft" : "complete");

  return {
    payload: completionPayload(
      basePayload,
      continuation.cleanOutput(clientContent).content,
      finalFinishReason,
    ),
    assistant: continuation.cleanOutput(assistant).content,
    finishReason: finalFinishReason,
    success,
    reason: completionReason,
    continuationCount,
    upstreamCallCount: continuation.upstreamCallCount,
    refusalFallbackCount: continuation.refusalFallbackCount,
    continuationDiagnostics,
    contractAnalysis,
  };
}
