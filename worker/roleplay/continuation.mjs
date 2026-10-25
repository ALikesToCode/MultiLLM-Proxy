import { prepareRoleplayCandidates } from "./capacity.mjs";
import {
  buildUpstreamPayload,
  estimateTokens,
} from "./memory.mjs";
import { applyRoleplayPromptCache } from "./prompt-cache.mjs";
import {
  analyzeRoleplayOutputContract,
  cleanRoleplayOutput,
} from "./output-contract.mjs";
import {
  attemptRoleplayCandidates,
  logRoleplayError,
  recordModelRefusal,
} from "./transport.mjs";
import { classifyRoleplayRefusal } from "./refusal-fallback.mjs";
import {
  isEmptyRoleplayReply,
  recordRoleplayHandoff,
  roleplayHandoffCall,
  roleplayHandoffMessages,
} from "./handoff.mjs";

// Legs that start the turn over on other candidates instead of continuing the current one.
const FRESH_LEG_REASONS = new Set(["semantic_refusal", "handoff", "empty_reply"]);

const LENGTH_CONTINUATION_INSTRUCTION = [
  "[Automatic continuation of an incomplete response]",
  "The preceding assistant message is an already-emitted partial response.",
  "Continue from its exact final character without repeating, recapping, or restarting it.",
  "Finish the current response naturally.",
  "Output only the missing continuation.",
];

const EMPTY_EOF_RETRY_INSTRUCTION = [
  "[Automatic retry after an empty provider stream]",
  "The previous provider attempt ended before any visible response was produced.",
  "Generate the complete response from the beginning using the conversation above.",
  "Do not mention the failed attempt, this retry, or any internal reasoning.",
  "Output only the finished response.",
];

const EMPTY_STORY_RETRY_INSTRUCTION = [
  "[Automatic retry after an image-only response]",
  "The previous provider attempt produced no visible story content before its IMAGE PROMPT block.",
  "Generate the complete response from the beginning using the conversation above.",
  "Include the story response first and exactly one complete IMAGE PROMPT block at the end.",
  "Do not mention the failed attempt, this retry, or any internal reasoning.",
  "Output only the finished response.",
];

function contractRepairInstruction(analysis) {
  const missing = analysis?.missingFieldLabels?.length
    ? analysis.missingFieldLabels.join(", ")
    : "the incomplete required fields";
  return [
    "[Automatic repair of an incomplete final output contract]",
    "The preceding assistant response is already emitted story content. Do not restart, recap, explain, or continue the story.",
    `Supply only these missing IMAGE PROMPT fields: ${missing}.`,
    "Do not add another IMAGE PROMPT marker when one is already present. Do not discuss whether the response was complete.",
    "Output only the missing labeled field lines and their visible descriptions.",
  ];
}

function continuationMessages(messages, assistant, reason, analysis) {
  if (reason === "empty_eof" || reason === "empty_story") {
    return [
      ...messages,
      {
        role: "system",
        content: (reason === "empty_story"
          ? EMPTY_STORY_RETRY_INSTRUCTION
          : EMPTY_EOF_RETRY_INSTRUCTION
        ).join("\n"),
      },
    ];
  }
  const instruction =
    reason === "output_contract"
      ? contractRepairInstruction(analysis)
      : [
          ...LENGTH_CONTINUATION_INSTRUCTION,
          reason === "incomplete_eof"
            ? "The provider stream ended without a terminal finish event before the response was complete."
            : "The provider reached an output limit before the response was complete.",
        ];
  return [
    ...messages,
    { role: "assistant", content: assistant },
    {
      role: "system",
      content: instruction.join("\n"),
    },
  ];
}

function continuationIdempotencyKey(base, attemptNumber) {
  if (!base) {
    return "";
  }
  const suffix = `:continue:${attemptNumber}`;
  return `${base.slice(0, 200 - suffix.length)}${suffix}`;
}

export function createRoleplayContinuation({
  state,
  candidate,
  messages,
  parsed,
  env,
  settings,
  signal,
  idempotencyKey,
  refusalFallbackCandidates = [],
  handoffTargets = [],
  laterCandidates = [],
}) {
  let currentState = state;
  let currentCandidate = candidate;
  // A handoff adds its note to the prompt of every later leg, and its draft stands in for the
  // reply if no later leg writes one.
  let legMessages = messages;
  let handoffDraft = "";
  let remainingHandoffTargets = [...handoffTargets];
  let remainingLaterCandidates = [...laterCandidates];
  let handoffCount = 0;
  let emptyReplyCount = 0;
  let remainingRefusalFallbackCandidates = settings.refusalFallbackEnabled
    ? [...refusalFallbackCandidates]
    : [];
  let refusalFallbackCount = 0;
  let upstreamCallCount = 1;
  const enabled =
    parsed.outputMode === "unlimited" &&
    (settings.maxAutoContinuations > 0 ||
      settings.maxOutputContractRepairs > 0);
  const canOpen =
    enabled ||
    remainingRefusalFallbackCandidates.length > 0 ||
    remainingHandoffTargets.length > 0 ||
    (settings.emptyReplyFallbackEnabled === true && remainingLaterCandidates.length > 0);

  const assess = ({ assistant, finishReason }) => {
    const cleaned = cleanRoleplayOutput(
      assistant,
      parsed.outputContract,
    );
    const contractAnalysis = analyzeRoleplayOutputContract(
      cleaned.content,
      parsed.outputContract,
    );
    if (finishReason === "length") {
      return {
        reason: "output_limit",
        limit: settings.maxAutoContinuations,
        contractAnalysis,
        cleaned,
      };
    }
    if (
      finishReason === "stop" &&
      contractAnalysis.required &&
      !contractAnalysis.storyPresent
    ) {
      return {
        reason: "empty_story",
        limit: settings.maxOutputContractRepairs,
        contractAnalysis,
        cleaned,
      };
    }
    if (finishReason === "stop" && !contractAnalysis.satisfied) {
      return {
        reason: "output_contract",
        limit: settings.maxOutputContractRepairs,
        contractAnalysis,
        cleaned,
      };
    }
    return { reason: "", limit: 0, contractAnalysis, cleaned };
  };

  const freshLegCandidates = (reason, handoff) => {
    if (reason === "semantic_refusal") return remainingRefusalFallbackCandidates;
    if (reason === "empty_reply") {
      return settings.emptyReplyFallbackEnabled === true ? remainingLaterCandidates : [];
    }
    if (!remainingHandoffTargets.length) return [];
    // A draft can stand in for the reply if every target fails; without one the rest of the
    // chain follows the targets.
    return handoff?.draft
      ? remainingHandoffTargets
      : [
          ...remainingHandoffTargets,
          ...remainingLaterCandidates.filter((entry) => !remainingHandoffTargets.includes(entry)),
        ];
  };

  const openResponse = async ({
    assistant,
    continuationCount,
    reason,
    contractAnalysis,
    handoff = null,
    signal: nextSignal = signal,
  }) => {
    const semanticRefusal = reason === "semantic_refusal";
    const freshLeg = FRESH_LEG_REASONS.has(reason);
    const retriesFromBeginning =
      reason === "empty_eof" || reason === "empty_story";
    const freshCandidates = freshLeg ? freshLegCandidates(reason, handoff) : [];
    if (
      freshLeg
        ? !freshCandidates.length
        : !enabled || (!assistant.trim() && !retriesFromBeginning)
    ) {
      return null;
    }
    if (reason === "handoff") {
      legMessages = roleplayHandoffMessages(legMessages, handoff);
      handoffDraft = handoff?.draft ?? "";
    }
    const nextMessages = freshLeg
      ? legMessages
      : continuationMessages(
          legMessages,
          assistant,
          reason,
          contractAnalysis,
        );
    const nextEstimatedInputTokens = estimateTokens(nextMessages);
    const nextCandidates = prepareRoleplayCandidates(
      freshLeg
        ? freshCandidates
        : [currentCandidate],
      nextEstimatedInputTokens,
      freshLeg ? parsed.maxTokens : null,
      settings,
    );
    if (semanticRefusal) {
      currentState = recordModelRefusal(
        currentState,
        currentCandidate,
      );
      remainingRefusalFallbackCandidates = [];
      refusalFallbackCount += 1;
    }
    if (reason === "handoff") {
      currentState = recordRoleplayHandoff(currentState);
      remainingHandoffTargets = [];
      handoffCount += 1;
      console.log(JSON.stringify({
        event: "roleplay_handoff",
        provider: currentCandidate.provider,
        model: currentCandidate.model,
        handoffReason: handoff?.reason,
        notesCharacters: handoff?.notes?.length ?? 0,
        draftCharacters: handoff?.draft?.length ?? 0,
      }));
    }
    if (reason === "empty_reply") {
      emptyReplyCount += 1;
      console.log(JSON.stringify({
        event: "roleplay_empty_reply_fallback",
        provider: currentCandidate.provider,
        model: currentCandidate.model,
      }));
    }
    if (!nextCandidates.length) {
      logRoleplayError(
        "roleplay_continuation_context_exhausted",
        new Error("Continuation no longer fits the selected context"),
        {
          provider: currentCandidate.provider,
          model: currentCandidate.model,
          continuationCount,
          continuationReason: reason,
        },
      );
      return null;
    }

    let attempted;
    try {
      upstreamCallCount += 1;
      attempted = await attemptRoleplayCandidates(
        currentState,
        nextCandidates,
        (nextCandidate) =>
          applyRoleplayPromptCache(
            buildUpstreamPayload(
              parsed,
              nextCandidate,
              nextMessages,
              settings,
            ),
            nextCandidate,
            nextMessages,
            settings,
            parsed.promptCache,
            nextEstimatedInputTokens,
          ),
        env,
        settings,
        nextSignal,
        continuationIdempotencyKey(idempotencyKey, continuationCount),
      );
    } catch (error) {
      if (nextSignal?.aborted) {
        throw error;
      }
      logRoleplayError("roleplay_continuation_fetch_failed", error, {
        provider: currentCandidate.provider,
        model: currentCandidate.model,
        continuationCount,
        continuationReason: reason,
      });
      return null;
    }
    if (nextSignal?.aborted) {
      attempted.controller?.abort(nextSignal.reason);
      attempted.cleanup?.();
      const response = attempted.response ?? attempted.terminalResponse;
      void response?.body?.cancel().catch(() => {});
      throw nextSignal.reason;
    }
    currentState = attempted.state;
    upstreamCallCount += attempted.fallbackCount ?? 0;
    if (semanticRefusal) {
      refusalFallbackCount += attempted.fallbackCount ?? 0;
    }

    if (attempted.terminalResponse) {
      const status = attempted.terminalResponse.status;
      await attempted.terminalResponse.body?.cancel();
      logRoleplayError(
        "roleplay_continuation_provider_rejected",
        new Error("Continuation provider did not return a usable response"),
        {
          provider: currentCandidate.provider,
          model: currentCandidate.model,
          continuationCount,
          continuationReason: reason,
          status,
        },
      );
      return null;
    }
    currentCandidate = attempted.candidate;
    if (freshLeg) {
      remainingLaterCandidates = attempted.laterCandidates ?? [];
      if (reason !== "handoff") remainingHandoffTargets = attempted.handoffTargets ?? [];
    }
    return attempted;
  };

  return {
    enabled,
    canOpen,
    get state() {
      return currentState;
    },
    get candidate() {
      return currentCandidate;
    },
    get refusalFallbackCount() {
      return refusalFallbackCount;
    },
    get refusalFallbackEnabled() {
      return remainingRefusalFallbackCandidates.length > 0;
    },
    // The stream holds a leg's frames until it shows visible text whenever that leg may still be
    // replaced: by a refusal fallback or by a handoff.
    get holdUntilVisible() {
      return (
        remainingRefusalFallbackCandidates.length > 0 ||
        remainingHandoffTargets.length > 0
      );
    },
    get handoffCount() {
      return handoffCount;
    },
    get handoffDraft() {
      return handoffDraft;
    },
    get emptyReplyCount() {
      return emptyReplyCount;
    },
    get upstreamCallCount() {
      return upstreamCallCount;
    },
    assess,
    cleanOutput(content) {
      return cleanRoleplayOutput(content, parsed.outputContract);
    },
    incompleteReason(input) {
      return assess(input).reason;
    },
    classifyRefusal: classifyRoleplayRefusal,
    detectHandoff(toolCalls) {
      return remainingHandoffTargets.length > 0 ? roleplayHandoffCall(toolCalls) : null;
    },
    detectEmptyReply(input) {
      // The output-contract repair already retries an image-only reply when it may run.
      if (input?.reason === "empty_story" && enabled) return false;
      return (
        settings.emptyReplyFallbackEnabled === true &&
        remainingLaterCandidates.length > 0 &&
        isEmptyRoleplayReply(input)
      );
    },
    openResponse,
    async open(input) {
      const attempted = await openResponse(input);
      if (!attempted) {
        return null;
      }
      const contentType =
        attempted.response.headers.get("Content-Type") ?? "";
      if (
        !attempted.response.body ||
        !contentType.toLowerCase().includes("text/event-stream")
      ) {
        attempted.cleanup();
        await attempted.response.body?.cancel();
        logRoleplayError(
          "roleplay_continuation_invalid_response",
          new Error("Continuation response was not an SSE stream"),
          {
            provider: currentCandidate.provider,
            model: currentCandidate.model,
            continuationCount: input.continuationCount,
            continuationReason: input.reason,
            status: attempted.response.status,
          },
        );
        return null;
      }
      return {
        upstreamBody: attempted.response.body,
        upstreamController: attempted.controller,
        cleanup: attempted.cleanup,
        reasoningMetadata: {
          provider: attempted.candidate.provider,
          model: attempted.candidate.model,
        },
        refusalFallbackEnabled: true,
      };
    },
  };
}
