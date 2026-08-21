import { prepareRoleplayCandidates } from "./capacity.mjs";
import {
  buildUpstreamPayload,
  estimateTokens,
} from "./memory.mjs";
import { applyRoleplayPromptCache } from "./prompt-cache.mjs";
import {
  attemptRoleplayCandidates,
  logRoleplayError,
} from "./transport.mjs";

const CONTINUATION_INSTRUCTION = [
  "[Automatic continuation after an upstream output limit]",
  "The preceding assistant message is an already-emitted partial response.",
  "Continue from its exact final character without repeating, recapping, or restarting it.",
  "Finish the current response naturally, including every caller-required final block.",
  "Output only the missing continuation.",
].join("\n");

function continuationMessages(messages, assistant) {
  return [
    ...messages,
    { role: "assistant", content: assistant },
    { role: "system", content: CONTINUATION_INSTRUCTION },
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
}) {
  let currentState = state;
  const enabled =
    parsed.outputMode === "unlimited" &&
    settings.maxAutoContinuations > 0;

  return {
    enabled,
    get state() {
      return currentState;
    },
    async open({ assistant, continuationCount }) {
      if (!enabled || !assistant.trim()) {
        return null;
      }
      const nextMessages = continuationMessages(messages, assistant);
      const [nextCandidate] = prepareRoleplayCandidates(
        [candidate],
        estimateTokens(nextMessages),
        null,
        settings,
      );
      if (!nextCandidate) {
        logRoleplayError(
          "roleplay_continuation_context_exhausted",
          new Error("Continuation no longer fits the selected context"),
          {
            provider: candidate.provider,
            model: candidate.model,
            continuationCount,
          },
        );
        return null;
      }

      const prepared = applyRoleplayPromptCache(
        buildUpstreamPayload(parsed, nextCandidate, nextMessages),
        nextCandidate,
        nextMessages,
        settings,
        parsed.promptCache,
      );
      let attempted;
      try {
        attempted = await attemptRoleplayCandidates(
          currentState,
          [nextCandidate],
          () => prepared,
          env,
          settings,
          signal,
          continuationIdempotencyKey(idempotencyKey, continuationCount),
        );
      } catch (error) {
        if (signal?.aborted) {
          throw error;
        }
        logRoleplayError("roleplay_continuation_fetch_failed", error, {
          provider: candidate.provider,
          model: candidate.model,
          continuationCount,
        });
        return null;
      }
      currentState = attempted.state;

      if (attempted.terminalResponse) {
        const status = attempted.terminalResponse.status;
        await attempted.terminalResponse.body?.cancel();
        logRoleplayError(
          "roleplay_continuation_provider_rejected",
          new Error("Continuation provider did not return a usable stream"),
          {
            provider: candidate.provider,
            model: candidate.model,
            continuationCount,
            status,
          },
        );
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
            provider: candidate.provider,
            model: candidate.model,
            continuationCount,
            status: attempted.response.status,
          },
        );
        return null;
      }
      return {
        upstreamBody: attempted.response.body,
        upstreamController: attempted.controller,
        cleanup: attempted.cleanup,
      };
    },
  };
}
