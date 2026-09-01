import {
  bufferedCompletionFrames,
  createSseAssistantCollector as createLegCollector,
} from "./sse-collector.mjs";
import { createRoleplayStreamValidationGate } from "./stream-validation-gate.mjs";
import {
  createRoleplayRefusalStreamGate,
  ROLEPLAY_REFUSAL_FALLBACK_FAILURE_MESSAGE,
} from "./refusal-fallback.mjs";

const SSE_ENCODER = new TextEncoder();
const HEARTBEAT_COMMENT = SSE_ENCODER.encode(
  ": roleplay-keepalive\n\n",
);
const MAX_COLLECTED_ASSISTANT_CHARACTERS = 1_000_000;

function logStreamError(event, error) {
  const errorName =
    error instanceof Error &&
    /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(error.name)
      ? error.name
      : "Error";
  console.error(JSON.stringify({ event, errorName }));
}

function delayedOutcome(delayMs) {
  let timer;
  const promise = new Promise((resolve) => {
    timer = setTimeout(
      () => resolve({ kind: "timer" }),
      delayMs,
    );
  });
  return {
    promise,
    cancel() {
      clearTimeout(timer);
    },
  };
}

function observedRead(reader) {
  return reader.read().then(
    (value) => ({ kind: "read", value }),
    (error) => ({ kind: "error", error }),
  );
}

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

export function createObservedStream({
  upstreamBody,
  requestSignal,
  upstreamController,
  heartbeatMs,
  onComplete,
  cleanup = () => {},
  openContinuation = null,
  getIncompleteReason = null,
  assessCompletion = null,
  cleanOutput = null,
  getUpstreamCallCount = null,
  getRefusalFallbackCount = null,
  bufferUntilValidated = false,
  maxContinuations = 0,
  reasoningMetadata = null,
  detectRefusal = null,
  refusalFallbackEnabled = false,
}) {
  let resolveCompletion;
  const completion = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  let reader = upstreamBody.getReader();
  let activeController = upstreamController;
  let activeCleanup = cleanup;
  let decoder = new TextDecoder();
  let currentReasoningMetadata = reasoningMetadata;
  const newCollector = () =>
    createLegCollector({
      maximumCharacters: MAX_COLLECTED_ASSISTANT_CHARACTERS,
      deferTerminalFrames:
        typeof openContinuation === "function" || bufferUntilValidated,
      reasoningMetadata: currentReasoningMetadata,
    });
  let collector = newCollector();
  const validationGate = createRoleplayStreamValidationGate(
    bufferUntilValidated,
  );
  const refusalGate = createRoleplayRefusalStreamGate(
    refusalFallbackEnabled,
  );
  let settled = false;
  let released = false;
  let pendingRead = null;
  let firstByteAt = 0;
  let legFirstByteAt = 0;
  let completionTokens = 0;
  let generationMs = 0;
  let heartbeatCount = 0;
  let continuationCount = 0;
  const continuationsByReason = {};
  const continuationDiagnostics = [];
  let pendingContinuation = null;
  let activeContinuationReason = "";
  let repairBaseline = null;
  let completedLeg = null;
  let assistant = "";
  let clientContent = "";
  let terminalFrames = [];
  let template = null;
  const streamStartedAt = performance.now();
  let lastDownstreamAt = streamStartedAt;

  const releaseReader = () => {
    if (!released) {
      released = true;
      reader.releaseLock();
    }
  };

  const cleanupLeg = () => {
    activeCleanup();
    activeCleanup = () => {};
  };

  const activateLeg = (next, decision) => {
    reader = next.upstreamBody.getReader();
    activeController = next.upstreamController;
    activeCleanup = next.cleanup ?? (() => {});
    decoder = new TextDecoder();
    currentReasoningMetadata =
      next.reasoningMetadata ?? currentReasoningMetadata;
    collector = newCollector();
    refusalGate.reset(Boolean(next.refusalFallbackEnabled));
    released = false;
    pendingRead = null;
    pendingContinuation = null;
    completedLeg = null;
    legFirstByteAt = 0;
    activeContinuationReason = decision.reason;
    repairBaseline = decision.contractAnalysis ?? null;
  };

  const settle = async (result) => {
    if (settled) {
      return;
    }
    settled = true;
    const completed = {
      ...result,
      heartbeatCount,
      continuationCount,
      upstreamCallCount:
        typeof getUpstreamCallCount === "function"
          ? getUpstreamCallCount()
          : continuationCount + 1,
      refusalFallbackCount:
        typeof getRefusalFallbackCount === "function"
          ? getRefusalFallbackCount()
          : 0,
      continuationDiagnostics,
      streamMs: performance.now() - streamStartedAt,
      ttfbMs: firstByteAt ? firstByteAt - streamStartedAt : 0,
      completionTokens,
      generationMs,
      tokensPerSecond:
        completionTokens > 0 && generationMs > 0
          ? completionTokens / (generationMs / 1_000)
          : null,
    };
    try {
      await onComplete(completed);
    } catch (error) {
      logStreamError("roleplay_stream_state_write_failed", error);
    } finally {
      resolveCompletion(completed);
    }
  };

  const stopUpstream = async (reason) => {
    activeController.abort(reason);
    try {
      await reader.cancel(reason);
    } catch {
      // The abort may already have errored the upstream reader.
    }
    pendingRead = null;
    releaseReader();
    cleanupLeg();
  };

  const millisecondsUntilHeartbeat = () =>
    Math.max(
      0,
      heartbeatMs - (performance.now() - lastDownstreamAt),
    );

  const enqueueHeartbeat = (controller) => {
    heartbeatCount += 1;
    controller.enqueue(HEARTBEAT_COMMENT.slice());
    lastDownstreamAt = performance.now();
  };

  const enqueueFrames = (controller, frames) => {
    for (const frame of frames) {
      controller.enqueue(SSE_ENCODER.encode(frame));
    }
    if (frames.length) {
      lastDownstreamAt = performance.now();
    }
  };

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        while (true) {
          if (requestSignal?.aborted) {
            throw new DOMException("Request aborted", "AbortError");
          }
          // Upstream events can be consumed and intentionally filtered. Only
          // bytes enqueued downstream satisfy the client's liveness timeout.
          if (millisecondsUntilHeartbeat() === 0) {
            enqueueHeartbeat(controller);
            return;
          }
          if (!pendingRead) {
            pendingRead = observedRead(reader);
          }

          const wait = delayedOutcome(millisecondsUntilHeartbeat());
          const outcome = await Promise.race([
            pendingRead,
            wait.promise,
          ]);
          wait.cancel();

          if (outcome.kind === "timer") {
            enqueueHeartbeat(controller);
            return;
          }

          pendingRead = null;
          if (outcome.kind === "error") {
            throw outcome.error;
          }
          const { value, done } = outcome.value;
          if (done) {
            if (!completedLeg) {
              const collected = collector.finish(decoder.decode());
              if (collected.completionTokens > 0 && legFirstByteAt) {
                completionTokens += collected.completionTokens;
                generationMs += Math.max(
                  0,
                  performance.now() - legFirstByteAt,
                );
              }
              const refusal = typeof detectRefusal === "function"
                ? detectRefusal({
                    assistant: collected.assistant,
                    refusal: collected.refusal,
                    finishReason: collected.finishReason,
                  })
                : { refused: false, reason: "" };
              const semanticRefusal = refusal.refused === true;
              const completedOutputFrames = [
                ...refusalGate.consume(collected.output),
                ...refusalGate.complete(semanticRefusal),
              ];
              const outputLimited = collected.finishReason === "length";
              const assistantAddition =
                activeContinuationReason === "output_contract"
                  ? collected.assistant.trimStart()
                  : collected.assistant;
              let candidateAssistant = joinContinuationText(
                assistant,
                assistantAddition,
                activeContinuationReason,
              );
              const clientAddition =
                activeContinuationReason === "output_contract"
                  ? assistantAddition
                  : collected.clientContent;
              let candidateClientContent = joinContinuationText(
                clientContent,
                clientAddition,
                activeContinuationReason,
              );
              let decision = typeof assessCompletion === "function"
                ? assessCompletion({
                    assistant: candidateAssistant,
                    finishReason: collected.finishReason,
                  })
                : {
                    reason:
                      typeof getIncompleteReason === "function"
                        ? getIncompleteReason({
                            assistant: candidateAssistant,
                            finishReason: collected.finishReason,
                          })
                        : "",
                    limit: maxContinuations,
                    contractAnalysis: null,
                    cleaned: { content: candidateAssistant },
                  };
              candidateAssistant =
                decision.cleaned?.content ?? candidateAssistant;
              if (typeof cleanOutput === "function") {
                candidateClientContent =
                  cleanOutput(candidateClientContent).content;
              }
              if (semanticRefusal) {
                decision = {
                  reason: "semantic_refusal",
                  limit: 1,
                  contractAnalysis: null,
                  cleaned: { content: assistant },
                };
              } else if (outputLimited) {
                decision = {
                  ...decision,
                  reason: "output_limit",
                  limit: maxContinuations,
                };
              } else if (!collected.terminated) {
                decision = {
                  ...decision,
                  reason:
                    candidateAssistant.trim() || !bufferUntilValidated
                      ? "incomplete_eof"
                      : "empty_eof",
                  limit:
                    candidateAssistant.trim() || !bufferUntilValidated
                      ? maxContinuations
                      : 1,
                };
              }

              let accepted = true;
              if (activeContinuationReason === "output_contract") {
                accepted = missingFieldsStrictlyDecreased(
                  repairBaseline,
                  decision.contractAnalysis,
                );
                continuationDiagnostics.push({
                  reason: activeContinuationReason,
                  schema: decision.contractAnalysis?.schema ?? "unknown",
                  missingBefore: repairBaseline?.missingFields ?? [],
                  missingAfter:
                    decision.contractAnalysis?.missingFields ?? [],
                  markerCount:
                    decision.contractAnalysis?.markerCount ?? 0,
                  charactersAdded: Math.max(
                    0,
                    candidateAssistant.length - assistant.length,
                  ),
                  accepted,
                });
              }

              const discardForFreshRetry =
                decision.reason === "empty_eof" ||
                decision.reason === "empty_story" ||
                decision.reason === "semantic_refusal";
              if (discardForFreshRetry) {
                continuationDiagnostics.push({
                  reason: decision.reason,
                  refusalKind:
                    decision.reason === "semantic_refusal"
                      ? refusal.reason
                      : undefined,
                  charactersDiscarded: collected.clientContent.length,
                  accepted: false,
                });
                if (decision.reason === "empty_eof") {
                  // Reasoning frames may already be visible downstream. Flush
                  // the leg's normalizer output so its <think> envelope closes
                  // before a retry starts, while still discarding it from the
                  // validated response and persisted assistant content.
                  enqueueFrames(controller, completedOutputFrames);
                }
                refusalGate.discardLeg();
                validationGate.discardLeg();
                template = collected.template ?? template;
                terminalFrames = [];
              } else if (accepted) {
                assistant = candidateAssistant;
                clientContent = candidateClientContent;
                template = collected.template ?? template;
                terminalFrames = collected.withheld;
                enqueueFrames(
                  controller,
                  validationGate.consume(completedOutputFrames, {
                    hold: activeContinuationReason === "output_contract",
                  }),
                );
              } else {
                decision = {
                  reason: "output_contract_no_progress",
                  limit: 0,
                  contractAnalysis: repairBaseline,
                  cleaned: { content: assistant },
                };
              }

              const incompleteReason = decision.reason ?? "";
              completedLeg = {
                collected,
                decision,
                incompleteReason,
                reasonCount:
                  continuationsByReason[incompleteReason] ?? 0,
                reasonLimit: Number.isFinite(decision.limit)
                  ? decision.limit
                  : maxContinuations,
              };
            }
            const {
              collected,
              decision,
              incompleteReason,
              reasonCount,
              reasonLimit,
            } = completedLeg;
            if (
              incompleteReason &&
              incompleteReason !== "output_contract_no_progress" &&
              typeof openContinuation === "function" &&
              reasonCount < reasonLimit &&
              !collected.truncated &&
              !requestSignal?.aborted
            ) {
              if (!pendingContinuation) {
                pendingContinuation = Promise.resolve(
                  openContinuation({
                    assistant,
                    continuationCount: continuationCount + 1,
                    reason: incompleteReason,
                    contractAnalysis: decision.contractAnalysis,
                  }),
                ).then(
                  (next) => ({ kind: "continuation", next }),
                  (error) => ({ kind: "continuation_error", error }),
                );
              }
              if (millisecondsUntilHeartbeat() === 0) {
                enqueueHeartbeat(controller);
                return;
              }
              const continuationWait = delayedOutcome(
                millisecondsUntilHeartbeat(),
              );
              const continuationOutcome = await Promise.race([
                pendingContinuation,
                continuationWait.promise,
              ]);
              continuationWait.cancel();
              if (continuationOutcome.kind === "timer") {
                enqueueHeartbeat(controller);
                return;
              }
              pendingContinuation = null;
              if (continuationOutcome.kind === "continuation_error") {
                throw continuationOutcome.error;
              }
              const { next } = continuationOutcome;
              if (next?.upstreamBody && next?.upstreamController) {
                releaseReader();
                cleanupLeg();
                continuationCount += 1;
                continuationsByReason[incompleteReason] = reasonCount + 1;
                activateLeg(next, decision);
                continue;
              }
            }
            const refusalFallbackFailed =
              incompleteReason === "semantic_refusal";
            if (refusalFallbackFailed) {
              enqueueFrames(
                controller,
                bufferedCompletionFrames(
                  template ?? collected.template,
                  ROLEPLAY_REFUSAL_FALLBACK_FAILURE_MESSAGE,
                  "stop",
                ),
              );
            } else if (bufferUntilValidated) {
              enqueueFrames(
                controller,
                bufferedCompletionFrames(
                  template ?? collected.template,
                  validationGate.remaining(clientContent),
                  incompleteReason === "output_limit" ? "length" : "stop",
                ),
              );
            } else {
              enqueueFrames(controller, terminalFrames);
            }
            releaseReader();
            cleanupLeg();
            controller.close();
            void settle({
              success:
                collected.terminated &&
                !incompleteReason &&
                !refusalFallbackFailed,
              assistant,
              finishReason: collected.finishReason,
              reason: refusalFallbackFailed
                ? "refusal_fallback_failed"
                : incompleteReason
                  ? incompleteReason
                  : collected.terminated
                    ? "complete"
                    : "incomplete_eof",
              contractAnalysis: decision.contractAnalysis,
            });
            return;
          }
          if (!value) {
            continue;
          }
          const now = performance.now();
          if (!firstByteAt) {
            firstByteAt = now;
          }
          if (!legFirstByteAt) {
            legFirstByteAt = now;
          }
          const decoded = decoder.decode(value, { stream: true });
          const frames = collector.consume(decoded);
          if (!frames.length) {
            continue;
          }
          const refusalCheckedFrames = refusalGate.consume(frames);
          const releasableFrames = validationGate.consume(
            refusalCheckedFrames,
            {
              hold: activeContinuationReason === "output_contract",
            },
          );
          if (!releasableFrames.length) {
            continue;
          }
          enqueueFrames(controller, releasableFrames);
          return;
        }
      } catch (error) {
        const reason = requestSignal?.aborted
          ? "request_aborted"
          : "upstream_error";
        await stopUpstream(error);
        void settle({
          success: false,
          assistant: "",
          finishReason: "",
          reason,
        });
        controller.error(error);
      }
    },
    async cancel(reason) {
      await stopUpstream(reason);
      await settle({
        success: false,
        assistant: "",
        finishReason: "",
        reason: "client_cancelled",
      });
    },
  });

  return { stream, completion };
}
