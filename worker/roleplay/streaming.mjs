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

function splitSseFrames(text, flush = false) {
  const frames = [];
  let remaining = text;
  while (remaining) {
    const boundary = /\r?\n\r?\n/.exec(remaining);
    if (!boundary) {
      break;
    }
    const end = boundary.index + boundary[0].length;
    frames.push(remaining.slice(0, end));
    remaining = remaining.slice(end);
  }
  if (flush && remaining) {
    frames.push(remaining);
    remaining = "";
  }
  return { frames, remaining };
}

function frameData(frame) {
  const data = frame
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n")
    .trim();
  if (!data) {
    return null;
  }
  if (data === "[DONE]") {
    return { done: true, data };
  }
  try {
    return { done: false, data, payload: JSON.parse(data) };
  } catch {
    return { done: false, data };
  }
}

function rewrittenChoiceFrame(payload, { finishReason, dropContent }) {
  const choices = Array.isArray(payload?.choices)
    ? [...payload.choices]
    : [];
  const original = choices[0] ?? {};
  const delta =
    original.delta && typeof original.delta === "object"
      ? { ...original.delta }
      : {};
  if (dropContent) {
    delete delta.content;
  }
  choices[0] = {
    ...original,
    delta,
    finish_reason: finishReason,
  };
  return `data: ${JSON.stringify({ ...payload, choices })}\n\n`;
}

function sseAssistantCollector(
  maximumCharacters = MAX_COLLECTED_ASSISTANT_CHARACTERS,
) {
  let buffered = "";
  let assistant = "";
  let legTerminated = false;
  let legFinishReason = "";
  let withheld = [];
  let truncated = false;

  const appendContent = (content) => {
    if (
      typeof content === "string" &&
      assistant.length < maximumCharacters
    ) {
      const remaining = maximumCharacters - assistant.length;
      assistant += content.slice(
        0,
        remaining,
      );
      truncated ||= content.length > remaining;
    } else if (typeof content === "string" && content) {
      truncated = true;
    }
  };

  const consumeFrame = (frame) => {
    const parsed = frameData(frame);
    if (!parsed) {
      return [frame];
    }
    if (parsed.done) {
      legTerminated = true;
      if (legFinishReason === "length") {
        withheld.push(frame);
        return [];
      }
      return [frame];
    }
    const choice = parsed.payload?.choices?.[0];
    if (!choice) {
      return [frame];
    }
    const content = choice?.delta?.content;
    appendContent(content);
    const finishReason =
      typeof choice.finish_reason === "string"
        ? choice.finish_reason
        : "";
    if (!finishReason) {
      return [frame];
    }
    legFinishReason = finishReason;
    legTerminated = true;
    if (finishReason !== "length") {
      return [frame];
    }

    if (typeof content === "string" && content) {
      withheld.push(
        rewrittenChoiceFrame(parsed.payload, {
          finishReason: "length",
          dropContent: true,
        }),
      );
      return [
        rewrittenChoiceFrame(parsed.payload, {
          finishReason: null,
          dropContent: false,
        }),
      ];
    }
    withheld.push(frame);
    return [];
  };

  const consumeBuffered = (text, flush = false) => {
    buffered += text;
    const split = splitSseFrames(buffered, flush);
    buffered = split.remaining;
    return split.frames.flatMap(consumeFrame);
  };

  return {
    consume(text) {
      return consumeBuffered(text);
    },
    finish(text = "") {
      const output = consumeBuffered(text, true);
      return {
        assistant,
        finishReason: legFinishReason,
        terminated: legTerminated,
        truncated,
        output,
        withheld: [...withheld],
      };
    },
    resetLeg() {
      buffered = "";
      legTerminated = false;
      legFinishReason = "";
      withheld = [];
    },
  };
}

function observedRead(reader) {
  return reader.read().then(
    (value) => ({ kind: "read", value }),
    (error) => ({ kind: "error", error }),
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
  maxContinuations = 0,
}) {
  let resolveCompletion;
  const completion = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  let reader = upstreamBody.getReader();
  let activeController = upstreamController;
  let activeCleanup = cleanup;
  const decoder = new TextDecoder();
  const collector = sseAssistantCollector();
  let settled = false;
  let released = false;
  let pendingRead = null;
  let firstByteAt = 0;
  let heartbeatCount = 0;
  let continuationCount = 0;
  let pendingContinuation = null;
  const streamStartedAt = performance.now();

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

  const activateLeg = (next) => {
    reader = next.upstreamBody.getReader();
    activeController = next.upstreamController;
    activeCleanup = next.cleanup ?? (() => {});
    released = false;
    pendingRead = null;
    pendingContinuation = null;
    collector.resetLeg();
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
      streamMs: performance.now() - streamStartedAt,
      ttfbMs: firstByteAt ? firstByteAt - streamStartedAt : 0,
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

  const enqueueFrames = (controller, frames) => {
    for (const frame of frames) {
      controller.enqueue(SSE_ENCODER.encode(frame));
    }
  };

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        while (true) {
          if (requestSignal?.aborted) {
            throw new DOMException("Request aborted", "AbortError");
          }
          if (!pendingRead) {
            pendingRead = observedRead(reader);
          }

          const wait = delayedOutcome(heartbeatMs);
          const outcome = await Promise.race([
            pendingRead,
            wait.promise,
          ]);
          wait.cancel();

          if (outcome.kind === "timer") {
            heartbeatCount += 1;
            controller.enqueue(HEARTBEAT_COMMENT.slice());
            return;
          }

          pendingRead = null;
          if (outcome.kind === "error") {
            throw outcome.error;
          }
          const { value, done } = outcome.value;
          if (done) {
            const collected = collector.finish(decoder.decode());
            const outputLimited = collected.finishReason === "length";
            enqueueFrames(controller, collected.output);
            if (
              outputLimited &&
              typeof openContinuation === "function" &&
              continuationCount < maxContinuations &&
              !collected.truncated &&
              !requestSignal?.aborted
            ) {
              if (!pendingContinuation) {
                pendingContinuation = Promise.resolve(
                  openContinuation({
                    assistant: collected.assistant,
                    continuationCount: continuationCount + 1,
                  }),
                ).then(
                  (next) => ({ kind: "continuation", next }),
                  (error) => ({ kind: "continuation_error", error }),
                );
              }
              const continuationWait = delayedOutcome(heartbeatMs);
              const continuationOutcome = await Promise.race([
                pendingContinuation,
                continuationWait.promise,
              ]);
              continuationWait.cancel();
              if (continuationOutcome.kind === "timer") {
                heartbeatCount += 1;
                controller.enqueue(HEARTBEAT_COMMENT.slice());
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
                activateLeg(next);
                continue;
              }
            }
            enqueueFrames(controller, collected.withheld);
            releaseReader();
            cleanupLeg();
            controller.close();
            void settle({
              success: collected.terminated && !outputLimited,
              assistant: collected.assistant,
              finishReason: collected.finishReason,
              reason: outputLimited
                ? "output_limit"
                : collected.terminated
                  ? "complete"
                  : "incomplete_eof",
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
          const decoded = decoder.decode(value, { stream: true });
          const frames = collector.consume(decoded);
          if (!frames.length) {
            continue;
          }
          enqueueFrames(controller, frames);
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
