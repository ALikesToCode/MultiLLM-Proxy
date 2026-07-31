const HEARTBEAT_COMMENT = new TextEncoder().encode(
  ": roleplay-keepalive\n\n",
);

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

function sseAssistantCollector(maximumCharacters = 64_000) {
  let buffered = "";
  let assistant = "";
  let terminated = false;
  let finishReason = "";

  const consumeLine = (line) => {
    if (!line.startsWith("data:")) {
      return;
    }
    const data = line.slice(5).trim();
    if (!data) {
      return;
    }
    if (data === "[DONE]") {
      terminated = true;
      return;
    }
    try {
      const payload = JSON.parse(data);
      const choice = payload?.choices?.[0];
      const content = choice?.delta?.content;
      if (
        typeof content === "string" &&
        assistant.length < maximumCharacters
      ) {
        assistant += content.slice(
          0,
          maximumCharacters - assistant.length,
        );
      }
      if (
        typeof choice?.finish_reason === "string" &&
        choice.finish_reason
      ) {
        finishReason = choice.finish_reason;
        terminated = true;
      }
    } catch {
      // Preserve provider stream even when a non-JSON data event appears.
    }
  };

  return {
    consume(text) {
      buffered += text;
      const lines = buffered.split(/\r?\n/);
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        consumeLine(line);
      }
    },
    finish(text = "") {
      buffered += text;
      if (buffered) {
        consumeLine(buffered);
      }
      return { assistant, finishReason, terminated };
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
  idleTimeoutMs,
  onComplete,
}) {
  let resolveCompletion;
  const completion = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  const reader = upstreamBody.getReader();
  const decoder = new TextDecoder();
  const collector = sseAssistantCollector();
  let settled = false;
  let released = false;
  let pendingRead = null;
  let firstByteAt = 0;
  let lastUpstreamByteAt = performance.now();
  let heartbeatCount = 0;
  const streamStartedAt = performance.now();

  const releaseReader = () => {
    if (!released) {
      released = true;
      reader.releaseLock();
    }
  };

  const settle = async (result) => {
    if (settled) {
      return;
    }
    settled = true;
    const completed = {
      ...result,
      heartbeatCount,
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
    upstreamController.abort(reason);
    try {
      await reader.cancel(reason);
    } catch {
      // The abort may already have errored the upstream reader.
    }
    pendingRead = null;
    releaseReader();
  };

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        if (requestSignal?.aborted) {
          throw new DOMException("Request aborted", "AbortError");
        }
        if (!pendingRead) {
          pendingRead = observedRead(reader);
        }

        const idleRemaining = Math.max(
          1,
          idleTimeoutMs -
            (performance.now() - lastUpstreamByteAt),
        );
        const wait = delayedOutcome(
          Math.min(heartbeatMs, idleRemaining),
        );
        const outcome = await Promise.race([
          pendingRead,
          wait.promise,
        ]);
        wait.cancel();

        if (outcome.kind === "timer") {
          if (
            performance.now() - lastUpstreamByteAt >=
            idleTimeoutMs
          ) {
            const error = new Error(
              "Upstream stream exceeded the idle timeout",
            );
            error.name = "TimeoutError";
            throw error;
          }
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
          releaseReader();
          controller.close();
          void settle({
            success: collected.terminated,
            assistant: collected.assistant,
            finishReason: collected.finishReason,
            reason: collected.terminated
              ? "complete"
              : "incomplete_eof",
          });
          return;
        }
        if (!value) {
          return;
        }
        const now = performance.now();
        lastUpstreamByteAt = now;
        if (!firstByteAt) {
          firstByteAt = now;
        }
        collector.consume(decoder.decode(value, { stream: true }));
        controller.enqueue(value);
      } catch (error) {
        const reason = requestSignal?.aborted
          ? "request_aborted"
          : error?.name === "TimeoutError"
            ? "idle_timeout"
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
