const DEFAULT_HEARTBEAT_MS = 10_000;
const MIN_HEARTBEAT_MS = 1_000;
const MAX_HEARTBEAT_MS = 60_000;
const HEARTBEAT_COMMENT = new TextEncoder().encode(
  ": multillm-keepalive\n\n",
);

function isEventStream(response) {
  return (
    response.body &&
    response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      .trim()
      .toLowerCase() === "text/event-stream"
  );
}

function observedRead(reader) {
  return reader.read().then(
    (value) => ({ kind: "read", value }),
    (error) => ({ kind: "error", error }),
  );
}

function delayedHeartbeat(delayMs) {
  let timer;
  const promise = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ kind: "heartbeat" }), delayMs);
  });
  return {
    promise,
    cancel() {
      clearTimeout(timer);
    },
  };
}

function createHeartbeatStream(upstreamBody, heartbeatMs, requestSignal) {
  const reader = upstreamBody.getReader();
  let pendingRead = null;
  let finished = false;
  let released = false;

  const releaseReader = () => {
    if (!released) {
      released = true;
      reader.releaseLock();
    }
  };

  const cancelUpstream = async (reason) => {
    if (finished) {
      return;
    }
    finished = true;
    try {
      await reader.cancel(reason);
    } finally {
      pendingRead = null;
      releaseReader();
    }
  };

  return new ReadableStream({
    async pull(controller) {
      try {
        while (!finished) {
          if (requestSignal?.aborted) {
            const reason =
              requestSignal.reason ??
              new DOMException("Request aborted", "AbortError");
            await cancelUpstream(reason);
            controller.error(reason);
            return;
          }

          if (!pendingRead) {
            pendingRead = observedRead(reader);
          }
          const heartbeat = delayedHeartbeat(heartbeatMs);
          const outcome = await Promise.race([
            pendingRead,
            heartbeat.promise,
          ]);
          heartbeat.cancel();

          if (outcome.kind === "heartbeat") {
            controller.enqueue(HEARTBEAT_COMMENT.slice());
            return;
          }

          pendingRead = null;
          if (outcome.kind === "error") {
            finished = true;
            releaseReader();
            controller.error(outcome.error);
            return;
          }

          const { done, value } = outcome.value;
          if (done) {
            finished = true;
            releaseReader();
            controller.close();
            return;
          }
          if (value?.byteLength) {
            controller.enqueue(value);
            return;
          }
        }
      } catch (error) {
        await cancelUpstream(error);
        controller.error(error);
      }
    },

    async cancel(reason) {
      await cancelUpstream(reason);
    },
  });
}

export function resolveSseHeartbeatMs(value) {
  if (value === undefined || value === null || value === "") {
    return DEFAULT_HEARTBEAT_MS;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return DEFAULT_HEARTBEAT_MS;
  }
  if (parsed === 0) {
    return 0;
  }
  return Math.min(
    MAX_HEARTBEAT_MS,
    Math.max(MIN_HEARTBEAT_MS, Math.round(parsed)),
  );
}

export function withSseHeartbeat(
  response,
  { heartbeatMs = DEFAULT_HEARTBEAT_MS, requestSignal } = {},
) {
  if (!isEventStream(response) || heartbeatMs <= 0) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  if (!headers.has("cache-control")) {
    headers.set("cache-control", "no-cache, no-transform");
  }
  headers.set("x-accel-buffering", "no");

  return new Response(
    createHeartbeatStream(response.body, heartbeatMs, requestSignal),
    {
      status: response.status,
      statusText: response.statusText,
      headers,
    },
  );
}
