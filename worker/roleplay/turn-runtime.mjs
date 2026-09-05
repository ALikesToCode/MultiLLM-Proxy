export class RoleplayTurnError extends Error {
  constructor(code, status, message) {
    super(message);
    this.name = "RoleplayTurnError";
    this.code = code;
    this.status = status;
  }
}

export function requestAbortReason(signal) {
  return signal?.reason instanceof RoleplayTurnError
    ? signal.reason
    : new RoleplayTurnError("request_aborted", 499, "Roleplay request was cancelled");
}

// A turn owns its deadline across headers, body reads and continuation legs.
export function createTurnScope(signal, timeoutMs = 600_000) {
  const controller = new AbortController();
  const abort = () => controller.abort(requestAbortReason(signal));
  const timer = setTimeout(() => controller.abort(new RoleplayTurnError(
    "turn_timeout", 504, "Roleplay generation exceeded the total turn deadline",
  )), timeoutMs);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  return {
    signal: controller.signal,
    dispose() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    },
  };
}

export class RoleplayTurnQueue {
  pending = 0;
  tail = Promise.resolve();

  async run(request, settings, handleTurn, waitUntil) {
    const slot = await this.acquire(request.signal, settings);
    const scope = createTurnScope(request.signal, settings.turnTimeoutMs);
    const finish = () => { scope.dispose(); slot.finish(); };
    try {
      const turnRequest = new Request(request, { signal: scope.signal });
      const result = await handleTurn(turnRequest, slot.queueMs);
      if (scope.signal.aborted) throw requestAbortReason(scope.signal);
      waitUntil(Promise.resolve(result.completion).finally(finish));
      return result.response;
    } catch (error) {
      finish();
      throw scope.signal.aborted ? requestAbortReason(scope.signal) : error;
    }
  }

  async acquire(signal, { maxPendingTurns = 4, queueTimeoutMs = 120_000 } = {}) {
    if (signal?.aborted) throw requestAbortReason(signal);
    if (this.pending >= maxPendingTurns) {
      throw new RoleplayTurnError(
        "session_queue_full", 429, "This session already has too many pending turns",
      );
    }
    const queuedAt = performance.now();
    const previous = this.tail;
    let release;
    const slot = new Promise((resolve) => { release = resolve; });
    // Cancelled waiters release their slot, never their predecessor's slot.
    this.tail = previous.then(() => slot);
    this.pending += 1;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      this.pending -= 1;
      release();
    };
    let timer;
    let abort;
    const interrupted = new Promise((_, reject) => {
      abort = () => reject(requestAbortReason(signal));
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      timer = setTimeout(() => reject(new RoleplayTurnError(
        "session_queue_timeout", 503, "Timed out waiting for the previous session turn",
      )), queueTimeoutMs);
    });
    try {
      await Promise.race([previous, interrupted]);
      if (signal?.aborted) throw requestAbortReason(signal);
      return { finish, queueMs: performance.now() - queuedAt };
    } catch (error) {
      finish();
      throw error;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
}
