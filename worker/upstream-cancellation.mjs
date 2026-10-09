// One owner for request abort, header timeout and the upstream response body.
export class UpstreamCancellation {
  constructor({ signal, headerTimeoutMs, timeoutReason = "upstream_header_timeout", onOutcome } = {}) {
    this.controller = new AbortController();
    this.parentSignal = signal;
    this.onOutcome = onOutcome;
    this.handedOff = false;
    this.settled = false;
    this.reader = null;
    this.bodyController = null;
    this.outcome = null;
    this.cancelPromise = null;
    this.forwardAbort = () => this.controller.abort(signal.reason);
    this.handleAbort = () => { void this.close(this.controller.signal.reason); };
    this.controller.signal.addEventListener("abort", this.handleAbort, { once: true });
    signal?.addEventListener("abort", this.forwardAbort, { once: true });
    if (signal?.aborted) this.forwardAbort();
    if (!this.settled && Number.isFinite(headerTimeoutMs) && headerTimeoutMs > 0) {
      this.timeout = setTimeout(() => this.controller.abort(timeoutReason), headerTimeoutMs);
    }
  }

  handoff() { this.handedOff = true; }

  headersReceived() { clearTimeout(this.timeout); }

  throwIfAborted() {
    if (this.controller.signal.aborted) throw new DOMException("Request aborted", "AbortError");
  }

  finish(reason) {
    if (this.settled) return;
    this.settled = true;
    clearTimeout(this.timeout);
    this.parentSignal?.removeEventListener("abort", this.forwardAbort);
    this.controller.signal.removeEventListener("abort", this.handleAbort);
    this.outcome = Object.freeze({
      reason, ambiguous: this.handedOff && reason !== "complete",
      usageState: "unknown", usage: null, replayPermission: false,
    });
    try { this.onOutcome?.(this.outcome); } catch {
      console.warn("Upstream cancellation observer failed");
    }
  }

  releaseReader() {
    if (this.reader) {
      this.reader.releaseLock();
      this.reader = null;
    }
  }

  complete() {
    this.finish("complete");
    this.releaseReader();
  }

  close(reason = "cancelled") {
    if (this.settled) return Promise.resolve();
    this.finish(reason === "upstream_header_timeout" ? reason : "cancelled");
    if (!this.controller.signal.aborted) this.controller.abort(reason);
    // Settle the downstream read without waiting for a remote acknowledgement.
    this.bodyController?.error(new DOMException("Request aborted", "AbortError"));
    if (this.reader) {
      try { this.cancelPromise = Promise.resolve(this.reader.cancel(reason)).catch(() => {}); }
      catch { this.cancelPromise = Promise.resolve(); }
      this.releaseReader();
    }
    return Promise.resolve();
  }

  cleanup() { void this.close(); }

  wrapResponse(response) {
    this.headersReceived();
    if (!response.body) {
      this.complete();
      return response;
    }
    const reader = response.body.getReader();
    this.reader = reader;
    const owner = this;
    const body = new ReadableStream({
      start(controller) { owner.bodyController = controller; },
      async pull(controller) {
        try {
          owner.throwIfAborted();
          const { value, done } = await reader.read();
          if (owner.settled) return;
          owner.throwIfAborted();
          if (done) {
            controller.close();
            owner.complete();
          } else controller.enqueue(value);
        } catch (error) {
          if (!owner.settled) {
            controller.error(error);
            owner.bodyController = null;
            void owner.close("interrupted");
          }
        }
      },
      cancel(reason) { return owner.close(reason); },
    }, { highWaterMark: 0 });
    const wrapped = new Response(body, {
      status: response.status, statusText: response.statusText, headers: response.headers,
    });
    if (owner.settled) {
      // An abort can race a fetch implementation returning its response.
      owner.bodyController.error(new DOMException("Request aborted", "AbortError"));
      owner.cancelPromise = Promise.resolve(reader.cancel()).catch(() => {});
      owner.releaseReader();
    }
    return wrapped;
  }
}

export async function readBoundedUpstreamBytes(stream, maximumBytes, signal, limitError) {
  if (!stream) return { bytes: new Uint8Array(), firstByteMs: 0 };
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  let firstByteAt = 0;
  let cancelled = false;
  let complete = false;
  const startedAt = performance.now();
  const cancel = (reason) => {
    if (cancelled || complete) return;
    cancelled = true;
    // A provider may never acknowledge cancellation. Do not wait on it.
    void reader.cancel(reason).catch(() => {});
  };
  const abort = () => cancel(signal.reason);
  const checkAbort = () => {
    if (signal?.aborted) throw new DOMException("Request aborted", "AbortError");
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      checkAbort();
      const { value, done } = await reader.read();
      checkAbort();
      if (done) { complete = true; break; }
      if (!value) continue;
      if (!firstByteAt) firstByteAt = performance.now();
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      size += chunk.byteLength;
      if (size > maximumBytes) throw limitError();
      chunks.push(chunk);
    }
  } finally {
    signal?.removeEventListener("abort", abort);
    if (!complete) cancel("incomplete_read");
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return { bytes, firstByteMs: firstByteAt ? firstByteAt - startedAt : 0 };
}
