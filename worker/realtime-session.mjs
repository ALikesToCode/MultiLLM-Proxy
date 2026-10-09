/** Coupled sockets with bounded lifetime; no payload storage or logging. */
export const REALTIME_TTL_MS = 900_000;
export const REALTIME_IDLE_MS = 30_000;
export const REALTIME_FRAME_BYTES = 1_048_576;
const byteLength = data => typeof data === "string" ? new TextEncoder().encode(data).byteLength
  : data instanceof ArrayBuffer || ArrayBuffer.isView(data) ? data.byteLength : Infinity;
const closeCode = code => [1000, 1001, 1008, 1011].includes(code) || (code >= 3000 && code <= 4999) ? code : 1011;
function exposesSecret(data, secret) {
  if (!secret) return false;
  if (typeof data === "string") {
    if (data.includes(secret)) return true;
    try { return JSON.stringify(JSON.parse(data)).includes(secret); } catch { return false; }
  }
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new TextDecoder().decode(bytes).includes(secret);
}

export function bridgeRealtime(client, upstream, { meter, finalize, signal, timers = globalThis, lease, heartbeat, secret }) {
  let closed = false, idleTimer, heartbeatTimer, resolveDone;
  const done = new Promise(resolve => { resolveDone = resolve; });
  const listeners = [];
  const listen = (socket, name, fn) => { socket.addEventListener(name, fn); listeners.push([socket, name, fn]); };
  const clear = () => {
    timers.clearTimeout(ttlTimer); timers.clearTimeout(idleTimer); timers.clearTimeout(heartbeatTimer);
    signal?.removeEventListener("abort", aborted);
    for (const [socket, name, fn] of listeners) socket.removeEventListener?.(name, fn);
  };
  const finish = (code, uncertain = false) => {
    if (closed) return done;
    closed = true; clear();
    for (const socket of [client, upstream]) { try { socket.close(code, code === 1000 ? "" : "Realtime session closed"); } catch { /* Already closed. */ } }
    const finalization = Promise.resolve().then(() => finalize(meter.finish({ uncertain }), code));
    void Promise.allSettled([finalization, Promise.resolve().then(() => lease?.release())]).then(results => {
      if (results.some(result => result.status === "rejected")) console.warn("Realtime finalization unavailable; retain monetary hold");
      resolveDone();
    });
    return done;
  };
  const aborted = () => { void finish(1008, true); };
  const idle = () => {
    timers.clearTimeout(idleTimer); idleTimer = timers.setTimeout(() => { void finish(1008, true); }, REALTIME_IDLE_MS); idleTimer?.unref?.();
  };
  const renew = () => {
    heartbeatTimer = timers.setTimeout(() => {
      if (closed) return;
      void Promise.resolve().then(() => { lease?.check(); return heartbeat?.(); })
        .then(() => { if (!closed) renew(); }, () => finish(1008, true));
    }, 10_000); heartbeatTimer?.unref?.();
  };
  const forward = (target, upstreamMessage) => event => {
    if (closed) return;
    if (byteLength(event.data) > REALTIME_FRAME_BYTES) { void finish(1008, true); return; }
    try {
      lease?.check();
      if (upstreamMessage && exposesSecret(event.data, secret)) { void finish(1008, true); return; }
      if (!upstreamMessage) meter.noteInput?.(event.data);
      const result = upstreamMessage ? meter.observe(event.data) : null;
      if (result === "policy") { void finish(1008, true); return; }
      target.send(event.data); idle();
      if (result === "upstream_error") void finish(1011, true);
    } catch { void finish(1011, true); }
  };
  const ttlTimer = timers.setTimeout(() => { void finish(1008, true); }, REALTIME_TTL_MS); ttlTimer?.unref?.();
  listen(client, "message", forward(upstream, false)); listen(upstream, "message", forward(client, true));
  for (const socket of [client, upstream]) {
    listen(socket, "close", event => { const code = closeCode(event.code); void finish(code, code !== 1000); });
    listen(socket, "error", () => { void finish(1011, true); });
  }
  idle(); if (heartbeat) renew();
  signal?.addEventListener("abort", aborted, { once: true }); if (signal?.aborted) aborted();
  return { done, close: finish };
}
