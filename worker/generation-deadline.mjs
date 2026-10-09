// One local generation budget across setup, retries, preflight and body reads.
import { UpstreamCancellation } from "./upstream-cancellation.mjs";

export const DEADLINE_HEADER = "X-MultiLLM-Deadline-Ms";
export const INTERNAL_DEADLINE_HEADER = "X-MultiLLM-Internal-Deadline-Ms";
const DEFAULT_MAX_MS = 300000;
let invalidMaximumLogged = false;

export class GenerationDeadlineExceeded extends Error {
  constructor() { super("Generation deadline exceeded"); this.status = 504; this.code = "generation_deadline_exceeded"; }
  response() { return Response.json(errorPayload(), { status: 504 }); }
}

export class InvalidGenerationDeadline extends Error {
  constructor() { super("Invalid generation deadline"); this.status = 400; }
  response() { return Response.json({ error: { code: "invalid_generation_deadline", message: this.message } }, { status: 400 }); }
}

class StreamPrefixUnavailable extends Error {
  response() { return Response.json({ error: { type: "upstream_error", code: "upstream_stream_invalid",
    message: "Upstream stream ended without a useful bounded prefix" } }, { status: 502 }); }
}

function errorPayload() {
  return { error: { message: "Generation deadline exceeded", type: "timeout_error", code: "generation_deadline_exceeded" } };
}

export function settlementInformation(owner, confirmedUsage = null) {
  return Object.freeze({ ambiguous: owner.handedOff && confirmedUsage === null,
    usageState: confirmedUsage === null ? "unknown" : "known", usage: confirmedUsage,
    replayPermission: false, cancellationOutcome: owner.outcome });
}

function errorEvent(protocol) {
  let payload = errorPayload();
  if (protocol === "responses") payload = { ...payload.error, type: "error" };
  if (protocol === "anthropic") payload = { type: "error", error: { ...payload.error, type: "api_error" } };
  return new TextEncoder().encode(`event: error\ndata: ${JSON.stringify(payload)}\n\n`);
}

function maximum(env) {
  const raw = String(env.GENERATION_DEADLINE_MAX_MS ?? "").trim();
  if (!raw) return DEFAULT_MAX_MS;
  if (/^[0-9]{1,6}$/.test(raw) && Number(raw) >= 1 && Number(raw) <= DEFAULT_MAX_MS) return Number(raw);
  if (!invalidMaximumLogged) { console.warn("Invalid GENERATION_DEADLINE_MAX_MS; generation deadlines disabled"); invalidMaximumLogged = true; }
  return null;
}

function milliseconds(value, limit) {
  if (!/^[0-9]{1,6}$/.test(value) || Number(value) < 1 || Number(value) > limit) throw new InvalidGenerationDeadline();
  return Number(value);
}

export class GenerationDeadline {
  constructor(expiresAt, now = () => performance.now()) { this.expiresAt = expiresAt; this.now = now; }
  remainingMs() { return Math.max(0, Math.floor(this.expiresAt - this.now())); }
  check() {
    if (this.expired || this.expiresAt <= this.now()) {
      this.expired = true;
      void this.owner?.close("generation_deadline_exceeded");
      throw new GenerationDeadlineExceeded();
    }
  }
  start(owner) {
    if (this.expiry) return;
    this.owner = owner;
    this.check();
    owner.throwIfAborted();
    this.abort = new Promise((resolve, reject) => {
      this.abortListener = () => reject(this.expired ? new GenerationDeadlineExceeded()
        : new DOMException("Request aborted", "AbortError"));
      owner.controller.signal.addEventListener("abort", this.abortListener, { once: true });
    });
    void this.abort.catch(() => {});
    this.expiry = new Promise((resolve, reject) => {
      this.timer = setTimeout(() => {
        this.expired = true;
        void owner.close("generation_deadline_exceeded");
        reject(new GenerationDeadlineExceeded());
      }, this.remainingMs());
    });
    // Lifecycle hooks can arm before the first asynchronous wait begins.
    void this.expiry.catch(() => {});
  }
  async run(action, owner = this.owner) {
    this.start(owner);
    this.check();
    const result = await Promise.race([Promise.resolve().then(action), this.expiry, this.abort]);
    this.check();
    return result;
  }
  async wait(ms, sleep = duration => new Promise(resolve => setTimeout(resolve, duration))) {
    this.check();
    if (!Number.isFinite(ms) || ms < 0 || ms >= this.remainingMs()) {
      void this.owner?.close("generation_deadline_exceeded");
      throw new GenerationDeadlineExceeded();
    }
    return this.run(() => sleep(ms));
  }
  stop() {
    clearTimeout(this.timer);
    this.owner?.controller.signal.removeEventListener("abort", this.abortListener);
  }
}

export function createGenerationDeadline(request, env = {}, { trustedInternal = false, limitsMs = [], now = () => performance.now() } = {}) {
  const limit = maximum(env);
  if (limit === null) return null;
  const publicMs = request.headers.get(DEADLINE_HEADER);
  const internalMs = trustedInternal ? request.headers.get(INTERNAL_DEADLINE_HEADER) : null;
  if (publicMs === null && internalMs === null) return null;
  const budgets = [publicMs, internalMs].filter(value => value !== null).map(value => milliseconds(value, limit));
  budgets.push(...limitsMs.filter(value => Number.isInteger(value) && value > 0));
  return new GenerationDeadline(now() + Math.min(...budgets), now);
}

export function forwardedDeadlineHeaders(original, deadline) {
  const headers = new Headers(original);
  headers.delete(INTERNAL_DEADLINE_HEADER);
  if (deadline) {
    deadline.check();
    const budget = deadline.remainingMs();
    if (budget < 1) throw new GenerationDeadlineExceeded();
    headers.delete(DEADLINE_HEADER);
    headers.set(INTERNAL_DEADLINE_HEADER, String(budget));
  }
  return headers;
}

function usefulPrefix(bytes, protocol) {
  const text = new TextDecoder().decode(bytes);
  const events = text.replaceAll("\r\n", "\n").split("\n\n");
  events.pop();
  return events.some(event => {
    const data = event.split("\n").filter(line => line.startsWith("data:")).map(line => line.slice(5).trimStart()).join("\n");
    if (!data) return false;
    if (data === "[DONE]") return false;
    try {
      const payload = JSON.parse(data);
      if (payload.error || payload.type === "error") return true;
      if (protocol === "responses") return /(?:delta|completed|failed)$/.test(payload.type ?? "");
      if (protocol === "anthropic") return payload.type === "content_block_delta" || payload.type === "message_stop";
      return payload.choices?.some(choice => choice.finish_reason != null || Object.entries(choice.delta ?? {}).some(([key, value]) =>
        ["content", "reasoning_content", "reasoning", "thinking", "tool_calls", "function_call"].includes(key) && Boolean(value)));
    } catch { return false; }
  });
}

export async function deadlineResponse(response, deadline, owner, { protocol = "chat", preflight = true } = {}) {
  deadline.check();
  if (!response.body) { deadline.stop(); owner.complete(); return response; }
  const sse = response.headers.get("content-type")?.startsWith("text/event-stream");
  const inspectPrefix = sse && preflight && response.status < 400;
  let useful = !inspectPrefix;
  const reader = response.body.getReader();
  owner.reader = reader;
  const read = () => deadline.run(() => reader.read(), owner);
  let first;
  const prefix = [];
  let size = 0;
  try {
    do {
      first = await read();
      if (first.done) break;
      prefix.push(first.value);
      size += first.value.byteLength;
      if (inspectPrefix) {
        const bytes = new Uint8Array(Math.min(size, 65536));
        let offset = 0;
        for (const chunk of prefix) {
          const inspected = chunk.subarray(0, bytes.length - offset);
          bytes.set(inspected, offset); offset += inspected.byteLength;
        }
        useful = usefulPrefix(bytes, protocol);
        if (useful) break;
      } else break;
    } while (size < 65536);
    if (!useful) throw new StreamPrefixUnavailable();
  } catch (error) {
    deadline.stop();
    await owner.close("interrupted");
    throw error;
  }
  const body = new ReadableStream({
    async pull(controller) {
      try {
        deadline.check();
        if (prefix.length) { controller.enqueue(prefix.shift()); return; }
        const chunk = first.done ? first : await read();
        if (chunk.done) { controller.close(); deadline.stop(); owner.complete(); }
        else controller.enqueue(chunk.value);
      } catch (error) {
        deadline.stop();
        await owner.close("interrupted");
        if (error instanceof GenerationDeadlineExceeded && sse) {
          controller.enqueue(errorEvent(protocol));
          controller.close();
        } else controller.error(error);
      }
    },
    cancel(reason) { deadline.stop(); return owner.close(reason); },
  }, { highWaterMark: 0 });
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}

export async function withGenerationDeadline(request, env, fetcher, options = {}) {
  let deadline;
  try { deadline = options.deadline ?? createGenerationDeadline(request, env, options); }
  catch (error) { if (error instanceof InvalidGenerationDeadline) return error.response(); throw error; }
  if (!deadline) return fetcher(request);
  const owner = options.owner ?? new UpstreamCancellation({ signal: request.signal, onOutcome: options.onOutcome });
  // A sanitized external request must never carry an internal transport budget.
  const headers = new Headers(request.headers);
  headers.delete(INTERNAL_DEADLINE_HEADER);
  headers.delete(DEADLINE_HEADER);
  const outbound = new Request(request, { headers, signal: owner.controller.signal });
  try {
    const response = await deadline.run(async () => {
      owner.handoff();
      const upstream = await fetcher(outbound, deadline);
      try { deadline.check(); owner.throwIfAborted(); }
      catch (error) { void upstream.body?.cancel("generation_cancelled").catch(() => {}); throw error; }
      return upstream;
    }, owner);
    return await deadlineResponse(response, deadline, owner, options);
  } catch (error) {
    deadline.stop();
    await owner.close("interrupted");
    if (error instanceof GenerationDeadlineExceeded) return error.response();
    if (error instanceof StreamPrefixUnavailable) return error.response();
    throw error;
  }
}

export function generationDeadlineHook(request, env, options = {}) {
  // Construct before asynchronous context/setup work, after trusted authorization.
  const deadline = createGenerationDeadline(request, env, options);
  const owner = options.owner ?? new UpstreamCancellation({ signal: request.signal, onOutcome: options.onOutcome });
  return Object.freeze({
    enabled: () => deadline !== null,
    deadline, owner,
    authorize() { deadline?.start(owner); },
    admit() { deadline?.check(); },
    before_dispatch() { deadline?.check(); },
    observe() { deadline?.check(); },
    finalize() { deadline?.stop(); },
    fetch: fetcher => withGenerationDeadline(request, env, fetcher, { ...options, deadline, owner }),
  });
}
