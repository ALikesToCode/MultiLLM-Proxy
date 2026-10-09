/** Restore authenticated placeholders across bounded JSON/SSE frames. */
import { PREFIX, preparePayload, resolvePIIPolicy } from "./pii-redaction.mjs";

const failures = new WeakSet();
export const isPIIFailure = response => failures.has(response);

const encoder = new TextEncoder();
const MAX_FRAME_BYTES = 65536, MAX_BODY_BYTES = 1024 * 1024;
const COMPLETE_TOKEN = /^__MLPII_[0-9a-f]{64}__/;

export class PIIStreamError extends Error {
  constructor(message) { super(message); this.name = "PIIStreamError"; }
}

class TextCarry {
  constructor(context) { this.context = context; this.pending = new Map(); }
  text(value, path) {
    const lane = JSON.stringify(path);
    const text = (this.pending.get(lane) ?? "") + value;
    this.pending.delete(lane);
    let output = "", index = 0;
    while (index < text.length) {
      const start = text.indexOf("_", index);
      if (start < 0) { output += text.slice(index); break; }
      output += text.slice(index, start);
      const rest = text.slice(start, start + 74), token = COMPLETE_TOKEN.exec(rest)?.[0];
      if (token) { output += this.context.restore(token); index = start + token.length; continue; }
      const partial = PREFIX.startsWith(rest) || (rest.startsWith(PREFIX) && rest.length < 74 && /^[0-9a-f]{0,64}_{0,2}$/.test(rest.slice(PREFIX.length)));
      if (partial) {
        if (this.pending.size >= 16) throw new PIIStreamError("PII stream exceeds the text lane limit");
        this.pending.set(lane, rest);
        if ([...this.pending.values()].reduce((n, item) => n + encoder.encode(item).length, 0) > 128)
          throw new PIIStreamError("PII stream exceeds the prefix limit");
        break;
      }
      output += "_"; index = start + 1;
    }
    return output;
  }
  transform(value, path = [], depth = 0, counter = { nodes: 0 }) {
    counter.nodes += 1;
    if (depth > 32 || counter.nodes > 32768) throw new PIIStreamError("PII stream exceeds the structure limit");
    if (typeof value === "string") return this.text(value, path);
    if (Array.isArray(value)) return value.map((item, i) => this.transform(item, [...path, i], depth + 1, counter));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.transform(item, [...path, key], depth + 1, counter)]));
    return value;
  }
  finish() { if (this.pending.size) throw new PIIStreamError("PII stream ended with an unresolved placeholder prefix"); }
}

export class PIIStreamParser {
  constructor(context) { this.context = context; this.carry = new TextCarry(context); this.buffer = ""; this.decoder = new TextDecoder("utf-8", { fatal: true }); }
  frame(frame) {
    const lines = frame.match(/[^\r\n]*(?:\r\n|\r|\n|$)/g).filter(Boolean);
    const indices = lines.flatMap((line, i) => line.startsWith("data:") ? [i] : []);
    if (!indices.length) return frame;
    const data = indices.map(i => lines[i].slice(5).trim()).join("\n");
    if (data === "[DONE]") { this.carry.finish(); return frame; }
    let value;
    try { value = JSON.parse(data); } catch { throw new PIIStreamError("PII stream contains invalid JSON data"); }
    const restored = this.carry.transform(value);
    if (JSON.stringify(restored) === JSON.stringify(value)) return frame;
    const ending = lines[indices[0]].endsWith("\r\n") ? "\r\n" : "\n";
    lines[indices[0]] = "data: " + JSON.stringify(restored) + ending;
    for (const i of indices.slice(1)) lines[i] = "";
    return lines.join("");
  }
  feed(bytes, final = false) {
    const output = [];
    let outputBytes = 0;
    const enqueue = frame => {
      const restored = encoder.encode(this.frame(frame));
      outputBytes += restored.length;
      if (outputBytes > MAX_BODY_BYTES) throw new PIIStreamError("PII stream exceeds the output queue limit");
      output.push(restored);
    };
    for (let offset = 0; offset < bytes.length; offset += 4096) {
      this.buffer += this.decoder.decode(bytes.subarray(offset, offset + 4096), { stream: true });
      let match;
      while ((match = /\r\n\r\n|\n\n|\r\r/.exec(this.buffer))) {
        const end = match.index + match[0].length, frame = this.buffer.slice(0, end);
        if (encoder.encode(frame).length > MAX_FRAME_BYTES) throw new PIIStreamError("PII stream frame exceeds the parser limit");
        this.buffer = this.buffer.slice(end); enqueue(frame);
      }
      if (encoder.encode(this.buffer).length > MAX_FRAME_BYTES) throw new PIIStreamError("PII response exceeds the parser limit");
    }
    if (final) {
      this.buffer += this.decoder.decode();
      if (this.buffer) enqueue(this.buffer);
      this.buffer = ""; this.carry.finish();
    }
    return output;
  }
  close() { this.buffer = ""; this.carry.pending.clear(); this.context.close(); }
}

async function readJSON(response, signal) {
  const reader = response.body.getReader(), chunks = [];
  let length = 0;
  let rejectAbort;
  const interrupted = new Promise((_, reject) => { rejectAbort = reject; });
  const abort = () => {
    void reader.cancel().catch(() => {});
    rejectAbort(new DOMException("The request was aborted", "AbortError"));
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    if (signal?.aborted) throw new DOMException("The request was aborted", "AbortError");
    while (true) {
      const { done, value } = await Promise.race([reader.read(), interrupted]);
      if (signal?.aborted) throw new DOMException("The request was aborted", "AbortError");
      if (done) break;
      length += value.length;
      if (length > MAX_BODY_BYTES) throw new PIIStreamError("PII response exceeds the body limit");
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    signal?.removeEventListener("abort", abort);
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function rehydrateResponse(response, context, { signal } = {}) {
  if (!context || context.closed) return response;
  const headers = new Headers(response.headers); headers.delete("content-length");
  if (!(headers.get("content-type") ?? "").toLowerCase().startsWith("text/event-stream")) {
    try {
      const carry = new TextCarry(context);
      const value = carry.transform(await readJSON(response, signal));
      carry.finish();
      return new Response(JSON.stringify(value), { status: response.status, statusText: response.statusText, headers });
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      headers.set("content-type", "application/json");
      const failure = new Response('{"error":{"code":"pii_rehydration_failed","message":"Unable to restore provider response"}}', { status: 502, headers });
      failures.add(failure);
      return failure;
    } finally { context.close(); }
  }
  const reader = response.body.getReader(), parser = new PIIStreamParser(context);
  let closed = false, downstream;
  function cleanup() {
    if (closed) return;
    closed = true; parser.close(); signal?.removeEventListener("abort", abort);
  }
  function abort() {
    cleanup(); void reader.cancel().catch(() => {});
    downstream?.error(new DOMException("The request was aborted", "AbortError"));
  }
  const body = new ReadableStream({
    start(controller) {
      downstream = controller;
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
    },
    async pull(controller) {
      if (closed) return;
      try {
        while (!closed) {
          const { done, value } = await reader.read();
          if (closed) return;
          const output = parser.feed(value ?? new Uint8Array(), done);
          for (const chunk of output) controller.enqueue(chunk);
          if (done) { cleanup(); reader.releaseLock(); controller.close(); }
          if (done || output.length) return;
        }
      } catch (error) {
        cleanup(); await reader.cancel().catch(() => {}); controller.error(error);
      }
    },
    async cancel(reason) { cleanup(); await reader.cancel(reason).catch(() => {}); },
  }, { highWaterMark: 0 });
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}

export async function piiFetch(request, env, options, fetchImpl) {
  const policy = options.raw ? null : resolvePIIPolicy(env, options);
  if (!policy) return fetchImpl(request);
  let prepared;
  try {
    prepared = await preparePayload(await readJSON(request.clone(), request.signal), env, options);
  } catch {
    if (request.signal.aborted) throw new DOMException("The request was aborted", "AbortError");
    if (policy.mode === "best_effort") {
      options.onDecision?.({ redacted: false, skipped: true, cacheable: true, replayable: true });
      return fetchImpl(request);
    }
    const response = Response.json({ error: { code: "pii_redaction_failed", message: "Required PII transformation failed before provider dispatch" } }, { status: 422 });
    failures.add(response); return response;
  }
  options.onDecision?.({ redacted: Boolean(prepared.context), skipped: prepared.skipped,
    cacheable: !prepared.context, replayable: !prepared.context });
  if (!prepared.context) return fetchImpl(request);
  const context = prepared.context;
  const headers = new Headers(request.headers);
  headers.delete("content-length"); headers.delete("idempotency-key");
  headers.set("cache-control", "no-store");
  try {
    const upstream = await fetchImpl(new Request(request, { headers, body: JSON.stringify(prepared.payload), duplex: "half" }));
    const response = await rehydrateResponse(upstream, context, { signal: request.signal });
    response.headers.set("cache-control", "no-store");
    return response;
  } catch (error) { context.close(); throw error; }
}
