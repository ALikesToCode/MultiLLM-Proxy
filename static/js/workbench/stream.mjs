// Render only visible answer text; reasoning signals contribute timings, not prose.
export class VisibleText {
  pending = "";
  depth = 0;
  consume(text, flush = false) {
    this.pending += text;
    let result = "";
    while (this.pending) {
      const tag = /<\/?think>/i.exec(this.pending);
      if (tag) {
        if (!this.depth) result += this.pending.slice(0, tag.index);
        this.depth = tag[0][1] === "/" ? Math.max(0, this.depth - 1) : this.depth + 1;
        this.pending = this.pending.slice(tag.index + tag[0].length);
      } else {
        const suffix = flush ? -1 : this.pending.lastIndexOf("<");
        const held = suffix >= 0 && ["<think>", "</think>"].some((token) => token.startsWith(this.pending.slice(suffix).toLowerCase()));
        const end = held ? suffix : this.pending.length;
        if (!this.depth) result += this.pending.slice(0, end);
        this.pending = this.pending.slice(end);
        break;
      }
    }
    return result;
  }
}

export async function consumeStream(response, { signal, onText = () => {}, startedAt = performance.now() } = {}) {
  if (!response.body) throw new Error("The response has no stream.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const visible = new VisibleText();
  let pending = "", text = "", terminal = false, finishReason = "", firstToken = null, firstContent = null, tokens = null;
  let state = "interrupted", message = "Stream ended before completion; partial output is preserved.";
  const append = (value) => {
    if (!value) return;
    if (firstContent === null && value.trim()) firstContent = performance.now();
    text += value;
    if (text.length > 200_000) throw new Error("Output exceeds the workbench display limit.");
    onText(text);
  };
  const parse = (frame) => {
    const payload = frame.split(/\r?\n/).filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\n").trim();
    if (!payload) return;
    if (payload === "[DONE]") { terminal = true; return; }
    const data = JSON.parse(payload);
    if (data.error) throw new Error("Provider reported a stream error; partial output is preserved.");
    const choice = data.choices?.[0];
    const delta = choice?.delta || {};
    if (firstToken === null && (delta.content || delta.reasoning_content || delta.reasoning)) firstToken = performance.now();
    if (typeof delta.content === "string") append(visible.consume(delta.content));
    if (choice?.finish_reason) finishReason = choice.finish_reason;
    if (Number.isSafeInteger(data.usage?.completion_tokens) && data.usage.completion_tokens >= 0) tokens = data.usage.completion_tokens;
  };
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
    while (!terminal) {
      const { value, done } = await reader.read();
      if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
      pending += done ? decoder.decode() : decoder.decode(value, { stream: true });
      if (pending.length > 1_000_000) throw new Error("Stream frame exceeds the workbench limit.");
      let boundary;
      while ((boundary = /\r?\n\r?\n/.exec(pending))) {
        const frame = pending.slice(0, boundary.index);
        pending = pending.slice(boundary.index + boundary[0].length);
        parse(frame);
        if (terminal) break;
      }
      if (done) { if (pending.trim()) parse(pending); break; }
    }
    append(visible.consume("", true));
    if ((terminal || finishReason === "stop") && !visible.depth && text.trim() && !["length", "content_filter"].includes(finishReason)) {
      state = "completed"; message = "Completed";
    } else if (finishReason === "length") message = "Output limit reached; partial output is preserved.";
  } catch (error) {
    state = signal?.aborted || error.name === "AbortError" ? "cancelled" : "interrupted";
    message = state === "cancelled" ? "Stopped; received text is preserved." : error.message;
  } finally {
    signal?.removeEventListener("abort", abort);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const endedAt = performance.now();
  return { text, status: state, message, ttft_ms: firstContent === null ? null : firstContent - startedAt,
    duration_ms: endedAt - startedAt, output_tokens: tokens,
    tps: tokens !== null && firstToken !== null && endedAt > firstToken ? tokens * 1000 / (endedAt - firstToken) : null };
}
