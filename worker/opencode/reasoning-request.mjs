import { applyOpencodeGlmReasoningPolicy, isOpencodeGlmModel } from "./reasoning-policy.mjs";

function leadingModel(prefix) {
  // JSON string tokens also cover escaped keys and model identifiers. This is
  // only an early passthrough check; rewriting still requires valid full JSON.
  const pair = /^\s*\{\s*("(?:[^"\\]|\\.)*")\s*:\s*("(?:[^"\\]|\\.)*")\s*[,}]/.exec(prefix);
  return pair && JSON.parse(pair[1]) === "model" ? JSON.parse(pair[2]) : null;
}

async function readGlmPayload(request) {
  if (!request.body) return null;
  const reader = request.clone().body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let modelKnown = false;
  let complete = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        complete = true;
        break;
      }
      text += decoder.decode(value, { stream: true });
      if (!modelKnown) {
        const model = leadingModel(text);
        if (model !== null && !isOpencodeGlmModel(model)) {
          // Do not wait for the rest of a non-GLM upload.
          return null;
        }
        modelKnown = model !== null;
      }
    }
    return JSON.parse(text + decoder.decode());
  } finally {
    // Awaiting clone cancellation would wait for the forwarding branch.
    if (!complete) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function withOpencodeGlmReasoning(request, pathname) {
  const path = pathname.toLowerCase().replace(/\/+$/, "");
  if (
    request.method !== "POST" ||
    !["/opencode/v1/chat/completions", "/opencode/chat/completions"].includes(path) ||
    !request.headers.get("content-type")?.toLowerCase().startsWith("application/json")
  ) return request;

  let payload;
  try {
    payload = await readGlmPayload(request);
  } catch {
    // Preserve malformed native requests for the upstream's validation.
    return request;
  }
  const normalized = applyOpencodeGlmReasoningPolicy(payload);
  const body = JSON.stringify(normalized);
  if (body === JSON.stringify(payload)) return request;

  const headers = new Headers(request.headers);
  if (headers.has("content-length")) {
    headers.set("content-length", String(new TextEncoder().encode(body).byteLength));
  }
  return new Request(request, {
    headers,
    body,
    duplex: "half",
  });
}
