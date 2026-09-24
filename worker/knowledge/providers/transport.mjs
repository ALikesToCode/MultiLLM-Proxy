import { invalidResponse, ProviderError, upstreamError } from "./errors.mjs";
import { withProviderKey } from "./keys.mjs";

export { invalidResponse, ProviderError } from "./errors.mjs";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15000;
const ORIGINS = new Set([
  "https://context7.com", "https://api.firecrawl.dev", "https://api.exa.ai",
  "https://index.mintlify.com", "https://mcp.deepwiki.com",
]);

async function readBounded(response, provider, maxBytes = MAX_RESPONSE_BYTES) {
  if (Number(response.headers.get("content-length")) > maxBytes) {
    await response.body?.cancel();
    throw new ProviderError(provider, "provider_response_too_large", "The knowledge provider response exceeded the size limit.");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new ProviderError(provider, "provider_response_too_large", "The knowledge provider response exceeded the size limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function parseResponse(text, type, provider, acceptText = false) {
  try {
    // Native calls may request plain-text documentation (for example Context7 type=txt).
    if (acceptText && /^text\/(?:plain|markdown)\b/i.test(type)) return { text };
    if (!type.includes("text/event-stream")) return JSON.parse(text);
    const messages = text.split(/\r?\n\r?\n/).flatMap((event) => {
      const data = event.split(/\r?\n/).filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trimStart()).join("\n");
      return data ? [JSON.parse(data)] : [];
    });
    const responses = messages.filter((message) => message?.jsonrpc === "2.0" && message.id === 1);
    if (responses.length !== 1) throw invalidResponse(provider);
    return responses[0];
  } catch {
    throw invalidResponse(provider);
  }
}

async function fetchBounded(provider, url, options, { fetchImpl = fetch, signal, timeoutMs = REQUEST_TIMEOUT_MS, maxResponseBytes, acceptText }) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (signal?.aborted) cancel();
  signal?.addEventListener("abort", cancel, { once: true });
  const timer = setTimeout(cancel, timeoutMs);
  try {
    if (controller.signal.aborted) throw new Error("aborted");
    // Workers supports manual redirects; the non-2xx check rejects them before any follow-up.
    const response = await fetchImpl(url, { ...options, redirect: "manual", signal: controller.signal });
    if (response.status < 200 || response.status >= 300) {
      let body = null;
      if ([402, 429].includes(response.status) || (provider === "alexandria" && response.status === 403)) {
        const text = await readBounded(response, provider);
        try { body = JSON.parse(text); } catch { /* An unstructured error cannot authorize another paid request. */ }
      } else {
        await response.body?.cancel();
      }
      throw upstreamError(provider, response.status, response.headers, body);
    }
    const text = await readBounded(response, provider, maxResponseBytes);
    return parseResponse(text, response.headers.get("content-type") || "", provider, acceptText);
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    if (controller.signal.aborted) {
      throw new ProviderError(provider, "provider_timeout", "The knowledge provider request was cancelled or timed out.", 504);
    }
    throw new ProviderError(provider, "provider_network_error", "The knowledge provider could not be reached.");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
  }
}

export async function requestJSON(provider, operation, url, options, context) {
  if (!ORIGINS.has(new URL(url).origin)) {
    throw new ProviderError(provider, "invalid_provider_target", "The knowledge provider target is not permitted.", 400);
  }
  if (typeof context.invoke !== "function") {
    throw new ProviderError(provider, "provider_admission_required", "Knowledge provider calls require an allowance reservation.", 503);
  }
  if (context.signal?.aborted) {
    throw new ProviderError(provider, "provider_timeout", "The knowledge provider request was cancelled or timed out.", 504);
  }
  return context.invoke(provider, operation, () => withProviderKey(provider, options, context,
    selected => fetchBounded(provider, url, selected, context)));
}

export function jsonPost(body, headers = {}) {
  return { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) };
}

export function requireArray(value, provider) {
  if (!Array.isArray(value)) throw invalidResponse(provider);
  return value;
}
