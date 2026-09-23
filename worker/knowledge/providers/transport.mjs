const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15000;
const ORIGINS = new Set([
  "https://context7.com", "https://api.firecrawl.dev", "https://api.exa.ai",
  "https://index.mintlify.com", "https://mcp.deepwiki.com",
]);

export class ProviderError extends Error {
  constructor(provider, code, message, status = 502) {
    super(message);
    this.name = "ProviderError";
    this.provider = provider;
    this.code = code;
    this.status = status;
  }
}

export function invalidResponse(provider) {
  return new ProviderError(provider, "provider_invalid_response", "The knowledge provider returned an invalid response.");
}

function upstreamError(provider, status) {
  const code = status === 429 ? "provider_rate_limited"
    : status === 402 ? "provider_allowance_exhausted"
      : [401, 403].includes(status) ? "provider_access_denied" : "provider_request_failed";
  return new ProviderError(provider, code, "The knowledge provider could not complete the request.", status);
}

async function readBounded(response, provider) {
  if (Number(response.headers.get("content-length")) > MAX_RESPONSE_BYTES) {
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
      if (size > MAX_RESPONSE_BYTES) {
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

function parseResponse(text, type, provider) {
  try {
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

async function fetchBounded(provider, url, options, { fetchImpl, signal }) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (signal?.aborted) cancel();
  signal?.addEventListener("abort", cancel, { once: true });
  const timer = setTimeout(cancel, REQUEST_TIMEOUT_MS);
  try {
    if (controller.signal.aborted) throw new Error("aborted");
    const response = await fetchImpl(url, { ...options, redirect: "error", signal: controller.signal });
    if (response.status < 200 || response.status >= 300) {
      await response.body?.cancel();
      throw upstreamError(provider, response.status);
    }
    const text = await readBounded(response, provider);
    return parseResponse(text, response.headers.get("content-type") || "", provider);
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
  return context.invoke(provider, operation, () => fetchBounded(provider, url, options, context));
}

export function jsonPost(body, headers = {}) {
  return { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) };
}

export function requireArray(value, provider) {
  if (!Array.isArray(value)) throw invalidResponse(provider);
  return value;
}
