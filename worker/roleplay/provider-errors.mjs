const MAX_PROVIDER_ERROR_INSPECTION_BYTES = 32 * 1024;
const MAX_PROVIDER_ERROR_INSPECTION_MS = 500;
const EXPLICIT_PROVIDER_ERROR_STATUSES = new Set([500, 502, 504]);

async function readProviderErrorClone(response) {
  const reader = response.clone().body?.getReader();
  if (!reader) {
    return new Uint8Array();
  }
  const chunks = [];
  let size = 0;
  const readPromise = (async () => {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        if (!value) {
          continue;
        }
        const chunk =
          value instanceof Uint8Array ? value : new Uint8Array(value);
        size += chunk.byteLength;
        if (size > MAX_PROVIDER_ERROR_INSPECTION_BYTES) {
          void reader
            .cancel("Provider error exceeded inspection limit")
            .catch(() => {});
          return null;
        }
        chunks.push(chunk);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return bytes;
    } catch {
      return null;
    } finally {
      reader.releaseLock();
    }
  })();
  let timeout;
  const timeoutPromise = new Promise((resolve) => {
    timeout = setTimeout(() => {
      void reader.cancel("Provider error inspection timed out").catch(() => {});
      resolve(null);
    }, MAX_PROVIDER_ERROR_INSPECTION_MS);
  });
  try {
    return await Promise.race([readPromise, timeoutPromise]);
  } finally {
    clearTimeout(timeout);
  }
}

export async function classifyExplicitProviderError(response) {
  if (!EXPLICIT_PROVIDER_ERROR_STATUSES.has(response.status)) {
    return null;
  }
  const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
  if (!contentType.includes("json")) {
    return null;
  }
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_PROVIDER_ERROR_INSPECTION_BYTES
  ) {
    return null;
  }

  let bytes;
  try {
    bytes = await readProviderErrorClone(response);
  } catch {
    return null;
  }
  if (!bytes) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  const error = payload?.error;
  const code = typeof error?.code === "string" ? error.code.toLowerCase() : "";
  const type = typeof error?.type === "string" ? error.type.toLowerCase() : "";
  if (code !== "provider_error" || type !== "provider_error") {
    return null;
  }
  return { code, type };
}
