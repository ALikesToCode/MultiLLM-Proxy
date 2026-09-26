/**
 * Media I/O for the Container, reachable only through its private outbound handler
 * (`http://media.internal`). The Worker fetches caller-supplied image URLs, so a URL can
 * reach only public HTTPS hosts: Workers cannot open private addresses, and the host
 * rule below refuses IP literals, internal names and credentials.
 */
import { publicHost } from "./knowledge/contracts.mjs";
import { logFailure } from "./log.mjs";

const ORIGIN = "http://media.internal";
const MAX_JSON_BYTES = 16 * 1024;
const MAX_FETCH_BYTES = 20 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const FETCH_TIMEOUT_MS = 30000;
const IMAGE_TYPE = /^image\/(?:png|jpeg|webp|gif)$/;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export const mediaFailure = (code, message, status) => Response.json({ error: { code, message } },
  { status, headers: { "cache-control": "no-store" } });
const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);

/** A caller-supplied URL the Worker may fetch or post to: HTTPS on a public host, default port. */
export function publicHttpsUrl(value) {
  if (typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f]/.test(value)) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")
    || !publicHost(url.hostname)) return null;
  return url;
}

export async function readJsonBody(request, maxBytes = MAX_JSON_BYTES) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") return null;
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) return null;
  const text = await request.text();
  if (text.length > maxBytes) return null;
  try {
    const body = JSON.parse(text);
    return isRecord(body) ? body : null;
  } catch { return null; }
}

/** Read at most `maxBytes` of a response body, or null when it is larger. */
export async function boundedBytes(response, maxBytes) {
  const length = response.headers.get("content-length");
  if (length !== null && Number(length) > maxBytes) {
    await response.body?.cancel();
    return null;
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/** GET a public URL, following at most three redirects that stay on public HTTPS hosts. */
export async function fetchPublic(value, { accept = "image/*", fetcher = fetch } = {}) {
  let url = publicHttpsUrl(value);
  for (let hop = 0; url && hop <= MAX_REDIRECTS; hop += 1) {
    const response = await fetcher(url.href, { redirect: "manual", headers: { accept },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!REDIRECT_STATUSES.has(response.status)) return response;
    const location = response.headers.get("location");
    await response.body?.cancel();
    url = location ? publicHttpsUrl(new URL(location, url).href) : null;
  }
  return null;
}

async function fetchImage(request) {
  const body = await readJsonBody(request);
  if (!body || typeof body.url !== "string") return mediaFailure("invalid_request", "Send {url, max_bytes}.", 400);
  const maxBytes = Number.isSafeInteger(body.max_bytes) && body.max_bytes > 0
    ? Math.min(body.max_bytes, MAX_FETCH_BYTES) : MAX_FETCH_BYTES;
  if (!publicHttpsUrl(body.url)) return mediaFailure("url_not_allowed", "Use an https URL on a public host.", 400);
  const response = await fetchPublic(body.url);
  if (!response) return mediaFailure("url_not_allowed", "The URL redirected somewhere that is not allowed.", 400);
  if (!response.ok) {
    await response.body?.cancel();
    return mediaFailure("fetch_failed", `The image URL answered HTTP ${response.status}.`, 502);
  }
  const type = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() ?? "";
  if (!IMAGE_TYPE.test(type)) {
    await response.body?.cancel();
    return mediaFailure("not_an_image", "The URL did not return an image.", 400);
  }
  const bytes = await boundedBytes(response, maxBytes);
  if (!bytes) return mediaFailure("too_large", "The image is too large.", 413);
  return new Response(bytes, { headers: { "content-type": type, "cache-control": "no-store" } });
}

export async function handleMediaOutbound(request, env) {
  const url = new URL(request.url);
  if (url.origin !== ORIGIN || url.search || url.hash || url.username || url.password) {
    return mediaFailure("not_found", "Unknown media operation.", 404);
  }
  try {
    if (url.pathname === "/v1/fetch" && request.method === "POST") return await fetchImage(request);
    return mediaFailure("not_found", "Unknown media operation.", 404);
  } catch (error) {
    logFailure("media_outbound_failed", error, { operation: url.pathname.split("/")[2] ?? "unknown" });
    return mediaFailure("media_unavailable", "The media operation failed.", 502);
  }
}
