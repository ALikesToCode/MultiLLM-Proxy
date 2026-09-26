/**
 * Media I/O for the Container, reachable only through its private outbound handler
 * (`http://media.internal`). The Worker fetches caller-supplied image URLs, so a URL can
 * reach only public HTTPS hosts: Workers cannot open private addresses, and the host
 * rule below refuses IP literals, internal names and credentials. With a MEDIA_BUCKET
 * binding it also stores, reads and deletes generated files in R2 under `media/<id>`.
 */
import { Buffer } from "node:buffer";
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

export const mediaObjectKey = fileId => `media/${fileId}`;
const FILE_PATH = /^\/v1\/files\/(m[a-z]_[A-Za-z0-9_-]{8,120})(\/meta|\/import)?$/;
const FILE_TYPES = { image: /^image\/(?:png|jpeg|webp|gif)$/, video: /^video\/(?:mp4|webm|quicktime)$/ };
const MAX_FILE_BYTES = { image: 50 * 1024 * 1024, video: 512 * 1024 * 1024 };
const OWNER = /^[^\x00-\x1f\x7f]{1,256}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;

function metadata(value) {
  if (!isRecord(value) || !OWNER.test(value.owner ?? "") || !Object.hasOwn(FILE_TYPES, value.kind ?? "")
    || (value.model !== undefined && value.model !== null && !MODEL.test(value.model))) return null;
  return { owner: value.owner, kind: value.kind, model: value.model ?? "", created: new Date().toISOString() };
}

function headerMetadata(header) {
  try { return metadata(JSON.parse(Buffer.from(header ?? "", "base64url").toString("utf8"))); } catch { return null; }
}

const contentType = headers => headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() ?? "";
const stored = (id, object, type) => Response.json({ version: 1, id, size: object.size, content_type: type },
  { headers: { "cache-control": "no-store" } });

/** R2 needs a stream of known length; workerd provides FixedLengthStream for that. */
function sizedBody(body, length) {
  if (typeof FixedLengthStream === "function") return body.pipeThrough(new FixedLengthStream(length));
  return new Response(body).arrayBuffer();
}

async function putFile(request, env, id) {
  const meta = headerMetadata(request.headers.get("x-media-metadata"));
  const type = contentType(request.headers);
  if (!meta || !FILE_TYPES[meta.kind].test(type)) return mediaFailure("invalid_request", "Unsupported media metadata or type.", 400);
  const length = Number(request.headers.get("content-length"));
  if (!request.body || !Number.isSafeInteger(length) || length <= 0) return mediaFailure("length_required", "Send Content-Length.", 411);
  if (length > MAX_FILE_BYTES[meta.kind]) return mediaFailure("too_large", "The file is too large.", 413);
  const object = await env.MEDIA_BUCKET.put(mediaObjectKey(id), await sizedBody(request.body, length),
    { httpMetadata: { contentType: type }, customMetadata: meta });
  return stored(id, object, type);
}

async function importFile(request, env, id) {
  const body = await readJsonBody(request);
  const meta = metadata(body?.metadata);
  if (!meta || typeof body.url !== "string") return mediaFailure("invalid_request", "Send {url, metadata}.", 400);
  const response = await fetchPublic(body.url, { accept: `${meta.kind}/*` });
  if (!response) return mediaFailure("url_not_allowed", "Use an https URL on a public host.", 400);
  if (!response.ok) {
    await response.body?.cancel();
    return mediaFailure("fetch_failed", `The media URL answered HTTP ${response.status}.`, 502);
  }
  const type = contentType(response.headers);
  if (!FILE_TYPES[meta.kind].test(type)) {
    await response.body?.cancel();
    return mediaFailure("unsupported_type", "The URL returned an unsupported media type.", 415);
  }
  const length = Number(response.headers.get("content-length"));
  let content;
  if (Number.isSafeInteger(length) && length > 0) {
    if (length > MAX_FILE_BYTES[meta.kind]) {
      await response.body?.cancel();
      return mediaFailure("too_large", "The file is too large.", 413);
    }
    content = await sizedBody(response.body, length);
  } else {
    content = await boundedBytes(response, MAX_FILE_BYTES.image);
    if (!content) return mediaFailure("too_large", "The file is too large.", 413);
  }
  const object = await env.MEDIA_BUCKET.put(mediaObjectKey(id), content, { httpMetadata: { contentType: type }, customMetadata: meta });
  return stored(id, object, type);
}

/** A header-safe description of a stored object. */
export function objectMetadata(id, object) {
  const custom = object.customMetadata ?? {};
  return { id, size: object.size, content_type: object.httpMetadata?.contentType ?? "application/octet-stream",
    owner: custom.owner ?? "", kind: custom.kind ?? "", model: custom.model || null,
    uploaded: object.uploaded instanceof Date ? object.uploaded.toISOString() : null };
}

/** R2 range results as the status and Content-Range of an HTTP reply. */
export function rangeHeaders(object, requested) {
  if (!requested || !object.range) return { status: 200, headers: {} };
  const offset = object.range.offset ?? Math.max(0, object.size - (object.range.suffix ?? object.size));
  const length = object.range.length ?? object.size - offset;
  return { status: 206, headers: { "content-range": `bytes ${offset}-${offset + length - 1}/${object.size}`,
    "content-length": String(length) } };
}

async function readFile(request, env, id) {
  const object = await env.MEDIA_BUCKET.get(mediaObjectKey(id), request.headers.has("range") ? { range: request.headers } : {});
  if (!object) return mediaFailure("not_found", "No such file.", 404);
  const meta = objectMetadata(id, object);
  const { status, headers } = rangeHeaders(object, request.headers.has("range"));
  return new Response(object.body, { status, headers: { "content-type": meta.content_type, "content-length": String(object.size),
    etag: object.httpEtag, "accept-ranges": "bytes", ...headers, "cache-control": "no-store",
    "x-media-metadata": Buffer.from(JSON.stringify(meta)).toString("base64url") } });
}

async function fileOperation(request, env, id, suffix) {
  if (!env.MEDIA_BUCKET) return mediaFailure("media_storage_not_configured", "No MEDIA_BUCKET is bound.", 503);
  if (!suffix && request.method === "PUT") return putFile(request, env, id);
  if (!suffix && request.method === "GET") return readFile(request, env, id);
  if (!suffix && request.method === "DELETE") {
    const existed = Boolean(await env.MEDIA_BUCKET.head(mediaObjectKey(id)));
    if (existed) await env.MEDIA_BUCKET.delete(mediaObjectKey(id));
    return Response.json({ version: 1, id, deleted: existed }, { headers: { "cache-control": "no-store" } });
  }
  if (suffix === "/meta" && request.method === "GET") {
    const object = await env.MEDIA_BUCKET.head(mediaObjectKey(id));
    return object ? Response.json({ version: 1, ...objectMetadata(id, object) }, { headers: { "cache-control": "no-store" } })
      : mediaFailure("not_found", "No such file.", 404);
  }
  if (suffix === "/import" && request.method === "POST") return importFile(request, env, id);
  return mediaFailure("not_found", "Unknown media operation.", 404);
}

export async function handleMediaOutbound(request, env) {
  const url = new URL(request.url);
  if (url.origin !== ORIGIN || url.search || url.hash || url.username || url.password) {
    return mediaFailure("not_found", "Unknown media operation.", 404);
  }
  try {
    if (url.pathname === "/v1/fetch" && request.method === "POST") return await fetchImage(request);
    const file = FILE_PATH.exec(url.pathname);
    if (file) return await fileOperation(request, env, file[1], file[2]);
    return mediaFailure("not_found", "Unknown media operation.", 404);
  } catch (error) {
    logFailure("media_outbound_failed", error, { operation: url.pathname.split("/")[2] ?? "unknown" });
    return mediaFailure("media_unavailable", "The media operation failed.", 502);
  }
}
