/**
 * Signed media links served from R2 at the edge. `GET /v1/media/files/{id}?expires=&signature=`
 * needs no API key and never wakes the Container; the signature (see media-signing.mjs)
 * names the file and its expiry. Requests without a signature go to the Container, which
 * serves the file to its owner.
 */
import { mediaFailure, mediaObjectKey, objectMetadata, rangeHeaders } from "./media-outbound.mjs";
import { FILE_ID, mediaSecret, verifyFileLink } from "./media-signing.mjs";

const PATH = /^\/v1\/media\/files\/([^/]+)$/;

/** The file ID of a signed link request the Worker answers itself, or null. */
export function signedMediaFileId(request, url) {
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  const match = PATH.exec(url.pathname);
  return match && FILE_ID.test(match[1]) && url.searchParams.has("signature") ? match[1] : null;
}

export async function serveSignedMediaFile(request, env, fileId, now = Date.now() / 1000) {
  const url = new URL(request.url);
  if (!env.MEDIA_BUCKET) return mediaFailure("media_storage_not_configured", "Media storage is not configured.", 404);
  const expires = url.searchParams.get("expires");
  if (!await verifyFileLink(mediaSecret(env), fileId, expires, url.searchParams.get("signature"), now)) {
    const expired = /^\d{1,12}$/.test(expires ?? "") && Number(expires) < now;
    return mediaFailure(expired ? "link_expired" : "invalid_link",
      expired ? "This media link has expired; request a new one with your API key." : "This media link is not valid.", 403);
  }
  const ranged = request.headers.has("range") && request.method === "GET";
  const object = request.method === "HEAD" ? await env.MEDIA_BUCKET.head(mediaObjectKey(fileId))
    : await env.MEDIA_BUCKET.get(mediaObjectKey(fileId), { ...(ranged ? { range: request.headers } : {}), onlyIf: request.headers });
  if (!object) return mediaFailure("not_found", "The file does not exist or has expired.", 404);
  const meta = objectMetadata(fileId, object);
  const headers = { "content-type": meta.content_type, etag: object.httpEtag, "accept-ranges": "bytes",
    "cache-control": `private, max-age=${Math.max(0, Math.min(3600, Math.floor(Number(expires) - now)))}`,
    "x-content-type-options": "nosniff", "content-disposition": "inline" };
  if (request.method === "HEAD") return new Response(null, { headers: { ...headers, "content-length": String(object.size) } });
  if (!("body" in object)) {
    const conditional = request.headers.has("if-none-match") || request.headers.has("if-modified-since");
    return new Response(null, { status: conditional ? 304 : 412, headers });
  }
  const { status, headers: range } = rangeHeaders(object, ranged);
  return new Response(object.body, { status, headers: { ...headers, "content-length": String(object.size), ...range } });
}
