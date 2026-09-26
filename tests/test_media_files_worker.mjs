import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import { collectContainerEnv } from "../worker/container-env.mjs";
import { serveSignedMediaFile, signedMediaFileId } from "../worker/media-files.mjs";
import { handleMediaOutbound } from "../worker/media-outbound.mjs";
import { mediaMac, verifyFileLink, webhookSignature } from "../worker/media-signing.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const FILE = "mf_0123456789abcdef";

export function memoryBucket() {
  const objects = new Map();
  return {
    objects,
    async put(key, body, options) {
      const bytes = new Uint8Array(await new Response(body).arrayBuffer());
      const object = { key, size: bytes.byteLength, bytes, httpMetadata: options.httpMetadata,
        customMetadata: options.customMetadata, uploaded: new Date(0), httpEtag: `"${key}-${bytes.byteLength}"` };
      objects.set(key, object);
      return object;
    },
    async head(key) {
      const object = objects.get(key);
      return object ? { ...object } : null;
    },
    async get(key, options = {}) {
      const object = objects.get(key);
      if (!object) return null;
      if (options.onlyIf?.get?.("if-none-match") === object.httpEtag) return { ...object };
      let { bytes } = object;
      let range;
      const header = options.range?.get?.("range");
      if (header) {
        const [, start, end] = /bytes=(\d+)-(\d+)/.exec(header);
        range = { offset: Number(start), length: Number(end) - Number(start) + 1 };
        bytes = bytes.slice(range.offset, range.offset + range.length);
      }
      return { ...object, range, body: new Response(bytes).body };
    },
    async delete(key) { objects.delete(key); },
    async list({ prefix }) { return { objects: [...objects.values()].filter(object => object.key.startsWith(prefix)) }; },
  };
}

const metadata = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const outbound = (path, init, env) => handleMediaOutbound(new Request(`http://media.internal${path}`, init), env);

async function signedLink(secret, id, expires) {
  return `https://gateway.example/v1/media/files/${id}?expires=${expires}&signature=${
    Buffer.from(await mediaMac(secret, "file", `${id}:${expires}`)).toString("base64url")}`;
}

test("signatures match services/media_signing.py", async () => {
  assert.equal(await verifyFileLink("parity-secret", FILE, "2000000000", "rOffj5ku5kWJTYCHV6r7c3o643_-cgliTTn2qxGpsRA", 2000000000 - 1000), true);
  assert.equal(await verifyFileLink("parity-secret", FILE, "2000000000", "rOffj5ku5kWJTYCHV6r7c3o643_-cgliTTn2qxGpsRB", 2000000000 - 1000), false);
  assert.equal(await verifyFileLink("parity-secret", FILE, "2000000000", "rOffj5ku5kWJTYCHV6r7c3o643_-cgliTTn2qxGpsRA", 2000000000 + 1), false);
  assert.equal(await webhookSignature("parity-secret", "alice", "evt_1", 1700000000, '{"a":1}'),
    "v1,v/mRpTaO+aKRBHnYz195WvhGuyasIR8b/ckkVa9FMu8=");
  assert.equal(`whsec_${Buffer.from(await mediaMac("parity-secret", "webhook", "alice")).toString("base64")}`,
    "whsec_mDjj2kRZZ7WCap4F63/rTQtrBvux7PsfG03IYoCycQ0=");
});

test("the Container stores, describes, reads and deletes files through media.internal", async () => {
  const env = { MEDIA_BUCKET: memoryBucket() };
  const put = await outbound(`/v1/files/${FILE}`, { method: "PUT", body: new Uint8Array([137, 80, 78, 71]),
    headers: { "content-type": "image/png", "content-length": "4", "x-media-metadata": metadata({ owner: "alice", kind: "image", model: "gguu:gpt-image-2" }) } }, env);
  assert.deepEqual(await put.json(), { version: 1, id: FILE, size: 4, content_type: "image/png" });
  assert.deepEqual(env.MEDIA_BUCKET.objects.get(`media/${FILE}`).customMetadata,
    { owner: "alice", kind: "image", model: "gguu:gpt-image-2", created: env.MEDIA_BUCKET.objects.get(`media/${FILE}`).customMetadata.created });
  const meta = await (await outbound(`/v1/files/${FILE}/meta`, { method: "GET" }, env)).json();
  assert.deepEqual({ owner: meta.owner, size: meta.size, content_type: meta.content_type }, { owner: "alice", size: 4, content_type: "image/png" });
  const read = await outbound(`/v1/files/${FILE}`, { method: "GET", headers: { range: "bytes=1-2" } }, env);
  assert.equal(read.status, 206);
  assert.equal(read.headers.get("content-range"), "bytes 1-2/4");
  assert.deepEqual(new Uint8Array(await read.arrayBuffer()), new Uint8Array([80, 78]));
  assert.deepEqual(await (await outbound(`/v1/files/${FILE}`, { method: "DELETE" }, env)).json(), { version: 1, id: FILE, deleted: true });
  assert.equal((await outbound(`/v1/files/${FILE}/meta`, { method: "GET" }, env)).status, 404);
  for (const [headers, status] of [[{ "content-type": "text/html", "content-length": "4" }, 400],
    [{ "content-type": "image/png" }, 411], [{ "content-type": "image/png", "content-length": String(60 * 1024 * 1024) }, 413]]) {
    const response = await outbound(`/v1/files/${FILE}`, { method: "PUT", body: new Uint8Array(4),
      headers: { ...headers, "x-media-metadata": metadata({ owner: "alice", kind: "image" }) } }, env);
    assert.equal(response.status, status, JSON.stringify(headers));
  }
  assert.equal((await outbound("/v1/files/../secret", { method: "GET" }, env)).status, 404);
  assert.equal((await outbound(`/v1/files/${FILE}`, { method: "GET" }, {})).status, 503);
});

test("provider URLs are copied into R2 only from public HTTPS hosts", async () => {
  const env = { MEDIA_BUCKET: memoryBucket() };
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    assert.equal(url, "https://provider.example.com/tmp/a.png");
    return new Response(new Uint8Array([1, 2, 3]), { headers: { "content-type": "image/png", "content-length": "3" } });
  };
  try {
    const imported = await outbound(`/v1/files/${FILE}/import`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://provider.example.com/tmp/a.png", metadata: { owner: "alice", kind: "image" } }) }, env);
    assert.deepEqual(await imported.json(), { version: 1, id: FILE, size: 3, content_type: "image/png" });
    const refused = await outbound(`/v1/files/${FILE}/import`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://169.254.169.254/latest", metadata: { owner: "alice", kind: "image" } }) }, env);
    assert.equal(refused.status, 400);
  } finally { globalThis.fetch = original; }
});

test("signed links are served from R2 at the edge with ranges and expiry", async () => {
  const env = { MEDIA_BUCKET: memoryBucket(), FLASK_SECRET_KEY: "flask-secret" };
  await env.MEDIA_BUCKET.put(`media/${FILE}`, new Uint8Array([1, 2, 3, 4, 5]),
    { httpMetadata: { contentType: "video/mp4" }, customMetadata: { owner: "alice", kind: "video" } });
  const now = 1_800_000_000;
  const link = await signedLink("flask-secret", FILE, now + 600);
  const request = (url, init) => new Request(url, init);
  assert.equal(signedMediaFileId(request(link), new URL(link)), FILE);
  assert.equal(signedMediaFileId(request(link, { method: "DELETE" }), new URL(link)), null);
  const unsigned = `https://gateway.example/v1/media/files/${FILE}`;
  assert.equal(signedMediaFileId(request(unsigned), new URL(unsigned)), null);
  const full = await serveSignedMediaFile(request(link), env, FILE, now);
  assert.equal(full.status, 200);
  assert.equal(full.headers.get("content-type"), "video/mp4");
  assert.equal(full.headers.get("cache-control"), "private, max-age=600");
  assert.deepEqual(new Uint8Array(await full.arrayBuffer()), new Uint8Array([1, 2, 3, 4, 5]));
  const head = await serveSignedMediaFile(request(link, { method: "HEAD" }), env, FILE, now);
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("content-length"), "5");
  const partial = await serveSignedMediaFile(request(link, { headers: { range: "bytes=2-3" } }), env, FILE, now);
  assert.equal(partial.status, 206);
  assert.equal(partial.headers.get("content-range"), "bytes 2-3/5");
  assert.equal((await serveSignedMediaFile(request(link), env, FILE, now + 601)).status, 403);
  assert.equal((await (await serveSignedMediaFile(request(link), env, FILE, now + 601)).json()).error.code, "link_expired");
  assert.equal((await serveSignedMediaFile(request(link.replace("signature=", "signature=x")), env, FILE, now)).status, 403);
  assert.equal((await serveSignedMediaFile(request(link), { ...env, MEDIA_SIGNING_SECRET: "rotated" }, FILE, now)).status, 403);
  assert.equal((await serveSignedMediaFile(request(link), { FLASK_SECRET_KEY: "flask-secret" }, FILE, now)).status, 404);
  await env.MEDIA_BUCKET.delete(`media/${FILE}`);
  assert.equal((await serveSignedMediaFile(request(link), env, FILE, now)).status, 404);
});

test("the Worker answers signed links itself and forwards unsigned ones to the Container", async () => {
  const worker = (await loadWorkerModule()).default;
  const forwarded = [];
  const container = { getByName: () => ({ fetch: async req => { forwarded.push(new URL(req.url).pathname); return Response.json({ ok: true }); } }) };
  const env = { MEDIA_BUCKET: memoryBucket(), FLASK_SECRET_KEY: "flask-secret", MULTILLM_PROXY_CONTAINER: container };
  await env.MEDIA_BUCKET.put(`media/${FILE}`, new Uint8Array([9]), { httpMetadata: { contentType: "image/png" }, customMetadata: { owner: "a", kind: "image" } });
  const link = await signedLink("flask-secret", FILE, Math.floor(Date.now() / 1000) + 600);
  const served = await worker.fetch(new Request(link), env);
  assert.equal(served.status, 200);
  assert.deepEqual(new Uint8Array(await served.arrayBuffer()), new Uint8Array([9]));
  await worker.fetch(new Request(`https://gateway.example/v1/media/files/${FILE}`, { headers: { authorization: "Bearer key" } }), env);
  assert.deepEqual(forwarded, [`/v1/media/files/${FILE}`]);
  assert.equal(collectContainerEnv({ MEDIA_BUCKET: {} }).MEDIA_STORAGE_ENABLED, "true");
  assert.equal(collectContainerEnv({}).MEDIA_STORAGE_ENABLED, undefined);
  assert.equal(collectContainerEnv({ MEDIA_SIGNING_SECRET: "s" }).MEDIA_SIGNING_SECRET, "s");
});
