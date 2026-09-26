import assert from "node:assert/strict";
import test from "node:test";

import { fetchPublic, handleMediaOutbound, publicHttpsUrl } from "../worker/media-outbound.mjs";

const fetchImage = body => handleMediaOutbound(new Request("http://media.internal/v1/fetch", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }), {});

async function withFetch(handler, run) {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  try { return await run(); } finally { globalThis.fetch = original; }
}

test("only public HTTPS hosts on the default port pass the URL rule", () => {
  for (const url of ["https://images.example.com/a.png", "https://cdn.provider.ai:443/x?sig=1"]) assert.ok(publicHttpsUrl(url), url);
  for (const url of ["http://images.example.com/a.png", "https://10.0.0.1/a.png", "https://[::1]/a.png", "https://localhost/a",
    "https://intelligence.internal/v1/store", "https://printer.local/a", "https://user:pass@images.example.com/a",
    "https://images.example.com:8443/a", "https://metadata/a", "ftp://images.example.com/a", "https://a.com/\n"]) {
    assert.equal(publicHttpsUrl(url), null, url);
  }
});

test("a fetched image is bounded and must be an image", async () => {
  await withFetch(async url => {
    assert.equal(url, "https://images.example.com/a.png");
    return new Response(new Uint8Array([137, 80, 78, 71]), { headers: { "content-type": "image/png" } });
  }, async () => {
    const response = await fetchImage({ url: "https://images.example.com/a.png", max_bytes: 10 });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "image/png");
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([137, 80, 78, 71]));
    assert.equal((await fetchImage({ url: "https://images.example.com/a.png", max_bytes: 2 })).status, 413);
  });
  await withFetch(async () => new Response("<html>", { headers: { "content-type": "text/html" } }), async () => {
    assert.equal((await fetchImage({ url: "https://images.example.com/a.png" })).status, 400);
  });
});

test("redirects are followed only to other public HTTPS hosts", async () => {
  const seen = [];
  await withFetch(async url => {
    seen.push(url);
    if (url.endsWith("/start")) return new Response(null, { status: 302, headers: { location: "https://cdn.example.com/final.png" } });
    if (url.endsWith("/final.png")) return new Response(new Uint8Array([1]), { headers: { "content-type": "image/png" } });
    return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data" } });
  }, async () => {
    assert.equal((await fetchImage({ url: "https://images.example.com/start" })).status, 200);
    assert.equal((await fetchImage({ url: "https://images.example.com/evil" })).status, 400);
    assert.equal(await fetchPublic("https://127.0.0.1/a"), null);
  });
  assert.deepEqual(seen, ["https://images.example.com/start", "https://cdn.example.com/final.png", "https://images.example.com/evil"]);
});

test("the private media host refuses other origins and operations", async () => {
  assert.equal((await handleMediaOutbound(new Request("http://other.internal/v1/fetch", { method: "POST" }), {})).status, 404);
  assert.equal((await handleMediaOutbound(new Request("http://media.internal/v1/fetch?x=1", { method: "POST" }), {})).status, 404);
  assert.equal((await handleMediaOutbound(new Request("http://media.internal/v1/unknown", { method: "POST" }), {})).status, 404);
  assert.equal((await fetchImage({ url: "https://10.1.2.3/a.png" })).status, 400);
});
