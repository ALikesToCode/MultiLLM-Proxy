import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

async function runtime(t, outboundService) {
  const bundle = await build({ stdin: { resolveDir: process.cwd(), contents: `
    import { requestJSON, jsonPost } from "./worker/knowledge/providers/transport.mjs";
    export default { async fetch() {
      try {
        const result = await requestJSON("firecrawl", "scrape", "https://api.firecrawl.dev/v2/scrape",
          jsonPost({ url: "https://docs.python.org/" }), {
            env: { FIRECRAWL_API_KEY: "synthetic-key" }, fetchImpl: fetch,
            invoke: (_provider, _operation, callback) => callback(),
          });
        return Response.json(result);
      } catch (error) { return Response.json({ code: error.code }, { status: 502 }); }
    }};
  ` }, bundle: true, write: false, format: "esm", platform: "neutral" });
  const mf = new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, script: bundle.outputFiles[0].text,
    compatibilityDate: "2026-07-28", outboundService }));
  t.after(() => mf.dispose());
  return mf;
}

test("provider transport dispatches through the native Workers fetch API", async t => {
  let calls = 0;
  const mf = await runtime(t, request => {
    calls += 1;
    assert.equal(request.headers.get("authorization"), "Bearer synthetic-key");
    return Response.json({ success: true });
  });
  const response = await mf.dispatchFetch("http://local/");
  assert.equal(response.status, 200, await response.clone().text());
  assert.deepEqual(await response.json(), { success: true });
  assert.equal(calls, 1);
});

test("native provider transport rejects redirects without forwarding credentials", async t => {
  const destinations = [];
  const mf = await runtime(t, request => {
    destinations.push(request.url);
    return new Response(null, { status: 302, headers: { Location: "https://other.example/" } });
  });
  const response = await mf.dispatchFetch("http://local/");
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), { code: "provider_request_failed" });
  assert.deepEqual(destinations, ["https://api.firecrawl.dev/v2/scrape"]);
});
