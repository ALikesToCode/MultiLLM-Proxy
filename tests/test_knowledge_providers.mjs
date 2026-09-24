import assert from "node:assert/strict";
import test from "node:test";
import { PROVIDERS, providerStatus, ProviderError, retrieve } from "../worker/knowledge/providers/index.mjs";
import { sourceLinks, sourceOperation, sourceURL } from "../worker/knowledge/providers/source-policy.mjs";

const SECRET = "fixture-private-key-do-not-return";
const ENV = { CONTEXT7_API_KEY: SECRET, FIRECRAWL_API_KEY: SECRET, EXA_API_KEY: SECRET };
const INTENT = { query: "How are request limits configured?", product: "Example", repository: "example/docs", version: "3.1.3", allowed_hosts: ["docs.example.com", "github.com"] };
const SOURCE = "https://docs.example.com/limits";

function fixture(responses, env = ENV) {
  const calls = [];
  const operations = [];
  return {
    calls, operations, env,
    async invoke(provider, suffix, callback) {
      operations.push([provider, suffix]);
      return callback();
    },
    async fetchImpl(url, options) {
      calls.push({ url: String(url), options, body: options.body ? JSON.parse(options.body) : null });
      assert.equal(options.redirect, "manual");
      assert.ok(options.signal instanceof AbortSignal);
      const next = responses.shift();
      assert.notEqual(next, undefined, "unexpected provider request");
      if (next instanceof Error) throw next;
      return next instanceof Response ? next : Response.json(next);
    },
  };
}

function firecrawlDoc(overrides = {}) {
  return { success: true, data: { markdown: "# Limits\nMaximum request body is configurable.", metadata: { sourceURL: SOURCE, title: "Request limits", contentType: "text/html", statusCode: 200 }, ...overrides } };
}

function rpcResult(result) {
  return { jsonrpc: "2.0", id: 1, result };
}

test("provider readiness exposes configuration metadata without credentials or connectivity claims", () => {
  const result = providerStatus({ ...ENV, unrelated: SECRET });
  assert.equal(PROVIDERS.length, 5);
  assert.equal(result.length, 5);
  assert.ok(result.every((item) => item.configured));
  assert.equal(JSON.stringify(result).includes(SECRET), false);
  assert.deepEqual(providerStatus({}).filter((item) => item.configured).map((item) => item.id), ["mintlify", "deepwiki"]);
  assert.equal(providerStatus({ EXA_API_KEY: "  " }).find((item) => item.id === "exa").configured, false);
  assert.ok(Object.isFrozen(PROVIDERS[0].capabilities));
});

test("unknown, unconfigured and invalid source policies fail before admission", async () => {
  const context = fixture([]);
  for (const [provider, intent, extra, code] of [
    ["not-a-provider", INTENT, {}, "unknown_knowledge_provider"],
    ["exa", INTENT, { env: {} }, "provider_not_configured"],
    ["exa", { ...INTENT, allowed_hosts: ["localhost"] }, {}, "invalid_source_policy"],
    ["exa", { ...INTENT, allowed_hosts: ["127.0.0.1"] }, {}, "invalid_source_policy"],
    ["exa", { ...INTENT, allowed_hosts: ["docs.example.com:9443"] }, {}, "invalid_source_policy"],
    ["exa", { ...INTENT, allowed_hosts: undefined }, {}, "invalid_source_policy"],
  ]) {
    await assert.rejects(retrieve(provider, intent, { ...context, ...extra }), { code });
  }
  assert.equal(context.calls.length, 0);
  assert.equal(context.operations.length, 0);
});

test("provider calls cannot bypass the allowance wrapper", async () => {
  const context = fixture([]);
  await assert.rejects(retrieve("exa", INTENT, { ...context, invoke: undefined }), { code: "provider_admission_required" });
  assert.equal(context.calls.length, 0);
});

test("Context7 resolves first, selects advertised version and returns its snippets only as provider context", async () => {
  const context = fixture([
    { results: [{ id: "/other/product", title: "Other" }, { id: "/example/docs", title: "Example", versions: ["v3.1.3"] }] },
    {
      codeSnippets: [{ codeId: "https://github.com/example/docs/blob/v3.1.3/limits.md#_snippet_0", codeTitle: "Limits", codeDescription: "Generated explanation", codeList: [{ code: "possibly_transformed()" }] }],
      infoSnippets: [{ pageId: SOURCE, breadcrumb: "Settings > Limits", content: "Unverified provider snippet" }, { content: "Snippet without a source" }],
    },
  ]);
  const result = await retrieve("context7", INTENT, context);
  assert.deepEqual(context.operations, [["context7", "search"], ["context7", "context"]]);
  const target = new URL(context.calls[1].url);
  assert.equal(target.searchParams.get("libraryId"), "/example/docs/v3.1.3");
  assert.equal(target.searchParams.get("type"), "json");
  assert.equal(context.calls[0].options.headers.Authorization, `Bearer ${SECRET}`);
  const [documentation, ...discoveries] = result.observations;
  assert.equal(documentation.kind, "provider_documentation");
  assert.equal(documentation.url, "https://context7.com/example/docs");
  for (const text of ["possibly_transformed()", "Unverified provider snippet", "Snippet without a source", `Source: ${SOURCE}`]) {
    assert.ok(documentation.text.includes(text), text);
  }
  assert.equal(discoveries.length, 2);
  assert.ok(discoveries.every((item) => item.kind === "discovery" && item.text === "" && !item.version_evidence));
  assert.ok(result.warnings.includes("context7_source_version_unverified"));
});

test("Context7 does not invent unsupported versions or promote unapproved citations", async () => {
  const context = fixture([
    { results: [{ id: "/example/docs", versions: ["2.0.0"] }] },
    { codeSnippets: [], infoSnippets: [{ pageId: "https://unapproved.example.org/doc", content: "text" }, { pageId: SOURCE }, { pageId: `${SOURCE}#same` }] },
  ]);
  const result = await retrieve("context7", INTENT, context);
  assert.equal(new URL(context.calls[1].url).searchParams.get("libraryId"), "/example/docs");
  const [documentation, ...discoveries] = result.observations;
  assert.equal(documentation.kind, "provider_documentation");
  assert.ok(!documentation.text.includes("unapproved.example.org"), "unapproved hosts are never cited as sources");
  assert.equal(discoveries.length, 1);
});

test("Context7 empty search avoids another billable call and enforces provider input bounds", async () => {
  const context = fixture([{ results: [] }]);
  assert.deepEqual((await retrieve("context7", INTENT, context)).observations, []);
  assert.equal(context.calls.length, 1);
  await assert.rejects(retrieve("context7", { ...INTENT, query: "x".repeat(501) }, context), { code: "invalid_provider_query" });
  await assert.rejects(retrieve("context7", { ...INTENT, product: undefined, repository: undefined }, context), { code: "provider_product_required" });
  assert.equal(context.calls.length, 1);
});

test("Exa search is bounded and only source text becomes an excerpt", async () => {
  const context = fixture([{ results: [
    { url: SOURCE, title: "Limits", text: "Original source text", summary: "Generated summary" },
    { url: "https://docs.example.com/other", summary: "Generated answer only" },
    { url: "https://unapproved.example.org/doc", text: "Disallowed content" },
  ], costDollars: { total: 0.006 } }]);
  const result = await retrieve("exa", INTENT, context);
  assert.deepEqual(context.operations, [["exa", "search"]]);
  const { body, options, url } = context.calls[0];
  assert.equal(url, "https://api.exa.ai/search");
  assert.equal(options.headers["x-api-key"], SECRET);
  assert.equal(body.type, "fast");
  assert.equal(body.numResults, 6);
  assert.deepEqual(body.contents, { text: { maxCharacters: 100000 }, highlights: false, subpages: 0 });
  assert.equal(result.observations[0].text, "Original source text");
  assert.equal(result.observations[0].freshness, "cached_or_unknown");
  assert.equal(result.observations[1].kind, "discovery");
  assert.equal(result.observations.length, 2);
  assert.equal(JSON.stringify(result).includes("Generated"), false);
  assert.ok(result.observations.every((item) => !item.version_evidence));
});

test("Exa contents acquires one approved source and verifies the returned source identity", async () => {
  const context = fixture([{ results: [{ id: SOURCE, url: SOURCE, text: "source" }], statuses: [{ id: SOURCE, status: "success" }] }]);
  const result = await retrieve("exa", { ...INTENT, source_url: SOURCE }, context);
  assert.deepEqual(context.operations, [["exa", await sourceOperation("contents", SOURCE)]]);
  assert.deepEqual(context.calls[0].body.urls, [SOURCE]);
  assert.equal(result.observations[0].kind, "source_excerpt");
  assert.equal(result.observations[0].freshness, "cached_or_unknown");
  for (const response of [
    { results: [{ url: "https://docs.example.com/unrelated", text: "wrong document" }] },
    { results: [], statuses: [{ id: SOURCE, status: "error", error: { tag: SECRET } }] },
  ]) {
    await assert.rejects(retrieve("exa", { ...INTENT, source_url: SOURCE }, fixture([response])), { code: "provider_invalid_response" });
  }
});

test("Exa search without approved hosts makes no outbound request", async () => {
  const context = fixture([]);
  const result = await retrieve("exa", { ...INTENT, allowed_hosts: [] }, context);
  assert.deepEqual(result.warnings, ["approved_source_hosts_required"]);
  assert.equal(context.calls.length, 0);
});

test("Firecrawl single-page extraction disables multi-page parsing and enhanced proxies", async () => {
  const context = fixture([firecrawlDoc()]);
  const result = await retrieve("firecrawl", { ...INTENT, source_url: `${SOURCE}#heading` }, context);
  assert.deepEqual(context.operations, [["firecrawl", await sourceOperation("scrape", SOURCE)]]);
  assert.deepEqual(context.calls[0].body, { url: SOURCE, formats: ["markdown"], onlyMainContent: true, parsers: [], proxy: "basic", timeout: 10000, maxAge: 172800000 });
  assert.equal(result.observations[0].url, SOURCE);
  assert.equal(result.observations[0].kind, "source_excerpt");
});

test("Firecrawl requires a source URL instead of starting an implicit crawl or search", async () => {
  const context = fixture([]);
  assert.deepEqual((await retrieve("firecrawl", INTENT, context)).warnings, ["firecrawl_requires_source_url"]);
  assert.equal(context.calls.length, 0);
});

test("Firecrawl rejects redirects outside policy and unsupported binary responses", async () => {
  const redirected = firecrawlDoc();
  redirected.data.metadata.url = "https://unapproved.example.org/redirected";
  const binary = firecrawlDoc();
  binary.data.metadata.contentType = "application/pdf";
  assert.deepEqual((await retrieve("firecrawl", { ...INTENT, source_url: SOURCE }, fixture([redirected]))).observations, []);
  assert.deepEqual((await retrieve("firecrawl", { ...INTENT, source_url: SOURCE }, fixture([binary]))).warnings, ["firecrawl_unsupported_source_format"]);
});

test("Firecrawl keeps the requested source for a same-page redirect only", async () => {
  const slash = firecrawlDoc();
  slash.data.metadata.url = `${SOURCE}/`;
  const moved = firecrawlDoc();
  moved.data.metadata.url = "https://docs.example.com/stable/limits";
  const same = await retrieve("firecrawl", { ...INTENT, source_url: SOURCE }, fixture([slash]));
  assert.equal(same.observations[0].url, SOURCE);
  assert.deepEqual(same.warnings, []);
  const other = await retrieve("firecrawl", { ...INTENT, source_url: SOURCE }, fixture([moved]));
  assert.equal(other.observations[0].url, "https://docs.example.com/stable/limits");
  assert.deepEqual(other.warnings, ["firecrawl_source_redirected"]);
});

test("Firecrawl rejects an error page or mismatched original source even on HTTP 200", async () => {
  for (const response of [
    { success: false, error: SECRET },
    firecrawlDoc({ metadata: { sourceURL: SOURCE, statusCode: 404, error: SECRET } }),
    firecrawlDoc({ metadata: { sourceURL: "https://docs.example.com/unrelated" } }),
  ]) {
    await assert.rejects(retrieve("firecrawl", { ...INTENT, source_url: SOURCE }, fixture([response])), { code: "provider_invalid_response" });
  }
});

test("source policy rejects private, credential-bearing and unapproved targets before spending", async () => {
  const invalid = [
    "http://docs.example.com/doc", "https://localhost/doc", "https://127.0.0.1/doc", "https://[::1]/doc",
    "https://user:password@docs.example.com/doc", "https://docs.example.com:9443/doc",
    "https://docs.example.com.evil.org/doc", "https://unapproved.example.org/doc",
    `https://docs.example.com/doc?api_key=${SECRET}`, "https://docs.example.com\\@evil.org/doc",
    "https://docs.example.com./doc", "https://docs.example.com/doc\nsecret",
  ];
  const context = fixture([]);
  for (const source_url of invalid) {
    assert.equal(sourceURL(source_url, INTENT.allowed_hosts), null);
    await assert.rejects(retrieve("exa", { ...INTENT, source_url }, context), { code: "source_not_allowed" });
  }
  assert.equal(context.operations.length, 0);
  assert.equal(sourceURL(`${SOURCE}?version=3.1#heading`, INTENT.allowed_hosts), `${SOURCE}?version=3.1`);
});

test("Mintlify derived context and discovered citations stay separate", async () => {
  const answer = `A generated explanation. [Original docs](${SOURCE}) and https://unapproved.example.org/doc`;
  const context = fixture([rpcResult({ content: [{ type: "text", text: answer }] })], {});
  const result = await retrieve("mintlify", INTENT, context);
  assert.equal(context.calls[0].url, "https://index.mintlify.com/mcp");
  assert.equal(context.calls[0].body.params.name, "context");
  assert.equal(context.calls[0].body.params.arguments.tokenBudget, 3000);
  assert.equal(context.calls[0].options.headers.Authorization, undefined);
  assert.equal(result.observations[0].kind, "derived_context");
  assert.deepEqual(result.observations.slice(1).map((item) => [item.kind, item.url]), [["discovery", SOURCE]]);
});

test("DeepWiki uses its current tool name and parses bounded SSE structured results", async () => {
  const message = rpcResult({ structuredContent: { result: `Repository explanation: ${SOURCE}` } });
  const response = new Response(`event: message\r\ndata: ${JSON.stringify(message)}\r\n\r\n`, { headers: { "Content-Type": "text/event-stream" } });
  const context = fixture([response], {});
  const result = await retrieve("deepwiki", INTENT, context);
  assert.equal(context.calls[0].body.params.name, "ask_wiki_question");
  assert.deepEqual(context.calls[0].body.params.arguments, { repoName: "example/docs", question: INTENT.query });
  assert.equal(result.observations[0].kind, "derived_context");
  assert.equal(result.observations[0].url, "https://deepwiki.com/example/docs");
  assert.equal(result.observations[1].url, SOURCE);
});

test("DeepWiki validates public repository syntax without querying private source paths", async () => {
  const context = fixture([]);
  for (const repository of [undefined, "/home/private/project", "https://github.com/example/docs", "../..", "example/docs/tree/main"]) {
    await assert.rejects(retrieve("deepwiki", { ...INTENT, repository }, context), { code: "provider_repository_required" });
  }
  assert.equal(context.operations.length, 0);
});

test("generated MCP errors and malformed wire responses never expose upstream bodies", async () => {
  for (const response of [
    rpcResult({ isError: true, content: [{ type: "text", text: SECRET }] }),
    { jsonrpc: "2.0", id: 1, error: { code: -32603, message: SECRET } },
    { jsonrpc: "2.0", id: 99, result: { content: [{ type: "text", text: SECRET }] } },
    new Response(`event: message\ndata: ${SECRET}\n\n`, { headers: { "Content-Type": "text/event-stream" } }),
  ]) {
    await assert.rejects(retrieve("mintlify", INTENT, fixture([response])), (error) => {
      assert.ok(error instanceof ProviderError);
      assert.equal(String(error).includes(SECRET), false);
      assert.equal(JSON.stringify(error).includes(SECRET), false);
      return true;
    });
  }
});

test("transport failures, redirects and invalid JSON are safe and never retried", async () => {
  for (const response of [
    new Error(`upstream sent ${SECRET}`),
    new Response(SECRET, { status: 403 }), new Response(SECRET, { status: 429 }),
    new Response(SECRET, { status: 302, headers: { Location: `https://evil.org/?key=${SECRET}` } }),
    new Response(SECRET, { status: 200, headers: { "Content-Type": "application/json" } }),
  ]) {
    const context = fixture([response]);
    await assert.rejects(retrieve("exa", INTENT, context), (error) => {
      assert.ok(error instanceof ProviderError);
      assert.equal(String(error).includes(SECRET), false);
      assert.equal(JSON.stringify(error).includes(SECRET), false);
      return true;
    });
    assert.equal(context.calls.length, 1);
    assert.equal(context.operations.length, 1);
  }
});

test("transport caps declared and streamed response bytes", async () => {
  let cancelled = 0;
  const streaming = new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(1024 * 1024 + 1)); },
    cancel() { cancelled += 1; },
  }));
  for (const response of [new Response("{}", { headers: { "Content-Length": "1048577" } }), streaming]) {
    await assert.rejects(retrieve("exa", INTENT, fixture([response])), { code: "provider_response_too_large" });
  }
  assert.equal(cancelled, 1);
});

test("aborted requests and denied reservations cannot start provider traffic", async () => {
  const context = fixture([]);
  await assert.rejects(retrieve("exa", INTENT, { ...context, signal: AbortSignal.abort() }), { code: "provider_timeout" });
  const denied = Object.assign(new Error("Allowance exhausted"), { code: "knowledge_budget_exceeded" });
  await assert.rejects(retrieve("exa", INTENT, { ...context, invoke: async () => { throw denied; } }), (error) => error === denied);
  assert.equal(context.calls.length, 0);
  assert.equal(context.operations.length, 0);
});

test("unsupported acquisition never calls an unrelated provider", async () => {
  const context = fixture([]);
  for (const provider of ["context7", "mintlify", "deepwiki"]) {
    assert.deepEqual((await retrieve(provider, { ...INTENT, source_url: SOURCE }, context)).warnings, ["provider_does_not_acquire_sources"]);
  }
  assert.equal(context.operations.length, 0);
});

test("citation discovery normalizes fragments, deduplicates and excludes unsafe URLs", () => {
  const links = sourceLinks(`[a](${SOURCE}#a) [b](${SOURCE}#b) <https://user:pass@docs.example.com/doc> javascript:bad https://127.0.0.1/doc`, INTENT.allowed_hosts);
  assert.deepEqual(links, [SOURCE]);
});

test("source acquisition operation identifiers are stable and distinct without leaking URLs", async () => {
  const first = await sourceOperation("contents", SOURCE);
  assert.equal(first, await sourceOperation("contents", SOURCE));
  assert.notEqual(first, await sourceOperation("contents", `${SOURCE}/other`));
  assert.match(first, /^contents:[a-f0-9]{24}$/);
  assert.equal(first.includes("example"), false);
});

test("caller cancellation propagates to an in-flight provider request", async () => {
  const controller = new AbortController();
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const context = fixture([]);
  context.fetchImpl = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(new Error(`cancelled ${SECRET}`)), { once: true });
    started();
  });
  const pending = retrieve("exa", INTENT, { ...context, signal: controller.signal });
  await ready;
  controller.abort();
  await assert.rejects(pending, { code: "provider_timeout", status: 504 });
});

test("schema failures and unexpectedly long source text remain bounded", async () => {
  await assert.rejects(retrieve("exa", INTENT, fixture([{ results: {} }])), { code: "provider_invalid_response" });
  const malformedContext = fixture([{ results: [{ id: "/example/docs", title: 42 }] }, { codeSnippets: {}, infoSnippets: [] }]);
  await assert.rejects(retrieve("context7", INTENT, malformedContext), { code: "provider_invalid_response" });
  const result = await retrieve("exa", INTENT, fixture([{ results: [{ url: SOURCE, text: "x".repeat(100005) }] }]));
  assert.equal(result.observations[0].text.length, 100000);
  assert.ok(result.warnings.includes("exa_content_truncated"));
});

test("fresh and forced Firecrawl acquisition explicitly bypasses cached content", async () => {
  for (const freshness of ["fresh", "force"]) {
    const context = fixture([firecrawlDoc()]);
    const result = await retrieve("firecrawl", { ...INTENT, source_url: SOURCE, freshness }, context);
    assert.equal(context.calls[0].body.maxAge, 0);
    assert.equal(result.observations[0].freshness, "live");
    assert.equal(result.observations[0].checked_at, undefined);
  }
  const normal = await retrieve("firecrawl", { ...INTENT, source_url: SOURCE }, fixture([firecrawlDoc()]));
  assert.equal(normal.observations[0].freshness, "cached_or_unknown");
});

test("fresh Exa search and contents require live crawling without fallback", async () => {
  for (const freshness of ["fresh", "force"]) {
    for (const source_url of [undefined, SOURCE]) {
      const context = fixture([{ results: [{ url: SOURCE, text: "live source" }], statuses: [{ id: SOURCE, status: "success" }] }]);
      const result = await retrieve("exa", { ...INTENT, freshness, source_url }, context);
      const options = source_url ? context.calls[0].body : context.calls[0].body.contents;
      assert.equal(options.maxAgeHours, 0, "livecrawl is deprecated; maxAgeHours 0 forces a fresh crawl");
      assert.equal(options.livecrawl, undefined);
      assert.equal(options.livecrawlTimeout, 10000);
      assert.equal(result.observations[0].freshness, "live");
      assert.equal(result.observations[0].checked_at, undefined);
    }
  }
});

test("failed live acquisition never promotes a cached fallback to fresh evidence", async () => {
  const exa = { results: [{ url: SOURCE, text: "cached fallback" }], statuses: [{ id: SOURCE, status: "error", error: { tag: "CRAWL_LIVECRAWL_TIMEOUT" } }] };
  for (const source_url of [undefined, SOURCE]) {
    const context = fixture([exa]);
    await assert.rejects(retrieve("exa", { ...INTENT, source_url, freshness: "fresh" }, context), { code: "provider_invalid_response" });
    assert.equal(context.calls.length, 1);
  }
  const firecrawl = firecrawlDoc({ metadata: { sourceURL: SOURCE, statusCode: 504, error: "origin timeout" } });
  const context = fixture([firecrawl]);
  await assert.rejects(retrieve("firecrawl", { ...INTENT, source_url: SOURCE, freshness: "force" }, context), { code: "provider_invalid_response" });
  assert.equal(context.calls.length, 1);
});

test("provider source policy accepts the full operator policy host limit", async () => {
  const allowed_hosts = Array.from({ length: 100 }, (_, index) => `docs${index}.example.com`);
  const context = fixture([{ results: [] }]);
  await retrieve("exa", { ...INTENT, allowed_hosts }, context);
  assert.equal(context.calls[0].body.includeDomains.length, 100);
  await assert.rejects(retrieve("exa", { ...INTENT, allowed_hosts: [...allowed_hosts, "extra.example.com"] }, context), { code: "invalid_source_policy" });
  assert.equal(context.calls.length, 1);
});
