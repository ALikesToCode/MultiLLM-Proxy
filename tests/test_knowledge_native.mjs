import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { dispatchNative, NATIVE_OPERATIONS } from "../worker/knowledge/native.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
import { fixture, principal } from "./knowledge_fixture.mjs";

const EXA_KEY = "synthetic-test-key";

async function setup({ hosts } = {}) {
  const f = await fixture();
  for (const id of ["context7", "deepwiki", "mintlify"]) f.policy.providers[id] = { ...f.policy.providers.exa };
  if (hosts) f.policy.allowed_hosts = hosts;
  await f.storage.put("policy", f.policy);
  Object.assign(f.env, { CONTEXT7_API_KEY: "synthetic-context7-key", FIRECRAWL_API_KEY: "synthetic-firecrawl-key" });
  const calls = [];
  const replies = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options, body: options.body ? JSON.parse(options.body) : undefined });
    const reply = replies.shift() ?? { json: { ok: true } };
    return reply.text !== undefined
      ? new Response(reply.text, { headers: { "content-type": reply.type ?? "text/plain" } })
      : Response.json(reply.json);
  };
  const call = (tool, payload) => dispatchNative(f.env, f.authority, principal, `native.${tool}`, payload, { fetchImpl });
  const reservations = async () => [...(await f.storage.list({ prefix: "reservation:" })).values()];
  return { f, calls, replies, call, reservations };
}

test("every native tool is a read operation with a provider request", async () => {
  const contracts = JSON.parse(await readFile(new URL("../worker/knowledge/native-tools.json", import.meta.url), "utf8"));
  assert.equal(NATIVE_OPERATIONS.length, Object.keys(contracts).length);
  for (const [name, spec] of Object.entries(contracts)) {
    assert.ok(["context7", "exa", "firecrawl", "deepwiki", "mintlify"].includes(spec.provider), name);
    assert.equal(spec.input.type, "object");
    assert.equal(spec.input.additionalProperties, false);
  }
});

test("Exa tools send the provider's own parameters with the pooled key and one unit", async () => {
  const { calls, replies, call, reservations } = await setup();
  replies.push({ json: { results: [{ url: "https://example.org/a", title: "A" }], costDollars: { total: 0.005 } } });
  const result = await call("exa_search", { query: "rust async runtimes", type: "deep", numResults: 20,
    includeDomains: ["docs.rs"], contents: { highlights: true, maxAgeHours: 0 } });
  assert.equal(calls[0].url, "https://api.exa.ai/search");
  assert.equal(calls[0].options.headers["x-api-key"], EXA_KEY);
  assert.deepEqual(calls[0].body, { query: "rust async runtimes", type: "deep", numResults: 20, includeDomains: ["docs.rs"],
    contents: { highlights: true, maxAgeHours: 0 } });
  assert.equal(result.result.results[0].url, "https://example.org/a");
  assert.deepEqual(result.usage, { provider: "exa", units: 1 });
  assert.equal(result.verification, "provider_generated_unverified");
  await call("exa_code_context", { query: "Express middleware" });
  assert.deepEqual(calls[1].body, { tokensNum: "dynamic", query: "Express middleware" });
  await call("exa_answer", { query: "What is Durable Objects?", text: true });
  assert.deepEqual([calls[2].url, calls[2].body.stream], ["https://api.exa.ai/answer", false]);
  assert.equal((await reservations()).length, 3);
});

test("Context7 tools resolve libraries and return JSON or plain-text documentation", async () => {
  const { calls, replies, call } = await setup();
  replies.push({ json: { results: [{ id: "/vercel/next.js", title: "Next.js" }] } }, { text: "## Middleware\n..." });
  await call("context7_resolve_library", { libraryName: "next.js", query: "middleware auth" });
  const search = new URL(calls[0].url);
  assert.equal(search.pathname, "/api/v2/libs/search");
  assert.equal(search.searchParams.get("libraryName"), "next.js");
  assert.equal(calls[0].options.headers.Authorization, "Bearer synthetic-context7-key");
  const docs = await call("context7_docs", { libraryId: "/vercel/next.js/v15.1.8", query: "middleware", type: "txt" });
  assert.equal(new URL(calls[1].url).searchParams.get("libraryId"), "/vercel/next.js/v15.1.8");
  assert.deepEqual(docs.result, { text: "## Middleware\n..." });
});

test("Firecrawl tools reserve crawl pages, honor the host policy and leave status reads free", async () => {
  const { calls, replies, call, reservations } = await setup();
  replies.push({ json: { success: true, id: "job-1" } });
  await call("firecrawl_crawl", { url: "https://flask.palletsprojects.com/en/3.1.x/", limit: 25 });
  assert.equal(calls[0].options.headers.Authorization, "Bearer synthetic-firecrawl-key");
  assert.equal((await reservations())[0].units, 25);
  await call("firecrawl_crawl", { url: "https://flask.palletsprojects.com/en/3.1.x/" });
  assert.equal(calls[1].body.limit, 10, "the default page limit is sent and charged");
  await call("firecrawl_crawl_status", { id: "job-1", skip: 10 });
  assert.equal(calls[2].url, "https://api.firecrawl.dev/v2/crawl/job-1?skip=10");
  assert.equal((await reservations()).length, 2);
  await assert.rejects(call("firecrawl_scrape", { url: "https://unlisted.example.org/" }), { code: "source_not_allowed" });
  for (const url of ["https://localhost/", "https://user:pass@flask.palletsprojects.com/", "ftp://flask.palletsprojects.com/"]) {
    await assert.rejects(call("firecrawl_scrape", { url }), { code: "source_not_allowed" });
  }
  await assert.rejects(call("firecrawl_crawl_status", { id: "../../v1/team" }), { code: "invalid_request" });
});

test("an any-public-host policy lets provider tools fetch any public site", async () => {
  const { calls, call } = await setup({ hosts: ["*"] });
  await call("firecrawl_scrape", { url: "https://unlisted.example.org/page", formats: ["markdown", { type: "json", prompt: "title" }] });
  assert.equal(calls[0].body.url, "https://unlisted.example.org/page");
  await call("firecrawl_extract", { urls: ["https://another-site.dev/*"], prompt: "pricing" });
  await assert.rejects(call("firecrawl_scrape", { url: "http://intranet.internal/" }), { code: "source_not_allowed" });
});

test("DeepWiki and Mintlify tools call their MCP servers without provider keys", async () => {
  const { calls, replies, call } = await setup();
  const answer = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "The router lives in src/router." }] } };
  replies.push({ json: answer }, { json: answer });
  const result = await call("deepwiki_ask", { repoName: ["vercel/next.js", "facebook/react"], question: "Where is routing?" });
  assert.equal(calls[0].url, "https://mcp.deepwiki.com/mcp");
  assert.deepEqual(calls[0].body.params, { name: "ask_wiki_question",
    arguments: { repoName: ["vercel/next.js", "facebook/react"], question: "Where is routing?" } });
  assert.equal(calls[0].options.headers.Authorization, undefined);
  assert.deepEqual(result.result, { text: "The router lives in src/router." });
  await call("mintlify_context", { query: "webhooks", product: "stripe", tokenBudget: 5000 });
  assert.equal(calls[1].body.params.name, "context");
});

test("arguments are validated against the published contract before any provider call", async () => {
  const { calls, call } = await setup();
  for (const [tool, payload] of [
    ["exa_search", {}],
    ["exa_search", { query: "x", unknown: true }],
    ["exa_search", { query: "x", numResults: 101 }],
    ["exa_search", { query: "x", type: "turbo" }],
    ["exa_code_context", { query: "x", tokensNum: "all" }],
    ["deepwiki_ask", { repoName: "not a repo", question: "x" }],
    ["deepwiki_ask", { repoName: Array(11).fill("a/b"), question: "x" }],
    ["firecrawl_extract", { urls: Array(11).fill("https://flask.palletsprojects.com/") }],
    ["context7_docs", { libraryId: "vercel/next.js", query: "x" }],
  ]) await assert.rejects(call(tool, payload), { code: "invalid_request" }, `${tool} ${JSON.stringify(payload).slice(0, 60)}`);
  assert.equal(calls.length, 0);
});

test("disabled providers and scopes are enforced through the Knowledge dispatcher", async () => {
  const { f, calls } = await setup();
  f.policy.providers.deepwiki.enabled = false;
  await f.storage.put("policy", f.policy);
  const envelope = (identity, operation, payload) => ({ version: 1, operation, principal: identity, payload });
  await assert.rejects(dispatchKnowledge(f.env, envelope(principal, "native.deepwiki_structure", { repoName: "a/b" }), { authority: f.authority }),
    { code: "provider_disabled" });
  await assert.rejects(dispatchKnowledge(f.env, envelope({ id: "writer", scopes: ["knowledge:manage"] }, "native.exa_search", { query: "x" }),
    { authority: f.authority }), { code: "insufficient_scope" });
  assert.equal(calls.length, 0);
});

test("provider failures reach the caller with their own code and status", async () => {
  const { f } = await setup();
  const failing = status => async () => new Response("{}", { status, headers: { "content-type": "application/json" } });
  for (const [status, code] of [[429, "provider_rate_limited"], [500, "provider_request_failed"], [401, "provider_access_denied"]]) {
    await assert.rejects(dispatchNative(f.env, f.authority, principal, "native.exa_search", { query: "x" }, { fetchImpl: failing(status) }),
      error => error.code === code && error.status === status && !String(error.message).includes("{}"));
  }
  const hung = async (url, options) => new Promise((_, reject) => options.signal.addEventListener("abort", () => reject(new Error("aborted"))));
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 20);
  await assert.rejects(dispatchNative(f.env, f.authority, principal, "native.deepwiki_structure", { repoName: "a/b" },
    { fetchImpl: hung, signal: controller.signal }), { code: "provider_timeout", status: 504 });
});
