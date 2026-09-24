# Knowledge provider contracts

The Knowledge Worker calls provider APIs from the server. Dashboard readiness
reports whether a credential is configured; it does not claim that the account
has allowance, that the provider is reachable, or that source indexing completed.
No provider key is returned to clients.

| Provider | Production secret | Operation | Evidence returned |
| --- | --- | --- | --- |
| Context7 | `CONTEXT7_API_KEY` | Library resolution and documentation context | Source discoveries; acquire original documents before serving excerpts |
| Firecrawl | `FIRECRAWL_API_KEY` | One approved source URL | Extracted Markdown |
| Exa | `EXA_API_KEY` | Bounded search or one approved source URL | Extracted source text and discoveries |
| Mintlify Index | None for the public MCP endpoint | Documentation context | Derived context and source discoveries |
| DeepWiki | None for the public MCP endpoint | Public repository question | Derived context and source discoveries |

Configure the three keys as secrets on the dedicated Knowledge Worker. Public
Mintlify and DeepWiki availability is still subject to provider access controls
and rate limits. Private repository access is outside this gateway's scope.

## Numbered keys and quota failover

Each keyed provider accepts the base name and numeric suffixes: for example,
`CONTEXT7_API_KEY`, `CONTEXT7_API_KEY_1`, `CONTEXT7_API_KEY_2`, through
`CONTEXT7_API_KEY_7`. The same convention applies to `FIRECRAWL_API_KEY` and
`EXA_API_KEY`. The base key is tried first, followed by suffixes in numeric order
(`_2` before `_10`). Gaps and a missing base key are allowed. Blank values and
duplicate keys are ignored; each provider supports up to 32 distinct keys.

After a recognized HTTP 402 credit refusal or HTTP 429 quota/rate-limit refusal,
the Worker marks the key unavailable and immediately tries the next available
key. It stays on that key for subsequent requests. Selection and cooldowns are
stored in the SQLite Durable Object and survive Worker restarts; stored key
identifiers are SHA-256 fingerprints. The dashboard exposes only the configured
key count. Firecrawl scraping and Alexandria share one credential pool.

Cooldowns honor `Retry-After` and `RateLimit-Reset` headers, capped at 31 days.
Without a reset hint, quota refusals cool down for 24 hours and rate limits for
60 seconds. An eligible active key stays selected even when an earlier key's
cooldown expires. Once every key is unavailable, requests stop without another
provider call until a cooldown expires or a new key is configured. Replacing a
key gives it fresh quota state.

Only structured refusals without evidence of accepted work can authorize
failover. Invalid credentials, denied access, required terms, timeouts, connection
errors, HTTP 5xx responses, and uncertain paid execution do not switch keys.
This behavior applies to live retrieval, source acquisition, background indexing,
and Alexandria. It does not change credentials used by a separately connected
Context7 MCP server or a directly invoked Firecrawl CLI.

Provision every numbered value as a secret on the private Knowledge Worker;
adding it to local `.env` does not update a deployed Worker. The empty entries in
`.env.example` show the naming convention. Do not put credentials in committed
configuration or pass them in command arguments.

## Requests and provenance

Context7 uses `GET https://context7.com/api/v2/libs/search` with `libraryName`
and `query`, followed by `GET https://context7.com/api/v2/context` with
`libraryId`, `query`, and `type=json`. Authentication is `Authorization: Bearer`.
The adapter prefers a matching repository or product and selects a version only
when it appears in the library's advertised `versions`. It takes source URLs
from `infoSnippets[].pageId` and `codeSnippets[].codeId`. Generated descriptions
and provider-assembled examples are not stored as primary evidence. Selecting a
versioned library does not establish the source document's version.
See the [official API schema](https://github.com/upstash/context7/blob/master/docs/openapi.json)
and [API guide](https://github.com/upstash/context7/blob/master/docs/api-guide.mdx).

Firecrawl uses `POST https://api.firecrawl.dev/v2/scrape` and a bearer key.
The request sets `formats: ["markdown"]`, `onlyMainContent: true`, `parsers: []`,
`proxy: "basic"`, a 10-second provider timeout, and a two-day maximum cache age
for ordinary retrieval. Fresh queries and forced background refresh set
`maxAge: 0` to require a new acquisition.
No crawl, browser action, AI extraction, or multi-page PDF parsing is requested.
The adapter checks `success`, page status, MIME type, original `metadata.sourceURL`,
and final `metadata.url`; a redirect outside approved hosts is not published. A
redirect that only adds or drops a trailing slash keeps the requested URL. Any other
redirect keeps its final URL, reports `firecrawl_source_redirected`, and is not retained
under the requested source, whose URL may carry version evidence.
The [v2 schema](https://github.com/firecrawl/firecrawl-docs/blob/main/api-reference/v2-openapi.json)
documents the original and final URL fields and parser behavior.

Exa uses `POST https://api.exa.ai/search` with `x-api-key`, search type `fast`,
at most five results, and `includeDomains` restricted to approved source hosts.
Content requests use `POST https://api.exa.ai/contents` with a single-item `urls`
array. Both ask for at most 100,000 characters of text per document, disable
highlights, and request no subpages. Only `results[].text` becomes source evidence;
summaries and synthesized outputs are ignored. Acquisition verifies the returned
source identity. See the [official Exa API schema](https://github.com/exa-labs/openapi-spec/blob/master/exa-openapi-spec.yaml).

Fresh queries and forced refresh set Exa's `livecrawl: "always"` with a
10-second timeout. This supported parameter forbids cached fallback; the schema
marks it deprecated in favor of `maxAgeHours`, so its compatibility should be
checked during provider upgrades. An explicit failed content status fails the
operation even if the provider also returns text. There is no retry using cache.
Successful forced acquisitions carry `freshness: "live"`; ordinary source
observations carry `freshness: "cached_or_unknown"`. These flags describe the
acquisition contract. The adapters supply no inferred source-check timestamp:
provider retrieval time alone does not establish when cached content was last
checked at its original source.

Mintlify uses the stateless MCP endpoint `https://index.mintlify.com/mcp`, tool
`context`, with `query`, optional `product`, approved `includeDomains`, and
`tokenBudget: 3000`. The public
[MCP implementation](https://github.com/mintlify/index/blob/main/src/mcp/mcpController.ts)
returns assembled text. It is preserved as derived context. Approved HTTPS
citations are separate discoveries requiring source acquisition.

DeepWiki uses `https://mcp.deepwiki.com/mcp`, tool `ask_wiki_question`, with
`repoName` in `owner/repo` format and `question`. The current tool name was
confirmed through the endpoint's unauthenticated `tools/list`; the
[repository README](https://github.com/CognitionAI/deepwiki/blob/main/README.md)
still names the older `ask_question` tool. JSON and SSE JSON-RPC results are
accepted. Answers remain derived context; the tool accepts no commit or version
selector, so it cannot establish an exact source version.

## Allowance and failure handling

Every HTTP operation passes through the caller's `invoke(provider, operation,
callback)` reservation wrapper. Context7's search and context requests reserve
separately. Exa contents and Firecrawl scrape identifiers include a deterministic
source URL hash so distinct acquisitions cannot share a reservation. The wrapper
is mandatory: adapters refuse to send requests without
it. The key failover described above stays inside this reservation, tries each
distinct key at most once, and never repeats accepted or ambiguous work. A fully
rejected operation settles at zero units; a successful fallback uses one stage's
configured allowance. Provider HTTP redirects are forbidden.
Transport uses fixed API origins, a 15-second deadline per attempt, caller cancellation, and a
1 MiB response cap. Upstream error bodies and network exception details are not
exposed or logged.

Requests and document counts are bounded, but these bounds are not a guarantee
of a fixed dollar price. Provider plans and prices can change. Exa returns
`costDollars`; its schema's price examples are not an account-specific quote.
Firecrawl documents a base credit per scrape; `parsers: []` prevents per-page PDF
charges, and unsupported binary content is not retained. Context7 request
allowance depends on the account. Public MCP services publish no billing receipt
through these tools. Admission limits must therefore be presented as gateway
operation allowances, not confirmed provider balances or reconciled dollar spend.
Keep reservations charged or unresolved after ambiguous network failures; a
timeout does not prove the provider did no work.

Source acquisition accepts exact approved public HTTPS hostnames, no IP literals,
credentials, nonstandard ports, or authentication query parameters. Host approval
is an operator responsibility; no private project files or local paths are sent.
Provider calls use fixed hosts, so discovered URLs are never fetched directly by
the Worker. Acquired snippets carry no invented version evidence.

## Verification

`node --test tests/test_knowledge_providers.mjs` exercises synthetic provider
fixtures, source policies, two-step admission, unsupported versions, raw versus
derived evidence, malformed JSON/SSE, oversized responses, redirects, and
credential-safe errors. These tests make no paid live provider requests.

`npm run test:knowledge` also covers numeric key ordering, durable cooldowns and
selection across SQLite restarts, concurrent selection, quota failover through
retrieval and ingestion, and Alexandria cost accounting without duplicate calls.

On 2026-09-23, Context7 documentation lookups worked before its account quota was
exhausted, and DeepWiki metadata discovery succeeded without authentication.
Mintlify metadata discovery returned Cloudflare access denied (Error 1010); it
was not retried. Production readiness still requires an allowed deployment
network and funded/configured provider accounts.
