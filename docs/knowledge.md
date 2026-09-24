# Knowledge Gateway

For complete agent setup and daily operations, see
[Knowledge access for agents](knowledge-agents.md) and the portable
[MultiLLM Knowledge skill](../skills/multillm-knowledge/SKILL.md).

For structured provider data with discovery and explicit credit-priced execution,
see [Firecrawl Alexandria](knowledge-alexandria.md). It shares `FIRECRAWL_API_KEY`
and has a separate allowance from ordinary source scraping.

Open **Knowledge** (`/knowledge`) in the administrator dashboard to manage public
documentation, inspect indexing jobs and allowances, and test cited retrieval.
The implementation includes REST, stateless remote MCP, five provider adapters,
an immutable source archive, and durable background indexing.

Code and synthetic tests are local verification. Deploying the resources,
configuring credentials and allowances, and completing live acceptance are
separate release steps. Configuration status is not a connectivity test.

## Production APIs and resources

| Connection | Required for | Configuration |
| --- | --- | --- |
| Cloudflare AI Search | Hybrid retrieval and managed indexing | `KNOWLEDGE_INDEX`, instance `multillm-knowledge` |
| Cloudflare R2 | Immutable source snapshots | `KNOWLEDGE_SNAPSHOTS`, private bucket `multillm-knowledge-snapshots` |
| SQLite-backed Durable Object | Sources, jobs, publication fences and operation allowances | `KNOWLEDGE_AUTHORITY` |
| Cloudflare Workflows | Acquisition, index submission and verification | `KNOWLEDGE_INGESTION` |
| Private Worker service binding | Existing Flask authentication to Knowledge | Main Worker `KNOWLEDGE_SERVICE` → `multillm-knowledge` |
| Exa | Discovery plus original source text | Knowledge Worker secret `EXA_API_KEY` |
| Firecrawl | Acquisition of a registered/discovered source | Knowledge Worker secret `FIRECRAWL_API_KEY` |
| Context7 | Library documentation discovery | Knowledge Worker secret `CONTEXT7_API_KEY` |
| Mintlify Index | Additional documentation discoveries | Public MCP; no key in this adapter |
| DeepWiki | Public repository discoveries | Public MCP; no key in this adapter |

The minimum useful live setup is Cloudflare plus Exa. Firecrawl can acquire and
refresh registered sources without Exa, but does not discover source URLs here.
Context7, Mintlify and DeepWiki results require a source acquisition provider
before becoming quoted evidence. Enable only the providers you need. No separate
answer-generation API key is required; AI Search manages its embedding/index
dependencies. Cloudflare account permissions and billing still apply.
Provider contracts and current access limitations are in
[knowledge-providers.md](knowledge-providers.md).

## Provision and deploy

Use the existing Cloudflare account and authentication. Review resource names in
`wrangler.knowledge.jsonc` and the service binding in `wrangler.jsonc` first.
The Knowledge Worker has no public route, `workers.dev` URL or preview URL.
Deploy it before the main Worker, which requires the service to exist.

Search uses the supported `KNOWLEDGE_SEARCH_AI.autorag()` binding against
`KNOWLEDGE_SEARCH_INSTANCE`; keep that name aligned with `KNOWLEDGE_INDEX`.
The instance binding still handles uploads, item metadata and chunk verification.
This separates queries from the instance binding's observed account-context
failures. Each query uses one transport and is never retried after an unknown
outcome. Removing the search AI binding selects the native instance search API.
See Cloudflare's [binding compatibility reference](https://developers.cloudflare.com/ai-search/api/migration/workers-binding/).

1. Create the private R2 bucket and AI Search instance. Use **built-in storage**
   for AI Search; do not connect the snapshot bucket as an automatic crawler.
   Enable hybrid keyword/vector indexing and declare the five metadata fields:

   ```bash
   npx wrangler r2 bucket create multillm-knowledge-snapshots
   npx wrangler ai-search create multillm-knowledge --type builtin --hybrid-search \
     --custom-metadata artifact_id:text --custom-metadata content_hash:text \
     --custom-metadata product:text --custom-metadata version_kind:text \
     --custom-metadata version:text
   ```

   The dashboard is an alternative to these creation commands. Existing resources
   should be inspected and reused, not recreated. See Cloudflare's
   [instance setup](https://developers.cloudflare.com/ai-search/get-started/dashboard/),
   [built-in storage](https://developers.cloudflare.com/ai-search/configuration/data-source/built-in-storage/)
   and [metadata schema](https://developers.cloudflare.com/ai-search/configuration/indexing/metadata/).

2. Validate and deploy the private Worker:

   ```bash
   npm run cf:knowledge:dry-run
   npm run cf:knowledge:deploy
   ```

   The configuration creates the Durable Object migration and Workflow binding.
   Set the selected provider secrets on this Worker, using the platform's private
   secret entry flow:

   ```bash
   npx wrangler secret put EXA_API_KEY --config wrangler.knowledge.jsonc
   npx wrangler secret put FIRECRAWL_API_KEY --config wrangler.knowledge.jsonc
   npx wrangler secret put CONTEXT7_API_KEY --config wrangler.knowledge.jsonc
   ```

   These keys belong on the Knowledge Worker. They are not passed to the Flask
   Container or returned to the dashboard. The main Worker derives
   `KNOWLEDGE_SERVICE_ENABLED=true` only from its service binding.

3. Deploy the main Worker using the existing
   [Container deployment procedure](cloudflare-containers.md). Keep the existing
   persisted user/key storage and session secrets configured. Keys the Worker can
   verify itself (the bootstrap `ADMIN_API_KEY` and durable D1 integration keys)
   are served at the edge: Worker → private Knowledge Worker, without waking the
   Container. Other keys take Flask authentication → fixed Container egress →
   private Knowledge Worker. Both paths use only
   `http://knowledge.internal/v1/dispatch`.

4. Open `/knowledge`. Confirm all four resource bindings appear configured.
   Review approved public hosts, retention, and provider billing controls. Set
   finite provider allowances, background caps, interactive reserves and units
   per admitted operation. Acknowledge retention permission and upstream billing
   controls, then enable the selected providers and Knowledge. Defaults are
   disabled with zero allowances.

5. Register public documentation for the project's resolved dependency versions.
   Use a versioned upstream source URL when available. A stable/latest page may
   provide useful related evidence but cannot prove an exact requested version.
   **Save source** registers metadata; **Refresh source** starts acquisition.
   Private project files and credentials must not be used as source URLs.

## Client routes

Create an account/key in **Access** with `knowledge:read`. Give automation
`knowledge:manage` only when it must change sources or policy. Existing chat keys
keep their previous permissions. Administrator accounts retain both abilities.

On Cloudflare, **Access** keys live in the Container's SQLite store unless
`CONTROL_PLANE_DATABASE_URL` is configured. That disk is reset whenever the
Container sleeps (after 15 idle minutes) or is redeployed, so those keys then fail
with `Invalid API key`. Give agents a durable D1 integration key instead; it
survives restarts and is verified at the edge:

```sh
node scripts/intelligence_operator.mjs provision --account-id <account> --database-id <database_id> \
  --principal integration:agents --scopes knowledge:read --credential-file /private/knowledge.key --apply
```

See [integration credentials](intelligence-d1.md#integration-credentials) for the
dry run, conflicts and uncertain outcomes.

| Method and route | Scope | Result |
| --- | --- | --- |
| `POST /v1/knowledge/context` | `knowledge:read` | Cited excerpts, related versions, coverage gaps and operation bounds |
| `POST /v1/knowledge/search` | `knowledge:read` | Same evidence contract for search clients |
| `GET /v1/knowledge/artifacts/<id>` | `knowledge:read` | Retained source text and immutable manifest |
| `GET /v1/knowledge/status` | `knowledge:manage` | Sources, recent jobs, policy, usage and setup |
| `POST /v1/knowledge/sources` | `knowledge:manage` | Register a source without immediate acquisition |
| `PATCH /v1/knowledge/sources/<id>` | `knowledge:manage` | Change enabled/pinned/refresh state with `expected_revision` |
| `POST /v1/knowledge/sources/<id>/refresh` | `knowledge:manage` | Create or reconcile its durable indexing job |
| `POST /v1/knowledge/jobs/<id>/cancel` | `knowledge:manage` | Fence future work/publication |
| `PUT /v1/knowledge/policy` | `knowledge:manage` | Save complete policy with `expected_revision` |

Send the proxy key as a bearer credential. Example JSON body for either query
route:

```json
{
  "query": "How are request size limits configured?",
  "product": "flask",
  "version": "3.1.3",
  "repository": "pallets/flask",
  "mode": "smart",
  "token_budget": 6000,
  "freshness": "normal"
}
```

The MCP endpoint is `/mcp`, using streamable HTTP with a privately configured
bearer key. It exposes seven read tools (context, search, artifacts and the four
[Alexandria tools](knowledge-alexandria.md#discover-inspect-execute)) and six
[management tools](knowledge-agents.md#connect-to-the-gateway), filtered by scope. Send
`Accept: application/json, text/event-stream` (clients that accept only JSON also
work), initialize with at least `protocolVersion`, and include the negotiated
`MCP-Protocol-Version` on later requests. Supported versions are `2025-06-18` and
`2025-03-26`. Responses are JSON; no persistent session or GET event stream is
required. Cross-origin browser MCP requests are refused. The edge Worker and Flask
serve the same catalogue: `routes/knowledge_mcp.py` is the source and
`python scripts/build_knowledge_mcp_catalogue.py` regenerates
`worker/knowledge-mcp-catalogue.json` (a test fails when they differ).

## Evidence, freshness and recovery

Excerpts include an original URL, SHA-256 content hash, immutable artifact ID and
UTF-8 byte locator. Index chunks must match the retained snapshot. Generated
provider answers are discoveries, never primary excerpts. Version claims require
a recognized upstream identity or operator-registered source and an explicit
versioned URL; caller-supplied target versions alone are not proof.

`fresh` bypasses evidence cache and requires an origin check within one hour.
Ordinary provider-cache retrieval has no invented check timestamp. `checked_at`,
`fetched_at` and `published_at` represent different events. Token counts are
conservative text/citation estimates, not an exact model tokenizer guarantee.
The complete response envelope and diagnostics are outside that excerpt budget.

Background jobs persist references and reuse retained live acquisitions. They
publish only after AI Search reports completion and its chunks match the source.
An upload acknowledgement alone is not readiness. After bounded polling,
`pending_index`/`unknown` remain visible; refreshing the source resumes
reconciliation using the same job and operation receipts. The hourly scheduler
also re-polls up to five such jobs that have been idle for ten minutes, including
discovered sources, so their uploads publish without a manual refresh. Ambiguous
acquisition or upload is never automatically paid for again. Cancellation stops
future steps; accepted upstream work and its charge may still complete.

Every result reports `index_diagnostics`: index hits returned, hits admitted as
evidence, and skipped hits by reason (`unpublished`, `superseded`, `ineligible`,
`unknown_revision`, `span_mismatch`, `not_fresh`). A query answered from the live
path despite many hits usually means those revisions are still awaiting publication.

The hourly scheduler rotates up to five eligible due registered sources and attempts
cleanup of up to ten expired revisions. Sources discovered by read queries never
refresh on a schedule; registering the same URL, product and version promotes the
discovery with the operator's settings. Reads reject expired sources immediately.
Retention applies to newly acquired/refreshed revisions; changes do not rewrite
old expiry timestamps. Cleanup runs even while Knowledge or an allowance is disabled.
Its deletes are idempotent: a revision whose cleanup fails stays unreadable and a
later run retries it, rotating through expired revisions so one failure cannot starve
the rest. Review private R2 lifecycle settings and AI Search retained items as part of
production operations.

Allowances are gateway operation units over a rolling 24-hour window, not provider
balances or dollar spend. Confirmed work ages out of admission; pending and
unknown work remains charged until reviewed. Readiness/status reads, catalogue
storage, Workflow control, index polling, R2 reads and runtime overhead are not
individual provider reservations. Include those costs in platform limits. Current
bounds are 200 registered sources, 200 discovered sources, 1,000 retained manifests,
1,000 jobs and 5,000 ledger records; capacity errors fail closed. A full discovery pool
evicts its oldest discovery that retains no revision and has no active job. Completed,
failed and cancelled jobs are pruned after 30 days, or oldest first when a new job needs
room. Only confirmed ledger rows older than 30 days are automatically pruned. Source
retention permission and billing hard stops are operator acknowledgements, not account
checks performed by this application.

## Verification before activation

Run `npm run test:knowledge`, `npm run test:worker`, Python tests, lint/type checks,
the static secret scan and `npm run cf:knowledge:dry-run`. Synthetic tests cover
scope/CSRF enforcement, private forwarding, real local Durable Object/R2 storage,
provider bounds, version separation, cancellation, concurrent allowances,
recovery, source-span verification and cache revocation.

Production acceptance must additionally exercise source registration → refresh →
verified publication → indexed query → artifact citation, plus a version mismatch,
revoked read key and exhausted allowance. Check the visible dashboard and its
network/console behavior in the approved browser session. Local tests and a
deployment dry run do not establish live provider or deployed readiness.
