# Knowledge implementation boundaries

The [gateway design](2026-09-15-knowledge-gateway-design.md) remains the product
contract. Implementation uses a private Knowledge Worker behind the existing
Flask authentication boundary. This retains persisted key revocation and keeps
retrieval and ingestion work out of the chat Container.

## Caller contract

Clients call `POST /v1/knowledge/context` or `POST /v1/knowledge/search` with a
scoped MultiLLM key. Remote MCP at `/mcp` exposes the same two operations.
The dashboard at `/knowledge` uses session authentication and CSRF-protected
administration routes. A read-only knowledge key cannot administer the corpus
or call chat routes.

```json
{
  "query": "How are request size limits configured?",
  "product": "flask",
  "version": "3.1.3",
  "mode": "smart",
  "token_budget": 6000,
  "freshness": "normal"
}
```

Flask sends a single bounded private request with a server-derived principal:

```json
{
  "version": 1,
  "operation": "context",
  "principal": {"id": "docs-client", "scopes": ["knowledge:read"]},
  "payload": {"query": "How are request size limits configured?"}
}
```

The fixed destination is `http://knowledge.internal/v1/dispatch`. The main
Worker's Container outbound handler forwards only that operation envelope to
`KNOWLEDGE_SERVICE`. The dedicated Worker has no public route, workers.dev URL,
or preview URL. Browser-provided identity headers are never accepted.

Success returns `{ "version": 1, "result": ... }`; failure returns
`{ "version": 1, "error": { "code": "...", "message": "..." } }` with the
appropriate HTTP status. Public REST unwraps the result. MCP wraps it in the
protocol's tool-result envelope.

## Ownership

| Module | Responsibility |
| --- | --- |
| `routes/knowledge.py`, `services/knowledge_client.py` | Public HTTP/MCP, authenticated principal, bounded private transport |
| `templates/knowledge.html`, `static/js/knowledge/`, `static/css/knowledge.css` | Sources, jobs, provider setup, allowances, evidence query tester |
| `worker/knowledge/service.mjs` | Private operation authorization and orchestration |
| `worker/knowledge/contracts.mjs`, `evidence.mjs` | Boundary validation, artifact identity, version qualification, citation spans and token packing |
| `worker/knowledge/authority.mjs`, `ledger.mjs` | Durable source catalogue, publication fences, jobs and operation reservations |
| `worker/knowledge/providers/` | Fixed-origin upstream adapters; source, discovery and derived-context separation |
| `worker/knowledge/corpus.mjs`, `ingestion.mjs` | R2 snapshots, AI Search, durable ingestion and readiness verification |
| `worker/knowledge/retrieval.mjs` | Bounded provider selection, cached/index/live evidence and gap reporting |

Catalogue, publication pointers and allowance reservations have one authority:
a SQLite-backed Durable Object. Document bodies live in R2. A Workflow performs
acquisition, snapshotting, upload reconciliation and publication independently
of interactive requests. No network operations execute in catalogue transactions.

The dashboard operations are `status`, `sources.create`, `sources.update`,
`sources.refresh`, `jobs.cancel`, and `policy.update`. They require
`knowledge:manage`. `context`, `search`, and `artifact` require `knowledge:read`.
Administrators have both permissions. The policy starts disabled, with zero
provider/background allocations. Credentials alone never enable spending.

## Invariants

- Normalize acquired source text once and retain its hash and UTF-8 byte spans.
  Search chunks must match that immutable snapshot before becoming excerpts.
- Requested versions never become observed versions. Unverified or mismatched
  versions are returned as related evidence with a coverage gap.
- Source publication uses a monotonic fence. Cancelled or superseded jobs cannot
  change a current revision. Duplicate work reuses durable receipts.
- Every upstream call has a prior finite reservation. Pending and unknown
  outcomes remain charged; retrying a job cannot replay an uncertain charge.
- Background reservations obey their own cap and preserve interactive capacity.
  Operation caps do not substitute for provider-side billing hard stops.
- Only approved public source hosts may enter the corpus. Generated explanations
  may aid discovery but cannot become quoted source excerpts.
- Cache identity includes the full request, principal, corpus generation and
  policy revision. Cache hits still pass current authentication and eligibility.

## Alternatives

A Flask-hosted retrieval service with a separate Cloudflare storage/ingestion
Worker was considered. It adds cross-runtime domain coordination and occupies
the existing chat Container during live retrieval. The private dedicated Worker
keeps one evidence implementation and one domain call per public operation.
The useful part of the alternative is retained: Flask remains the existing
authentication authority. Cold Container authentication remains part of latency.

## Verification and release

Exercise scope/CSRF enforcement, protocol negotiation, unknown charges,
concurrent reservations, restart persistence, stale publication, missing source
spans, unsupported versions, provider failures and cancelled jobs with synthetic
fixtures before regression checks. Production activation separately requires
configured provider credentials, Cloudflare resources, reviewed retention and
billing controls, and representative live provider/indexing checks. Local tests
cannot establish those production conditions.
