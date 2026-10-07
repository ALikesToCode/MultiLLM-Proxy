# Learned product-site registry

## Purpose and ownership

Mintlify searches multiple products and can return homonyms such as overflow.co payment
availability for CSS overflow-clip-margin, or docs.codex.io wallets for the Codex CLI.
The catalogue now remembers sites that produced retained evidence for a product.
`worker/knowledge/product-sites.mjs` owns validation, persistence, learning, bounds and
rebuild. `provider-site-filter.mjs` owns provider-section decisions. The existing
`evidence.mjs` exports the shared `site()` helper and section separator.

## Stored contract

Each `product-sites:<product>` record is:

```json
{
  "product": "codex",
  "sites": {
    "openai.com": {"verified": 5, "first_seen": "2026-10-07T00:00:00Z", "last_seen": "2026-10-07T00:00:00Z", "pinned": false}
  },
  "blocked": {"codex.io": {"at": "2026-10-07T00:00:00Z", "note": "Different product"}},
  "revision": 1
}
```

Product names follow source API string validation and lowercasing. `site()` reduces a
URL hostname to its last two labels after removing `www`. Management accepts unique
lowercase public hostnames up to 253 characters and canonicalizes them through the
same helper. This deliberately preserves the existing approximation, including its
multi-label public-suffix limitations.

Learning runs inside the catalogue transaction at `job.publish`, including completed
job retries. Retrieval calls the internal `product_sites.learn` operation only after
snapshot confirmation and byte-span validation admits a live excerpt. Manifest
admission alone does not learn. Empty products and unreadable/missing live excerpts
do not learn. Publication and live verification of the same artifact count once.
Separate providers or content revisions have separate artifact identities.

`product-site-artifact:<id>` markers outlive artifact expiry. A bounded counter limits
them to 10,000 across the catalogue. Records are limited to 400 products. Automatic
learning quietly stops at either limit; explicit updates reject new products at the
product limit. These additional global caps bound a historical store that would
otherwise grow forever despite the 1,000-manifest retention limit. Status reports only
aggregate product/site/block/identity counts and caps, never whole registries.

Each product has at most 64 sites and 64 blocked entries. A new learned or pinned site
evicts the unpinned entry with the fewest verifications, then the oldest `last_seen`
(with hostname as a stable tie-breaker). Pins are never evicted. A pin batch protects
all its requested existing pins before making room. A fully pinned registry declines
new learned sites. Artifact identities are still remembered to make retries idempotent.
Unpinning an entry with no verifications removes it from the trusted-site map.

## Rebuild

`product_sites.update` with `rebuild: true` scans all retained manifests (bounded at
1,000) for that product, groups distinct artifact IDs by canonical site and recomputes
counts, first and last timestamps. It preserves pinned and blocked entries, fills
remaining slots with the strongest learned sites, and replaces that product's durable
identity markers. Rebuild intentionally resets historical knowledge to currently
stored manifests, including unpublished ones, as requested by the backfill contract.
Artifacts that expired before rebuild no longer contribute. Later reacquisition may
learn those artifacts in the new history. Explicit rebuild can recover identity-store
capacity, but cannot exceed the global cap. All operations are serialized by the
existing KnowledgeCatalogue Durable Object transaction.

## Retrieval and policy

The optional product registry is loaded in the existing `catalogue.state` round trip.
A registry storage failure returns null, so the original filter continues to operate.
Learning errors cannot fail publication or evidence retrieval and create no gaps. Live
learning has its own 250 ms wait budget and stores registry/count/identity updates in
one atomic write batch so caught failures cannot inflate later retries.

`product_sites_mode` is optional in complete policy updates and defaults to `observe`,
including policies persisted before this feature. The dashboard preserves a mode set
through management APIs when saving unrelated policy fields.

For each `derived_context` section with a Source URL:

1. Blocked sites are rejected, even when pinned or present in answer evidence.
2. Learned or pinned sites, candidate evidence URLs, and `provider_documentation`
   Source URLs are trusted.
3. Unknown sites are rejected when at least two sites have learned verifications,
   or the sum of verifications reaches five. Pins with zero verifications do not
   establish a product.
4. Before establishment, the unchanged foreign-section heuristic decides.

Source-less sections are preserved. Registry decisions also cover a single Source-bearing
section without a separator; the legacy heuristic continues to judge separated sections
only. `off` uses the original section filter and discovery list. `observe` uses the
original section filter and attaches at most ten `{provider, site, reason}` flags for
`blocked` or `unverified_site` decisions. `enforce` applies all four steps and includes
registry rejections in the existing per-provider dropped count. Outside `off`, discovery
URLs from actually dropped sites are removed. No new gaps are introduced. Bundle status
is computed using the original filter's provider-context availability so removing the
last section cannot change partial status into insufficient evidence.

Registry learning does not change corpus generation. Cache keys include the registry's
filtering state (known sites, blocked sites, establishment threshold), with matching
checks on cache reads. Count-only increments that do not change a decision retain
cache reuse. Answers are written under the final state key after live learning. Policy
revisions continue to invalidate caches through the existing mechanism.

## Management and deployment

The `manage` MCP toolset exposes:

- `knowledge_product_sites_get` with `{product}`.
- `knowledge_product_sites_update` with `{product, pin?, unpin?, block?, unblock?, note?, rebuild?}`.

Both require `knowledge:manage`; REST mirrors them at `GET` and `PATCH`
`/v1/knowledge/product-sites/<product>`. Product duplication in a REST body is rejected.
Private service validation is authoritative for both the edge and Flask transports,
matching the existing source-management APIs. Site lists accept at most 64 unique input
hostnames, notes at most 500 characters, and rebuild must be boolean. Opposite actions
on a canonical site in the same request are invalid. Pins and blocks may coexist, with
blocks taking precedence. Operations return the registry directly.

The Python management definitions generate `worker/knowledge-mcp-catalogue.json`.
Service dispatch, Container transport, edge REST and Flask REST advertise the same
operations and scopes. No new resources, migrations, bindings or environment variables
are required. Operator backfill is a per-product rebuild after deployment, followed by
review of observation flags before selecting enforcement through a complete policy
update. No production calls, pushes or deployment form part of this implementation.

## Verification

Synthetic tests cover publication/live idempotence, retry after artifact expiry, bounded
learning, pinned eviction protection, rebuild preservation, canonical validation,
Durable Object reopen, real homonym replays, cold-start compatibility, block precedence,
observation limits, source-less sections, discovery removal, stable status/gaps, cache
invalidation, storage failure fallback, and REST/MCP scope and operation parity. Existing
Knowledge suites remain part of the acceptance gate.
