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
do not learn. Publication and live verification count once per (product, canonical
page URL), even across providers, content revisions and reacquisitions. A repeat updates
the marker's and learned site's `last_seen` without increasing `verified` or revision.

`product-site-page:<slot>` markers contain a digest of product and canonical URL, site,
first/last seen timestamps and an `identity_epoch`. They outlive artifact expiry and
are bounded to 10,000 slots globally. At capacity the least recently seen identity is
evicted, decrementing its site's verification count and removing zero-count unpinned
sites. A new page replaces the victim slot in the same atomic write as both registries
and the count. Pinned sites survive with zero verifications. Site entries also retain
`identity_epoch`, so a marker from an evicted site cannot decrement a later incarnation.
Management responses omit this internal bookkeeping field.
Records remain limited to 400 products; automatic learning declines new products at
that limit. Status retains the `artifact_identities` and `artifact_identity_limit` field
names for compatibility, with page-identity semantics.

Each product has at most 64 sites and 64 blocked entries. A new learned or pinned site
evicts the unpinned entry with the fewest verifications, then the oldest `last_seen`
(with hostname as a stable tie-breaker). Pins are never evicted. A pin batch protects
all its requested existing pins before making room. A fully pinned registry declines
new learned sites. Page identities are still remembered to make retries idempotent.
Unpinning an entry with no verifications removes it from the trusted-site map.

## Rebuild

`product_sites.update` with `rebuild: true` scans retained manifests in 1,000-entry
pages using `startAfter`, bounded at 100,000 total. It rejects a catalogue exceeding
that cap without saving a partial rebuild. It groups distinct canonical pages by site and recomputes
counts, first and last timestamps. It preserves pinned and blocked entries, fills
remaining slots with the strongest learned sites, and replaces that product's durable
identity markers. Rebuild intentionally resets historical knowledge to currently
stored manifests, including unpublished ones, as requested by the backfill contract.
Artifacts that expired before rebuild no longer contribute. Later reacquisition may
learn those pages in the new history. Rebuild applies the same global LRU identity cap,
updating other products' counts if their older identities are evicted. Writes use batches
of at most 128 records. All operations are serialized by the existing catalogue transaction.
On the first registry read, round-1 revision markers trigger a one-time rebuild of
existing product registries from retained manifests; pins and blocks survive. Old markers
and their counter are removed. Expired history cannot be reconstructed because old
markers carry only product names, not URLs. A schema marker prevents repeat migration.

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
