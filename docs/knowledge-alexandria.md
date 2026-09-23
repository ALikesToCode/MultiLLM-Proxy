# Firecrawl Alexandria

Alexandria is available in the Knowledge dashboard and through the gateway's REST
and MCP interfaces. It uses the same `FIRECRAWL_API_KEY` as ordinary Firecrawl
scraping. Capabilities and their prices come from discovery; no provider-specific
addresses are hardcoded for execution.

## Production setup

1. Deploy the private Knowledge Worker and its Durable Object catalogue using the
   [Knowledge setup guide](knowledge.md). Alexandria does not require R2, AI Search
   or the indexing Workflow; those bindings serve the documentation corpus.
2. Set `FIRECRAWL_API_KEY` as a secret on the **private Knowledge Worker**. Local
   `.env` entries do not provision Worker secrets. No separate Alexandria key is
   needed. The key's organization must have Alexandria access.
3. Discovery and inspection work with spending disabled. To execute, enable the
   Knowledge policy and the separate **Alexandria** allowance, choose a finite
   daily credit allowance, and confirm the upstream billing and retention controls.
   Existing six-provider policies gain a disabled Alexandria allowance automatically.
4. If Firecrawl requires provider terms, an organization admin must review and
   accept them in Firecrawl. The gateway returns an action-required error and never
   accepts terms or automatically retries the call.

Create a gateway API key with `knowledge:read` for REST or MCP clients. Dashboard
actions require an admin session and CSRF protection. Provider credentials stay in
the private Worker and are never returned to the browser or client.

## Discover, inspect, execute

All routes below are `POST`, accept JSON, and use the gateway API key as a Bearer
token. Corresponding dashboard routes use `/admin/knowledge/alexandria/`.

| REST route | MCP tool | Cost |
| --- | --- | --- |
| `/v1/knowledge/alexandria/search` | `knowledge_alexandria_search` | 0 credits |
| `/v1/knowledge/alexandria/inspect` | `knowledge_alexandria_inspect` | 0 credits |
| `/v1/knowledge/alexandria/execute` | `knowledge_alexandria_execute` | Published capability price |
| `/v1/knowledge/alexandria/receipt` | `knowledge_alexandria_receipt` | No new provider call |

Search accepts `{"query":"podcast conversations about AI agents","limit":5}`.
It calls Firecrawl `/v2/search` with **only** `sources: ["alexandria"]`; ordinary
web search is not included. Results include `provider`, `capability`, `creditsCost`,
`perRecord`, input and response contracts, a `quote_id`, and `expires_at`.

Inspect accepts `{"quote_id":"<returned quote_id>"}` and calls Firecrawl's native
`firecrawl/find-tools` catalogue capability through `/v2/scrape`, filtered to that
provider and capability. This is the native SDK's `findTools()` HTTP contract.

Execute accepts:

```json
{
  "quote_id": "<returned quote_id>",
  "request_id": "<new UUID for this deliberate retrieval>",
  "options": {"<option name from discovery>": "<value>"},
  "reserve_credits": 15,
  "accept_variable_cost": false
}
```

The example reservation is illustrative: use the selected capability's actual
published price. Quotes last ten minutes and belong to the authenticated principal.
Execution rejects invented provider/capability fields, undiscovered or expired
quotes, unsupported option names, and missing required options. Firecrawl validates
provider-specific option types, ranges and relationships. Each execution sends one
capability to `/v2/scrape`; provider data is returned as `data` without being indexed
or retained in the corpus. Discovery contracts retain any published attribution
requirements, which clients must preserve when using the records.
Execution requests use a 10-second upstream deadline, a 15-second transport timeout,
and a 1 MiB response limit. Interrupted or oversized responses keep an unknown-cost
receipt so callers cannot accidentally purchase the same request again.

Every completed call reports `cost: {"credits": N, "state": "confirmed"}` using
Firecrawl's response. Search and inspection report zero according to their free
contract; an unexpected reported charge is surfaced as an error with its cost.
Provider failures can still carry confirmed charges. A transport failure or
malformed charge receipt reports `credits: null, state: "unknown"`, never a guessed
zero. Receipts include the gateway and upstream request IDs, upstream scrape ID when available,
published price, reserved credits, and whether the charge exceeded the reservation.

## Allowances and retries

Alexandria allowance units are **Firecrawl credits**, separate from the conservative
operation units used by the other adapters. Admission atomically reserves the
requested credits; confirmed settlement replaces that reservation with the actual
charge. Pending and unknown reservations stay counted across daily windows.
Concurrent calls cannot oversubscribe the configured reservations.

`reserve_credits` is a local admission reservation, **not an upstream price cap**.
For a fixed-price call, reserve at least the published price. For per-record pricing,
choose bounded options from the discovered contract, reserve for the expected record
count, and explicitly set `accept_variable_cost: true`. The actual total or a changed
upstream price can exceed the reservation. Such charges remain fully counted and are
flagged in the receipt. Configure Firecrawl's own account billing limit to bound
upstream spending.

Reuse the same `request_id` and identical payload after an interrupted execution.
The gateway returns its durable receipt and **does not call the provider again**.
Read the receipt separately with `{"request_id":"<original id>"}`. Receipt lookup
does not depend on the quote still being valid. Lookup and replay responses contain
the original retrieval's `cost` and a separate zero-credit `call_cost` for the lookup.
A pending receipt means work may
still complete; a missing receipt also does not prove an in-flight request was not
accepted. The gateway does not retry, refund unknown reservations, or recover a
lost provider record automatically. Replays return `data_retained: false`.

The catalogue retains at most 500 unexpired quotes and 5,000 execution receipts.
Expired quotes are pruned. Receipt identities survive regular ledger maintenance
to prevent repeat purchases; once full, the catalogue requires deliberate operator
archival before admitting more executions. No automatic destructive archive runs.

## Direct CLI use

Use an Alexandria-capable Firecrawl CLI (verified against `firecrawl-cli` 1.24.4,
Firecrawl SDK 4.40.0). Authenticate interactively with `firecrawl login`; never put
keys in command arguments or shell history. If installed alongside an older CLI as
`firecrawl-alexandria`, substitute that command name in these examples.

```sh
firecrawl search "podcast conversations about AI agents" --sources alexandria --json
firecrawl find-tools --options '{"providers":["<discovered provider>"],"capabilities":["<discovered capability>"],"level":"tools","expand":["options","response"]}' --json
firecrawl scrape '<discovered provider>/<discovered capability>' --options '{"<discovered option>":"<value>"}' --request-id '<unique request ID>' --json
```

Read the contract and price before the last command; it spends credits. Report the
receipt's actual credits after each call. Direct CLI calls use Firecrawl billing
directly and do not pass through this gateway's allowance or discovery enforcement.
The Developer and Research indexes remain separate native APIs; this feature does
not route those searches through Alexandria or add new index adapters.

Contracts: [Alexandria guide](https://docs.firecrawl.dev/features/alexandria),
[CLI setup](https://docs.firecrawl.dev/sdks/cli),
[Firecrawl MCP](https://docs.firecrawl.dev/mcp-server).
