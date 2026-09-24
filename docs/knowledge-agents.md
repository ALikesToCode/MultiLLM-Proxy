# Knowledge access for agents

Use the [MultiLLM Knowledge skill](../skills/multillm-knowledge/SKILL.md) for the
complete operating workflow: source registration, indexing, cited retrieval,
refresh and cancellation, allowances, numbered key failover, and Alexandria.
The [production guide](knowledge.md) documents the resources and API contracts.
The website serves `/agent-onboarding` with a copyable setup prompt, client
configuration, and the downloadable skill. `/llms.txt` (also `/llm.txt`) links to
`/llms-full.txt`, `/agent-onboarding/SKILL.md`, `/agent-onboarding/prompt.txt`, and
`/agent-onboarding/config.json`. These public routes contain no account data or keys.

## Connect to the gateway

1. In the dashboard's **Access** page, create a proxy key with `knowledge:read`,
   or provision a durable integration key with
   `scripts/intelligence_operator.mjs provision --scopes knowledge:read`
   ([details](knowledge.md#client-routes)). Add `knowledge:manage` only for source
   or policy administration. Keep the key in the client's private credential
   environment or secret store.
2. Add a remote HTTP MCP connection to `https://<gateway-origin>/mcp`, sending the
   proxy key as `Authorization: Bearer ...`. Use an environment reference supported
   by the client; do not copy the value into a committed configuration file.
3. Initialize MCP and list tools. The server negotiates `2025-06-18` or
   `2025-03-26` and returns operating instructions. Send
   `Accept: application/json, text/event-stream` (JSON-only clients also work) and
   use the negotiated `MCP-Protocol-Version` thereafter. This server returns JSON
   without a persistent session or GET event stream.
4. Confirm the tools permitted by the key are discoverable. A key with both scopes
   sees all thirty tools below. Ask a small evidence question
   before using results in a larger task. Scope errors require a correctly scoped
   proxy key; provider keys cannot authenticate to this endpoint.

| MCP tool | Purpose |
| --- | --- |
| `knowledge_context` | Cited excerpts with version evidence and coverage gaps |
| `knowledge_search` | Source evidence and retrieval diagnostics |
| `knowledge_alexandria_search` | Free capability discovery and prices |
| `knowledge_alexandria_inspect` | Free inspection of a discovered capability |
| `knowledge_alexandria_execute` | Explicit credit-priced retrieval |
| `knowledge_alexandria_receipt` | Lookup without purchasing again |
| `knowledge_context7_resolve_library`, `knowledge_context7_docs` | Context7 library lookup and documentation |
| `knowledge_exa_search`, `knowledge_exa_contents`, `knowledge_exa_code_context`, `knowledge_exa_answer` | Exa search, page contents, code context and cited answers |
| `knowledge_firecrawl_scrape`, `_search`, `_map`, `_crawl`, `_crawl_status`, `_extract`, `_extract_status` | Firecrawl scraping, search, site maps, crawls and structured extraction |
| `knowledge_deepwiki_structure`, `knowledge_deepwiki_contents`, `knowledge_deepwiki_ask` | DeepWiki repository documentation and answers |
| `knowledge_mintlify_context` | Mintlify Index research with citations |
| `knowledge_artifact` | Retained source text and citation manifest |
| `knowledge_status` | Source, job, configuration and allowance status (manage) |
| `knowledge_source_register` | Register public documentation without fetching (manage) |
| `knowledge_source_update` | Change enabled, pinned and refresh state (manage) |
| `knowledge_source_refresh` | Start or reconcile indexing (manage) |
| `knowledge_job_cancel` | Fence future job work (manage) |
| `knowledge_policy_update` | Save a complete policy with revision protection (manage) |

The same operations are available through REST. `/knowledge` provides the
administrator UI. The private Knowledge Worker has no public client URL.

## Install the operating skill

Copy the whole `skills/multillm-knowledge` directory into an unused skill directory
for each client:

| Client | User skill directory |
| --- | --- |
| Codex | `~/.codex/skills/multillm-knowledge/` |
| Claude Code | `~/.claude/skills/multillm-knowledge/` |

Preserve any existing installation and review differences before an update. In a
fresh session, invoke `$multillm-knowledge` in Codex or `/multillm-knowledge` in
Claude Code. The skill is self-contained when used outside this checkout.

Useful initial tasks:

> Use the MultiLLM Knowledge Gateway to find documentation for the dependency
> version in this repository. Cite original sources and list coverage gaps.

> Register the approved versioned documentation source, refresh it, and verify
> publication, indexed retrieval and the retained citation artifact.

> Discover an Alexandria capability for this dataset. Show its contract and
> published price before retrieval, then report the actual receipt cost.

## Official Firecrawl skills

The official [Firecrawl skills repository](https://github.com/firecrawl/skills)
supplies general Firecrawl workflows. The following additions were reviewed at
revision `c469b462a22f6a2ea25ce4dca77ce4c4dc8c5d91`:

| Skill | Use |
| --- | --- |
| `firecrawl-alexandria` | Structured capability discovery and retrieval |
| `firecrawl-knowledge-base` | Organizing a reusable public web corpus |
| `firecrawl-knowledge-ingest` | Planning source acquisition |
| `firecrawl-build` | Choosing an application integration |
| `firecrawl-build-onboarding` | Existing-project integration setup |
| `firecrawl-build-scrape` | Source acquisition integration |
| `firecrawl-build-search` | Search integration |
| `firecrawl-build-interact` | Interactive acquisition integration |

Existing search, scrape, Developer Index and Research Index skills remain useful.
The MultiLLM skill adds the gateway-specific contracts and controls. General
Firecrawl browser/ingestion capabilities do not mean this gateway accepts private
portals or local file uploads. Follow the workstation's browser policy and the
user's authorization. Installing a skill does not authorize vendor feedback or
transmitting task details.

Reuse an existing Firecrawl CLI/MCP connection for explicitly direct tasks. The
[CLI guide](https://docs.firecrawl.dev/sdks/cli) and
[MCP guide](https://docs.firecrawl.dev/mcp-server) describe those connections.
For Alexandria, use a capable CLI (`firecrawl-alexandria` if installed alongside
an older `firecrawl`) and follow the [discovery and receipt workflow](knowledge-alexandria.md).
Direct calls do not use the gateway's allowances or retained corpus.

## Production acceptance

Confirm private Worker bindings, deployed provider secret counts, scoped MCP
discovery, and the complete source → refresh → publication → indexed query →
artifact journey. Test version mismatch and allowance exhaustion as well.
Credential configuration and synthetic tests cannot establish live provider access.

Before first paid activation, the operator must choose finite allowances and
acknowledge upstream billing controls and source retention rights. The default
policy keeps paid retrieval disabled. Alexandria search and inspection remain
available for free discovery. See [production setup](knowledge.md#provision-and-deploy)
and [credit accounting](knowledge-alexandria.md#allowances-and-retries).
