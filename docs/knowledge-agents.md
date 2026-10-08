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
   sees every tool permitted by those scopes. Ask a small evidence question
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
| `knowledge_skills_find`, `knowledge_skills_get` | Find and load operator skills (read) |
| `knowledge_skills_discover`, `knowledge_skills_preview` | Search the library, public skill marketplaces and GitHub; read an external SKILL.md as untrusted data (read) |
| `knowledge_skills_sync` | Upload or delete operator skills (manage) |
| `knowledge_skills_import`, `knowledge_skills_report` | Import a reviewed external skill pinned to a commit or version; report upstream updates and library gaps (manage) |
| `knowledge_artifact` | Retained source text and citation manifest |
| `knowledge_status` | Source, job, configuration and allowance status (manage) |
| `knowledge_source_register` | Register public documentation without fetching (manage) |
| `knowledge_source_update` | Change enabled, pinned and refresh state (manage) |
| `knowledge_source_refresh` | Start or reconcile indexing (manage) |
| `knowledge_job_cancel` | Fence future job work (manage) |
| `knowledge_policy_update` | Save a complete policy with revision protection (manage) |
| `knowledge_memos_stats` | Memo counts, hit counts and age ranges (manage) |
| `knowledge_memos_purge` | Purge one product or all memos (manage) |

A normal query may return `path: "memo"` with validated cited revisions and
`memo` metadata. Exact repeats are enabled by default; similar questions remain
in observe mode and report `index_diagnostics.memo_candidate` while retrieval
runs. Use `freshness: "fresh"` to bypass both memos and the evidence cache.

The same operations are available through REST. `/knowledge` provides the
administrator UI. The private Knowledge Worker has no public client URL. Chat, model
and media tools are a separate server at `/v1/mcp`; see [MultiLLM MCP server](mcp.md).

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

## Skills hub

Upload the local library once, then search a few skills per prompt instead of
listing every skill. `knowledge_skills_find` defaults to hybrid search and three
results; `mode: "fast"` uses only BM25. Results carry high/low confidence;
`min_confidence: "high"` filters weak matches before limits and suggestion counts. `knowledge_skills_get` loads `SKILL.md` or a
referenced relative path. These are operator instructions (`trust: "operator"`);
provider evidence remains untrusted data. `/mcp?toolsets=skills` lists only the
seven skills tools, subject to the key's scopes.

### Marketplaces and GitHub

`knowledge_skills_discover` (POST `/v1/knowledge/skills/discover`, `knowledge:read`)
searches the operator library and, in parallel, SkillsMP, skills.sh, ClawHub,
SkillHub (skills.palebluedot.live), claude-plugins.dev and GitHub code search. It
takes `{query, limit?, sources?}`: `limit` is 1–20 (default 10) and `sources` picks
from `library`, `skillsmp`, `skills-sh`, `clawhub`, `skillhub`, `claude-plugins` and
`github` (default all). Marketplaces receive the query's content words, never the
full prompt; secrets in the query are rejected before any call.

The reply has three parts. `library` holds operator skills (`trust: "operator"`) to
load with `knowledge_skills_get`. `external` holds candidates (`trust: "external"`)
merged by repository and skill name, with `found_in`, stars/installs, a GitHub or
ClawHub `url`, an `install` command and a `preview` object. `sources` gives each
source's `ok`, `timeout`, `rate_limited`, `access_denied`, `error`,
`not_configured` or `skipped` status. Skills that SkillHub marks malicious or ClawHub
marks suspicious are withheld and counted in `withheld_flagged`. Each source has
4.5 s. A source that fails three times in a row, or hits a rate limit once, is
`skipped` for 10 minutes (`retry_after` gives the seconds left); one success clears
it. Answers in which every searched source succeeded are cached for 15 minutes.
An external result the library already has carries `library: {skill_id, root,
match}`: `imported` for the same imported origin, `same_name` for any library skill
with that name. ClawHub skills are named `owner/slug`, because slugs repeat across
owners.

`knowledge_skills_preview` (POST `/v1/knowledge/skills/preview`) takes a result's
`preview` object: `{repository, path, ref?}`, `{repository, name}` (tries
`skills/<name>`, `<name>`, `.claude/skills/<name>`, `.agents/skills/<name>`, then
SkillHub's recorded folder) or `{clawhub}`. It returns the SKILL.md (at most
128 KiB) with `review_flags` such as `pipe_to_shell`, `credential_paths`,
`instruction_override` or `embedded_secret`. Flags are prompts for review, not a
verdict. Discovery and preview never change the library; only an approved import
does.

### Importing and watching external skills

`knowledge_skills_import` (POST `/v1/knowledge/skills/import`, `knowledge:manage`)
copies one skill folder into the `imported` root. It takes `{repository, path,
ref?}` for GitHub (the preview's `path` works) or `{clawhub: "owner/slug"}`. The
first call imports nothing: it resolves the ref to a commit (or ClawHub's latest
version), reads the folder and returns a plan with the files, any skipped files,
`review_flags` per file and an `apply` payload. ClawHub's own verdict is checked:
`malicious` is refused and any status other than `clean` adds the
`marketplace_suspicious` flag. To import, send the plan's `apply` payload (which
pins `commit` or `version`) plus `accept_flags` listing every review flag the
operator accepted. Missing flags return `review_required`; embedded secrets are
always refused. Folders follow the sync limits (40 files, 128 KiB SKILL.md,
256 KiB per file, 5 MiB total); oversized files are skipped and listed.

Imported skills are served by `knowledge_skills_get` with `trust: "operator"` and
an `origin` (repository, path, ref, commit or ClawHub version, accepted flags), and
the hint hook can suggest them. An import never replaces a skill from another root
or another origin (`skill_exists`); `knowledge_skills_sync` cannot write the
`imported` root, and its `delete` removes an import. Re-importing the same origin
at a new pin updates it.

The hourly cron checks up to five imported skills a day each against their
upstream. For GitHub it resolves the ref; an unchanged commit or folder tree costs
one or two API calls. `knowledge_skills_report` with `{kind: "updates"}` lists each
import with `status` (`unchecked`, `current`, `changed` or `error`), the latest
commit or version, per-file `changes` with bounded unified diffs, new
`review_flags` and an `apply` payload. `check: true` checks the two least recently
checked imports now. Updates
are never applied: adopting one is another import with that payload.

`{kind: "gaps"}` lists searches the library could not answer with a
high-confidence skill, by count, with up to three external candidates seen. Only
discovery searches that include the library count, keyed by their sorted content
words; a later confident answer removes the gap, and gaps expire after 90 days.

GitHub code search needs the Knowledge Worker secret `GITHUB_TOKEN` (a
fine-grained token with public read access only); without it the `github` source
reports `not_configured`. Imports and update checks work without it, but share
GitHub's unauthenticated limit of 60 requests an hour per IP address, which other
Cloudflare tenants also use; a refusal returns `upstream_rate_limited`. The other marketplaces index GitHub too. SkillsMP works
anonymously; the optional `SKILLSMP_API_KEY` secret raises its rate limit.

From the repository, use Python 3.11+ and an existing private environment containing
`MULTILLM_BASE_URL` and `MULTILLM_KNOWLEDGE_API_KEY`. Sync requires
`knowledge:manage` on the operator key; hooks and retrieval need only `knowledge:read`.
An explicit `--key-file` wins over the environment key, and `--base-url` wins over
the environment URL. Both clients send `User-Agent: multillm-skills/1`.

```sh
python3 scripts/skills_sync.py --dry-run
python3 scripts/skills_sync.py --key-file /private/path/operator-key --base-url https://gateway.example
```

The defaults are `~/.claude/skills`, `~/.claude/skills-library`, `~/.codex/skills`
and `~/.agents/skills`. Override them with repeated `--root LABEL=PATH`, and set
`--base-url` or `--key-file PATH` if needed. Dry run prints only metadata and a
plan; it never reads the key or contacts the service. Keep the receipt file:
only previously successful uploads from the selected root labels are eligible
for deletion. An unavailable root or invalid local skill disables pruning for
that root. The default state is `~/.config/multillm/skills-sync-state.json` (0600,
parent created 0700), overridable with `--state-file`. Duplicate slugs retain the
first root's skill: identical SKILL.md hashes count as `duplicates`; differing
hashes report `duplicate_conflict` with both root labels, not a rejection.
High-confidence secrets reject the containing skill without printing the secret.
Absolute, tilde-prefixed, `..` and external references are ignored; escaping
collected symlinks are skipped and counted as `skipped_files`, as are extra files
over the size, 40-file or reference limits; only a SKILL.md over 128 KiB rejects
a skill. Missing files are ignored. Only local referenced files/directories are uploaded in bounded batches
of at most 16 skills and 8 MiB, retaining the 5 MiB per-skill cap. Summaries give
counts and each rejected/conflicting slug with its safe reason, never content.

Confidence tokenization lowercases Unicode letters/numbers, drops single letters
and fixed English stopwords, and lightly stems plurals except `ss`, `us`, `is`.
High confidence means all name tokens match (multi-token names need distinctive
`nidf >= 3.5`; single-token names need full-text frequency at most `max(3, 0.03*N)`),
or at least three name/description matches with at least `2 + floor(query_tokens/20)`
distinctive terms. These named constants and corpus statistics are documented in
the [design](plans/2026-10-07-knowledge-skills-hub-design.md). Ranking still uses
BM25, optional semantic cosine and the helpful prior. `SKILLS_CONFIDENT_COSINE`
is disabled when unset; calibrate it using labeled prompts and deployed embeddings
before enabling it. The fast hook does not use semantic confidence.

The optional prompt hook uses POST `/v1/knowledge/skills/find` with JSON
`{query, mode: "fast", limit: 3, min_confidence: "high"}` and a total 1.5 s budget
(a live find takes about 0.7 s).
The GET search mirror remains for manual use; its query URL may be logged by
Cloudflare, Worker observability and Flask. POST keeps hook prompts out of URLs.
It adds at most 600 UTF-8 bytes of context (about 150 tokens), and emits nothing on
errors, timeouts, prompts shorter than 12 characters or no high-confidence match.
Key-file reading is included in the total time budget.
Install these snippets yourself, merging with existing hooks. Replace the absolute
repository path, private read-key path and base URL. File paths belong in the
command; do not put credential values in JSON. Flags take precedence over the
client's inherited environment.

Claude Code `settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [{
      "hooks": [{
        "type": "command",
        "command": "python3 /absolute/path/MultiLLM-Proxy/scripts/hooks/skill_hint.py --agent claude --key-file /private/path/read-key --base-url https://gateway.example",
        "timeout": 2
      }]
    }]
  }
}
```

Codex `hooks.json` (user or trusted project configuration):

```json
{
  "hooks": {
    "UserPromptSubmit": [{
      "hooks": [{
        "type": "command",
        "command": "python3 /absolute/path/MultiLLM-Proxy/scripts/hooks/skill_hint.py --agent codex --key-file /private/path/read-key --base-url https://gateway.example",
        "timeout": 2
      }]
    }]
  }
}
```

Review and trust a new Codex hook through `/hooks`. Both clients accept
`hookSpecificOutput.additionalContext` for UserPromptSubmit. Codex defaults to
approximately 2,500 tokens per model-visible hook message; this hook stays well
below it. See the official [Claude Code hook reference](https://code.claude.com/docs/en/hooks)
and [Codex hook reference](https://developers.openai.com/codex/hooks). Whether Codex hooks
fire under the T3 app-server remains unverified; retrieval through MCP works
without a hook.

Only returned find results increment `suggested`. A successful get increments `fetched`; it increments
`helpful` once if the same principal was offered the skill in the preceding
30 minutes. Ranking adds a small `0.03 * log(1 + helpful)` prior. Counters stay in
the private index and are omitted from compact retrieval results. Superseded,
deleted and interrupted R2 revisions are cleaned on subsequent non-dry syncs
after a one-minute grace period. Cleanup is bounded to 64 pending revisions;
retry sync after the grace period if storage cleanup applies backpressure.

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

## Handoffs

Use the `handoff` MCP toolset (`/mcp?toolsets=handoff`) to continue a task in
another agent or thread. All four tools use `knowledge:read` and store context
only for the authenticated principal. Claude Code and Codex share handoffs only
when their keys belong to the same principal; the shared agent key does:

| Tool | Input and result |
| --- | --- |
| `knowledge_handoff_save` | `project`, `title`, `sections`, `source`; optional `branch`, `summary`, `ttl_days`; returns id and expiry |
| `knowledge_handoff_get` | `project` or `id`, optional `branch`; project must match when supplied with id; returns compact markdown and the full structured record |
| `knowledge_handoff_list` | Optional `project`, `limit` (1–20); returns metadata |
| `knowledge_handoff_delete` | `id`; returns whether it was deleted |

Use owner/name from the git origin URL (otherwise the directory name) for
`project`, and the current git branch for `branch`. Project matching folds ASCII
case while preserving the saved spelling. Load by project and branch; when the
branch has no unexpired record, get falls back to the newest project record. Use the returned context as operator notes.
Defaults are 14-day retention, 50 records per project and 500 per principal.
The existing firewall rejects secrets before saving. See [REST contracts](knowledge.md#handoff-api)
and [the design](plans/2026-10-07-knowledge-handoffs-design.md) for all field limits.

`scripts/handoff.py` requires Python 3.11+ and only the standard library. Run
from the project directory; set `MULTILLM_BASE_URL` to the HTTPS gateway origin
and provide `MULTILLM_KNOWLEDGE_API_KEY` privately in the environment (or use
`--key-file` pointing to an existing private credential file). No credentials
are written by the script. Every HTTP request sends `User-Agent: multillm-handoff/1`;
the gateway rejects urllib's default User-Agent with Cloudflare error 1010 (403).

```bash
python3 /path/to/MultiLLM-Proxy/scripts/handoff.py build > /tmp/task-handoff.json
python3 /path/to/MultiLLM-Proxy/scripts/handoff.py print --input /tmp/task-handoff.json
python3 /path/to/MultiLLM-Proxy/scripts/handoff.py save --input /tmp/task-handoff.json
python3 /path/to/MultiLLM-Proxy/scripts/handoff.py load
```

`build` discovers the newest Claude Code or Codex transcript matching cwd.
For an explicit file use `--transcript PATH --agent claude` (or `codex`). `save`
and `print` can build directly or accept `--input -` from stdin. Project identity
comes from the origin's owner/repository, falling back to the directory name.
Extraction keeps edited-file inputs, failed shell commands, branch, HEAD,
status, the first operator message as goal, the last three operator messages,
and the final assistant message (500-character state and 4,000-character summary).
Injected tags, agent instructions, interrupted requests, metadata, compaction and
sidechain user records are excluded. User messages are labeled `User:` in
deterministic `decisions`; they are not inferred decisions. Tool output is used only to identify failure status, never copied.
High-confidence secrets are redacted before truncation and before saving.
Transcript recovery reads the last 64 MiB, drops any partial first line, and skips
lines over 1 MiB in bounded reads; the goal is the first operator message in that
window. Discovery examines
at most 20,000 files per client. Claude paths encode all punctuation as hyphens
and fall back to bounded cwd-field matching for shortened paths. Recorded cwd
paths are resolved before matching in both clients so symlink aliases agree.
Codex discovery checks date directories and rollout filenames newest first.

`build --summarize MODEL` optionally uses `/v1/chat/completions` with at most
30,000 characters of sanitized sections and the closing summary. Supply a
separate chat credential through `--chat-key-file PATH` or `MULTILLM_API_KEY`.
The Knowledge key is never sent to chat. With no chat key it writes
`summarize skipped: no chat key` to stderr and keeps the deterministic sections.
Invalid, failed or oversized summaries also preserve those sections. This opt-in
call can consume the selected model's allowance. Review a handoff before saving it.

The optional `scripts/hooks/handoff_hint.py` accepts SessionStart JSON on stdin
and emits `hookSpecificOutput.additionalContext` only for `startup`, `clear`, or
an absent source. The default `--mode pointer` gives a hint of at most 600 UTF-8
bytes, with the saved branch, agent, age, a title clipped to 120 characters and
explicit loading instructions. The CLI command uses the absolute script path
from the hook location, so it works in the operator project directory. Long
identities use clipped labels and the CLI instruction to keep the pointer bounded. Use `--mode full` to opt into rendered markdown.
`resume` and `compact` emit nothing. It prints only unexpired
handoffs younger than 48 hours, finishes within approximately 1.6 seconds, and
stays silent on configuration, transcript, git or network errors. Nothing
installs this hook automatically. Merge a snippet into existing settings after
reviewing it; replace `/path/to/MultiLLM-Proxy` with the checkout location.

Claude Code (`.claude/settings.json`):

```json
{"hooks":{"SessionStart":[{"matcher":"startup|clear","hooks":[{"type":"command","command":"python3 /path/to/MultiLLM-Proxy/scripts/hooks/handoff_hint.py --agent claude","timeout":2}]}]}}
```

Codex (`.codex/hooks.json`):

```json
{"hooks":{"SessionStart":[{"matcher":"startup|clear","hooks":[{"type":"command","command":"python3 /path/to/MultiLLM-Proxy/scripts/hooks/handoff_hint.py --agent codex","timeout":2,"additionalContextLimit":2500}]}]}}
```

The formats follow the official [Claude Code hooks](https://code.claude.com/docs/en/hooks)
and [Codex hooks](https://developers.openai.com/codex/hooks) documentation.
Codex requires review/trust of non-managed hooks. Hook firing through the T3
app-server remains unverified; use the MCP get tool or `load` explicitly there.

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
