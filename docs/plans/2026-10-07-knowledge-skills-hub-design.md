# Knowledge skills hub

## Purpose and trust

A personal library shared by Claude Code, Codex and OpenCode is retrieved a few
skills at a time instead of listing hundreds of folders in every prompt.
`knowledge_skills_get` returns operator instructions with `trust: "operator"`.
The MCP instruction exception applies only to that tool. Other Knowledge text
remains untrusted evidence. The feature never sends file contents to an upstream
provider. Workers AI receives only `name: description` for skill embeddings and
the user's query for hybrid search; fast search makes no embedding call.
Marketplace discovery (below) is the exception: it sends the query's content words
to public skill marketplaces and, when configured, GitHub.
An operator-approved import (below) is the only way external text becomes operator
text: it pins a GitHub commit or ClawHub version and records the review flags the
operator accepted. Upstream changes are reported, never applied.

## Storage and index

`KnowledgeSkills` is a SQLite Durable Object accessed with
`KNOWLEDGE_SKILLS.idFromName("personal")`. The binding and migration tag
`add-knowledge-skills` follow `knowledge-memos-v1` in `wrangler.knowledge.jsonc`.
It reuses `KNOWLEDGE_SNAPSHOTS` R2 and `KNOWLEDGE_SEARCH_AI` Workers AI. No D1
migration, new bucket, public Worker endpoint or provider key is required.

Each skill has a unique slug of its name, name, description, one root label
(`claude`, `claude-library`, `codex`, `agents`), path/byte-size/SHA-256 manifest,
content hash, timestamp, quantized embedding and suggested/fetched/helpful
counters. A slug cannot change root ownership in place. SHA-256 over the root,
metadata and sorted manifest is the content hash. Identical revisions skip R2,
embedding and metadata writes. Files live under
`skills/<skill_id>/<content_hash>/<relative path>`.

Limits: 2,000 skills; 128 KiB SKILL.md; 256 KiB per file; 5 MiB total per skill;
40 files; 100-character names/slugs; 2,000-character descriptions/queries;
240-character relative paths. Traversal, absolute paths, ambiguous encodings,
duplicate paths, invalid UTF-8 SKILL.md and mismatched file hashes are rejected.
Base64 uploads are decoded before bounds, hashes and secret scanning.

The cached in-memory inverted index uses BM25 (k1 1.2, b 0.75) over name with
weight 3, description with weight 2, and headings plus the first 2,000 SKILL.md
characters with weight 1. All fields and queries use lowercase Unicode letter/number
tokens, discard one-character tokens and a fixed English stopword list (function
words, pronouns, auxiliaries and politeness), then strip final `s` on tokens longer
than three characters except endings `ss`, `us`, `is`. Hyphenated names split.
Heading extraction is additionally capped at 128
headings/8,000 characters; query terms at 64. BM25 is normalized by the largest
lexical score for the query. Hybrid adds cosine similarity of
Int8-quantized `@cf/baai/bge-m3` vectors, then `0.03 * log(1 + helpful)`.
No lexical or positive semantic match means no result, regardless of prior.
Ties sort by skill_id. Hybrid is the default; fast bypasses Workers AI. A failed,
invalid or slower-than-350 ms embedding silently falls back to lexical search.

Ranking and confidence are separate. Each result carries `confidence: "high" | "low"`.
The index retains name-only and name/description token sets, name/description
document frequency (`ndf`) and full-text frequency (`fdf`). For N skills,
`nidf(t) = ln(1 + (N - ndf(t) + 0.5) / (ndf(t) + 0.5))`.
High lexical confidence requires either:

- Every name token appears in the query. Multi-token names need a name token with
  `nidf >= DISTINCTIVE_IDF` (3.5); single-token names need `fdf <= max(3, 0.03 * N)`
  (`SINGLE_NAME_MIN_DOCUMENTS`, `SINGLE_NAME_DOCUMENT_RATIO`).
- `MIN_MATCHES` (3) distinct query tokens match name/description, including at least
  `MIN_DISTINCTIVE` (2) plus `floor(query_token_count / LONG_QUERY_TERMS)` distinctive
  matches. `LONG_QUERY_TERMS` is 20. Confidence uses the entire token set even when
  ranking uses its first 64 tokens.

`min_confidence: "high"` filters before the limit and suggestion writes; omitting
it returns both confidence levels. Hybrid may also assign high confidence when
cosine reaches optional `SKILLS_CONFIDENT_COSINE` (a finite value in (0, 1]). It is
disabled when unset or invalid. Before enabling after deployment, run the labeled
evaluation set with deployed bge-m3 query/skill embeddings, sweep candidate cosine
thresholds, inspect every false positive, and retain the silence/required/acceptable
targets on held-out prompts. Lexical-only evaluation cannot calibrate cosine.
Leave the variable unset until those measurements justify a threshold.

Only returned find results increment suggested and retain a principal-digest
suggestion receipt. A successful, integrity-checked get increments fetched and
consumes that principal/skill receipt, incrementing helpful only within 30
minutes. Receipts expire and are capped at 5,000; another principal, an expired
receipt, failed fetch or repeat get cannot increment helpful. Counter updates
are transactional and counters saturate at JavaScript's safe integer maximum.
Updates preserve counters; deletion removes the metadata and suggestion receipts.

Syncs serialize within the DO. Publish metadata only after every immutable file
has uploaded. Record interrupted uploads before writing R2. A bounded SQLite
cleanup queue retains at most 64 pending revisions, protecting active hashes,
and deletes obsolete R2 paths on subsequent non-dry syncs after 60 seconds.
Outstanding R2 promises keep their revision protected from cleanup and reuse,
even after a request timeout. The receipt cap also bounds these promises.
Unavailable cleanup applies retryable per-skill backpressure instead of growing
storage indefinitely. R2 operations have three-second deadlines, sync has a
45-second work budget, private DO dispatch a 50-second deadline. A failed update
preserves the last published revision. Old files can remain until another sync;
operators should repeat sync after the grace period. Never apply a bucket-wide
expiry rule to active skills.

## Contracts and ingress

| MCP tool | Input | Output | Scope |
| --- | --- | --- | --- |
| knowledge_skills_find | query; limit 1–5 default 3; mode fast/hybrid default hybrid; optional roots array; optional min_confidence high | Array of skill_id, name, description, score, confidence, why (matched terms), files (paths) | knowledge:read |
| knowledge_skills_get | skill_id; optional path default SKILL.md | skill_id, path, text, files, content_hash, trust operator | knowledge:read |
| knowledge_skills_sync | skills array; optional delete array and dry_run boolean | results array: skill_id, created/updated/unchanged/deleted/rejected status, safe rejection reason | knowledge:manage |
| knowledge_skills_discover | query (≤500); limit 1–20 default 10; optional sources array of library, skillsmp, skills-sh, clawhub, skillhub, claude-plugins, github | library (find results, trust operator), external (merged candidates, trust external), sources (per-source status and count), optional withheld_flagged and cached | knowledge:read |
| knowledge_skills_preview | repository with path or name, optional ref; or clawhub owner/slug alone | trust external, name, description, url, location, review_flags, text | knowledge:read |
| knowledge_skills_import | repository with path and optional ref, or clawhub owner/slug; commit (40-hex) or version applies; optional accept_flags | plan: status review, would_be, skill_id, origin, files, skipped, review_flags, flagged_files, apply; applied: status created/updated/unchanged, origin with accepted_flags | knowledge:manage |
| knowledge_skills_report | kind updates or gaps; limit 1–50 default 20; check boolean (updates) | kind, items, optional checked | knowledge:manage |

Binary referenced files return `content_base64` instead of text; UTF-8 files,
including base64-encoded UTF-8 uploads, return text. Find/get omit counters,
embeddings, byte bookkeeping and timestamps. Skills bypass the context/search
agent-evidence trimming. MCP find has text content containing the result array,
and no structuredContent because MCP's structuredContent is an object.

The `skills` toolset narrows discovery; calls remain available according to scope.
REST mirrors on Flask and edge are GET `/v1/knowledge/skills?query=...&mode=fast&limit=3&roots=agents,codex`,
POST `/v1/knowledge/skills/find` with JSON `{query, limit?, mode?, roots?, min_confidence?}`,
GET `/v1/knowledge/skills/<skill_id>?path=references/guide.md`, and POST
`/v1/knowledge/skills` for sync. GET search URLs may be logged by Cloudflare, Worker
observability and Flask access logs. The hook uses POST to keep prompts out of URLs. Duplicate/unknown query parameters fail closed.
All routes dispatch privately through `skills.find/get/sync` to the Skills DO.

Sync batches are capped at 16 skills/8 MiB encoded request, deletion lists at
2,000 unique IDs. This additional transport bound accommodates the documented
file sizes without changing the 64 KiB cap on other public Knowledge calls.
Flask and edge use the existing private `secret_scan_checked` marker for sync,
then the Skills handler performs decoded per-file checks through the existing
high-confidence secret detector. Metadata is also checked before embedding.
An unsafe skill returns rejected, secret_detected, relative file and finding
types only; other safe skills in the batch continue. Invalid skill IDs or duplicate
batch identities reject the batch before storage. Find/get retain the normal
outbound firewall. Frozen inventories include the seven skills Flask routes and all
seven skills Worker modules. The catalogue is regenerated from Python contracts.

## Marketplace discovery

`worker/knowledge/skills-market.mjs` runs in the stateless Knowledge Worker, not
the Skills DO. Discover calls the DO's find for the library slice and fans out to
the marketplaces with `Promise.all` over per-source searches that never reject.
Each request uses the provider transport's bounded fetch: fixed HTTPS URLs,
manual redirects, a 4.5-second timeout and a 1 MiB response cap. A failure,
timeout or 429 affects only that source's status. The query is secret-scanned by
the normal dispatch firewall first; marketplaces receive at most eight content
words (stopwords and "skill(s)" removed).

| Source | Endpoint | Fields used |
| --- | --- | --- |
| skillsmp | `skillsmp.com/api/v1/skills/search` | name, description, githubUrl (repository, ref, folder), stars, contentLanguage |
| skills-sh | `skills.sh/api/search` | source (repository), skillId, installs |
| clawhub | `clawhub.ai/api/v1/search` | install.reference (owner/slug; `skills-sh:` entries map to their repository), summary, downloads, installs, stars, isSuspicious, clawHubVerdict |
| skillhub | `skills.palebluedot.live/api/skills` | name, description, githubOwner/Repo, stars, downloads, securityScore, isMalicious |
| claude-plugins | `claude-plugins.dev/api/skills` | name, description, sourceUrl and rawFileUrl (repository, ref, folder), stars, installs |
| github | `api.github.com/search/code` (`filename:SKILL.md`, needs GITHUB_TOKEN) | repository, folder |

Candidates merge on lowercase repository plus slugged name (ClawHub-only skills on
their owner/slug, because ClawHub slugs repeat across owners). The English description and folder win over translations, then the
shortest folder. A merged skill flagged by any source is withheld. Ranking adds
query-term coverage of name and description (name counted twice, the skills
tokenizer), 0.2 × capped log popularity (installs, downloads, or stars/10) and
0.1 per extra source. Lexically unrelated candidates appear only when relevant
ones do not fill the limit. Fan-outs in which every searched source succeeded are
cached in the Cache API for 15 minutes, keyed by keywords, the sorted sources
actually searched and limit; partial ones are not.

Discovery bookkeeping lives in the Skills DO and fails open. Before the fan-out
`market.state` returns sources in a cooldown: three consecutive failures, or one
rate limit, skip a source for 10 minutes, and a success clears its row. After the
fan-out one `market.record` call stores the outcomes, returns installed markers
(same imported origin, else a library skill_id equal to the slugged name) and
records a gap when the library slice had no high-confidence result. Gap rows hold
only the sorted content words and three candidate names, URLs and install
commands; at most 500 rows for 90 days, removed when a later search answers
confidently.

Preview fetches only `raw.githubusercontent.com/<repository>/<ref>/<folder>/SKILL.md`,
SkillHub's detail record for a folder, or ClawHub's file endpoint (with `owner`).
Text over 128 KiB is refused. Review flags are fixed regexes plus the
high-confidence secret detector. Discovery and preview store nothing external.

## Imports and the update watch

`worker/knowledge/skills-import.mjs` copies one folder into the `imported` root,
which `skills.sync` refuses (`import_only`). GitHub imports resolve the ref with
`commits/{ref}` (`application/vnd.github.sha`), list the folder with
`git/trees/{commit}:{folder}?recursive=1` (truncated listings are refused; symlinks
and submodules skipped) and read files from `raw.githubusercontent.com` at the
commit, six at a time. ClawHub imports read `versions/{version}?owner=` for the file
list and verify each download's SHA-256; a `malicious` verdict is refused and any
other non-`clean` status adds `marketplace_suspicious`. Files are chosen SKILL.md
first, then by path, within the sync limits; the rest are listed as skipped.

Without a pin the request is a plan: the DO validates the skill in a dry run (so
secrets, limits and conflicts surface) and nothing is written. With the plan's
commit or version and `accept_flags` covering every review flag, the DO writes the
skill through the sync path with `origin` (source, repository, path, ref, commit,
folder tree SHA or ClawHub version, imported_at, accepted_flags). Existing skills
from another root or origin are never replaced (`skill_exists`). Identical content
at a new pin updates only the origin. `get` returns the origin with operator
trust; that is the point of the operator's approval.

The hourly cron runs the watch in its own `waitUntil`, beside catalogue
maintenance. `imports.due` returns up to five imports not checked for 24 hours (or
never checked under their current pin). GitHub checks resolve the ref; an equal
commit, or an equal folder tree at a new commit, is `current`. Otherwise the folder
is read at the new pin and compared by SHA-256 with the stored manifest; text
changes get unified diffs against the R2 copy (8 KiB per file, 48 KiB per check,
LCS for up to 250,000 line pairs). `imports.checked` stores the result only if the
pin is still current. `report` with `check: true` checks two imports in the
request, which keeps two full snapshots inside the 55-second deadline. Nothing is
applied.


`scripts/skills_sync.py` is Python 3.11+ stdlib plus the repository's standalone
`services.secret_scan` detector, without importing application configuration.
It defaults to the four labeled skill roots. Repeated `--root LABEL=PATH`
selects roots; `--base-url` or MULTILLM_BASE_URL supplies the gateway URL; the key
comes from explicit `--key-file PATH`, taking precedence over
MULTILLM_KNOWLEDGE_API_KEY so rotated-out parent environments cannot win.
Both clients send `User-Agent: multillm-skills/1`, avoiding the Cloudflare rule
that rejects urllib's default user agent. Sync needs an operator key with
`knowledge:manage`; the hook needs only `knowledge:read`.
Only HTTPS or local test HTTP is accepted; redirects are refused.

The bounded frontmatter reader supports scalar strings (plain, single-quoted,
JSON double-quoted) and YAML literal/folded blocks for name/description. It does
not claim to implement arbitrary YAML. Metadata whitespace is collapsed to one
line for the API, while uploaded SKILL.md bytes and hashes remain unchanged.
Other control characters reject the local skill and disable pruning for its root.
Markdown links, inline paths and standard
scripts/references/assets/templates/examples paths collect files recursively
within the folder; unreferenced files are omitted. Absolute paths, `~` prefixes,
any `..` segment and references resolving outside the skill are mentions and
ignored, including in nested files. Missing references remain ignored. Collected
symlinks resolving outside are skipped and counted in `skipped_files`, without
rejecting the skill. Only SKILL.md limits reject a skill: an extra file that is
oversized, beyond 40 files, past the 5 MiB total or past the reference budget is
skipped and counted the same way, so large skills keep their instructions. A SKILL.md escape leaves no uploadable instructions; skip it
and disable pruning for that root without reading its target. Each root scan is capped at
10,000 entries and each skill at 200 discovered references, in addition to the
server's file/byte caps. Duplicate slugs use the first selected root. Matching
SKILL.md SHA-256 hashes increment `duplicates` only; differing hashes yield
`duplicate_conflict` records with slug, kept root and skipped root, not rejections.
The client reserves 4 KiB below the 8 MiB transport cap for the private envelope;
large JSON-escaped text uses base64 so one maximal 5 MiB skill fits a batch.
Batches contain at most 16 skills and 40 files to reduce deadline rejections
during sequential R2 uploads. The server allows 45 seconds per request, and each
skill stays in one batch.

Dry run reads only the selected library and bounded local receipts, prints the
plan, and does not read a key or contact the service. A receipt file (default
`~/.config/multillm/skills-sync-state.json`, overridable with --state-file) tracks only confirmed
successful uploads by root label. Pruning only considers selected, available
roots and previously synced IDs missing locally. Any invalid/unreadable skill
disables pruning for its root, preserving the last safe revision. Atomically
replace receipts after each verified batch with mode 0600; the parent directory
is created with mode 0700. Remote failure does not clear them. Summary output gives
counts by status, duplicates and skipped files, plus every rejected/conflicting
slug and safe reason/root labels, never content or credentials.

## Optional prompt hook

`scripts/hooks/skill_hint.py` reads bounded JSON stdin, selects the prompt and
agent (`turn_id` identifies Codex, or --agent claude/codex), and requests REST
POST find with `mode: "fast"`, `limit: 3`, `min_confidence: "high"`. A daemon worker plus an absolute deadline bounds DNS,
read and decode time; 50 ms of the 1.5 s budget is reserved for formatting and
process overhead. All errors, invalid arguments, timeouts, short prompts below
12 characters, missing configuration and no high-confidence results emit nothing
and exit zero. There is no normalized-score threshold. `--base-url` wins over
MULTILLM_BASE_URL; `--key-file` wins over MULTILLM_KNOWLEDGE_API_KEY. Key-file reads
run inside the same total deadline, and any read/parse error stays silent.

Context is capped at 600 UTF-8 bytes (approximately 150 tokens), uses name,
description's first 100 characters and the get tool/skill_id, and never loads
instructions automatically. Token count is an approximation rather than a
model-specific tokenizer guarantee. Both agents receive JSON:

```json
{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"Relevant skills: Testing - Test behavior (load with knowledge_skills_get skill_id=testing)"}}
```

Verified against public official documentation on 2026-10-07:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks): UserPromptSubmit
  input includes prompt; hookSpecificOutput.additionalContext adds prompt context.
- [Codex hooks](https://developers.openai.com/codex/hooks):
  UserPromptSubmit input adds turn_id and prompt; the same JSON context format
  is accepted. Codex discovers hooks.json next to active config layers and
  requires review/trust for non-managed hooks. Each model-visible hook output
  defaults to approximately 2,500 tokens, with spill/truncation above the threshold.

Installation snippets are in [knowledge-agents.md](../knowledge-agents.md#skills-hub).
Installation is an operator action. Codex hook delivery under the T3 app-server
is unknown and remains optional; MCP retrieval needs no hook.

## Validation and rollout

Local tests cover lexical/hybrid ranking, root filtering, failed embedding,
feedback identity/TTL, paths/integrity, storage and batch bounds, scope enforcement,
REST/MCP parity and toolsets, decoded-secret isolation, immutable revision failure,
cleanup backpressure, SQLite/R2 restart, and the 2,000-skill fast path including
suggestion writes and JSON encoding. Client tests use only temporary skill trees
and a fake loopback HTTP server. Existing Knowledge/Worker and touched Python
suites plus catalogue --check validate integration. No deployed service is tested. The external evaluation uses 495 real-library
records and 39 labeled prompts, kept outside the repository. The implemented
fast index reached none silent 17/17, required first 9/11, acceptable only 10/11.
No skill-specific or prompt-specific rules were introduced.

Before deployment, include the appended DO migration and KNOWLEDGE_SKILLS binding,
retain the existing R2/AI bindings, review resource costs and avoid expiring active
skills objects. Upload from an approved local library with a manage key; use a
read key for prompt hooks. No provider allowance is purchased by a skills call;
Workers AI and R2 use their existing platform billing. Live latency, cloud resource
limits and optional hook delivery remain operator checks after deployment.
