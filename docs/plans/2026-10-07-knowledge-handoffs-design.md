# Cross-agent Knowledge handoffs

## Purpose and ownership

Preserve bounded operator task context between agents and threads without
replaying complete transcripts. Handoffs are separate from shared answer memos
and indexed documentation. The Knowledge Worker owns validation and SQLite
storage; the edge and Flask mirror transport and authentication. Local transcript
extraction and optional model summarization stay outside server storage.

## Record and validation

The saved record is `{id, project, branch, title, created_at, expires_at, source,
sections, summary}`. UUID ids and UTC timestamps are server-generated. Project
is a nonblank string of 1–200 characters, branch defaults to an empty string and
is at most 200, and required title is at most 200. Source requires agent `claude`,
`codex`, `opencode` or `other`; optional thread id is at most 200 characters.
Summary defaults to empty and is at most 4,000 characters. String lengths count
Unicode code points; multiline text is supported, other control characters rejected.

Sections contain goal and state (strings), files `{path, change}` (maximum 100),
decisions (30), failed attempts (30), commands `{command, outcome}` (30), next
steps (30) and open questions (20). Every section string is at most 500
characters. Missing section fields normalize to empty strings or arrays; null,
wrong types, unknown fields and excess counts fail validation. The complete
record, including generated metadata, must fit 32 KiB of serialized UTF-8 JSON.
Local validation reserves the same metadata space before saving.

Save accepts `{project, branch?, title, summary?, sections, source, ttl_days?}`.
TTL is an integer from 1 through 90 days, default 14. List accepts optional
project and a 1–20 integer limit, default 20. Get requires project or id and accepts
optional branch; when both project and id are supplied they must match. Delete
requires id. These strict schemas are declared in `routes/knowledge_handoffs.py` and generated into the Worker MCP catalogue.

## Private storage and dispatch

`KnowledgeHandoffs` wraps `HandoffStore` with SQLite Durable Object storage.
`KNOWLEDGE_HANDOFFS.idFromName(principal.id)` makes records private to the
principal. The table contains an insertion sequence, unique id, project, branch,
creation/expiry timestamps and serialized record, plus project/branch/sequence
and expiry indexes. A synchronous transaction inserts the record, removes
expired rows, retains the newest 50 rows in its project and retains the newest
500 rows in the principal's object. Insertion sequence resolves timestamp ties.
Project filtering and per-project eviction use SQLite ASCII `NOCASE`, preserving
the saved spelling. Branch matching remains case-sensitive. Get/list filter
expiry immediately; physical expiry cleanup happens at the next save. No D1 migration or paid provider is involved.

The binding and `add-knowledge-handoffs` migration are appended after existing
DO migration tags in `wrangler.knowledge.jsonc`. Missing binding or a private
fetch/JSON deadline of two seconds returns `handoffs_unavailable` (503).
Retrieval/provider bindings are not needed for this feature.

The existing Knowledge firewall checks REST bodies and MCP arguments before
dispatch. A high-confidence finding returns HTTP 422 `secret_detected` with
finding types and counts, never secret values. There is deliberately no second
scanner in the handoff handler. Tests prove rejection precedes object creation
and storage. The frozen coverage inventory includes the new Flask routes and
Worker modules; internal DO forwarding is reachable only after service protection.

## MCP and REST contracts

Toolset `handoff` contains `knowledge_handoff_save`, `_get`, `_list`, `_delete`.
Each requires `knowledge:read`, including save/delete; `knowledge:manage` alone
is insufficient. Save/delete are correctly annotated as mutations. All response
envelopes include `trust: "operator"`; this describes provenance, not executable
instructions. MCP instructions gain one self-contained handoff sentence.

Save returns `{id, expires_at, trust}`. Get returns `{record, markdown, trust}`;
when absent or expired, record is null and markdown empty. An exact branch miss
falls back to the newest project record. Id lookup stays scoped to the principal;
project is optional and must match case-insensitively when supplied. Keys share handoffs across clients only if they
belong to the same principal; the shared agent key does. List returns
`{handoffs: [{id, project, branch, title,
source: {agent}, created_at}], trust}`; delete returns `{deleted, trust}` and
is idempotent. The envelopes follow the repository's structured-result pattern.

Compact markdown prioritizes goal, state, next steps and open questions before
files, decisions, failed commands and summary. It is limited to 4,500 UTF-8
bytes using the existing retrieval byte/3 estimate (about 1,500 tokens), without
splitting Unicode characters. The structured record retains all fields. MCP
get's text content is the markdown; its structured content contains the envelope.

REST uses POST/GET `/v1/knowledge/handoffs` for save/list, GET
`/v1/knowledge/handoffs/latest?project=...&branch=...` for newest/fallback, GET
`/v1/knowledge/handoffs/{id}` for id lookup (optional `project` must match), and
DELETE at the same id path without query/body. Unknown or duplicate query fields, save queries and
read/delete bodies are rejected. Shared route fixtures verify edge/Flask parity.

## Local recovery

`scripts/handoff.py` exposes build, save, print and load using Python 3.11+
stdlib. Contracts/rendering, transcript facts and CLI/HTTP orchestration have
separate modules. Project identity parses owner/name from git origin or uses the
cwd name. Git reads branch, HEAD and short status with a two-second timeout.

Build discovers the newest matching Claude project JSONL or Codex
`YYYY/MM/DD/rollout-*.jsonl` session metadata, or accepts an explicit transcript.
Claude directory names replace every non-alphanumeric cwd character with a
hyphen. If absent, discovery scans project JSONL files for a matching cwd in the
first 20 bounded lines. Codex date directories and rollout filenames are checked
newest first, stopping at the first metadata match in the first five lines.
Discovery examines up to 20,000 files per client; lines use the 1 MiB parse cap
and date-directory enumeration is also bounded to 20,000 entries. Parsing accepts
at most 64 MiB total and 1 MiB per line, skips malformed JSON lines, and fails if byte limits are exceeded. These operational
caps bound recovery; large threads need a smaller explicit transcript.

Synthetic fixtures reflect inspected key/type shapes only. Claude Edit/Write/
MultiEdit/NotebookEdit inputs identify files; Bash inputs and failure statuses
identify failed commands. Codex function/custom calls recognize apply_patch
headers and shell commands, matching call ids and bounded shell sessions to
nonzero outputs. Structured exit status takes precedence over text in tool
output. File facts reflect tool inputs, not independent proof a filesystem
mutation completed. At most 100 files, 100 outstanding shell calls, 100 running
sessions, 30 failures and the last three operator user messages are retained. The
first remaining user message becomes goal (500 characters); the final assistant
text becomes state (500) and summary (4,000), redacted before truncation. The
last three user messages are labeled `User:` in decisions. User facts exclude
Claude isMeta/isCompactSummary/isSidechain records, XML-like leading tags,
AGENTS.md instructions, interrupted requests and every non-user role.
No decisions or next steps are inferred in deterministic mode. HEAD and status
appear as command outcomes. Transcript formats can drift; nested tool calls
embedded in arbitrary orchestration JavaScript are not decoded.

Every retained fact is scanned with `services.secret_scan`, with high-confidence
redaction before truncation and another bounded payload redaction before output
or sending. Tool outputs are never copied wholesale. Explicit input JSON and
HTTP bodies/responses are capped at 64 KiB. HTTPS origins are required except
loopback HTTP for local tests; redirects and environment proxies are disabled to
avoid forwarding credentials. Keys come privately from
`MULTILLM_KNOWLEDGE_API_KEY` or an explicit key file; base origin comes from
`MULTILLM_BASE_URL` or `--base-url`. Every request uses
`User-Agent: multillm-handoff/1`; Cloudflare rejects urllib's default agent with
error 1010 (HTTP 403). Errors do not print response bodies or keys.

Optional `--summarize MODEL` sends at most 30,000 characters of sanitized facts
to `/v1/chat/completions`, including the 4,000-character closing summary. It
uses a separate chat key from `--chat-key-file PATH` or `MULTILLM_API_KEY`, with
the same validation as the Knowledge credential. The Knowledge key is never
sent to chat. Without a chat key it prints exactly
`summarize skipped: no chat key` to stderr and preserves deterministic sections.
Only schema-valid, redacted sections fitting the final record are accepted. Oversized input, invalid responses and transport failures preserve
the deterministic sections. This opt-in operation may consume model allowance.

## Optional SessionStart context

The hook accepts stdin JSON with `hook_event_name: "SessionStart"` and cwd.
Only `startup`, `clear`, or an absent source triggers loading; `resume`, `compact`
and other sources emit nothing. It loads the current project's branch/fallback
record and emits only unexpired notes younger than 48 hours. Both clients receive JSON with
`hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: ...}`.
Default `--mode pointer` is at most 600 UTF-8 bytes: project, saved branch, source
agent, age, title clipped to 120 characters and explicit MCP/CLI load instructions.
Long identities use clipped labels and the CLI instruction to preserve that bound.
`--mode full` opts into the existing rendered markdown. Both example matchers are
`startup|clear`.
A supervised daemon worker has a 0.9-second wall deadline, with HTTP timeout
0.8 seconds; all errors and timeouts are silent with exit zero. Process startup
adds a small overhead. Nothing modifies or installs global client configuration.

Current public format references, checked 2026-10-07:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks): common stdin cwd/
  event fields and SessionStart JSON additional context (plain stdout also works).
- [Codex hooks](https://developers.openai.com/codex/hooks): `hooks.json`,
  common stdin fields and the same SessionStart output. Default per-handler
  additional-context threshold is approximately 2,500 tokens; the example sets
  that value explicitly. Non-managed hooks require review/trust.

Configuration snippets live in [Knowledge access for agents](../knowledge-agents.md#handoffs).
Codex hook firing through the T3 app-server is unknown and has not been
validated. MCP get and CLI load remain explicit alternatives.

## Verification and rollout

Tests cover CRUD, branch fallback, principal isolation, transaction eviction,
TTL boundaries, validation/UTF-8 bounds, safe firewall rejection, rendering,
scopes/toolsets, shared REST parity, catalogue generation and real local SQLite
DO persistence/restart/concurrency. Round-2 regressions cover ASCII project
matching/eviction, id-only lookup, schema descriptions and parity, punctuation
and cwd-fallback discovery, newest-first Codex discovery, injected-message
filtering, first-user goals/closing summaries, separate chat authorization,
User-Agent headers, pointer/full output, source gating and UTF-8 pointer bounds.
Local synthetic transcripts exercise facts, redaction, identity, fake-server summary fallback, CLI round trips, redirects,
and silent hook failure/deadlines/output for both clients.

Before release, preserve and apply the appended DO migration and binding on the
private Knowledge Worker, then release the matching main Worker catalogue and
Flask routes. No D1 migration, new provider secret or global hook installation
is required. Live deployed acceptance and optional client hook activation remain
operator steps. No production service was contacted during implementation.

## Review round 2 integration notes

The id-only REST request already forwarded the path id without a project in both
runtimes; relaxing Worker/MCP validation and expanding the shared route fixture
provides that contract without duplicate ingress validation. Project/branch
descriptions appear wherever those fields exist; delete remains an id-only tool
and list has no branch selector. No irrelevant fields were added.

The pointer may omit the inline MCP argument JSON for long identities so it can
stay within 600 bytes; its CLI instruction loads the complete current identity.
Production reachability is covered by the required User-Agent in fake-server
tests, not live requests. No operator credentials or real transcripts were read.
