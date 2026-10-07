# Shadow evaluation on opted-in gateway traffic

## Contract and integration

The existing outbound firewall, tool-call repair, image quality judge, answer
memos, product sites, comparison lab, accounted dispatch, judge routing, D1 RPC
and five-minute health schedule are preserved. The existing policy store supports
seed-only writes and has no guarded replacement path. This feature adds that
path with fixed shared SQL, validation, compare-and-swap and atomic backups.

`shadow_eval_rate` mirrors nullable `secret_scan_mode` across AuthService local
schema, key controls, backup restore compatibility and Worker control users.
Null/omitted/zero means no sampling; the range is 0–0.2. Migration 0014 adds the
column plus samples, results, config and policy backup tables. It does not depend
on 0012 or the parallel cascade migration. Cascade eligibility is prefix-only.

Sampling occurs after successful unified chat dispatch (including native Responses
normalization) or the dedicated intelligence response. A single probability draw
per request prevents double sampling. The request callback wraps SSE only for an
opted-in eligible request, forwards identical chunks and submits only a successful
terminal stream. A 32-entry daemon queue stores without blocking the user; queue
full, validation or storage failures drop the sample and never fail the request.

Each sample stores UUID, creation time, key identity, route, deterministic task,
messages/tools/tool_choice/response_format ≤65,536 UTF-8 bytes, production model,
content/tool_calls ≤32,768 bytes, latency and numeric token usage. Task precedence
is declared tools/fences → coding, JSON format → extraction, writing cues →
writing, math/step-by-step → reasoning, otherwise chat. Scan the full original
request and answer, skipping high-confidence or truncated scans; heuristic values
are retained exactly. Both Flask and private D1 ingress enforce the contract.
Samples are inaccessible after seven days and at most 2,000 survive an atomic
insert/eviction transaction. Metadata lists show the newest 20 without text.
Individual sample text requires an explicit admin request. Purge deletes samples
and results after explicit confirmation, retaining allowance counters/backups.

Config has enabled=false, five task candidate lists, judge env override or
free:json, max_replays_per_run=3 and daily_cap=50. Candidate lists allow at most
eight unique provider:model/auto:/cascade: IDs each; per-run count is 1–20 and
daily cap 1–500. Config saves require the previous normalized config. Optional
evaluation daily/monthly USD budgets are separate from the sampled key's budget.

Cron cleans expired D1 records directly, then uses Container.fetchIfRunning for
POST /admin/shadow-eval/run. It never calls waking fetch or renews idle time.
The admin API endpoint uses existing API authentication, not dashboard sessions.
A fresh background request context installs internal:shadow-evaluation. A process
lock plus D1 lease serializes work; transactional claims deduplicate sample/route
and reserve the UTC daily count before calls. Changing config cancels new claims;
purging does not replenish the cap. Crashed/failed claims are not retried.

Candidates reviewed as free/subscription run first, stably within billing classes.
Each replay calls normal unified dispatch through accounted_dispatch, then two
judge calls through the same accounting path. Per-call admission, budgets, route
health, firewall and tool repair remain active. No call is charged to the sampled
key. Background requests cannot sample themselves. The runner starts at most
20 replays, checking a four-minute deadline between calls, with existing dispatch
timeouts and a five-minute lease. Candidate output is limited to 2,048 tokens.

Judges receive task rubric and untrusted request/answers labeled A/B, without
model/key/route metadata. Random ordering is reversed for the second judgment.
Strict JSON has winner A/B/tie, finite confidence 0–1 and ≤3 reasons of ≤160
characters. Consistent judgments produce candidate win/loss/tie; disagreement is
a tie. Malformed responses/call failures yield failed, excluded from ratings.
Reasons and judge text are discarded. Routed free/auto judges use excluding_gemini;
explicit concrete Gemini is permitted. Coding/tool samples count validity through
repair_tool_calls without extracting calls from answer text.

Results contain sample/task, actual candidate/production model, requested candidate
route, outcome, judge identifier, numeric latencies/usage/costs and optional tool
validity counts. Failed attempts retain status, never prompt/answer/judge text.
Results are capped at 10,000/90 days and read in pages of 50. Elo is task-specific,
initial 1500, K=32, chronological with ID tie-breaks. Exported league rows have
wins/losses/ties, comparison count, rounded Elo, median latency, median known USD
cost and tool validity counts. Unknown cost is null.

Proposals validate the current policy, deep-copy it and change only task_scores
for registered candidates with ≥20 valid comparisons in that task. Scores use
round(100/(1+10**((1500-rating)/400))). Chat/extraction are added to the existing
policy task vocabulary. Auto-route suggestions require 20 comparisons for every
route candidate and remain suggestions. Apply requires explicit true confirmation
and the SHA-256 proposal revision, then full policy validation and an atomic
expected-policy update with a pre-update backup; at most 20 backups are retained.
No automatic policy/route write exists. General control-plane exports exclude all
shadow tables, so retained traffic cannot enter exports.

## Reviewed dispatch inventory

/admin/workbench/shadow/{config,league,samples,samples/<identifier>,purge,propose,apply}
are administrator-only storage/aggregation/validation paths, with CSRF on writes,
no-store responses and existing dashboard audit hooks on settings/apply/purge.
/admin/shadow-eval/run is API-admin-only and starts normal accounted unified
candidate/judge dispatch. The private http://intelligence.internal/v1/shadow-eval
handler executes only bounded fixed SQL and does not call providers. The new
scheduled module performs D1 cleanup and fetchIfRunning only. The frozen firewall
inventory includes all new modules/routes and now recognizes Flask get/post/put/
patch/delete decorators as well as route/add_url_rule.

## Explicit adaptations and limitations

* The base had no policy replacement/backup path; migration 0014 includes one
  additional backup table and implements a guarded path instead of reusing a
  nonexistent one.
* Default per-key state is nullable rather than literal 0 to mirror the lead's
  secret_scan_mode decision; both mean disabled.
* High-confidence answer findings and truncated scans also skip capture to avoid
  persisting credentials or incomplete privacy checks.
* Native Responses normalization is sampled at the chat dispatch seam so routed
  traffic is covered without storing protocol-specific fields.
* Replay output is capped at 2,048 tokens, matching the existing lab's bounded
  generation. Runs use a four-minute between-call deadline and five-minute lease;
  an already-running call is governed by the dispatch timeout, not force-killed.
* Result retention, candidate/config bounds, newest-20 metadata lists and capped
  policy backups bound new stores and loops where the original design omitted
  limits. Failed attempts consume the cap and cannot be blindly retried.
* Auto-route orders are suggested only. Explicit Apply changes policy scores;
  a separate normal auto-route edit is required for an order change.
* D1 has no native TTL in this design. Access expiry is strict; physical cleanup
  runs every five-minute cron plus writes/reads/runs, subject to runtime availability.
  Local SQLite cleanup runs on accesses/runs and needs an external timer while idle.
* The task vocabulary gains chat/extraction so those scored tasks pass existing
  policy validation. Quality tiers and other routing policy fields are unchanged.

## Release steps and verification

Apply 0014 before release; reuse existing INTELLIGENCE_DB/private outbound binding,
cron and Container. No new binding or Durable Object migration is required.
Set SHADOW_EVAL_JUDGE_MODEL before first config seed if changing the default;
afterward use dashboard config. Optional SHADOW_EVAL_DAILY_BUDGET_USD and
SHADOW_EVAL_MONTHLY_BUDGET_USD constrain the evaluation principal. Review provider
entitlements and configure candidates, then explicitly enable and opt in keys.
No live provider, remote migration or deployment is part of local verification.

Synthetic Python/Worker acceptance tests cover sampling/probability, normalized
and streaming responses, task/secret/size contracts, TTL/caps/purge, no-wake cron,
leases/daily limits, independent accounting with exactly one ledger row per call,
Gemini exclusions, swapped judging/malformed output, tool validity, known Elo math,
20-comparison thresholds, policy validation/CAS/backups, admin revalidation/CSRF,
explicit apply/purge confirmation and text-free league/metadata exports.

## Source boundaries

New feature modules are at most 205 lines. Two existing integration files remain
over 1,000 lines: cloudflare-worker.mjs (2,128) adds only the schedule import and
waitUntil call; services/auth_service.py (1,208) adds the nullable field to the
existing schema/read/write paths. A whole-file extraction is unsafe within this
feature's scope. The next cohesive boundaries are Worker request/provider
transport orchestration and AuthService account schema/persistence adapters.
